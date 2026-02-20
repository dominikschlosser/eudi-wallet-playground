/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RequestObjectService {

    private static final Logger LOG = LoggerFactory.getLogger(RequestObjectService.class);
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);
    private final Map<String, StoredRequestObject> store = new ConcurrentHashMap<>();

    public String store(SignedJWT requestObject, JWK signerKey) {
        cleanupExpired();
        String id = UUID.randomUUID().toString();
        store.put(id, new StoredRequestObject(requestObject, signerKey, calculateExpiry(requestObject)));
        return id;
    }

    public ResolvedRequestObject resolve(String id, String walletNonce, SigningRequest signingRequest) {
        cleanupExpired();
        StoredRequestObject stored = store.get(id);
        if (stored == null) {
            return null;
        }
        if (stored.expiresAt().isBefore(Instant.now())) {
            store.remove(id);
            return null;
        }
        SignedJWT source = stored.payload();
        JWTClaimsSet claims = safeClaims(source);
        boolean walletNonceApplied = walletNonce != null && !walletNonce.isBlank();
        try {
            boolean needsSignature = signingRequest != null;
            if (!needsSignature && source.getHeader() != null) {
                needsSignature = (source.getHeader().getX509CertChain() != null && !source.getHeader().getX509CertChain().isEmpty())
                        || source.getHeader().getCustomParam("jwt") != null
                        || source.getHeader().getJWK() != null;
            }
            SigningRequest effectiveSigning = null;
            if (needsSignature) {
                JWSAlgorithm alg = signingRequest != null ? signingRequest.alg() : null;
                if (alg == null && source.getHeader() != null) {
                    alg = source.getHeader().getAlgorithm();
                }
                if (alg == null) {
                    alg = JWSAlgorithm.RS256;
                }
                // Prefer the stored key (it matches the original x5c/JWK headers).
                // Adapt the algorithm to the stored key type if needed.
                JWK key = stored.signerKey();
                if (key == null && signingRequest != null) {
                    key = signingRequest.jwk();
                }
                if (key == null) {
                    LOG.error("No signing key available for request object {}", id);
                } else {
                    alg = algorithmForKey(key, alg);
                    effectiveSigning = new SigningRequest(alg, key);
                }
            }
            if (walletNonceApplied) {
                JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(claims);
                builder.claim("wallet_nonce", walletNonce);
                claims = builder.build();
            }
            JWSAlgorithm requestedAlg = effectiveSigning != null ? effectiveSigning.alg() : null;
            if (requestedAlg == null) {
                PlainJWT plain = new PlainJWT(claims);
                return new ResolvedRequestObject(plain.serialize(), walletNonceApplied, claims, false);
            }
            JWSHeader.Builder header = new JWSHeader.Builder(requestedAlg)
                    .type(source.getHeader() != null ? source.getHeader().getType() : null);
            if (effectiveSigning != null && effectiveSigning.jwk() != null) {
                boolean hasX5c = source.getHeader() != null && source.getHeader().getX509CertChain() != null
                        && !source.getHeader().getX509CertChain().isEmpty();
                if (hasX5c) {
                    // x509_hash / x509_san_dns: the spec requires x5c for trust establishment.
                    // Omit jwk to avoid ambiguity — the wallet should verify via the x5c chain.
                    header.x509CertChain(source.getHeader().getX509CertChain());
                } else {
                    header.jwk(effectiveSigning.jwk().toPublicJWK());
                }
                if (effectiveSigning.jwk().getKeyID() != null) {
                    header.keyID(effectiveSigning.jwk().getKeyID());
                }
            }
            if (source.getHeader() != null && source.getHeader().getCustomParams() != null) {
                source.getHeader().getCustomParams().forEach(header::customParam);
            }
            SignedJWT reSigned = new SignedJWT(header.build(), claims);
            boolean signed = applySignature(reSigned, effectiveSigning);
            return new ResolvedRequestObject(reSigned.serialize(), walletNonceApplied, claims, signed);
        } catch (Exception e) {
            LOG.warn("Failed to re-sign request object with wallet_nonce: {}", e.getMessage(), e);
            if (walletNonceApplied) {
                // OID4VP 1.0 Section 5.10: "When received, the Verifier MUST use it as the
                // wallet_nonce value in the signed authorization request object."
                // Returning the original without wallet_nonce would cause the wallet to reject it.
                throw new IllegalStateException("Failed to re-sign request object with wallet_nonce", e);
            }
            return new ResolvedRequestObject(source.serialize(), false, claims, source != null);
        }
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        store.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    private Instant calculateExpiry(SignedJWT jwt) {
        Instant expires = Instant.now().plus(DEFAULT_TTL);
        try {
            if (jwt.getJWTClaimsSet() != null && jwt.getJWTClaimsSet().getExpirationTime() != null) {
                Instant claimExp = jwt.getJWTClaimsSet().getExpirationTime().toInstant();
                if (claimExp.isBefore(expires)) {
                    expires = claimExp;
                }
            }
        } catch (Exception ignored) {
        }
        return expires;
    }

    private JWTClaimsSet safeClaims(SignedJWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (Exception e) {
            return new JWTClaimsSet.Builder().build();
        }
    }

    private boolean applySignature(SignedJWT jwt, SigningRequest signingRequest) {
        if (jwt == null || signingRequest == null || signingRequest.jwk() == null) {
            return false;
        }
        try {
            JWK jwk = signingRequest.jwk();
            if (jwk instanceof RSAKey rsa) {
                jwt.sign(new RSASSASigner(rsa));
                return true;
            }
            if (jwk instanceof ECKey ec) {
                jwt.sign(new ECDSASigner(ec));
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns the given algorithm if it is compatible with the key type,
     * otherwise returns a default algorithm matching the key.
     */
    private JWSAlgorithm algorithmForKey(JWK key, JWSAlgorithm requested) {
        String name = requested.getName().toUpperCase();
        if (key instanceof ECKey && !name.startsWith("ES")) {
            return JWSAlgorithm.ES256;
        }
        if (key instanceof RSAKey && !(name.startsWith("RS") || name.startsWith("PS"))) {
            return JWSAlgorithm.RS256;
        }
        return requested;
    }

    private record StoredRequestObject(SignedJWT payload, JWK signerKey, Instant expiresAt) {
    }

    public record ResolvedRequestObject(String serialized, boolean walletNonceApplied, JWTClaimsSet claims, boolean signed) {
    }

    public record SigningRequest(JWSAlgorithm alg, JWK jwk) {
    }
}
