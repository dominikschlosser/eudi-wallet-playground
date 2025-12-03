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
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RequestObjectService {
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
            if (needsSignature && stored.signerKey() != null) {
                JWSAlgorithm alg = signingRequest != null ? signingRequest.alg() : null;
                if (alg == null && source.getHeader() != null) {
                    alg = source.getHeader().getAlgorithm();
                }
                if (alg == null) {
                    alg = JWSAlgorithm.RS256;
                }
                effectiveSigning = new SigningRequest(alg, stored.signerKey());
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
                header.jwk(effectiveSigning.jwk().toPublicJWK());
                if (effectiveSigning.jwk().getKeyID() != null) {
                    header.keyID(effectiveSigning.jwk().getKeyID());
                }
                if (effectiveSigning.jwk() instanceof RSAKey && source.getHeader() != null && source.getHeader().getX509CertChain() != null) {
                    header.x509CertChain(source.getHeader().getX509CertChain());
                }
            }
            if (source.getHeader() != null && source.getHeader().getCustomParams() != null) {
                source.getHeader().getCustomParams().forEach(header::customParam);
            }
            SignedJWT reSigned = new SignedJWT(header.build(), claims);
            boolean signed = applySignature(reSigned, effectiveSigning);
            return new ResolvedRequestObject(reSigned.serialize(), walletNonceApplied, claims, signed);
        } catch (Exception e) {
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

    private record StoredRequestObject(SignedJWT payload, JWK signerKey, Instant expiresAt) {
    }

    public record ResolvedRequestObject(String serialized, boolean walletNonceApplied, JWTClaimsSet claims, boolean signed) {
    }

    public record SigningRequest(JWSAlgorithm alg, JWK jwk) {
    }
}
