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
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import tools.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class VerifierAuthService {
    private final VerifierKeyService verifierKeyService;
    private final VerifierCryptoService verifierCryptoService;
    private final RequestObjectService requestObjectService;
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;

    public VerifierAuthService(VerifierKeyService verifierKeyService,
                               VerifierCryptoService verifierCryptoService,
                               RequestObjectService requestObjectService,
                               VerifierProperties properties,
                               ObjectMapper objectMapper) {
        this.verifierKeyService = verifierKeyService;
        this.verifierCryptoService = verifierCryptoService;
        this.requestObjectService = requestObjectService;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public WalletAuthRequest buildWalletAuthorizationUrl(URI callback, String state, String nonce,
                                                         String dcqlQuery,
                                                         String walletAuthOverride,
                                                         String effectiveClientId,
                                                         String authType,
                                                         String clientMetadata,
                                                         String walletClientCert,
                                                         String attestationCert,
                                                         String attestationIssuer,
                                                         String responseTypeOverride,
                                                         String responseModeOverride,
                                                         String requestObjectMode,
                                                         String requestUriMethod,
                                                         String walletAudience,
                                                         String verifierInfo,
                                                         UriComponentsBuilder baseUri) {
        String effectiveWalletAuth = walletAuthOverride != null && !walletAuthOverride.isBlank()
                ? walletAuthOverride
                : properties.walletAuthEndpoint();
        String attestationValue = null;
        String effectiveResponseType = responseTypeOverride != null && !responseTypeOverride.isBlank()
                ? responseTypeOverride
                : "vp_token";
        String effectiveResponseMode = responseModeOverride != null && !responseModeOverride.isBlank()
                ? responseModeOverride
                : "direct_post";
        // OID4VP 1.0 (published 9 July 2025), Section 5.8: for static discovery metadata the aud MUST be "https://self-issued.me/v2".
        String effectiveAudience = walletAudience != null && !walletAudience.isBlank()
                ? walletAudience
                : "https://self-issued.me/v2";
        boolean usedRequestUri = false;
        if ("verifier_attestation".equalsIgnoreCase(authType)) {
            requestObjectMode = "request_uri";
        }
        RequestObjectMode parsedMode = RequestObjectMode.fromString(requestObjectMode);
        UriComponentsBuilder builder = effectiveWalletAuth != null && !effectiveWalletAuth.isBlank()
                ? UriComponentsBuilder.fromUriString(effectiveWalletAuth)
                : baseUri.cloneBuilder().path("/oid4vp/auth");
        UriComponentsBuilder populated = builder.queryParam("client_id", qp(effectiveClientId));

        if ("x509_hash".equalsIgnoreCase(authType) || "x509_san_dns".equalsIgnoreCase(authType)) {
            JWK popKey = verifierCryptoService.parsePrivateKeyWithCertificate(walletClientCert);
            List<Base64> x5c = verifierCryptoService.extractCertChain(walletClientCert).stream()
                    .map(Base64::new)
                    .toList();
            if (x5c.isEmpty()) {
                throw new IllegalStateException("client_cert must include a certificate chain for x509-bound client_id");
            }
            BuiltRequestObject requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType,
                    effectiveResponseMode, dcqlQuery, clientMetadata, null, x5c, popKey, effectiveAudience, verifierInfo);
            usedRequestUri = populateWithRequestObject(populated, requestObject, requestObjectMode, requestUriMethod, baseUri);
        } else if ("verifier_attestation".equalsIgnoreCase(authType)) {
            JWK popKey = verifierKeyService.loadOrCreateSigningKey();
            JWK attestationSignerKey = verifierKeyService.loadOrCreateSigningKey();
            if (attestationCert != null && !attestationCert.isBlank()) {
                attestationSignerKey = verifierCryptoService.parsePrivateKeyWithCertificate(attestationCert);
            }
            attestationValue = createVerifierAttestation(effectiveClientId, attestationIssuer, attestationSignerKey, popKey, callback.toString());
            BuiltRequestObject requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType,
                    effectiveResponseMode, dcqlQuery, clientMetadata, attestationValue, null, popKey, effectiveAudience, verifierInfo);
            usedRequestUri = populateWithRequestObject(populated, requestObject, requestObjectMode, requestUriMethod, baseUri);
        } else {
            if (parsedMode == RequestObjectMode.REQUEST_URI) {
                JWK signerKey = verifierKeyService.loadOrCreateSigningKey();
                BuiltRequestObject requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType,
                        effectiveResponseMode, dcqlQuery, clientMetadata, null, null, signerKey, effectiveAudience, verifierInfo);
                usedRequestUri = populateWithRequestObject(populated, requestObject, requestObjectMode, requestUriMethod, baseUri);
            } else {
                populated
                        .queryParam("response_type", qp(effectiveResponseType))
                        .queryParam("nonce", qp(nonce))
                        .queryParam("response_mode", qp(effectiveResponseMode))
                        .queryParam("response_uri", qp(callback.toString()))
                        .queryParam("state", qp(state));
                populated.queryParam("dcql_query", qp(dcqlQuery));
                if (clientMetadata != null && !clientMetadata.isBlank()) {
                    populated.queryParam("client_metadata", qp(clientMetadata));
                }
                if (walletClientCert != null && !walletClientCert.isBlank()) {
                    populated.queryParam("client_cert", qp(walletClientCert));
                }
            }
        }
        return new WalletAuthRequest(populated.build(true).toUri(), authType != null && authType.equalsIgnoreCase("verifier_attestation") ? attestationValue : null, usedRequestUri);
    }

    private boolean populateWithRequestObject(UriComponentsBuilder builder, BuiltRequestObject requestObject, String requestObjectMode, String requestUriMethod, UriComponentsBuilder baseUri) {
        RequestObjectMode mode = RequestObjectMode.fromString(requestObjectMode);
        if (mode == RequestObjectMode.REQUEST_URI) {
            String id = requestObjectService.store(requestObject.jwt(), requestObject.signerKey());
            URI requestUri = baseUri.cloneBuilder()
                    .path("/verifier/request-object/{id}")
                    .buildAndExpand(id)
                    .toUri();
            builder.queryParam("request_uri", qp(requestUri.toString()));
            if (requestUriMethod != null && !requestUriMethod.isBlank()) {
                builder.queryParam("request_uri_method", qp(requestUriMethod));
            }
            return true;
        } else {
            builder.queryParam("request", qp(requestObject.jwt().serialize()));
            return false;
        }
    }

    private BuiltRequestObject buildRequestObject(String responseUri, String state, String nonce,
                                                  String clientId, String responseType, String responseMode,
                                                  String dcqlQuery,
                                                  String clientMetadata, String attestationJwt,
                                                  List<Base64> x5c,
                                                  JWK signerKey,
                                                  String audience,
                                                  String verifierInfo) {
        try {
            JWSAlgorithm alg = resolveAlg(signerKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(alg)
                    .type(new JOSEObjectType("oauth-authz-req+jwt"));
            if (attestationJwt != null && !attestationJwt.isBlank()) {
                headerBuilder.customParam("jwt", attestationJwt);
            }
            if (x5c != null && !x5c.isEmpty()) {
                // x509_hash / x509_san_dns: the spec requires x5c for trust establishment.
                // Omit jwk to avoid ambiguity — the wallet should verify via the x5c chain.
                headerBuilder.x509CertChain(x5c);
            } else {
                headerBuilder.jwk(signerKey.toPublicJWK());
            }
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .claim("client_id", clientId)
                    .claim("response_type", responseType)
                    .claim("response_mode", responseMode)
                    .claim("response_uri", responseUri)
                    .claim("state", state)
                    .claim("nonce", nonce);
            if (audience != null && !audience.isBlank()) {
                claims.audience(audience);
            }
            if (dcqlQuery != null && !dcqlQuery.isBlank()) {
                try {
                    claims.claim("dcql_query", parseJsonClaim(dcqlQuery));
                } catch (Exception e) {
                    claims.claim("dcql_query", dcqlQuery);
                }
            }
            if (clientMetadata != null && !clientMetadata.isBlank()) {
                try {
                    claims.claim("client_metadata", parseJsonClaim(clientMetadata));
                } catch (Exception e) {
                    claims.claim("client_metadata", clientMetadata);
                }
            }
            // verifier_info: array of attestation objects about the verifier (e.g., registration certificates)
            if (verifierInfo != null && !verifierInfo.isBlank()) {
                try {
                    claims.claim("verifier_info", parseJsonClaim(verifierInfo));
                } catch (Exception e) {
                    // If parsing fails, skip verifier_info rather than failing the whole request
                }
            }
            claims.expirationTime(Date.from(Instant.now().plusSeconds(600)));
            SignedJWT jwt = new SignedJWT(headerBuilder.build(), claims.build());
            if (signerKey instanceof RSAKey rsaKey) {
                jwt.sign(new RSASSASigner(rsaKey));
            } else if (signerKey instanceof ECKey ecKey) {
                jwt.sign(new ECDSASigner(ecKey));
            } else {
                throw new IllegalStateException("Unsupported signer key");
            }
            return new BuiltRequestObject(jwt, signerKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build request object", e);
        }
    }

    private Object parseJsonClaim(String json) throws IOException {
        if (json == null || json.isBlank()) {
            return null;
        }
        // JWTClaimsSet expects JSON-compatible Java types (Map/List/String/Number/Boolean), not Jackson JsonNode instances.
        return objectMapper.readValue(json, Object.class);
    }

    private String createVerifierAttestation(String clientIdWithPrefix,
                                             String issuerOverride,
                                             JWK attestationSignerKey,
                                             JWK proofOfPossessionKey,
                                             String responseUri) {
        try {
            String issuer = issuerOverride != null && !issuerOverride.isBlank() ? issuerOverride : "demo-attestation-issuer";
            String baseClientId = clientIdWithPrefix.startsWith("verifier_attestation:")
                    ? clientIdWithPrefix.substring("verifier_attestation:".length())
                    : clientIdWithPrefix;
            if (proofOfPossessionKey == null) {
                throw new IllegalStateException("Missing proof-of-possession key for verifier_attestation");
            }
            String kid = attestationSignerKey.getKeyID();
            if ((kid == null || kid.isBlank()) && attestationSignerKey instanceof RSAKey rsaKey) {
                kid = Base64URL.encode(rsaKey.toRSAPublicKey().getEncoded()).toString();
                attestationSignerKey = new RSAKey.Builder(rsaKey.toRSAPublicKey())
                        .privateKey(rsaKey.toRSAPrivateKey())
                        .keyID(kid)
                        .build();
            } else if ((kid == null || kid.isBlank()) && attestationSignerKey instanceof ECKey ecKey) {
                attestationSignerKey = new ECKey.Builder(ecKey.getCurve(), ecKey.toECPublicKey())
                        .privateKey(ecKey.toECPrivateKey())
                        .keyIDFromThumbprint()
                        .build();
                kid = attestationSignerKey.getKeyID();
            }
            JWSAlgorithm alg = resolveAlg(attestationSignerKey);
            JWSHeader header = new JWSHeader.Builder(alg)
                    .type(JOSEObjectType.JWT)
                    .jwk(attestationSignerKey.toPublicJWK())
                    .build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(baseClientId)
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                    .claim("cnf", Map.of("jwk", proofOfPossessionKey.toPublicJWK().toJSONObject()))
                    .claim("redirect_uris", responseUri != null && !responseUri.isBlank() ? List.of(responseUri) : List.of())
                    .build();
            SignedJWT att = new SignedJWT(header, claims);
            if (attestationSignerKey instanceof RSAKey rsaKey) {
                att.sign(new RSASSASigner(rsaKey));
            } else if (attestationSignerKey instanceof ECKey ecKey) {
                att.sign(new ECDSASigner(ecKey));
            } else {
                throw new IllegalStateException("Unsupported attestation signing key");
            }
            return att.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create verifier attestation", e);
        }
    }

    private String qp(String value) {
        return value == null ? null : UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }

    private JWSAlgorithm resolveAlg(JWK signerKey) {
        if (signerKey == null) {
            return JWSAlgorithm.RS256;
        }
        if (signerKey.getAlgorithm() instanceof JWSAlgorithm alg) {
            return alg;
        }
        if (signerKey instanceof RSAKey) {
            return JWSAlgorithm.RS256;
        }
        if (signerKey instanceof ECKey ecKey) {
            Curve curve = ecKey.getCurve();
            if (Curve.P_384.equals(curve)) {
                return JWSAlgorithm.ES384;
            }
            if (Curve.P_521.equals(curve)) {
                return JWSAlgorithm.ES512;
            }
            return JWSAlgorithm.ES256;
        }
        return JWSAlgorithm.RS256;
    }

    public record WalletAuthRequest(URI uri, String attestationJwt, boolean usedRequestUri) {
    }

    public record BuiltRequestObject(SignedJWT jwt, JWK signerKey) {
    }

    public enum RequestObjectMode {
        BY_VALUE,
        REQUEST_URI;

        static RequestObjectMode fromString(String value) {
            if (value != null && value.equalsIgnoreCase("request_uri")) {
                return REQUEST_URI;
            }
            return BY_VALUE;
        }
    }
}
