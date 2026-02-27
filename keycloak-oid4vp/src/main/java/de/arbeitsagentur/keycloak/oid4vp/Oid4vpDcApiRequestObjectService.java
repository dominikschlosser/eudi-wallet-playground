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
package de.arbeitsagentur.keycloak.oid4vp;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.JsonNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class Oid4vpDcApiRequestObjectService {
    private static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    private final KeycloakSession session;
    private final ObjectMapper objectMapper;

    public Oid4vpDcApiRequestObjectService(KeycloakSession session, ObjectMapper objectMapper) {
        this.session = Objects.requireNonNull(session);
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    public DcApiRequestObject buildRequestObject(Oid4vpConfig config, String origin, String clientId, String state, String nonce, int lifespanSeconds) {
        if (config == null) {
            return null;
        }
        String mode = config.dcApiRequestMode();
        if (mode == null || mode.isBlank() || "auto".equalsIgnoreCase(mode)) {
            try {
                return buildSignedRequestObject(config, origin, clientId, state, nonce, lifespanSeconds);
            } catch (Exception e) {
                return null;
            }
        }
        if ("unsigned".equalsIgnoreCase(mode)) {
            return null;
        }
        if ("signed".equalsIgnoreCase(mode)) {
            return buildSignedRequestObject(config, origin, clientId, state, nonce, lifespanSeconds);
        }
        throw new IllegalArgumentException("Unsupported dcApiRequestMode: " + mode);
    }

    public record DcApiRequestObject(String requestObjectJwt, String responseEncryptionPrivateJwk, String responseUri) {
    }

    /**
     * Result of decrypting an encrypted response, including the optional
     * {@code mdoc_generated_nonce} extracted from the JWE {@code apu} header.
     */
    public record DecryptedResponse(JsonNode payload, String mdocGeneratedNonce) {}

    /**
     * Decrypt an encrypted response JWT using the provided private key.
     * Supports both EC keys (ECDH-ES) and RSA keys (RSA-OAEP-256).
     * Extracts the {@code mdoc_generated_nonce} from the JWE {@code apu} header if present.
     */
    public DecryptedResponse decryptEncryptedResponse(String encryptedResponseJwt, String responseEncryptionPrivateJwk) {
        if (encryptedResponseJwt == null || encryptedResponseJwt.isBlank()) {
            throw new IllegalArgumentException("Missing encrypted response");
        }
        if (responseEncryptionPrivateJwk == null || responseEncryptionPrivateJwk.isBlank()) {
            throw new IllegalStateException("Missing response encryption key");
        }
        try {
            JWEObject jwe = JWEObject.parse(encryptedResponseJwt);
            // Detect key type from the JWK and use appropriate decrypter
            if (responseEncryptionPrivateJwk.contains("\"kty\":\"EC\"") ||
                responseEncryptionPrivateJwk.contains("\"kty\": \"EC\"")) {
                ECKey privateKey = ECKey.parse(responseEncryptionPrivateJwk);
                jwe.decrypt(new ECDHDecrypter(privateKey));
            } else {
                RSAKey privateKey = RSAKey.parse(responseEncryptionPrivateJwk);
                jwe.decrypt(new RSADecrypter(privateKey.toRSAPrivateKey()));
            }
            String mdocGeneratedNonce = extractApuNonce(jwe);
            JsonNode payload = objectMapper.readTree(jwe.getPayload().toString());
            return new DecryptedResponse(payload, mdocGeneratedNonce);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt encrypted response", e);
        }
    }

    private String extractApuNonce(JWEObject jwe) {
        try {
            com.nimbusds.jose.util.Base64URL apu = jwe.getHeader().getAgreementPartyUInfo();
            if (apu != null) {
                return new String(apu.decode(), java.nio.charset.StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            // apu extraction is best-effort
        }
        return null;
    }

    private DcApiRequestObject buildSignedRequestObject(Oid4vpConfig config, String origin, String clientId, String state, String nonce, int lifespanSeconds) {
        if (config == null) {
            throw new IllegalArgumentException("config must not be null");
        }
        String effectiveClientId = config.dcApiClientId() != null && !config.dcApiClientId().isBlank()
                ? config.dcApiClientId()
                : clientId;
        if (effectiveClientId == null || effectiveClientId.isBlank()) {
            throw new IllegalStateException("Unable to determine client_id for signed DC API request object");
        }
        if (origin == null || origin.isBlank()) {
            throw new IllegalStateException("Unable to determine current origin for expected_origins");
        }

        ECKey responseEncryptionKey = createResponseEncryptionKey();

        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = Instant.now().plusSeconds(lifespanSeconds).getEpochSecond();
        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", effectiveClientId);
        claims.put("expected_origins", List.of(origin));
        claims.put("client_id", effectiveClientId);
        claims.put("response_type", "vp_token");
        claims.put("response_mode", "dc_api.jwt");
        claims.put("response_uri", origin + "/");
        claims.put("nonce", nonce);
        claims.put("state", state);
        claims.put("client_metadata", buildEncryptedResponseClientMetadata(responseEncryptionKey));

        String dcqlQuery = config.dcqlQuery();
        if (dcqlQuery != null && !dcqlQuery.isBlank()) {
            claims.put("dcql_query", parseJsonClaim(dcqlQuery));
        }

        // verifier_info: array of attestation objects about the verifier (e.g., registration certificates)
        String verifierInfo = config.verifierInfo();
        if (verifierInfo != null && !verifierInfo.isBlank()) {
            Object parsedVerifierInfo = parseJsonClaim(verifierInfo);
            if (parsedVerifierInfo != null) {
                claims.put("verifier_info", parsedVerifierInfo);
            }
        }

        String dcApiResponseUri = origin + "/";
        try {
            String jwt;
            // Use x509 signing key from PEM if available (HAIP-compliant ES256 signing)
            if (config.x509SigningKeyJwk() != null && !config.x509SigningKeyJwk().isBlank()) {
                ECKey ecSigningKey = ECKey.parse(config.x509SigningKeyJwk());
                JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(REQUEST_OBJECT_TYP))
                        .keyID(ecSigningKey.getKeyID());
                if (ecSigningKey.getX509CertChain() != null && !ecSigningKey.getX509CertChain().isEmpty()) {
                    headerBuilder.x509CertChain(ecSigningKey.getX509CertChain());
                }
                JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
                for (var entry : claims.entrySet()) {
                    claimsSetBuilder.claim(entry.getKey(), entry.getValue());
                }
                SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsSetBuilder.build());
                signedJWT.sign(new ECDSASigner(ecSigningKey));
                jwt = signedJWT.serialize();
            } else {
                // Fallback to realm signing key
                KeyWrapper signingKey = resolveSigningKey(config.dcApiSigningKeyId());
                JWSBuilder builder = new JWSBuilder()
                        .type(REQUEST_OBJECT_TYP)
                        .kid(signingKey.getKid());
                if (signingKey.getCertificateChain() != null && !signingKey.getCertificateChain().isEmpty()) {
                    builder = builder.x5c(signingKey.getCertificateChain());
                } else if (signingKey.getPublicKey() != null) {
                    builder = builder.jwk(toPublicJwk(signingKey));
                }
                jwt = builder
                        .jsonContent(claims)
                        .sign(new AsymmetricSignatureSignerContext(signingKey));
            }
            return new DcApiRequestObject(jwt, responseEncryptionKey.toJSONString(), dcApiResponseUri);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign DC API request object", e);
        }
    }

    private Object parseJsonClaim(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            return json;
        }
    }

    private KeyWrapper resolveSigningKey(String preferredKid) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalStateException("Missing realm context");
        }
        if (preferredKid != null && !preferredKid.isBlank()) {
            return session.keys()
                    .getKeysStream(realm)
                    .filter(key -> preferredKid.equals(key.getKid()))
                    .filter(key -> KeyUse.SIG.equals(key.getUse()))
                    .filter(key -> key.getPrivateKey() != null)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Signing key not found in realm keys: kid=" + preferredKid));
        }
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, realm.getDefaultSignatureAlgorithm());
        if (key == null) {
            throw new IllegalStateException("No active realm signing key found for algorithm " + realm.getDefaultSignatureAlgorithm());
        }
        return key;
    }

    private JWK toPublicJwk(KeyWrapper key) {
        if (key == null || key.getPublicKey() == null) {
            throw new IllegalArgumentException("Missing public key");
        }
        String algorithm = key.getAlgorithmOrDefault();
        JWKBuilder builder = JWKBuilder.create()
                .kid(key.getKid())
                .algorithm(algorithm);

        String publicAlgorithm = key.getPublicKey().getAlgorithm();
        if (publicAlgorithm != null && publicAlgorithm.equalsIgnoreCase("RSA")) {
            return builder.rsa(key.getPublicKey(), KeyUse.SIG);
        }
        if (publicAlgorithm != null && publicAlgorithm.equalsIgnoreCase("EC")) {
            return builder.ec(key.getPublicKey(), KeyUse.SIG);
        }
        throw new IllegalStateException("Unsupported signing public key algorithm: " + publicAlgorithm);
    }

    /**
     * Create an EC key for ECDH-ES key agreement.
     * Per HAIP Section 5-2.5, ECDH-ES must be used for response encryption.
     */
    private ECKey createResponseEncryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    private Object buildEncryptedResponseClientMetadata(ECKey responseEncryptionKey) {
        if (responseEncryptionKey == null) {
            return new LinkedHashMap<>();
        }
        var meta = new LinkedHashMap<String, Object>();

        // Build the public key JWK with explicit alg and use fields
        ECKey publicKey = responseEncryptionKey.toPublicJWK();
        Map<String, Object> jwk = new LinkedHashMap<>(publicKey.toJSONObject());
        jwk.put("alg", JWEAlgorithm.ECDH_ES.getName());
        jwk.put("use", "enc");
        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", List.of(jwk));
        meta.put("jwks", jwks);

        // OID4VP 1.0: encrypted_response_enc_values_supported declares supported content encryption methods
        // HAIP Section 5-2.5: MUST support A128GCM and A256GCM
        // The key agreement algorithm (ECDH-ES) is conveyed via the JWK's "alg" field
        meta.put("encrypted_response_enc_values_supported", List.of(
                EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()));

        // vp_formats_supported declares which credential formats the verifier can accept
        // Required per OID4VP 1.0 Section 11.1
        var vpFormats = new LinkedHashMap<String, Object>();
        vpFormats.put("dc+sd-jwt", Map.of("sd-jwt_alg_values", List.of("ES256"), "kb-jwt_alg_values", List.of("ES256")));
        vpFormats.put("mso_mdoc", Map.of("alg", List.of("ES256")));
        meta.put("vp_formats_supported", vpFormats);
        return meta;
    }
}
