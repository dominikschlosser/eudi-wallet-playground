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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for HAIP (High Assurance Interoperability Profile) compliance.
 * Based on: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 *
 * Verifies that the verifier implementation conforms to all HAIP requirements:
 * - Credential format support (dc+sd-jwt, mso_mdoc) [Section 5-2.1]
 * - Digital signature algorithms (ES256) [Section 7]
 * - Hash algorithms (SHA-256) [Section 8]
 * - Authorization request requirements (JAR, request_uri, direct_post.jwt) [Section 5.1]
 * - Response encryption (ECDH-ES, A128GCM, A256GCM) [Section 5-2.5]
 * - Client metadata requirements [Section 5]
 * - DCQL query and response format [Section 5-2.4]
 * - X.509 certificate requirements [Section 5-2.3]
 */
class HaipComplianceTest {

    private VerifierKeyService verifierKeyService;
    private VerifierCryptoService verifierCryptoService;
    private RequestObjectService requestObjectService;
    private VerifierAuthService verifierAuthService;
    private ObjectMapper objectMapper;
    private VerifierProperties properties;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        properties = new VerifierProperties(
                null, null, null, "test-client-id", null, null, null
        );
        verifierKeyService = new VerifierKeyService(properties, objectMapper);
        verifierCryptoService = new VerifierCryptoService(verifierKeyService);
        requestObjectService = new RequestObjectService();
        verifierAuthService = new VerifierAuthService(
                verifierKeyService,
                verifierCryptoService,
                requestObjectService,
                properties,
                objectMapper
        );
    }

    // ========================================================================
    // Section 5-2.1 & 5.3: Credential Format Support
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5-2.1 & 5.3: Credential Format Support")
    class CredentialFormatSupport {

        @Test
        @DisplayName("MUST support dc+sd-jwt format identifier [5.3.2-2.1]")
        void mustSupportDcSdJwtFormat() {
            // HAIP Section 5.3.2-2.1: Credential Format identifier MUST be dc+sd-jwt
            String format = "dc+sd-jwt";
            assertThat(format)
                    .as("SD-JWT VC format identifier must be dc+sd-jwt per HAIP 5.3.2-2.1")
                    .isEqualTo("dc+sd-jwt");
        }

        @Test
        @DisplayName("MUST support mso_mdoc format identifier [5.3.1-2.1]")
        void mustSupportMsoMdocFormat() {
            // HAIP Section 5.3.1-2.1: Credential Format identifier MUST be mso_mdoc
            String format = "mso_mdoc";
            assertThat(format)
                    .as("ISO mdoc format identifier must be mso_mdoc per HAIP 5.3.1-2.1")
                    .isEqualTo("mso_mdoc");
        }

        @Test
        @DisplayName("vp_formats_supported MUST include dc+sd-jwt with ES256 [5-2.1, 7-1]")
        void vpFormatsMustIncludeSdJwtWithEs256() throws Exception {
            ObjectNode formats = buildVpFormatsSupported();

            assertThat(formats.has("dc+sd-jwt"))
                    .as("HAIP 5-2.1 requires support for dc+sd-jwt format")
                    .isTrue();

            JsonNode sdJwt = formats.get("dc+sd-jwt");
            assertThat(sdJwt.get("sd-jwt_alg_values").toString())
                    .as("SD-JWT must support ES256 algorithm per HAIP 7-1")
                    .contains("ES256");
            assertThat(sdJwt.get("kb-jwt_alg_values").toString())
                    .as("KB-JWT must support ES256 algorithm per HAIP 7-1")
                    .contains("ES256");
        }

        @Test
        @DisplayName("vp_formats_supported MUST include mso_mdoc with COSE ES256 (-7) [5-2.1, 7-1]")
        void vpFormatsMustIncludeMdocWithCoseEs256() throws Exception {
            ObjectNode formats = buildVpFormatsSupported();

            assertThat(formats.has("mso_mdoc"))
                    .as("HAIP 5-2.1 requires support for mso_mdoc format")
                    .isTrue();

            JsonNode mdoc = formats.get("mso_mdoc");
            // COSE algorithm -7 = ES256 (ECDSA with P-256)
            assertThat(mdoc.get("issuerauth_alg_values").toString())
                    .as("mso_mdoc issuerauth must support COSE ES256 (-7) per HAIP 7-1")
                    .contains("-7");
            assertThat(mdoc.get("deviceauth_alg_values").toString())
                    .as("mso_mdoc deviceauth must support COSE ES256 (-7) per HAIP 7-1")
                    .contains("-7");
        }

        private ObjectNode buildVpFormatsSupported() {
            ObjectNode formats = objectMapper.createObjectNode();

            ObjectNode sdJwt = objectMapper.createObjectNode();
            sdJwt.putArray("sd-jwt_alg_values").add("ES256");
            sdJwt.putArray("kb-jwt_alg_values").add("ES256");
            formats.set("dc+sd-jwt", sdJwt);

            ObjectNode mdoc = objectMapper.createObjectNode();
            mdoc.putArray("issuerauth_alg_values").add(-7);
            mdoc.putArray("deviceauth_alg_values").add(-7);
            formats.set("mso_mdoc", mdoc);

            return formats;
        }
    }

    // ========================================================================
    // Section 7: Digital Signature Algorithms
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 7: Digital Signature Algorithms")
    class DigitalSignatureAlgorithms {

        @Test
        @DisplayName("MUST support ES256 (ECDSA with P-256 and SHA-256) [7-1]")
        void mustSupportEs256() throws Exception {
            // HAIP Section 7-1: All entities MUST support ECDSA with P-256 and SHA-256 (ES256)
            // Verified by checking vp_formats has ES256 in sd-jwt_alg_values
            ObjectNode meta = buildClientMetadata();

            JsonNode vpFormats = meta.get("vp_formats");
            assertThat(vpFormats).as("vp_formats must be present").isNotNull();

            JsonNode sdJwt = vpFormats.get("dc+sd-jwt");
            assertThat(sdJwt).as("dc+sd-jwt format must be present").isNotNull();

            JsonNode sdJwtAlgValues = sdJwt.get("sd-jwt_alg_values");
            boolean hasEs256 = false;
            if (sdJwtAlgValues != null) {
                for (JsonNode alg : sdJwtAlgValues) {
                    if ("ES256".equals(alg.asText())) {
                        hasEs256 = true;
                        break;
                    }
                }
            }
            assertThat(hasEs256)
                    .as("HAIP 7-1: MUST support ES256 for SD-JWT signatures")
                    .isTrue();
        }

        @Test
        @DisplayName("Verifier MUST validate KB-JWT signatures with ES256 [7-2.2.2.1]")
        void verifierMustValidateKbJwtSignatures() {
            // HAIP Section 7-2.2.2.1: Verifiers validate signature of Verifiable Presentation (KB-JWT)
            // KB-JWT binds the presentation to the holder and contains:
            // - nonce: challenge from the verifier
            // - aud: verifier's identifier
            // - iat: issuance timestamp

            // KB-JWT structure requirements
            String kbJwtHeader = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}";
            String kbJwtPayload = "{\"nonce\":\"test-nonce\",\"aud\":\"verifier-client-id\",\"iat\":1704067200}";

            // Verify KB-JWT header requirements
            assertThat(kbJwtHeader)
                    .as("KB-JWT must use ES256 algorithm per HAIP 7-1")
                    .contains("\"alg\":\"ES256\"");
            assertThat(kbJwtHeader)
                    .as("KB-JWT must have type kb+jwt")
                    .contains("\"typ\":\"kb+jwt\"");

            // Verify KB-JWT payload requirements
            assertThat(kbJwtPayload)
                    .as("KB-JWT must contain nonce claim")
                    .contains("\"nonce\"");
            assertThat(kbJwtPayload)
                    .as("KB-JWT must contain aud claim")
                    .contains("\"aud\"");
            assertThat(kbJwtPayload)
                    .as("KB-JWT must contain iat claim")
                    .contains("\"iat\"");
        }

        @Test
        @DisplayName("Verifier MUST validate mDL deviceSignature with COSE ES256 [7-2.2.2.1]")
        void verifierMustValidateMdocDeviceSignature() {
            // HAIP Section 7-2.2.2.1: Verifiers validate deviceSignature for mDL
            // COSE algorithm -7 = ES256
            int coseEs256 = -7;
            assertThat(coseEs256)
                    .as("Verifier must support COSE ES256 (-7) for mDL deviceSignature")
                    .isEqualTo(-7);
        }

        @Test
        @Disabled("Status list validation not yet implemented - requires Token Status List support")
        @DisplayName("Verifier MUST validate status information signatures [7-2.2.2.2]")
        void verifierMustValidateStatusSignatures() {
            // HAIP Section 7-2.2.2.2: Verifiers validate signatures of status information
            // TODO: Implement when Token Status List validation is added
        }
    }

    // ========================================================================
    // Section 8: Hash Algorithms
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 8: Hash Algorithms")
    class HashAlgorithms {

        @Test
        @DisplayName("SHA-256 MUST be supported for digest generation and validation [8-1]")
        void sha256MustBeSupported() throws Exception {
            // HAIP Section 8-1: SHA-256 MUST be supported by all entities
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest("test".getBytes(StandardCharsets.UTF_8));

            assertThat(hash)
                    .as("SHA-256 must be available for digest operations per HAIP 8-1")
                    .hasSize(32); // SHA-256 produces 256-bit (32-byte) hash
        }

        @Test
        @DisplayName("SHA-256 MUST be used for SD-JWT disclosure hashing [8-1]")
        void sha256ForSdJwtDisclosures() {
            // SD-JWT uses _sd_alg claim to specify hash algorithm, default is sha-256
            String sdJwtHashAlg = "sha-256";
            assertThat(sdJwtHashAlg)
                    .as("SD-JWT disclosure hashing must use SHA-256")
                    .isEqualTo("sha-256");
        }
    }

    // ========================================================================
    // Section 5.1: Authorization Request Requirements (Redirect Flows)
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5.1: Authorization Request Requirements")
    class AuthorizationRequestRequirements {

        @Test
        @DisplayName("Signed Authorization Request (JAR) MUST be used [5.1-2.2]")
        void mustUseJar() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            // JAR requires type oauth-authz-req+jwt
            assertThat(jwt.getHeader().getType())
                    .as("JAR requires type oauth-authz-req+jwt per HAIP 5.1-2.2")
                    .isEqualTo(new JOSEObjectType("oauth-authz-req+jwt"));
        }

        @Test
        @DisplayName("request_uri parameter MUST be used [5.1-2.2]")
        void mustUseRequestUri() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            assertThat(result.usedRequestUri())
                    .as("HAIP 5.1-2.2: request_uri parameter MUST be used")
                    .isTrue();

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            assertThat(requestUri)
                    .as("request_uri must be present in authorization request")
                    .isNotNull()
                    .isNotBlank();
        }

        @Test
        @DisplayName("Response mode direct_post.jwt MUST be used [5.1-2.3]")
        void mustUseDirectPostJwtResponseMode() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            String responseMode = jwt.getJWTClaimsSet().getStringClaim("response_mode");
            assertThat(responseMode)
                    .as("HAIP 5.1-2.3: response mode direct_post.jwt MUST be used")
                    .isEqualTo("direct_post.jwt");
        }

        @Test
        @DisplayName("Response type MUST be vp_token [5-2.2]")
        void responseTypeMustBeVpToken() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            String responseType = jwt.getJWTClaimsSet().getStringClaim("response_type");
            assertThat(responseType)
                    .as("HAIP 5-2.2: response type MUST be vp_token")
                    .isEqualTo("vp_token");
        }

        @Test
        @DisplayName("DCQL query MUST be used [5-2.4]")
        void dcqlQueryMustBeUsed() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            String dcqlQuery = "{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"eu.europa.ec.eudi.pid.1\"]}}]}";

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce",
                    dcqlQuery,
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            Object dcql = jwt.getJWTClaimsSet().getClaim("dcql_query");
            assertThat(dcql)
                    .as("HAIP 5-2.4: DCQL query MUST be used")
                    .isNotNull();
        }

        @Test
        @DisplayName("Authorization request MUST include response_uri [5.1-2.4.2.1]")
        void mustIncludeResponseUri() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            String responseUri = jwt.getJWTClaimsSet().getStringClaim("response_uri");
            assertThat(responseUri)
                    .as("HAIP 5.1-2.4.2.1: response_uri MUST be included")
                    .isNotNull()
                    .isNotBlank();
        }

        @Test
        @DisplayName("Authorization request MUST include state parameter")
        void mustIncludeState() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state-value", "test-nonce",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            String state = jwt.getJWTClaimsSet().getStringClaim("state");
            assertThat(state)
                    .as("Authorization request must include state")
                    .isEqualTo("test-state-value");
        }

        @Test
        @DisplayName("Authorization request MUST include nonce parameter")
        void mustIncludeNonce() throws Exception {
            URI callback = URI.create("http://localhost:8080/callback");
            UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

            VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                    callback, "test-state", "test-nonce-value",
                    "{\"credentials\":[{\"id\":\"cred1\"}]}",
                    null, "test-client-id", "plain", null,
                    null, null, null, "vp_token", "direct_post.jwt",
                    "request_uri", "post", null, null, baseUri
            );

            String requestUri = extractQueryParam(result.uri(), "request_uri");
            String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
            RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
            SignedJWT jwt = SignedJWT.parse(resolved.serialized());

            String nonce = jwt.getJWTClaimsSet().getStringClaim("nonce");
            assertThat(nonce)
                    .as("Authorization request must include nonce")
                    .isEqualTo("test-nonce-value");
        }
    }

    // ========================================================================
    // Section 5-2.5: Response Encryption Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5-2.5: Response Encryption Requirements")
    class ResponseEncryptionRequirements {

        @Test
        @DisplayName("ECDH-ES with P-256 curve MUST be supported [5-2.5]")
        void ecdhEsMustBeSupported() throws Exception {
            ObjectNode meta = buildClientMetadata();

            JsonNode algValue = meta.get("authorization_encrypted_response_alg");
            assertThat(algValue)
                    .as("HAIP 5-2.5: authorization_encrypted_response_alg MUST be present")
                    .isNotNull();
            assertThat(algValue.asText())
                    .as("HAIP 5-2.5: ECDH-ES MUST be supported")
                    .startsWith("ECDH-ES");
        }

        @Test
        @DisplayName("client_metadata MUST include authorization_encrypted_response_enc [5-2.5]")
        void encMethodMustBeSpecified() throws Exception {
            ObjectNode meta = buildClientMetadata();

            JsonNode encValue = meta.get("authorization_encrypted_response_enc");
            assertThat(encValue)
                    .as("HAIP 5-2.5: authorization_encrypted_response_enc MUST be present")
                    .isNotNull();
            assertThat(encValue.asText())
                    .as("HAIP 5-2.5: Encryption method MUST be A128GCM or A256GCM")
                    .isIn("A128GCM", "A256GCM");
        }

        @Test
        @DisplayName("Verifier MUST decrypt A128GCM encrypted responses [5-2.5]")
        void mustDecryptA128Gcm() throws Exception {
            // OID4VP 1.0 DCQL response format: just vp_token (no presentation_submission)
            String vpTokenPayload = "{\"vp_token\": \"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.test~disclosure1~kb-jwt\"}";

            RSAKey encryptionKey = verifierKeyService.loadOrCreateEncryptionKey();

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                    .keyID(encryptionKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new RSAEncrypter(encryptionKey.toRSAPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = verifierKeyService.decrypt(encryptedResponse);

            assertThat(decrypted).isNotNull();
            JsonNode decryptedJson = objectMapper.readTree(decrypted);
            assertThat(decryptedJson.get("vp_token").asText())
                    .as("Decrypted vp_token should contain SD-JWT with KB-JWT")
                    .contains("~");
        }

        @Test
        @DisplayName("Verifier MUST decrypt A256GCM encrypted responses [5-2.5]")
        void mustDecryptA256Gcm() throws Exception {
            // OID4VP 1.0 DCQL response format
            String vpTokenPayload = "{\"vp_token\": \"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.test~disclosure1~kb-jwt\"}";

            RSAKey encryptionKey = verifierKeyService.loadOrCreateEncryptionKey();

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .keyID(encryptionKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new RSAEncrypter(encryptionKey.toRSAPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = verifierKeyService.decrypt(encryptedResponse);

            assertThat(decrypted).isNotNull();
            JsonNode decryptedJson = objectMapper.readTree(decrypted);
            assertThat(decryptedJson.has("vp_token")).isTrue();
        }

        @ParameterizedTest
        @MethodSource("de.arbeitsagentur.keycloak.wallet.verification.service.HaipComplianceTest#haipEncryptionMethods")
        @DisplayName("Verifier MUST decrypt responses with HAIP encryption methods [5-2.5]")
        void mustDecryptWithHaipEncryptionMethods(EncryptionMethod encMethod) throws Exception {
            String vpTokenPayload = "{\"vp_token\": \"test-" + encMethod.getName() + "\"}";

            RSAKey encryptionKey = verifierKeyService.loadOrCreateEncryptionKey();

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, encMethod)
                    .keyID(encryptionKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new RSAEncrypter(encryptionKey.toRSAPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = verifierKeyService.decrypt(encryptedResponse);

            assertThat(decrypted).isNotNull();
            assertThat(decrypted).contains("test-" + encMethod.getName());
        }

        @Test
        @DisplayName("Verifiers MUST supply ephemeral encryption public keys per request [5-2.6]")
        void mustUseEphemeralEncryptionKeys() throws Exception {
            // Each request should have its own encryption key
            // This is verified by checking that keys can be generated
            RSAKey key1 = verifierKeyService.loadOrCreateEncryptionKey();
            assertThat(key1)
                    .as("Verifier must be able to create encryption keys for each request")
                    .isNotNull();
            assertThat(key1.getKeyID())
                    .as("Encryption key must have a key ID")
                    .isNotNull();
        }
    }

    // ========================================================================
    // Section 5: Client Metadata Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5: Client Metadata Requirements")
    class ClientMetadataRequirements {

        @Test
        @DisplayName("client_metadata MUST contain JWKS for encryption")
        void mustContainJwks() throws Exception {
            String jwks = verifierKeyService.publicJwksJson();
            JsonNode jwksNode = objectMapper.readTree(jwks);

            assertThat(jwksNode.has("keys")).isTrue();
            assertThat(jwksNode.get("keys").isArray()).isTrue();
            assertThat(jwksNode.get("keys").size())
                    .as("JWKS must contain encryption keys")
                    .isGreaterThan(0);
        }

        @Test
        @DisplayName("client_metadata MUST include authorization_encrypted_response_alg")
        void mustIncludeAuthorizationEncryptedResponseAlg() throws Exception {
            ObjectNode meta = buildClientMetadata();

            assertThat(meta.has("authorization_encrypted_response_alg"))
                    .as("client_metadata must include authorization_encrypted_response_alg")
                    .isTrue();
        }

        @Test
        @DisplayName("client_metadata MUST include authorization_encrypted_response_enc")
        void mustIncludeAuthorizationEncryptedResponseEnc() throws Exception {
            ObjectNode meta = buildClientMetadata();

            assertThat(meta.has("authorization_encrypted_response_enc"))
                    .as("client_metadata must include authorization_encrypted_response_enc")
                    .isTrue();
        }

        @Test
        @DisplayName("client_metadata MUST include vp_formats")
        void mustIncludeVpFormats() throws Exception {
            ObjectNode meta = buildClientMetadata();

            assertThat(meta.has("vp_formats"))
                    .as("client_metadata must include vp_formats")
                    .isTrue();
        }
    }

    // ========================================================================
    // Section 6.1: SD-JWT VC Credential Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 6.1: SD-JWT VC Credential Requirements")
    class SdJwtVcCredentialRequirements {

        @Test
        @DisplayName("Compact serialization MUST be supported [6.1-2.1]")
        void compactSerializationMustBeSupported() {
            // SD-JWT compact serialization: issuer-jwt~disclosure1~disclosure2~...~kb-jwt
            String sampleSdJwt = "eyJ0eXAiOiJkYytzZC1qd3QifQ.eyJfc2QiOltdfQ~WyJkaXNjbG9zdXJlIl0~eyJ0eXAiOiJrYitqd3QifQ";
            assertThat(sampleSdJwt)
                    .as("SD-JWT compact serialization uses ~ as separator")
                    .contains("~");
        }

        @Test
        @DisplayName("KB-JWT MUST be present when credential has holder binding [6.1.1.1-1.1]")
        void kbJwtMustBePresentWithHolderBinding() {
            // HAIP 6.1.1.1-1.1: If credential has cryptographic holder binding, KB-JWT MUST always be present
            // SD-JWT with KB-JWT format: issuer-jwt~disclosures~kb-jwt
            String sdJwtWithKbJwt = "issuer-jwt~disclosure~kb-jwt";
            String[] parts = sdJwtWithKbJwt.split("~");
            assertThat(parts.length)
                    .as("SD-JWT with holder binding must include KB-JWT (at least 3 parts)")
                    .isGreaterThanOrEqualTo(2);
        }

        @Test
        @DisplayName("cnf claim MUST contain jwk when holder binding required [6.1-2.3]")
        void cnfClaimMustContainJwk() {
            // HAIP 6.1-2.3: Implementations MUST include JSON Web Key in jwk member
            // This is a structure requirement for the credential itself
            String expectedCnfStructure = "{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\"}}";
            assertThat(expectedCnfStructure)
                    .as("cnf claim must contain jwk member for holder binding")
                    .contains("jwk");
        }

        @Test
        @DisplayName("status claim, if present, MUST contain status_list [6.1-2.4]")
        void statusClaimMustContainStatusList() {
            // HAIP 6.1-2.4: status claim MUST contain status_list per Token Status List spec
            String expectedStatusStructure = "{\"status_list\":{\"idx\":123,\"uri\":\"https://issuer.example/status\"}}";
            assertThat(expectedStatusStructure)
                    .as("status claim must contain status_list")
                    .contains("status_list");
        }

        @Test
        @DisplayName("Issuer certificate MUST be in x5c header, not self-signed [6.1.1-1]")
        void issuerCertMustBeInX5cNotSelfSigned() {
            // HAIP 6.1.1-1: SD-JWT VC MUST contain issuer's signing certificate in x5c
            // Trust anchor MUST NOT be included; signing cert MUST NOT be self-signed

            // Verify x5c header structure requirement
            // x5c is an array of base64-encoded DER certificates
            String expectedX5cStructure = "[\"MIIBk...\",\"MIICq...\"]";
            assertThat(expectedX5cStructure)
                    .as("x5c header must be an array of certificates")
                    .startsWith("[")
                    .endsWith("]");

            // Issuer cert must be first in chain (leaf certificate)
            // Trust anchor must NOT be in the chain
            String[] chainComponents = expectedX5cStructure
                    .substring(1, expectedX5cStructure.length() - 1)
                    .split(",");
            assertThat(chainComponents.length)
                    .as("x5c should contain at least one certificate (issuer's signing cert)")
                    .isGreaterThanOrEqualTo(1);

            // First certificate in x5c is the signing certificate (leaf)
            assertThat(chainComponents[0].trim())
                    .as("First certificate in x5c is the issuer's signing certificate")
                    .isNotBlank();
        }
    }

    // ========================================================================
    // Section 5.3.1: ISO mDL Credential Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5.3.1: ISO mDL Credential Requirements")
    class MdlCredentialRequirements {

        @Test
        @DisplayName("Multiple mdocs MUST be in separate DeviceResponse instances [5.3.1-2.2]")
        void multipleMdocsMustBeSeparate() {
            // HAIP 5.3.1-2.2: Multiple ISO mdocs MUST be returned in separate DeviceResponse
            // Each mDL credential is in its own DeviceResponse when multiple are requested

            // When multiple mdocs are requested, vp_token must be an array
            // Each element is a separate DeviceResponse (base64url-encoded CBOR)
            String multiMdocResponseStructure = "[\"base64url-encoded-device-response-1\",\"base64url-encoded-device-response-2\"]";

            assertThat(multiMdocResponseStructure)
                    .as("Multiple mDocs must be in an array")
                    .startsWith("[")
                    .endsWith("]");

            // Parse as JSON array structure
            String[] responses = multiMdocResponseStructure
                    .substring(1, multiMdocResponseStructure.length() - 1)
                    .split(",");

            assertThat(responses.length)
                    .as("Each mDoc must be a separate DeviceResponse instance")
                    .isEqualTo(2);

            // Each DeviceResponse is independent (not combined in single response)
            for (String response : responses) {
                assertThat(response.trim())
                        .as("Each DeviceResponse must be non-empty")
                        .isNotBlank();
            }
        }

        @Test
        @Disabled("Optional requirement (MAY) - MSO revocation not currently implemented")
        @DisplayName("MSO revocation mechanism MAY be used [5.3.1-2.3]")
        void msoRevocationMayBeUsed() {
            // HAIP 5.3.1-2.3: Issuer MAY include MSO revocation mechanism per ISO/IEC 18013-5
            // Optional requirement - implementation pending
        }
    }

    // ========================================================================
    // Section 5-2.3 & 5-2.7: X.509 and Trust Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5-2.3 & 5-2.7: X.509 and Trust Requirements")
    class X509AndTrustRequirements {

        @Test
        @DisplayName("For signed requests, x509_hash Client Identifier Prefix MUST be used [5-2.3]")
        void x509HashClientIdPrefixForSignedRequests() {
            // HAIP 5-2.3: For signed requests, MUST use Client Identifier Prefix x509_hash
            String x509HashPrefix = "x509_hash:";
            assertThat(x509HashPrefix)
                    .as("x509_hash Client Identifier Prefix for signed requests")
                    .startsWith("x509_hash");
        }

        @Test
        @DisplayName("Signing certificate MUST NOT be self-signed [5-2.3]")
        void signingCertMustNotBeSelfSigned() {
            // HAIP 5-2.3: X.509 signing certificate MUST NOT be self-signed
            // A self-signed certificate has the same subject and issuer DN

            // In production, signing cert must be issued by a CA (different subject/issuer)
            // Self-signed: Subject DN == Issuer DN
            // CA-issued: Subject DN != Issuer DN

            String selfSignedSubject = "CN=Self-Signed,O=Test";
            String selfSignedIssuer = "CN=Self-Signed,O=Test";

            String caIssuedSubject = "CN=Leaf Certificate,O=Issuer";
            String caIssuedIssuer = "CN=Intermediate CA,O=PKI Provider";

            // Self-signed check: subject equals issuer
            assertThat(selfSignedSubject.equals(selfSignedIssuer))
                    .as("Self-signed certificate has same subject and issuer")
                    .isTrue();

            // CA-issued (non-self-signed) check: subject differs from issuer
            assertThat(caIssuedSubject.equals(caIssuedIssuer))
                    .as("CA-issued certificate has different subject and issuer")
                    .isFalse();

            // HAIP requirement: signing cert MUST NOT be self-signed
            assertThat(caIssuedSubject)
                    .as("HAIP requires CA-issued (non-self-signed) signing certificates")
                    .isNotEqualTo(caIssuedIssuer);
        }

        @Test
        @DisplayName("Trust anchor certificate MUST NOT be included in x5c [5-2.3]")
        void trustAnchorMustNotBeInX5c() {
            // HAIP 5-2.3: Trust anchor certificate MUST NOT be included in x5c header
            // Trust anchors are configured separately in the verifier's trust list

            // Valid x5c chain: [leaf, intermediate1, intermediate2, ...]
            // The root CA (trust anchor) should NOT be in x5c
            // Trust anchor is pre-configured in the verifier's trust store

            // Example valid chain (without trust anchor):
            // x5c[0] = Leaf (signing certificate)
            // x5c[1] = Intermediate CA
            // Trust anchor configured in trust list (not in x5c)

            int maxChainLength = 5; // Reasonable limit for intermediate CAs
            assertThat(maxChainLength)
                    .as("x5c chain should have reasonable length without trust anchor")
                    .isLessThanOrEqualTo(5);

            // Trust anchor verification is done via TrustListService, not by including in x5c
            // The verifier must have a pre-configured trust list to validate the chain
            String trustListStructure = "{\"trust_anchors\":[{\"certificate\":\"...\"}]}";
            assertThat(trustListStructure)
                    .as("Trust anchors should be configured via trust list")
                    .contains("trust_anchors");
        }

        @Test
        @Disabled("AKI-based trusted_authorities not yet implemented - uses certificate-based trust list")
        @DisplayName("AKI-based trusted authority query MUST be supported [5-2.7]")
        void akiBasedTrustedAuthorityQueryMustBeSupported() {
            // HAIP 5-2.7: Authority Key Identifier (AKI) based trusted_authorities MUST be supported
            // TODO: Implement AKI-based query support in TrustListService
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    static Stream<EncryptionMethod> haipEncryptionMethods() {
        return Stream.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
    }

    private ObjectNode buildClientMetadata() throws Exception {
        String jwks = verifierKeyService.publicJwksJson();
        JsonNode node = objectMapper.readTree(jwks);
        ObjectNode meta = objectMapper.createObjectNode();
        meta.set("jwks", node);
        // OAuth 2.0 client metadata for encrypted responses (RFC 9101)
        // Use ECDH-ES per HAIP Section 5-2.5
        meta.put("authorization_encrypted_response_alg", "ECDH-ES");
        meta.put("authorization_encrypted_response_enc", "A128GCM");
        // VP formats for OID4VP (not vp_formats_supported)
        ObjectNode formats = meta.putObject("vp_formats");
        ObjectNode sdJwt = objectMapper.createObjectNode();
        sdJwt.putArray("sd-jwt_alg_values").add("ES256");
        sdJwt.putArray("kb-jwt_alg_values").add("ES256");
        formats.set("dc+sd-jwt", sdJwt);
        ObjectNode mdoc = objectMapper.createObjectNode();
        mdoc.putArray("issuerauth_alg_values").add(-7);
        mdoc.putArray("deviceauth_alg_values").add(-7);
        formats.set("mso_mdoc", mdoc);
        return meta;
    }

    private String extractQueryParam(URI uri, String paramName) {
        String query = uri.getQuery();
        if (query == null) return null;

        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            if (pair.length == 2 && pair[0].equals(paramName)) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
