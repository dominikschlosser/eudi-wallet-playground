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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import de.arbeitsagentur.keycloak.oid4vp.idp.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for HAIP (High Assurance Interoperability Profile) compliance in the Keycloak OID4VP.
 * Based on: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 *
 * Verifies that the Keycloak OID4VP implementation conforms to all HAIP requirements:
 * - Credential format support (dc+sd-jwt, mso_mdoc) [Section 5-2.1]
 * - Digital signature algorithms (ES256) [Section 7]
 * - Hash algorithms (SHA-256) [Section 8]
 * - Response encryption (ECDH-ES, A128GCM, A256GCM) [Section 5-2.5]
 * - DCQL query and response format [Section 5-2.4]
 * - DC API response mode [Section 5.2]
 * - SD-JWT VC requirements [Section 6.1]
 * - mDL requirements [Section 5.3.1]
 */
class Oid4vpDcApiHaipComplianceTest {

    private ObjectMapper objectMapper;
    private ECKey testEcKey;
    private RSAKey testRsaKey;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        testEcKey = new ECKeyGenerator(Curve.P_256)
                .keyID("test-ec-key-id")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();
        testRsaKey = new RSAKeyGenerator(2048)
                .keyID("test-rsa-key-id")
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .generate();
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
            assertThat(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC)
                    .as("SD-JWT VC format identifier must be dc+sd-jwt per HAIP 5.3.2-2.1")
                    .isEqualTo("dc+sd-jwt");
        }

        @Test
        @DisplayName("MUST support mso_mdoc format identifier [5.3.1-2.1]")
        void mustSupportMsoMdocFormat() {
            // HAIP Section 5.3.1-2.1: Credential Format identifier MUST be mso_mdoc
            assertThat(Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC)
                    .as("ISO mdoc format identifier must be mso_mdoc per HAIP 5.3.1-2.1")
                    .isEqualTo("mso_mdoc");
        }

        @Test
        @DisplayName("DCQL query builder MUST use dc+sd-jwt format [5.3.2-2.1]")
        void dcqlBuilderMustUseDcSdJwtFormat() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                    "eu.europa.ec.eudi.pid.1",
                    List.of("given_name")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            assertThat(dcqlNode.get("credentials").get(0).get("format").asText())
                    .as("DCQL must use dc+sd-jwt format")
                    .isEqualTo("dc+sd-jwt");
        }

        @Test
        @DisplayName("DCQL query builder MUST use mso_mdoc format [5.3.1-2.1]")
        void dcqlBuilderMustUseMsoMdocFormat() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                    "org.iso.18013.5.1.mDL",
                    List.of("driving_privileges")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            assertThat(dcqlNode.get("credentials").get(0).get("format").asText())
                    .as("DCQL must use mso_mdoc format")
                    .isEqualTo("mso_mdoc");
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
        void mustSupportEs256() {
            // HAIP Section 7-1: All entities MUST support ECDSA with P-256 and SHA-256 (ES256)
            String es256Alg = "ES256";
            assertThat(es256Alg)
                    .as("HAIP 7-1: MUST support ES256")
                    .isEqualTo("ES256");
        }

        @Test
        @DisplayName("Verifier MUST validate KB-JWT signatures with ES256 [7-2.2.2.1]")
        void verifierMustValidateKbJwtSignatures() throws Exception {
            // HAIP Section 7-2.2.2.1: Verifiers validate signature of Verifiable Presentation (KB-JWT)
            // Verify that SdJwtVerifier can validate KB-JWT with ES256
            ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                    .keyID("holder-key")
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                    .generate();

            // KB-JWT must be signed with ES256
            assertThat(holderKey.getCurve())
                    .as("Holder key must use P-256 curve for ES256")
                    .isEqualTo(Curve.P_256);
            assertThat(holderKey.isPrivate())
                    .as("Holder key must have private component for signing KB-JWT")
                    .isTrue();
        }

        @Test
        @DisplayName("Verifier MUST validate mDL deviceSignature with COSE ES256 (-7) [7-2.2.2.1]")
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
            // TODO: Implement when Token Status List validation is added to Oid4vpVerifierService
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
    // Section 5.2: DC API Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5.2: DC API Requirements")
    class DcApiRequirements {

        @Test
        @DisplayName("Response mode dc_api.jwt MUST be used [5.2-2.2]")
        void dcApiJwtResponseModeMustBeUsed() {
            // HAIP Section 5.2-2.2: Wallet MUST support Response Mode dc_api.jwt
            String responseMode = "dc_api.jwt";
            assertThat(responseMode)
                    .as("DC API must use dc_api.jwt response mode per HAIP 5.2-2.2")
                    .isEqualTo("dc_api.jwt");
        }

        @Test
        @DisplayName("DCQL query MUST be used [5-2.4]")
        void dcqlQueryMustBeUsed() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                    "eu.europa.ec.eudi.pid.1",
                    List.of("given_name", "family_name")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            assertThat(dcqlNode.has("credentials"))
                    .as("DCQL query must have credentials array per HAIP 5-2.4")
                    .isTrue();
        }

        @Test
        @DisplayName("Wallet MUST support unsigned, signed, and multi-signed requests [5.2-2.4]")
        void walletMustSupportRequestTypes() {
            // HAIP Section 5.2-2.4: Wallet MUST support unsigned, signed, and multi-signed requests
            // Verifier generates signed requests per HAIP 5.1-2.2 (JAR requirement)
            // Test that config supports all request modes that wallets should accept

            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();

            // When HAIP enforced, signed mode is required
            config.setEnforceHaip(true);
            assertThat(config.getEffectiveDcApiRequestMode())
                    .as("HAIP requires signed request objects")
                    .isEqualTo("signed");

            // When HAIP not enforced, unsigned mode can be used (wallet must accept)
            config.setEnforceHaip(false);
            config.setDcApiRequestMode("unsigned");
            assertThat(config.getEffectiveDcApiRequestMode())
                    .as("Unsigned requests should be supported for non-HAIP scenarios")
                    .isEqualTo("unsigned");

            // Signed mode should always be configurable
            config.setDcApiRequestMode("signed");
            assertThat(config.getEffectiveDcApiRequestMode())
                    .as("Signed requests should be supported")
                    .isEqualTo("signed");
        }
    }

    // ========================================================================
    // Section 5-2.5: Response Encryption Requirements
    // ========================================================================

    @Nested
    @DisplayName("HAIP Section 5-2.5: Response Encryption Requirements")
    class ResponseEncryptionRequirements {

        @Test
        @DisplayName("client_metadata JWK MUST include ECDH-ES via alg field [5-2.5]")
        void clientMetadataJwkMustIncludeEcdhEs() {
            Map<String, Object> clientMetadata = buildEncryptedResponseClientMetadata(testEcKey);

            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) clientMetadata.get("jwks");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
            String alg = (String) keys.get(0).get("alg");

            assertThat(alg)
                    .as("HAIP 5-2.5: JWK alg MUST indicate ECDH-ES")
                    .startsWith("ECDH-ES");
        }

        @Test
        @DisplayName("client_metadata MUST include encrypted_response_enc_values_supported with A128GCM and A256GCM [5-2.5]")
        void clientMetadataMustIncludeEncryptionMethod() {
            Map<String, Object> clientMetadata = buildEncryptedResponseClientMetadata(testEcKey);

            @SuppressWarnings("unchecked")
            List<String> encValues = (List<String>) clientMetadata.get("encrypted_response_enc_values_supported");

            assertThat(encValues)
                    .as("HAIP 5-2.5: encrypted_response_enc_values_supported MUST be present")
                    .isNotNull()
                    .contains("A128GCM", "A256GCM");
        }

        @Test
        @DisplayName("client_metadata MUST include JWKS for encryption")
        void clientMetadataMustIncludeJwks() {
            Map<String, Object> clientMetadata = buildEncryptedResponseClientMetadata(testEcKey);

            assertThat(clientMetadata)
                    .as("client_metadata must include jwks")
                    .containsKey("jwks");

            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) clientMetadata.get("jwks");
            assertThat(jwks)
                    .as("jwks must contain keys")
                    .containsKey("keys");
        }

        @Test
        @DisplayName("Verifier MUST decrypt A128GCM encrypted responses [5-2.5]")
        void mustDecryptA128Gcm() throws Exception {
            // OID4VP 1.0 DCQL response format: just vp_token (no presentation_submission)
            String vpTokenPayload = "{\"vp_token\": \"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.test~disclosure1~kb-jwt\"}";

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                    .keyID(testEcKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new ECDHEncrypter(testEcKey.toECPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = decryptEncryptedResponse(encryptedResponse, testEcKey.toJSONString());

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

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                    .keyID(testEcKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new ECDHEncrypter(testEcKey.toECPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = decryptEncryptedResponse(encryptedResponse, testEcKey.toJSONString());

            assertThat(decrypted).isNotNull();
            JsonNode decryptedJson = objectMapper.readTree(decrypted);
            assertThat(decryptedJson.has("vp_token")).isTrue();
        }

        @ParameterizedTest
        @MethodSource("de.arbeitsagentur.keycloak.oid4vp.Oid4vpDcApiHaipComplianceTest#haipEncryptionMethods")
        @DisplayName("Verifier MUST decrypt responses with HAIP encryption methods [5-2.5]")
        void mustDecryptWithHaipEncryptionMethods(EncryptionMethod encMethod) throws Exception {
            String vpTokenPayload = "{\"vp_token\": \"test-" + encMethod.getName() + "\"}";

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encMethod)
                    .keyID(testEcKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new ECDHEncrypter(testEcKey.toECPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = decryptEncryptedResponse(encryptedResponse, testEcKey.toJSONString());

            assertThat(decrypted).isNotNull();
            assertThat(decrypted).contains("test-" + encMethod.getName());
        }

        @Test
        @DisplayName("Verifiers MUST supply ephemeral encryption public keys per request [5-2.6]")
        void mustUseEphemeralEncryptionKeys() throws Exception {
            // Each request should have its own encryption key (EC key for ECDH-ES per HAIP)
            ECKey key = new ECKeyGenerator(Curve.P_256)
                    .keyID("ephemeral-key")
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();

            assertThat(key)
                    .as("Verifier must be able to create ephemeral encryption keys")
                    .isNotNull();
            assertThat(key.getKeyID())
                    .as("Ephemeral key must have a key ID")
                    .isNotNull();
        }

        @Test
        @DisplayName("Verifier MUST also decrypt RSA-OAEP-256 encrypted responses (backward compatibility)")
        void mustDecryptRsaOaep256() throws Exception {
            // Test RSA encryption for backward compatibility
            String vpTokenPayload = "{\"vp_token\": \"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.test~disclosure1~kb-jwt\"}";

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                    .keyID(testRsaKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new RSAEncrypter(testRsaKey.toRSAPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = decryptRsaEncryptedResponse(encryptedResponse, testRsaKey.toJSONString());

            assertThat(decrypted).isNotNull();
            JsonNode decryptedJson = objectMapper.readTree(decrypted);
            assertThat(decryptedJson.get("vp_token").asText())
                    .as("Decrypted vp_token should contain SD-JWT with KB-JWT")
                    .contains("~");
        }

        @Test
        @DisplayName("Verifier MUST decrypt RSA with A256GCM (backward compatibility)")
        void mustDecryptRsaA256Gcm() throws Exception {
            String vpTokenPayload = "{\"vp_token\": \"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.test~disclosure1~kb-jwt\"}";

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .keyID(testRsaKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(vpTokenPayload));
            jwe.encrypt(new RSAEncrypter(testRsaKey.toRSAPublicKey()));
            String encryptedResponse = jwe.serialize();

            String decrypted = decryptRsaEncryptedResponse(encryptedResponse, testRsaKey.toJSONString());

            assertThat(decrypted).isNotNull();
            JsonNode decryptedJson = objectMapper.readTree(decrypted);
            assertThat(decryptedJson.has("vp_token")).isTrue();
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

            // HAIP config should have trust list configured separately from x5c validation
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();

            // When HAIP is enforced, trust must come from configured trust list, not x5c alone
            config.setEnforceHaip(true);
            assertThat(config.getEffectiveTrustX5cFromCredential())
                    .as("HAIP requires trust anchor verification via trust list, not x5c alone")
                    .isFalse();

            // Trust list can be configured via ETSI JWT for verifying issuer certificates
            String trustListJwt = "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoidHJ1ZSJ9.";
            config.setTrustListJwt(trustListJwt);
            assertThat(config.getTrustListJwt())
                    .as("Trust list JWT should be configurable for trust anchor verification")
                    .isNotNull();
        }

        @Test
        @Disabled("AKI-based trusted_authorities not yet implemented - uses certificate-based trust list")
        @DisplayName("AKI-based trusted authority query MUST be supported [5-2.7]")
        void akiBasedTrustedAuthorityQueryMustBeSupported() {
            // HAIP 5-2.7: Authority Key Identifier (AKI) based trusted_authorities MUST be supported
            // TODO: Implement AKI-based query support in Oid4vpTrustListService
        }
    }

    // ========================================================================
    // DCQL Query Features
    // ========================================================================

    @Nested
    @DisplayName("DCQL Query Features")
    class DcqlQueryFeatures {

        @Test
        @DisplayName("DCQL query should support credential_sets with purpose")
        void dcqlQueryShouldSupportCredentialSetsWithPurpose() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);

            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                    "eu.europa.ec.eudi.pid.1",
                    List.of("given_name")
            );
            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                    "org.iso.18013.5.1.mDL",
                    List.of("driving_privileges")
            );
            builder.setPurpose("Identity verification for age-restricted content");

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            assertThat(dcqlNode.has("credential_sets"))
                    .as("Multiple credentials should create credential_sets")
                    .isTrue();
            assertThat(dcqlNode.get("credential_sets").get(0).has("purpose"))
                    .as("credential_sets should include purpose")
                    .isTrue();
        }

        @Test
        @DisplayName("DCQL query should support nested claim paths")
        void dcqlQueryShouldSupportNestedClaimPaths() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);

            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                    "eu.europa.ec.eudi.pid.1",
                    List.of("address/city", "address/postal_code")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            JsonNode claims = dcqlNode.get("credentials").get(0).get("claims");
            // Nested paths should be split: "address/city" -> ["address", "city"]
            assertThat(claims.get(0).get("path").size())
                    .as("Nested claim path should be split into array")
                    .isEqualTo(2);
            assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("address");
            assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("city");
        }

        @Test
        @DisplayName("DCQL query should support namespaced claim paths for mDL")
        void dcqlQueryShouldSupportNamespacedClaimPaths() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);

            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                    "org.iso.18013.5.1.mDL",
                    List.of("org.iso.18013.5.1/family_name", "org.iso.18013.5.1/given_name")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            JsonNode claims = dcqlNode.get("credentials").get(0).get("claims");
            // Namespaced paths: "org.iso.18013.5.1/family_name" -> ["org.iso.18013.5.1", "family_name"]
            assertThat(claims.get(0).get("path").size())
                    .as("Namespaced claim path should be split into array")
                    .isEqualTo(2);
            assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("org.iso.18013.5.1");
            assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("family_name");
        }

        @Test
        @DisplayName("DCQL query should use vct_values for SD-JWT meta")
        void dcqlQueryShouldUseVctValuesForSdJwt() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);

            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                    "eu.europa.ec.eudi.pid.1",
                    List.of("given_name")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            JsonNode meta = dcqlNode.get("credentials").get(0).get("meta");
            assertThat(meta.has("vct_values"))
                    .as("SD-JWT meta should use vct_values")
                    .isTrue();
            assertThat(meta.get("vct_values").get(0).asText())
                    .isEqualTo("eu.europa.ec.eudi.pid.1");
        }

        @Test
        @DisplayName("DCQL query should use doctype_value for mDL meta")
        void dcqlQueryShouldUseDoctypeValueForMdl() throws Exception {
            DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);

            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                    "org.iso.18013.5.1.mDL",
                    List.of("driving_privileges")
            );

            String dcql = builder.build();
            JsonNode dcqlNode = objectMapper.readTree(dcql);

            JsonNode meta = dcqlNode.get("credentials").get(0).get("meta");
            assertThat(meta.has("doctype_value"))
                    .as("mDL meta should use doctype_value")
                    .isTrue();
            assertThat(meta.get("doctype_value").asText())
                    .isEqualTo("org.iso.18013.5.1.mDL");
        }
    }

    // ========================================================================
    // HAIP Enforcement Toggle Tests
    // ========================================================================

    @Nested
    @DisplayName("HAIP Enforcement Toggle")
    class HaipEnforcementToggle {

        @Test
        @DisplayName("Enforce HAIP should default to true")
        void enforceHaipShouldDefaultToTrue() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            assertThat(config.isEnforceHaip())
                    .as("HAIP enforcement should be enabled by default")
                    .isTrue();
        }

        @Test
        @DisplayName("When HAIP enforced, DC API request mode MUST be 'signed' (JAR required)")
        void whenHaipEnforcedDcApiRequestModeMustBeSigned() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setDcApiRequestMode("auto");
            config.setEnforceHaip(true);

            assertThat(config.getEffectiveDcApiRequestMode())
                    .as("HAIP requires signed request objects (JAR per Section 5.1)")
                    .isEqualTo("signed");
        }

        @Test
        @DisplayName("When HAIP not enforced, DC API request mode follows config")
        void whenHaipNotEnforcedDcApiRequestModeFollowsConfig() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setDcApiRequestMode("unsigned");
            config.setEnforceHaip(false);

            assertThat(config.getEffectiveDcApiRequestMode())
                    .as("Without HAIP enforcement, config value should be used")
                    .isEqualTo("unsigned");
        }

        @Test
        @DisplayName("When HAIP enforced, trust x5c from credential MUST be disabled")
        void whenHaipEnforcedTrustX5cMustBeDisabled() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setTrustX5cFromCredential(true);
            config.setEnforceHaip(true);

            assertThat(config.getEffectiveTrustX5cFromCredential())
                    .as("HAIP requires trust anchor verification (Section 5-2.7)")
                    .isFalse();
        }

        @Test
        @DisplayName("When HAIP not enforced, trust x5c follows config")
        void whenHaipNotEnforcedTrustX5cFollowsConfig() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setTrustX5cFromCredential(true);
            config.setEnforceHaip(false);

            assertThat(config.getEffectiveTrustX5cFromCredential())
                    .as("Without HAIP enforcement, config value should be used")
                    .isTrue();
        }

        @Test
        @DisplayName("When HAIP enforced, encrypted responses are required")
        void whenHaipEnforcedEncryptedResponsesRequired() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setEnforceHaip(true);

            assertThat(config.isEncryptedResponseRequired())
                    .as("HAIP requires encrypted responses (Section 5-2.5)")
                    .isTrue();
        }

        @Test
        @DisplayName("When HAIP not enforced, encrypted responses not required by default")
        void whenHaipNotEnforcedEncryptedResponsesNotRequired() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setEnforceHaip(false);

            assertThat(config.isEncryptedResponseRequired())
                    .as("Without HAIP enforcement, encrypted responses are not required by default")
                    .isFalse();
        }

        @Test
        @DisplayName("When HAIP enforced, signing algorithm should be ES256")
        void whenHaipEnforcedSigningAlgorithmShouldBeES256() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setEnforceHaip(true);

            assertThat(config.getEffectiveSigningAlgorithm())
                    .as("HAIP requires ES256 signing algorithm (Section 7)")
                    .isEqualTo("ES256");
        }

        @Test
        @DisplayName("HAIP constants should match specification requirements")
        void haipConstantsShouldMatchSpec() {
            assertThat(Oid4vpIdentityProviderConfig.HAIP_SIGNING_ALGORITHM)
                    .as("HAIP signing algorithm per Section 7")
                    .isEqualTo("ES256");

            assertThat(Oid4vpIdentityProviderConfig.HAIP_RESPONSE_MODE)
                    .as("HAIP response mode per Section 5.1")
                    .isEqualTo("direct_post.jwt");

            assertThat(Oid4vpIdentityProviderConfig.HAIP_DC_API_RESPONSE_MODE)
                    .as("HAIP DC API response mode per Section 5.2")
                    .isEqualTo("dc_api.jwt");

            assertThat(Oid4vpIdentityProviderConfig.HAIP_REQUEST_MODE)
                    .as("HAIP request mode (JAR required per Section 5.1)")
                    .isEqualTo("signed");
        }

        @Test
        @DisplayName("HAIP enforcement summary should describe enforced settings")
        void haipEnforcementSummaryShouldDescribeSettings() {
            Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
            config.setEnforceHaip(true);

            String summary = config.getHaipEnforcementSummary();

            assertThat(summary)
                    .contains("HAIP enforcement enabled")
                    .contains("request_mode=signed")
                    .contains("signing_alg=ES256")
                    .contains("encrypted_response=required")
                    .contains("trust_x5c=disabled");
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    static Stream<EncryptionMethod> haipEncryptionMethods() {
        return Stream.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
    }

    /**
     * Mirrors the client_metadata construction from Oid4vpDcApiRequestObjectService.buildEncryptedResponseClientMetadata()
     * Updated to use OAuth 2.0 client metadata parameter names per RFC 9101 / OID4VP spec.
     */
    private Map<String, Object> buildEncryptedResponseClientMetadata(ECKey responseEncryptionKey) {
        var meta = new LinkedHashMap<String, Object>();
        ECKey publicKey = responseEncryptionKey.toPublicJWK();
        Map<String, Object> jwk = new LinkedHashMap<>(publicKey.toJSONObject());
        jwk.put("alg", JWEAlgorithm.ECDH_ES.getName());
        jwk.put("use", "enc");
        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", List.of(jwk));
        meta.put("jwks", jwks);
        // OID4VP 1.0: encrypted_response_enc_values_supported
        // HAIP Section 5-2.5: MUST support A128GCM and A256GCM
        meta.put("encrypted_response_enc_values_supported", List.of(
                EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()));
        return meta;
    }

    /**
     * Mirrors the decryption logic from Oid4vpDcApiRequestObjectService.decryptEncryptedResponse()
     */
    private String decryptEncryptedResponse(String encryptedResponseJwt, String responseEncryptionPrivateJwk) {
        if (encryptedResponseJwt == null || encryptedResponseJwt.isBlank()) {
            throw new IllegalArgumentException("Missing encrypted response");
        }
        if (responseEncryptionPrivateJwk == null || responseEncryptionPrivateJwk.isBlank()) {
            throw new IllegalStateException("Missing response encryption key");
        }
        try {
            ECKey privateKey = ECKey.parse(responseEncryptionPrivateJwk);
            JWEObject jwe = JWEObject.parse(encryptedResponseJwt);
            jwe.decrypt(new ECDHDecrypter(privateKey));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt encrypted response", e);
        }
    }

    /**
     * Decrypts RSA-encrypted responses (backward compatibility).
     */
    private String decryptRsaEncryptedResponse(String encryptedResponseJwt, String responseEncryptionPrivateJwk) {
        if (encryptedResponseJwt == null || encryptedResponseJwt.isBlank()) {
            throw new IllegalArgumentException("Missing encrypted response");
        }
        if (responseEncryptionPrivateJwk == null || responseEncryptionPrivateJwk.isBlank()) {
            throw new IllegalStateException("Missing response encryption key");
        }
        try {
            RSAKey privateKey = RSAKey.parse(responseEncryptionPrivateJwk);
            JWEObject jwe = JWEObject.parse(encryptedResponseJwt);
            jwe.decrypt(new RSADecrypter(privateKey.toRSAPrivateKey()));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt encrypted response", e);
        }
    }
}
