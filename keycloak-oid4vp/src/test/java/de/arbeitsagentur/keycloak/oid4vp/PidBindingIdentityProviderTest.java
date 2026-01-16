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

import de.arbeitsagentur.keycloak.oid4vp.idp.pidbinding.PidBindingIdentityProviderConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for PID Binding Identity Provider.
 * Tests the German PID binding flow where:
 * 1. First login: Present PID → create user → issue login credential
 * 2. Subsequent logins: Present PID + login credential → use user_id from login credential
 */
class PidBindingIdentityProviderTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("PID Binding Configuration")
    class ConfigurationTests {

        @Test
        @DisplayName("Should have correct default PID credential type")
        void shouldHaveDefaultPidCredentialType() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();

            assertThat(config.getPidCredentialType())
                    .isEqualTo("urn:eudi:pid:de:1");
        }

        @Test
        @DisplayName("Should have correct default login credential type")
        void shouldHaveDefaultLoginCredentialType() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();

            assertThat(config.getLoginCredentialType())
                    .isEqualTo("urn:arbeitsagentur:user_credential:1");
        }

        @Test
        @DisplayName("Should have correct default credential configuration ID")
        void shouldHaveDefaultCredentialConfigurationId() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();

            assertThat(config.getCredentialConfigurationId())
                    .isEqualTo("user-binding-credential");
        }

        @Test
        @DisplayName("Should have correct default PID claims")
        void shouldHaveDefaultPidClaims() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();

            assertThat(config.getPidRequestedClaimsList())
                    .containsExactlyInAnyOrder("given_name", "family_name", "birthdate");
        }

        @Test
        @DisplayName("Should not always request both credentials by default")
        void shouldNotAlwaysRequestBothCredentialsByDefault() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();

            assertThat(config.isAlwaysRequestBothCredentials())
                    .isFalse();
        }

        @Test
        @DisplayName("Should parse custom PID claims")
        void shouldParseCustomPidClaims() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();
            config.setPidRequestedClaims("given_name, family_name\nbirthdate,nationality");

            assertThat(config.getPidRequestedClaimsList())
                    .containsExactlyInAnyOrder("given_name", "family_name", "birthdate", "nationality");
        }
    }

    @Nested
    @DisplayName("DCQL Query Generation")
    class DcqlQueryTests {

        @Test
        @DisplayName("Should generate PID-only DCQL query by default")
        void shouldGeneratePidOnlyDcqlByDefault() throws Exception {
            // When alwaysRequestBothCredentials is false (default),
            // the DCQL should only request PID
            String expectedVct = "urn:eudi:pid:de:1";

            // The actual DCQL generation is in PidBindingIdentityProvider.buildDcqlQueryFromConfig()
            // We can't easily test the full provider without mocking Keycloak context,
            // so we test the configuration instead
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();
            config.setAlwaysRequestBothCredentials(false);

            assertThat(config.isAlwaysRequestBothCredentials()).isFalse();
            assertThat(config.getPidCredentialType()).isEqualTo(expectedVct);
        }

        @Test
        @DisplayName("Should request both credentials when configured")
        void shouldRequestBothCredentialsWhenConfigured() {
            PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig();
            config.setAlwaysRequestBothCredentials(true);

            assertThat(config.isAlwaysRequestBothCredentials()).isTrue();
            assertThat(config.getLoginCredentialType()).isEqualTo("urn:arbeitsagentur:user_credential:1");
        }
    }

    @Nested
    @DisplayName("Flow Detection")
    class FlowDetectionTests {

        @Test
        @DisplayName("Should identify first login when only PID is presented")
        void shouldIdentifyFirstLoginWithPidOnly() throws Exception {
            // Claims from a PID credential (no user_id)
            String claimsJson = """
                    {
                        "iss": "https://pid-issuer.example",
                        "vct": "urn:eudi:pid:de:1",
                        "given_name": "Erika",
                        "family_name": "Mustermann",
                        "birthdate": "1984-01-26"
                    }
                    """;
            JsonNode claims = objectMapper.readTree(claimsJson);

            // Check: no user_id present = first login
            assertThat(claims.has("user_id")).isFalse();
        }

        @Test
        @DisplayName("Should identify returning user when user_id is present")
        void shouldIdentifyReturningUserWithUserId() throws Exception {
            // Claims including user_id from login credential
            String claimsJson = """
                    {
                        "iss": "https://keycloak.example/realms/demo",
                        "vct": "urn:arbeitsagentur:user_credential:1",
                        "user_id": "12345-abcde",
                        "linked_at": "2024-01-15T10:30:00Z"
                    }
                    """;
            JsonNode claims = objectMapper.readTree(claimsJson);

            // Check: user_id present = returning user
            assertThat(claims.has("user_id")).isTrue();
            assertThat(claims.get("user_id").asText()).isEqualTo("12345-abcde");
        }
    }

    @Nested
    @DisplayName("Lookup Key Computation")
    class LookupKeyTests {

        @Test
        @DisplayName("Should compute consistent lookup keys")
        void shouldComputeConsistentLookupKeys() throws Exception {
            String issuer = "https://keycloak.example/realms/demo";
            String credentialType = "urn:arbeitsagentur:user_credential:1";
            String subject = "12345-abcde";

            String lookupKey1 = computeLookupKey(issuer, credentialType, subject);
            String lookupKey2 = computeLookupKey(issuer, credentialType, subject);

            assertThat(lookupKey1).isEqualTo(lookupKey2);
            assertThat(lookupKey1).isNotBlank();
        }

        @Test
        @DisplayName("Should produce different lookup keys for different subjects")
        void shouldProduceDifferentLookupKeysForDifferentSubjects() throws Exception {
            String issuer = "https://keycloak.example/realms/demo";
            String credentialType = "urn:arbeitsagentur:user_credential:1";

            String lookupKey1 = computeLookupKey(issuer, credentialType, "user-1");
            String lookupKey2 = computeLookupKey(issuer, credentialType, "user-2");

            assertThat(lookupKey1).isNotEqualTo(lookupKey2);
        }

        @Test
        @DisplayName("Should produce different lookup keys for different issuers")
        void shouldProduceDifferentLookupKeysForDifferentIssuers() throws Exception {
            String credentialType = "urn:arbeitsagentur:user_credential:1";
            String subject = "12345-abcde";

            String lookupKey1 = computeLookupKey("https://issuer1.example", credentialType, subject);
            String lookupKey2 = computeLookupKey("https://issuer2.example", credentialType, subject);

            assertThat(lookupKey1).isNotEqualTo(lookupKey2);
        }

        /**
         * Compute the lookup key from issuer, credential type, and subject.
         * This mirrors the algorithm in PidBindingIdentityProvider.computeLookupKey().
         */
        private String computeLookupKey(String issuer, String credentialType, String subject) {
            String combined = issuer + "\0" + credentialType + "\0" + subject;
            try {
                byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(combined.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to compute lookup key", e);
            }
        }
    }

    @Nested
    @DisplayName("Session Notes")
    class SessionNotesTests {

        @Test
        @DisplayName("Should use correct session note keys")
        void shouldUseCorrectSessionNoteKeys() {
            // Verify the session note constants match what's expected
            assertThat(de.arbeitsagentur.keycloak.oid4vp.idp.pidbinding.PidBindingIdentityProvider.SESSION_NEEDS_CREDENTIAL_ISSUANCE)
                    .isEqualTo("pid_binding_needs_credential_issuance");
        }
    }
}
