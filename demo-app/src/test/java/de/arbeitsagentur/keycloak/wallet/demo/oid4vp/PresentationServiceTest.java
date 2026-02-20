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
package de.arbeitsagentur.keycloak.wallet.demo.oid4vp;

import tools.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.authlete.sd.Disclosure;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;

class PresentationServiceTest {

    @TempDir
    Path tempDir;

    private PresentationService presentationService;
    private CredentialStore credentialStore;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        WalletProperties properties = new WalletProperties(
                "http://issuer.example",
                "wallet-demo",
                "client",
                "secret",
                "did:example:wallet",
                tempDir,
                tempDir.resolve("keys.json"),
                null,
                null,
                null,
                null,
                List.of("demo-attestation-issuer"),
                null
        );
        credentialStore = new CredentialStore(properties, objectMapper);
        presentationService = new PresentationService(credentialStore, objectMapper);
    }

    @Test
    void matchesCredentialSetByVct() throws Exception {
        saveCredential("user", Map.of(
                "vct", "https://credentials.example.com/identity_credential",
                "credentialSubject", Map.of("personal_id", "ID-123"),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "credential_set": [{ "vct": "https://credentials.example.com/identity_credential" }],
                    "claims": [{ "path": ["personal_id"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("pid");
    }

    @Test
    void claimSetMustAllMatch() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice", "family_name", "Doe"),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "full-name",
                    "format": "dc+sd-jwt",
                    "claim_set": [{
                      "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] }
                      ]
                    }],
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
    }

    @Test
    void claimSetFailureReturnsEmpty() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "full-name",
                    "format": "dc+sd-jwt",
                    "claim_set": [{
                      "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] }
                      ]
                    }],
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void dcqlNestedPathsAreMatchedWithJsonPath() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of(
                        "given_name", "Alice",
                        "address", Map.of("country", "DE")
                ),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "address-proof",
                    "format": "dc+sd-jwt",
                    "claims": [
                      { "path": ["address", "country"], "value": "DE" },
                      { "path": ["given_name"] }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).disclosedClaims())
                .containsEntry("given_name", "Alice")
                .containsEntry("country", "DE");
    }

    @Test
    void nestedClaimDisclosuresAreIncludedInVpToken() throws Exception {
        Disclosure countryDisclosure = new Disclosure("address.country", "DE");
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("address", Map.of("country", "DE"), "given_name", "Alice"),
                "disclosures", List.of(countryDisclosure.getDisclosure()),
                "rawCredential", "hdr.payload.sig"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "claims": [
                      { "path": ["address", "country"] },
                      { "path": ["given_name"] }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        PresentationService.DescriptorMatch match = bundle.get().matches().get(0);
        assertThat(match.vpToken()).contains(countryDisclosure.getDisclosure());
        assertThat(match.disclosedClaims()).containsEntry("country", "DE");
    }

    @Test
    void dcqlConstantValuesMustMatch() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-123"),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "claims": [
                      { "path": ["personal_id"], "value": "OTHER" }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void multipleDescriptorsCanReuseSingleCredential() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of(
                        "given_name", "Alice",
                        "family_name", "Doe",
                        "personal_id", "ID-123"
                ),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "given-name-primary",
                      "format": "dc+sd-jwt",
                      "claims": [
                        { "path": ["given_name"], "value": "Alice" }
                      ]
                    },
                    {
                      "id": "given-name-secondary",
                      "format": "dc+sd-jwt",
                      "claims": [
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSetsFilterEntriesByVctAndFormat() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "pid.jwt~disc"
        ));
        saveCredential("user", Map.of(
                "id", "StudentCard",
                "type", List.of("StudentCard", "VerifiableCredential"),
                "format", "jwt_vc",
                "credentialSubject", Map.of("student_id", "S-42"),
                "rawCredential", "student.header.payload.signature"
        ));
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "credential_set": [{ "vct": "urn:eudi:pid:1" }],
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "credential_set": [
                        { "format": "jwt_vc" },
                        "StudentCard"
                      ],
                      "claims": [{ "path": ["student_id"] }]
                    }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(2);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("pid");
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Alice");
        assertThat(bundle.get().matches().get(1).descriptorId()).isEqualTo("credential-2");
        assertThat(bundle.get().matches().get(1).credential().get("format")).isEqualTo("jwt_vc");
        assertThat(bundle.get().matches().get(1).disclosedClaims()).containsEntry("student_id", "S-42");
    }

    @Test
    void flattenedClaimsStillMatchJsonPathConstraints() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of(
                        "address.country", "DE",
                        "given_name", "Alice"
                ),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "address-proof",
                    "claims": [
                      { "path": ["address", "country"], "value": "DE" },
                      { "path": ["given_name"] }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).disclosedClaims())
                .containsEntry("country", "DE")
                .containsEntry("given_name", "Alice");
    }

    @Test
    void claimSetsAllowAnyMatchingCombination() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of(
                        "given_name", "Alex",
                        "birthdate", "2000-01-01"
                ),
                "rawCredential", "aaa.bbb.ccc~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "alternative-proof",
                    "claim_set": [
                      [{ "path": ["document_number"] }],
                      { "claims": [{ "path": ["birthdate"], "value": "2000-01-01" }] }
                    ],
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("alternative-proof");
    }

    @Test
    void findPresentationReturnsAggregatedTokens() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "token-1"
        ));
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("family_name", "Doe"),
                "rawCredential", "token-2"
        ));
        String dcql = """
                {
                  "credentials": [
                    { "id": "first", "claims": [{ "path": ["given_name"] }] },
                    { "id": "second", "claims": [{ "path": ["family_name"] }] }
                  ]
                }
                """;

        Optional<PresentationService.Presentation> presentation = presentationService.findPresentation("user", dcql);
        assertThat(presentation).isPresent();
        assertThatJson(presentation.get().vpToken()).isArray().containsExactly("token-1", "token-2");
    }

    @Test
    void multipleDescriptorsPickDifferentCredentialsWhenConstrained() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-123", "given_name", "Alice"),
                "rawCredential", "pid-1"
        ));
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-999", "given_name", "Bob"),
                "rawCredential", "pid-2"
        ));
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "alice",
                      "claims": [
                        { "path": ["personal_id"], "value": "ID-123" },
                        { "path": ["given_name"] }
                      ]
                    },
                    {
                      "id": "bob",
                      "claims": [
                        { "path": ["personal_id"], "value": "ID-999" },
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(2);
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("personal_id", "ID-123");
        assertThat(bundle.get().matches().get(1).disclosedClaims()).containsEntry("personal_id", "ID-999");
    }

    @Test
    void allCredentialRequestsMustBeSatisfied() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-123"),
                "rawCredential", "pid-1"
        ));
        String dcql = """
                {
                  "credentials": [
                    { "id": "one", "claims": [{ "path": ["personal_id"], "value": "ID-123" }] },
                    { "id": "two", "claims": [{ "path": ["personal_id"], "value": "NOPE" }] }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void duplicateDescriptorIdsAreNormalized() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-123"),
                "rawCredential", "pid-1"
        ));
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-456"),
                "rawCredential", "pid-2"
        ));
        String dcql = """
                {
                  "credentials": [
                    { "id": "dup", "claims": [{ "path": ["personal_id"], "value": "ID-123" }] },
                    { "id": "dup", "claims": [{ "path": ["personal_id"], "value": "ID-456" }] }
                  ]
                }
                """;

        Optional<PresentationService.PresentationOptions> options = presentationService.preparePresentationOptions("user", dcql);
        assertThat(options).isPresent();
        List<String> ids = options.get().options().stream().map(opt -> opt.request().id()).toList();
        assertThat(new HashSet<>(ids)).hasSize(2);
    }

    @Test
    void duplicateCandidatesAreDeduplicatedPerDescriptor() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "pid-1"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "single",
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationOptions> options = presentationService.preparePresentationOptions("user", dcql);
        assertThat(options).isPresent();
        assertThat(options.get().options()).hasSize(1);
        assertThat(options.get().options().get(0).candidates()).hasSize(1);
    }

    @Test
    void credentialsWithoutRequestedClaimsAreNotMatched() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("family_name", "Doe"),
                "rawCredential", "pid-1"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationOptions> options = presentationService.preparePresentationOptions("user", dcql);
        assertThat(options).isEmpty();
    }

    @Test
    void singleRequestWithMultipleCredentialsSelectsOne() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-123"),
                "rawCredential", "pid-1"
        ));
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("personal_id", "ID-123"),
                "rawCredential", "pid-2"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "single",
                    "claims": [{ "path": ["personal_id"], "value": "ID-123" }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
    }

    @Test
    void missingSecondaryClaimStillMatchesWhenOnlyPrimaryConstrained() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "pid-1"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "claims": [
                      { "path": ["given_name"], "value": "Alice" },
                      { "path": ["family_name"] }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Alice");
        assertThat(bundle.get().matches().get(0).disclosedClaims()).doesNotContainKey("family_name");
    }

    @Test
    void multipleConstraintsMustAllMatch() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("country", "DE", "age", 25),
                "rawCredential", "pid-1"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "claims": [
                      { "path": ["country"], "value": "DE" },
                      { "path": ["age"], "value": "26" }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSetAndClaimSetMustBothMatch() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "credentialSubject", Map.of("country", "DE"),
                "rawCredential", "pid-1"
        ));
        saveCredential("user", Map.of(
                "vct", "urn:eudi:student:1",
                "credentialSubject", Map.of("country", "DE"),
                "rawCredential", "student-1"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "credential_set": [{ "vct": "urn:eudi:pid:1" }],
                    "claim_set": [[{ "path": ["country"], "value": "DE" }]],
                    "claims": [{ "path": ["country"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).credential().get("rawCredential")).isEqualTo("pid-1");
    }

    @Test
    void formatMismatchDoesNotFallback() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice"),
                "format", "jwt_vc",
                "rawCredential", "jwt-cred"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "format": "dc+sd-jwt",
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void dcqlAbsentFallsBackToStoredClaims() throws Exception {
        saveCredential("user", Map.of(
                "credentialSubject", Map.of("given_name", "Alice", "family_name", "Doe"),
                "rawCredential", "pid-1"
        ));

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", null);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).requestedClaims()).extracting("name")
                .containsExactlyInAnyOrder("given_name", "family_name");
    }

    // ============================================================================
    // Root-level credential_sets tests
    // These test the DCQL credential_sets feature where multiple credential types
    // can be requested with options for which combination satisfies the request.
    // ============================================================================

    @Test
    void credentialSets_eitherOrOption_walletHasFirstCredential_shouldMatch() throws Exception {
        // Wallet has SD-JWT PID only
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice", "family_name", "Doe"),
                "rawCredential", "sdjwt.pid.token~disc"
        ));

        // DCQL requests either SD-JWT PID (cred1) or mDoc PID (cred2)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }, { "path": ["family_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }, { "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["cred1"], ["cred2"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("cred1");
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Alice");
    }

    @Test
    void credentialSets_eitherOrOption_walletHasSecondCredential_shouldMatch() throws Exception {
        // Wallet has mDoc PID only
        saveCredential("user", Map.of(
                "vct", "eu.europa.ec.eudi.pid.1",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("given_name", "Bob", "family_name", "Smith"),
                "rawCredential", "mdoc-pid-token"
        ));

        // DCQL requests either SD-JWT PID (cred1) or mDoc PID (cred2)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }, { "path": ["family_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }, { "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["cred1"], ["cred2"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("cred2");
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Bob");
    }

    @Test
    void credentialSets_eitherOrOption_walletHasBothCredentials_shouldMatchFirst() throws Exception {
        // Wallet has both SD-JWT and mDoc PID
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));
        saveCredential("user", Map.of(
                "vct", "eu.europa.ec.eudi.pid.1",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "mdoc-pid"
        ));

        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["cred1"], ["cred2"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        // Should return first satisfiable option (cred1)
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("cred1");
    }

    @Test
    void credentialSets_eitherOrOption_walletHasNeither_shouldFail() throws Exception {
        // Wallet has a different credential type
        saveCredential("user", Map.of(
                "vct", "urn:some:other:credential",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Charlie"),
                "rawCredential", "other.token~disc"
        ));

        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["cred1"], ["cred2"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSets_bothRequired_walletHasBoth_shouldMatch() throws Exception {
        // Wallet has both credentials
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));
        saveCredential("user", Map.of(
                "vct", "org.iso.18013.5.1.mDL",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("family_name", "Doe"),
                "rawCredential", "mdoc-mdl"
        ));

        // Both cred1 AND cred2 are required (single option with both IDs)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["cred1", "cred2"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(2);
        assertThat(bundle.get().matches().stream().map(PresentationService.DescriptorMatch::descriptorId).toList())
                .containsExactlyInAnyOrder("cred1", "cred2");
    }

    @Test
    void credentialSets_bothRequired_walletHasOnlyOne_shouldFail() throws Exception {
        // Wallet has only the first credential
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // Both cred1 AND cred2 are required
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["cred1", "cred2"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSets_mixedOptions_prefersSingleCredentialOverPair() throws Exception {
        // Wallet has SD-JWT PID only
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice", "family_name", "Doe"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // Options: either single SD-JWT OR (mDoc AND mDL pair)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "sdjwt_pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "mdoc_pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "mdl",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["sdjwt_pid"], ["mdoc_pid", "mdl"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("sdjwt_pid");
    }

    @Test
    void credentialSets_multipleCredentialSets_allMustBeSatisfied() throws Exception {
        // Wallet has PID and mDL
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));
        saveCredential("user", Map.of(
                "vct", "org.iso.18013.5.1.mDL",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("family_name", "Doe"),
                "rawCredential", "mdoc-mdl"
        ));

        // Two credential_sets: one for PID (either format), one for mDL
        // Per OID4VP 1.0 Section 6.2: ALL required credential_sets must be satisfied
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid_sdjwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "mdl",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [
                    { "options": [["pid_sdjwt"], ["pid_mdoc"]] },
                    { "options": [["mdl"]] }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        // Should return BOTH: one from first set (pid_sdjwt) AND one from second set (mdl)
        assertThat(bundle.get().matches()).hasSize(2);
        assertThat(bundle.get().matches().stream().map(PresentationService.DescriptorMatch::descriptorId).toList())
                .containsExactlyInAnyOrder("pid_sdjwt", "mdl");
    }

    @Test
    void credentialSets_multipleCredentialSets_failsIfOneSetCannotBeSatisfied() throws Exception {
        // Wallet has only PID, no mDL
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // Two required credential_sets: PID and mDL
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "mdl",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [
                    { "options": [["pid"]] },
                    { "options": [["mdl"]] }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        // Should fail because mDL credential_set cannot be satisfied
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSets_optionalSet_ignoredWhenNotSatisfiable() throws Exception {
        // Wallet has only PID
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // PID is required, mDL is optional (required: false)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "mdl",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": [
                    { "options": [["pid"]] },
                    { "options": [["mdl"]], "required": false }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        // Should succeed because only required set (PID) is satisfied; optional mDL is skipped
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("pid");
    }

    @Test
    void credentialSets_noCredentialSets_requiresAllCredentials() throws Exception {
        // When no credential_sets is present, all credentials must match (original behavior)
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // Request two credentials without credential_sets - both must be present
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        // Should fail because cred2 (mDoc) is not in wallet
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSets_emptyCredentialSets_fallsBackToAllRequired() throws Exception {
        // Empty credential_sets array should behave like no credential_sets
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "cred1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "cred2",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["family_name"] }]
                    }
                  ],
                  "credential_sets": []
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        // Should fail because empty credential_sets falls back to requiring all
        assertThat(bundle).isEmpty();
    }

    @Test
    void credentialSets_withPurpose_stillMatchesCorrectly() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // credential_sets with purpose field (should be ignored for matching)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "purpose": "Identity verification for age check",
                    "options": [["pid"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
    }

    @Test
    void credentialSets_threeWayOptions_selectsFirstSatisfiable() throws Exception {
        // Wallet has only SD-JWT PID
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // Three options: mDoc PID, mDL, or SD-JWT PID (in that order)
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "mdoc_pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [{ "path": ["given_name"] }]
                    },
                    {
                      "id": "mdl",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                      "claims": [{ "path": ["family_name"] }]
                    },
                    {
                      "id": "sdjwt_pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"] }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["mdoc_pid"], ["mdl"], ["sdjwt_pid"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        // First two options (mdoc_pid, mdl) are not in wallet, so third option (sdjwt_pid) should match
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("sdjwt_pid");
    }

    @Test
    void credentialSets_claimsMustAlsoMatch_withinSatisfiedOption() throws Exception {
        // Wallet has SD-JWT PID but with different claim value
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of("given_name", "Bob"),
                "rawCredential", "sdjwt.pid~disc"
        ));

        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [{ "path": ["given_name"], "value": "Alice" }]
                    }
                  ],
                  "credential_sets": [{
                    "options": [["pid"]]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        // Should fail because claim value doesn't match
        assertThat(bundle).isEmpty();
    }

    // ============================================================================
    // meta (vct_values / doctype_value) tests
    // ============================================================================

    @Test
    void metaVctValuesMatchesSdJwtCredential() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:de:1",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.pid~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Alice");
    }

    @Test
    void metaVctValuesMismatchRejectsCredential() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:other:credential",
                "credentialSubject", Map.of("given_name", "Alice"),
                "rawCredential", "sdjwt.other~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void metaDoctypeValueMatchesMdocCredential() throws Exception {
        saveCredential("user", Map.of(
                "vct", "eu.europa.ec.eudi.pid.1",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("given_name", "Bob"),
                "rawCredential", "mdoc-pid"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid_mdoc",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                    "claims": [{ "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Bob");
    }

    @Test
    void metaDoctypeValueMismatchRejectsMdocCredential() throws Exception {
        saveCredential("user", Map.of(
                "vct", "eu.europa.ec.eudi.pid.1",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("given_name", "Bob"),
                "rawCredential", "mdoc-pid"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isEmpty();
    }

    @Test
    void metaVctValuesAcceptsAnyListedValue() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:de:2",
                "credentialSubject", Map.of("given_name", "Charlie"),
                "rawCredential", "sdjwt.pid.v2~disc"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:de:2"] },
                    "claims": [{ "path": ["given_name"] }]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches().get(0).disclosedClaims()).containsEntry("given_name", "Charlie");
    }

    // ============================================================================
    // mDoc 2-element claims paths
    // ============================================================================

    @Test
    void mdocTwoElementPathMatchesFlatClaim() throws Exception {
        saveCredential("user", Map.of(
                "vct", "eu.europa.ec.eudi.pid.1",
                "format", "mso_mdoc",
                "credentialSubject", Map.of("resident_street", "Main St 1", "resident_city", "Berlin"),
                "rawCredential", "mdoc-pid"
        ));
        String dcql = """
                {
                  "credentials": [{
                    "id": "pid_mdoc",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                    "claims": [
                      { "path": ["eu.europa.ec.eudi.pid.1", "resident_street"] },
                      { "path": ["eu.europa.ec.eudi.pid.1", "resident_city"] }
                    ]
                  }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).disclosedClaims())
                .containsEntry("resident_street", "Main St 1")
                .containsEntry("resident_city", "Berlin");
    }

    // ============================================================================
    // Sandbox DCQL query end-to-end
    // ============================================================================

    @Test
    void sandboxDcqlQueryMatchesSdJwtPid() throws Exception {
        saveCredential("user", Map.of(
                "vct", "urn:eudi:pid:de:1",
                "format", "dc+sd-jwt",
                "credentialSubject", Map.of(
                        "given_name", "Alice",
                        "family_name", "Doe",
                        "birth_date", "1990-01-01",
                        "address", Map.of("street_address", "Main St 1", "locality", "Berlin")
                ),
                "rawCredential", "sdjwt.pid~disc"
        ));

        // Exact sandbox DCQL query — must match the registration certificate
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] },
                        { "path": ["birth_date"] },
                        { "path": ["address", "street_address"] },
                        { "path": ["address", "locality"] }
                      ]
                    },
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "address", "street_address"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "address", "locality"] }
                      ]
                    }
                  ],
                  "credential_sets": [{ "options": [["pid_sd_jwt"], ["pid_mdoc"]] }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("pid_sd_jwt");
        assertThat(bundle.get().matches().get(0).disclosedClaims())
                .containsEntry("given_name", "Alice")
                .containsEntry("family_name", "Doe");
    }

    @Test
    void sandboxDcqlQueryMatchesMdocPid() throws Exception {
        // mDoc claims are stored flat (namespace elements) — the mock wallet resolves
        // 3-element DCQL paths ["ns", "address", "street_address"] by claim name (last segment)
        saveCredential("user", Map.of(
                "vct", "eu.europa.ec.eudi.pid.1",
                "format", "mso_mdoc",
                "credentialSubject", Map.of(
                        "given_name", "Bob",
                        "family_name", "Smith",
                        "birth_date", "1985-06-15",
                        "street_address", "Elm Ave 42",
                        "locality", "Munich"
                ),
                "rawCredential", "mdoc-pid-token"
        ));

        // Same sandbox DCQL query — should fall through to mDoc option
        String dcql = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] },
                        { "path": ["birth_date"] },
                        { "path": ["address", "street_address"] },
                        { "path": ["address", "locality"] }
                      ]
                    },
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "address", "street_address"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "address", "locality"] }
                      ]
                    }
                  ],
                  "credential_sets": [{ "options": [["pid_sd_jwt"], ["pid_mdoc"]] }]
                }
                """;

        Optional<PresentationService.PresentationBundle> bundle = presentationService.preparePresentations("user", dcql);
        assertThat(bundle).isPresent();
        assertThat(bundle.get().matches()).hasSize(1);
        assertThat(bundle.get().matches().get(0).descriptorId()).isEqualTo("pid_mdoc");
        assertThat(bundle.get().matches().get(0).disclosedClaims())
                .containsEntry("given_name", "Bob")
                .containsEntry("family_name", "Smith")
                .containsEntry("street_address", "Elm Ave 42")
                .containsEntry("locality", "Munich");
    }

    private void saveCredential(String userId, Map<String, Object> credential) throws Exception {
        Map<String, Object> toStore = new HashMap<>(credential);
        toStore.putIfAbsent("format", "dc+sd-jwt");
        credentialStore.saveCredential(userId, toStore);
    }
}
