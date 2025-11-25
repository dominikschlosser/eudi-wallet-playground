package de.arbeitsagentur.keycloak.wallet.demo.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
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
                java.util.List.of("demo-attestation-issuer")
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

    private void saveCredential(String userId, Map<String, Object> credential) throws Exception {
        Map<String, Object> toStore = new HashMap<>(credential);
        toStore.putIfAbsent("format", "dc+sd-jwt");
        credentialStore.saveCredential(userId, toStore);
    }
}
