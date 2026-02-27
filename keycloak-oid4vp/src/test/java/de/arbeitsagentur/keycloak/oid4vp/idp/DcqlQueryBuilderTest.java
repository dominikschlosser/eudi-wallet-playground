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
package de.arbeitsagentur.keycloak.oid4vp.idp;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DcqlQueryBuilderTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void buildDefaultDcqlWhenNoCredentialTypes() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER).build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        assertThat(node.has("credentials")).isTrue();
        assertThat(node.get("credentials").size()).isEqualTo(1);
        assertThat(node.get("credentials").get(0).get("id").asText()).isEqualTo("cred1");
    }

    @Test
    void buildSingleSdJwtCredential() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("given_name", "family_name")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        // Should have one credential
        assertThat(node.get("credentials").size()).isEqualTo(1);

        JsonNode cred = node.get("credentials").get(0);
        assertThat(cred.get("id").asText()).isEqualTo("cred1");
        assertThat(cred.get("format").asText()).isEqualTo("dc+sd-jwt");

        // Should have vct_values in meta
        assertThat(cred.get("meta").get("vct_values").get(0).asText()).isEqualTo("eu.europa.ec.eudi.pid.1");

        // Should have claims
        assertThat(cred.get("claims").size()).isEqualTo(2);
        assertThat(cred.get("claims").get(0).get("path").get(0).asText()).isEqualTo("given_name");
        assertThat(cred.get("claims").get(1).get("path").get(0).asText()).isEqualTo("family_name");

        // No credential_sets for single credential
        assertThat(node.has("credential_sets")).isFalse();
    }

    @Test
    void buildSingleMdocCredential() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                        "org.iso.18013.5.1.mDL",
                        List.of("driving_privileges")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        JsonNode cred = node.get("credentials").get(0);
        assertThat(cred.get("format").asText()).isEqualTo("mso_mdoc");

        // Should have doctype_value in meta (not vct_values)
        assertThat(cred.get("meta").has("doctype_value")).isTrue();
        assertThat(cred.get("meta").get("doctype_value").asText()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(cred.get("meta").has("vct_values")).isFalse();

        // mdoc claim paths must have exactly 2 elements: [namespace, element_identifier]
        // Namespace equals the doctype (e.g., "org.iso.18013.5.1.mDL")
        JsonNode claims = cred.get("claims");
        assertThat(claims.get(0).get("path").size()).isEqualTo(2);
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("driving_privileges");
    }

    @Test
    void buildMultipleCredentialsOptionalMode() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("given_name", "family_name")
                )
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                        "org.iso.18013.5.1.mDL",
                        List.of("driving_privileges")
                )
                .setAllCredentialsRequired(false) // optional mode (default)
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        // Should have two credentials
        assertThat(node.get("credentials").size()).isEqualTo(2);

        // First credential: SD-JWT PID
        JsonNode cred1 = node.get("credentials").get(0);
        assertThat(cred1.get("id").asText()).isEqualTo("cred1");
        assertThat(cred1.get("format").asText()).isEqualTo("dc+sd-jwt");
        assertThat(cred1.get("meta").get("vct_values").get(0).asText()).isEqualTo("eu.europa.ec.eudi.pid.1");

        // Second credential: mDL
        JsonNode cred2 = node.get("credentials").get(1);
        assertThat(cred2.get("id").asText()).isEqualTo("cred2");
        assertThat(cred2.get("format").asText()).isEqualTo("mso_mdoc");
        assertThat(cred2.get("meta").get("doctype_value").asText()).isEqualTo("org.iso.18013.5.1.mDL");

        // Should have credential_sets with optional mode (each ID as separate option)
        assertThat(node.has("credential_sets")).isTrue();
        JsonNode credentialSets = node.get("credential_sets");
        assertThat(credentialSets.size()).isEqualTo(1);

        JsonNode options = credentialSets.get(0).get("options");
        assertThat(options.size()).isEqualTo(2);
        // Optional mode: [["cred1"], ["cred2"]]
        assertThat(options.get(0).size()).isEqualTo(1);
        assertThat(options.get(0).get(0).asText()).isEqualTo("cred1");
        assertThat(options.get(1).size()).isEqualTo(1);
        assertThat(options.get(1).get(0).asText()).isEqualTo("cred2");
    }

    @Test
    void buildMultipleCredentialsAllRequiredMode() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("given_name")
                )
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                        "org.iso.18013.5.1.mDL",
                        List.of("driving_privileges")
                )
                .setAllCredentialsRequired(true) // all mode
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        // Should have credential_sets with all mode (single option with all IDs)
        JsonNode options = node.get("credential_sets").get(0).get("options");
        assertThat(options.size()).isEqualTo(1);
        // All mode: [["cred1", "cred2"]]
        assertThat(options.get(0).size()).isEqualTo(2);
        assertThat(options.get(0).get(0).asText()).isEqualTo("cred1");
        assertThat(options.get(0).get(1).asText()).isEqualTo("cred2");
    }

    @Test
    void buildMdocWithExplicitNamespacePath() throws Exception {
        // When namespace is already in the path (via /), it should NOT double-prefix
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                        "org.iso.18013.5.1.mDL",
                        List.of("org.iso.18013.5.1/driving_privileges")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        assertThat(claims.get(0).get("path").size()).isEqualTo(2);
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("org.iso.18013.5.1");
        assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("driving_privileges");
    }

    @Test
    void buildWithNestedClaimPaths() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("address/city", "address/street")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        // Nested paths should be split: "address/city" -> ["address", "city"]
        assertThat(claims.get(0).get("path").size()).isEqualTo(2);
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("address");
        assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("city");
    }

    @Test
    void buildWithNamespacedClaimPaths() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("eu.europa.ec.eudi.pid.1/family_name", "eu.europa.ec.eudi.pid.1/given_name")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        // Namespaced paths: "eu.europa.ec.eudi.pid.1/family_name" -> ["eu.europa.ec.eudi.pid.1", "family_name"]
        assertThat(claims.get(0).get("path").size()).isEqualTo(2);
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("eu.europa.ec.eudi.pid.1");
        assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("family_name");
    }

    @Test
    void buildWithNoClaims() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialType(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1"
                        // No claims specified
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode cred = node.get("credentials").get(0);

        // Should not have claims array when no claims specified
        assertThat(cred.has("claims")).isFalse();
    }

    @Test
    void buildFromMapperSpecs() throws Exception {
        Map<String, DcqlQueryBuilder.CredentialTypeSpec> specs = new LinkedHashMap<>();
        specs.put("key1", DcqlQueryBuilder.CredentialTypeSpec.fromPaths(
                Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                "eu.europa.ec.eudi.pid.1",
                List.of("given_name", "family_name")
        ));
        specs.put("key2", DcqlQueryBuilder.CredentialTypeSpec.fromPaths(
                Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                "org.iso.18013.5.1.mDL",
                List.of("driving_privileges")
        ));

        String dcql = DcqlQueryBuilder.fromMapperSpecs(OBJECT_MAPPER, specs, false, null).build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        assertThat(node.get("credentials").size()).isEqualTo(2);
        assertThat(node.has("credential_sets")).isTrue();
    }

    @Test
    void buildWithPurpose() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type1", List.of("claim1"))
                .addCredentialTypeWithPaths(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type2", List.of("claim2"))
                .setPurpose("Identity verification for account creation")
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        // Should have credential_sets with purpose
        assertThat(node.has("credential_sets")).isTrue();
        JsonNode credentialSet = node.get("credential_sets").get(0);
        assertThat(credentialSet.has("purpose")).isTrue();
        assertThat(credentialSet.get("purpose").asText()).isEqualTo("Identity verification for account creation");
    }

    @Test
    void buildWithPurposeFromMapperSpecs() throws Exception {
        Map<String, DcqlQueryBuilder.CredentialTypeSpec> specs = new LinkedHashMap<>();
        specs.put("key1", DcqlQueryBuilder.CredentialTypeSpec.fromPaths(
                Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type1", List.of("claim1")
        ));
        specs.put("key2", DcqlQueryBuilder.CredentialTypeSpec.fromPaths(
                Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type2", List.of("claim2")
        ));

        String dcql = DcqlQueryBuilder.fromMapperSpecs(OBJECT_MAPPER, specs, false, "Age verification").build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        assertThat(node.get("credential_sets").get(0).get("purpose").asText()).isEqualTo("Age verification");
    }

    @Test
    void buildSingleCredentialNoPurpose() throws Exception {
        // Purpose should NOT appear for single credential (no credential_sets)
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type1", List.of("claim1"))
                .setPurpose("Some purpose")
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        // Single credential = no credential_sets, so no purpose
        assertThat(node.has("credential_sets")).isFalse();
    }

    @Test
    void buildWithOptionalClaimsGeneratesClaimSets() throws Exception {
        // When optional claims are present, claim_sets should be generated
        List<DcqlQueryBuilder.ClaimSpec> claimSpecs = List.of(
                new DcqlQueryBuilder.ClaimSpec("document_number", false),  // required
                new DcqlQueryBuilder.ClaimSpec("family_name", false),      // required
                new DcqlQueryBuilder.ClaimSpec("given_name", false),       // required
                new DcqlQueryBuilder.ClaimSpec("nationalities", true)      // optional
        );

        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialType(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        claimSpecs
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode cred = node.get("credentials").get(0);

        // Should have claims with IDs
        JsonNode claims = cred.get("claims");
        assertThat(claims.size()).isEqualTo(4);
        assertThat(claims.get(0).get("id").asText()).isEqualTo("claim1");
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("document_number");

        // Should have claim_sets with two options
        assertThat(cred.has("claim_sets")).isTrue();
        JsonNode claimSets = cred.get("claim_sets");
        assertThat(claimSets.size()).isEqualTo(2);

        // Option 1: All claims (preferred)
        JsonNode allClaims = claimSets.get(0);
        assertThat(allClaims.size()).isEqualTo(4);
        assertThat(allClaims.get(0).asText()).isEqualTo("claim1");
        assertThat(allClaims.get(1).asText()).isEqualTo("claim2");
        assertThat(allClaims.get(2).asText()).isEqualTo("claim3");
        assertThat(allClaims.get(3).asText()).isEqualTo("claim4");

        // Option 2: Required claims only (fallback)
        JsonNode requiredClaims = claimSets.get(1);
        assertThat(requiredClaims.size()).isEqualTo(3);
        assertThat(requiredClaims.get(0).asText()).isEqualTo("claim1");
        assertThat(requiredClaims.get(1).asText()).isEqualTo("claim2");
        assertThat(requiredClaims.get(2).asText()).isEqualTo("claim3");
    }

    @Test
    void buildWithAllRequiredClaimsNoClaimSets() throws Exception {
        // When all claims are required, no claim_sets should be generated
        List<DcqlQueryBuilder.ClaimSpec> claimSpecs = List.of(
                new DcqlQueryBuilder.ClaimSpec("document_number", false),
                new DcqlQueryBuilder.ClaimSpec("family_name", false),
                new DcqlQueryBuilder.ClaimSpec("given_name", false)
        );

        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialType(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        claimSpecs
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode cred = node.get("credentials").get(0);

        // Should NOT have claim_sets when all claims are required
        assertThat(cred.has("claim_sets")).isFalse();
    }

    @Test
    void buildFromMapperSpecsWithOptionalClaims() throws Exception {
        // Test that fromMapperSpecs correctly handles optional claims
        List<DcqlQueryBuilder.ClaimSpec> claimSpecs = List.of(
                new DcqlQueryBuilder.ClaimSpec("document_number", false),
                new DcqlQueryBuilder.ClaimSpec("family_name", false),
                new DcqlQueryBuilder.ClaimSpec("nationality", true)  // optional
        );

        Map<String, DcqlQueryBuilder.CredentialTypeSpec> specs = new LinkedHashMap<>();
        specs.put("key1", new DcqlQueryBuilder.CredentialTypeSpec(
                Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                "eu.europa.ec.eudi.pid.1",
                claimSpecs
        ));

        String dcql = DcqlQueryBuilder.fromMapperSpecs(OBJECT_MAPPER, specs, false, null).build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode cred = node.get("credentials").get(0);

        // Should have claim_sets because of optional claim
        assertThat(cred.has("claim_sets")).isTrue();
        JsonNode claimSets = cred.get("claim_sets");

        // Two options: all claims and required only
        assertThat(claimSets.size()).isEqualTo(2);
        assertThat(claimSets.get(0).size()).isEqualTo(3); // all claims
        assertThat(claimSets.get(1).size()).isEqualTo(2); // required only
    }

    @Test
    void buildWithArrayWildcardPath() throws Exception {
        // "nationalities/null" should produce ["nationalities", null] (JSON null, not the string "null")
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("given_name", "nationalities/null")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        // given_name: simple path
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("given_name");

        // nationalities: path with null wildcard for array elements
        JsonNode natPath = claims.get(1).get("path");
        assertThat(natPath.size()).isEqualTo(2);
        assertThat(natPath.get(0).asText()).isEqualTo("nationalities");
        assertThat(natPath.get(1).isNull()).isTrue();
    }

    @Test
    void buildWithArrayIndexPath() throws Exception {
        // "nationalities/0" should produce ["nationalities", 0] (JSON number, not the string "0")
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("given_name", "nationalities/0")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        // nationalities: path with numeric index
        JsonNode natPath = claims.get(1).get("path");
        assertThat(natPath.size()).isEqualTo(2);
        assertThat(natPath.get(0).asText()).isEqualTo("nationalities");
        assertThat(natPath.get(1).isNumber()).isTrue();
        assertThat(natPath.get(1).intValue()).isEqualTo(0);
    }

    @Test
    void buildEuPidMdocUsesFullDoctypeAsNamespace() throws Exception {
        // EU PID doctype "eu.europa.ec.eudi.pid.1" must be used as-is for the namespace
        // (not stripped to "eu.europa.ec.eudi.pid")
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("given_name", "family_name", "birth_date")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        // All claims should have the full doctype as namespace
        for (int i = 0; i < claims.size(); i++) {
            JsonNode path = claims.get(i).get("path");
            assertThat(path.size()).isEqualTo(2);
            assertThat(path.get(0).asText()).isEqualTo("eu.europa.ec.eudi.pid.1");
        }
        assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("given_name");
        assertThat(claims.get(1).get("path").get(1).asText()).isEqualTo("family_name");
        assertThat(claims.get(2).get("path").get(1).asText()).isEqualTo("birth_date");
    }

    @Test
    void buildMdocArrayWildcardPathUsesNamespacePrefixAndNull() throws Exception {
        // For mDoc, "nationalities/null" should produce [doctype, "nationalities", null]
        // but since mDoc paths only have 2 elements, the /null is for SD-JWT only
        // mDoc should just use [doctype, "nationalities"]
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(
                        Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC,
                        "eu.europa.ec.eudi.pid.1",
                        List.of("nationality")
                )
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);
        JsonNode claims = node.get("credentials").get(0).get("claims");

        assertThat(claims.get(0).get("path").size()).isEqualTo(2);
        assertThat(claims.get(0).get("path").get(0).asText()).isEqualTo("eu.europa.ec.eudi.pid.1");
        assertThat(claims.get(0).get("path").get(1).asText()).isEqualTo("nationality");
    }

    @Test
    void buildThreeCredentialTypesOptionalMode() throws Exception {
        String dcql = new DcqlQueryBuilder(OBJECT_MAPPER)
                .addCredentialTypeWithPaths(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type1", List.of("claim1"))
                .addCredentialTypeWithPaths(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, "type2", List.of("claim2"))
                .addCredentialTypeWithPaths(Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC, "type3", List.of("claim3"))
                .setAllCredentialsRequired(false)
                .build();

        JsonNode node = OBJECT_MAPPER.readTree(dcql);

        assertThat(node.get("credentials").size()).isEqualTo(3);

        // Optional mode: [["cred1"], ["cred2"], ["cred3"]]
        JsonNode options = node.get("credential_sets").get(0).get("options");
        assertThat(options.size()).isEqualTo(3);
        for (int i = 0; i < 3; i++) {
            assertThat(options.get(i).size()).isEqualTo(1);
            assertThat(options.get(i).get(0).asText()).isEqualTo("cred" + (i + 1));
        }
    }
}
