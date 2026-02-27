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

import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builder for DCQL (Digital Credentials Query Language) queries.
 * <p>
 * Constructs DCQL queries from credential type specifications, supporting:
 * - Multiple credential types (SD-JWT VC and mso_mdoc)
 * - Claim path specifications per credential type
 * - credential_sets for multi-credential requests (optional/all modes)
 * - claim_sets for optional claims within a credential
 */
public class DcqlQueryBuilder {
    /**
     * Path separator for namespace-qualified claim paths.
     * Example: "eu.europa.ec.eudi.pid.1/family_name" splits to ["eu.europa.ec.eudi.pid.1", "family_name"]
     */
    public static final String PATH_SEPARATOR = "/";
    /**
     * Delimiter used in type keys to encode format and type together.
     * Format: "format|type" (e.g., "dc+sd-jwt|eu.europa.ec.eudi.pid.1")
     */
    public static final String TYPE_KEY_DELIMITER = "|";

    private final ObjectMapper objectMapper;
    private final List<CredentialTypeSpec> credentialTypes = new ArrayList<>();
    private boolean allCredentialsRequired = false;
    private String purpose;

    /**
     * Specification for a single claim with optional flag.
     */
    public record ClaimSpec(String path, boolean optional) {
        public ClaimSpec(String path) {
            this(path, false);
        }
    }

    /**
     * Specification for a credential type to request.
     */
    public record CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {
        public CredentialTypeSpec(String format, String type) {
            this(format, type, List.of());
        }

        /**
         * Convenience constructor for simple claim paths (all required).
         */
        public static CredentialTypeSpec fromPaths(String format, String type, List<String> claimPaths) {
            List<ClaimSpec> specs = claimPaths.stream()
                    .map(ClaimSpec::new)
                    .toList();
            return new CredentialTypeSpec(format, type, specs);
        }
    }

    public DcqlQueryBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Add a credential type to request with claim specifications.
     */
    public DcqlQueryBuilder addCredentialType(String format, String type, List<ClaimSpec> claimSpecs) {
        credentialTypes.add(new CredentialTypeSpec(format, type, claimSpecs != null ? claimSpecs : List.of()));
        return this;
    }

    /**
     * Add a credential type to request with simple claim paths (all required).
     */
    public DcqlQueryBuilder addCredentialTypeWithPaths(String format, String type, List<String> claimPaths) {
        return addCredentialType(format, type,
                claimPaths != null ? claimPaths.stream().map(ClaimSpec::new).toList() : List.of());
    }

    /**
     * Add a credential type to request without specific claims.
     */
    public DcqlQueryBuilder addCredentialType(String format, String type) {
        return addCredentialType(format, type, List.of());
    }

    /**
     * Set whether all credentials are required (true) or any one suffices (false).
     * Only applicable when multiple credential types are added.
     */
    public DcqlQueryBuilder setAllCredentialsRequired(boolean required) {
        this.allCredentialsRequired = required;
        return this;
    }

    /**
     * Set the purpose description for the credential request.
     * This is optional and will be included in credential_sets if set.
     */
    public DcqlQueryBuilder setPurpose(String purpose) {
        this.purpose = purpose;
        return this;
    }

    /**
     * Build the DCQL query JSON string.
     * <p>
     * If optional claims are present, generates claim_sets with two options:
     * 1. All claims (required + optional)
     * 2. Only required claims
     */
    public String build() {
        if (credentialTypes.isEmpty()) {
            return buildDefaultDcql();
        }

        try {
            List<Map<String, Object>> credentials = new ArrayList<>();
            List<String> credentialIds = new ArrayList<>();
            int credIndex = 1;

            for (CredentialTypeSpec typeSpec : credentialTypes) {
                String credId = "cred" + credIndex++;
                credentialIds.add(credId);
                credentials.add(buildCredentialEntry(typeSpec, credId));
            }

            Map<String, Object> dcqlQuery = new LinkedHashMap<>();
            dcqlQuery.put("credentials", credentials);

            if (credentials.size() > 1) {
                dcqlQuery.put("credential_sets", List.of(buildCredentialSet(credentialIds)));
            }

            return objectMapper.writeValueAsString(dcqlQuery);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build DCQL query", e);
        }
    }

    private Map<String, Object> buildCredentialEntry(CredentialTypeSpec typeSpec, String credId) {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("id", credId);
        credential.put("format", typeSpec.format());
        credential.put("meta", buildMetaConstraint(typeSpec));

        if (!typeSpec.claimSpecs().isEmpty()) {
            addClaimsWithOptionalSets(credential, typeSpec.claimSpecs(), typeSpec.format(), typeSpec.type());
        }
        return credential;
    }

    private Map<String, Object> buildMetaConstraint(CredentialTypeSpec typeSpec) {
        Map<String, Object> meta = new LinkedHashMap<>();
        if (Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(typeSpec.format())) {
            meta.put("doctype_value", typeSpec.type());
        } else {
            meta.put("vct_values", List.of(typeSpec.type()));
        }
        return meta;
    }

    private void addClaimsWithOptionalSets(Map<String, Object> credential, List<ClaimSpec> claimSpecs,
                                             String format, String type) {
        List<Map<String, Object>> claims = new ArrayList<>();
        List<String> requiredClaimIds = new ArrayList<>();
        List<String> allClaimIds = new ArrayList<>();
        boolean hasOptionalClaims = false;
        int claimIndex = 1;

        for (ClaimSpec claimSpec : claimSpecs) {
            String claimId = "claim" + claimIndex++;
            Map<String, Object> claim = new LinkedHashMap<>();
            claim.put("id", claimId);
            claim.put("path", splitClaimPath(claimSpec.path(), format, type));
            claims.add(claim);
            allClaimIds.add(claimId);
            if (claimSpec.optional()) {
                hasOptionalClaims = true;
            } else {
                requiredClaimIds.add(claimId);
            }
        }
        credential.put("claims", claims);

        // Add claim_sets if there are optional claims with fallback to required-only
        if (hasOptionalClaims && !requiredClaimIds.isEmpty()) {
            credential.put("claim_sets", List.of(allClaimIds, requiredClaimIds));
        }
    }

    private Map<String, Object> buildCredentialSet(List<String> credentialIds) {
        Map<String, Object> credentialSet = new LinkedHashMap<>();
        if (purpose != null && !purpose.isBlank()) {
            credentialSet.put("purpose", purpose);
        }

        if (allCredentialsRequired) {
            credentialSet.put("options", List.of(credentialIds));
        } else {
            List<List<String>> options = credentialIds.stream()
                    .map(List::of)
                    .toList();
            credentialSet.put("options", options);
        }
        return credentialSet;
    }

    private String buildDefaultDcql() {
        return "{\"credentials\":[{\"id\":\"cred1\",\"claims\":[{\"path\":[\"given_name\"]},{\"path\":[\"family_name\"]}]}]}";
    }

    /**
     * Create a builder from aggregated mapper information.
     * This is a convenience method for use with IdP mappers.
     */
    public static DcqlQueryBuilder fromMapperSpecs(ObjectMapper objectMapper,
                                                    Map<String, CredentialTypeSpec> credentialTypes,
                                                    boolean allCredentialsRequired,
                                                    String purpose) {
        DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
        builder.setAllCredentialsRequired(allCredentialsRequired);
        builder.setPurpose(purpose);
        for (CredentialTypeSpec spec : credentialTypes.values()) {
            builder.credentialTypes.add(spec);
        }
        return builder;
    }

    /**
     * Create a builder from simple path lists (all claims required).
     * This is a convenience method for backward compatibility.
     */
    public static DcqlQueryBuilder fromSimplePaths(ObjectMapper objectMapper,
                                                    Map<String, List<String>> claimPathsByType,
                                                    Map<String, String> formatByType,
                                                    boolean allCredentialsRequired,
                                                    String purpose) {
        Map<String, CredentialTypeSpec> specs = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : claimPathsByType.entrySet()) {
            String typeKey = entry.getKey();
            String format = formatByType.get(typeKey);
            String type = extractTypeFromKey(typeKey);
            specs.put(typeKey, CredentialTypeSpec.fromPaths(format, type, entry.getValue()));
        }
        return fromMapperSpecs(objectMapper, specs, allCredentialsRequired, purpose);
    }

    /**
     * Splits a claim path into segments using the PATH_SEPARATOR.
     * <p>
     * For mso_mdoc credentials, paths MUST have exactly two elements per OID4VP 1.0 Section 7.2:
     * {@code ["namespace", "element_identifier"]}. If only a simple element name is given,
     * the namespace is derived from the doctype by removing its last segment
     * (e.g., "org.iso.18013.5.1.mDL" → "org.iso.18013.5.1").
     * <p>
     * A literal {@code "null"} segment is converted to JSON {@code null}, which acts as a DCQL
     * wildcard for array element selection (e.g., {@code "nationalities/null"} →
     * {@code ["nationalities", null]}). Non-negative integer segments are converted to JSON
     * numbers for specific array index selection (e.g., {@code "nationalities/0"} →
     * {@code ["nationalities", 0]}).
     *
     * @param path   the claim path (e.g., "eu.europa.ec.eudi.pid.1/family_name" or "given_name")
     * @param format the credential format (may be null)
     * @param type   the credential type / doctype (may be null)
     * @return list of path segments (may contain {@code null} for array wildcard selectors)
     */
    private static List<Object> splitClaimPath(String path, String format, String type) {
        if (path == null || path.isBlank()) {
            return List.of();
        }
        if (path.contains(PATH_SEPARATOR)) {
            return Arrays.stream(path.split(PATH_SEPARATOR))
                    .<Object>map(DcqlQueryBuilder::parsePathSegment)
                    .collect(Collectors.toList());
        }
        // For mso_mdoc, claim paths must be [namespace, element_identifier]
        // The namespace is the doctype itself (e.g., "eu.europa.ec.eudi.pid.1")
        if (Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(format) && type != null) {
            return List.of(type, path);
        }
        return List.of(path);
    }

    /**
     * Parses a single path segment from its string representation.
     * <ul>
     *   <li>{@code "null"} → JSON {@code null} (array wildcard)</li>
     *   <li>Non-negative integer strings (e.g. {@code "0"}, {@code "42"}) → {@link Integer}</li>
     *   <li>Everything else → kept as {@link String}</li>
     * </ul>
     */
    private static Object parsePathSegment(String segment) {
        if ("null".equals(segment)) {
            return null;
        }
        try {
            int index = Integer.parseInt(segment);
            if (index >= 0) {
                return index;
            }
        } catch (NumberFormatException ignored) {
        }
        return segment;
    }

    /**
     * Extracts the credential type from a type key that may contain a format prefix.
     * Type key format: "format|type" or just "type"
     *
     * @param typeKey the type key (e.g., "dc+sd-jwt|eu.europa.ec.eudi.pid.1" or "eu.europa.ec.eudi.pid.1")
     * @return the credential type portion
     */
    private static String extractTypeFromKey(String typeKey) {
        if (typeKey == null || typeKey.isBlank()) {
            return typeKey;
        }
        int delimiterIndex = typeKey.indexOf(TYPE_KEY_DELIMITER);
        if (delimiterIndex >= 0 && delimiterIndex < typeKey.length() - 1) {
            return typeKey.substring(delimiterIndex + 1);
        }
        return typeKey;
    }
}
