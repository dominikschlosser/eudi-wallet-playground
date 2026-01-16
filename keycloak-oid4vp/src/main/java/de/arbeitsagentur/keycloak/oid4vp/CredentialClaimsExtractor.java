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

import org.jboss.logging.Logger;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Extracts and processes claims from verified credentials.
 */
public final class CredentialClaimsExtractor {

    private static final Logger LOG = Logger.getLogger(CredentialClaimsExtractor.class);
    private static final List<String> COMMON_IDENTITY_CLAIMS =
            List.of("sub", "personal_id", "email", "given_name", "family_name");

    private CredentialClaimsExtractor() {}

    /**
     * Extracts a claim value as a string.
     */
    public static String extractClaim(Map<String, Object> claims, String claimName) {
        if (claims == null || claimName == null) {
            return null;
        }
        Object value = claims.get(claimName);
        if (value == null) {
            return null;
        }
        if (value instanceof String s) {
            return s;
        }
        return value.toString();
    }

    /**
     * Extracts the credential type from claims.
     * Uses 'vct' for SD-JWT, 'docType' for mDoc, or a fallback based on presentation type.
     */
    public static String extractCredentialType(Map<String, Object> claims,
                                                Oid4vpVerifierService.PresentationType type) {
        if (claims.containsKey("vct")) {
            return extractClaim(claims, "vct");
        }
        if (claims.containsKey("docType")) {
            return extractClaim(claims, "docType");
        }
        return type == Oid4vpVerifierService.PresentationType.MDOC ? "mso_mdoc" : "dc+sd-jwt";
    }

    /**
     * Builds a JSON metadata string for storing in federated identity token field.
     * Includes credential attributes and matched claim values for bi-directional verification.
     */
    public static String buildCredentialMetadataJson(String issuer, String credentialType, String subject,
                                                      String userMappingClaim, Map<String, Object> claims,
                                                      ObjectMapper objectMapper) {
        try {
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("issuer", issuer);
            metadata.put("credential_type", credentialType);
            metadata.put("subject", subject);
            metadata.put("user_mapping_claim", userMappingClaim);
            metadata.put("linked_at", Instant.now().toString());

            Map<String, Object> matchedClaims = new LinkedHashMap<>();
            String mappingValue = extractClaim(claims, userMappingClaim);
            if (mappingValue != null) {
                matchedClaims.put(userMappingClaim, mappingValue);
            }

            for (String claimName : COMMON_IDENTITY_CLAIMS) {
                String value = extractClaim(claims, claimName);
                if (value != null && !matchedClaims.containsKey(claimName)) {
                    matchedClaims.put(claimName, value);
                }
            }

            if (!matchedClaims.isEmpty()) {
                metadata.put("matched_claims", matchedClaims);
            }

            return objectMapper.writeValueAsString(metadata);
        } catch (Exception e) {
            LOG.warnf("Failed to build credential metadata JSON: %s", e.getMessage());
            return "{}";
        }
    }
}
