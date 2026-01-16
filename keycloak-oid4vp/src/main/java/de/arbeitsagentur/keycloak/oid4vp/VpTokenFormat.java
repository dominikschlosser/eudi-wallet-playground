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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Detects and parses VP token formats.
 *
 * VP tokens can be in two formats:
 * - Single credential: raw JWT/SD-JWT string (e.g., "eyJ...")
 * - Multi-credential: JSON object mapping credential IDs to arrays (e.g., {"pid": ["eyJ..."], "login_cred": ["eyJ..."]})
 */
public final class VpTokenFormat {

    public enum Type {
        SINGLE_CREDENTIAL,
        MULTI_CREDENTIAL
    }

    private VpTokenFormat() {}

    /**
     * Detects the VP token format by fully parsing the JSON.
     * Returns MULTI_CREDENTIAL only if there are 2+ credential entries.
     * A single credential wrapped in JSON (e.g., {"pid": ["cred"]}) is treated as SINGLE_CREDENTIAL.
     */
    public static Type detect(String vpToken, ObjectMapper objectMapper) {
        if (vpToken == null || vpToken.isBlank()) {
            return Type.SINGLE_CREDENTIAL;
        }

        String trimmed = vpToken.trim();
        if (!trimmed.startsWith("{")) {
            return Type.SINGLE_CREDENTIAL;
        }

        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (!node.isObject()) {
                return Type.SINGLE_CREDENTIAL;
            }

            // Count credential entries (keys with non-empty arrays containing strings)
            int credentialCount = 0;
            for (var entry : node.properties()) {
                JsonNode value = entry.getValue();
                if (value != null && value.isArray() && !value.isEmpty()) {
                    JsonNode firstElement = value.get(0);
                    if (firstElement != null && firstElement.isTextual()) {
                        credentialCount++;
                    }
                }
            }

            // Only return MULTI_CREDENTIAL if there are actually multiple credentials
            return credentialCount >= 2 ? Type.MULTI_CREDENTIAL : Type.SINGLE_CREDENTIAL;
        } catch (Exception e) {
            return Type.SINGLE_CREDENTIAL;
        }
    }

    /**
     * Extracts the credential string from a VP token.
     * Handles both raw credentials and single-credential JSON wrappers like {"pid": ["cred"]}.
     */
    public static String extractSingleCredential(String vpToken, ObjectMapper objectMapper) {
        if (vpToken == null || vpToken.isBlank()) {
            return vpToken;
        }

        String trimmed = vpToken.trim();
        if (!trimmed.startsWith("{")) {
            return trimmed;
        }

        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (!node.isObject()) {
                return trimmed;
            }

            // Find the first credential array and return its first element
            for (var entry : node.properties()) {
                JsonNode value = entry.getValue();
                if (value != null && value.isArray() && !value.isEmpty()) {
                    JsonNode firstElement = value.get(0);
                    if (firstElement != null && firstElement.isTextual()) {
                        return firstElement.asText();
                    }
                }
            }

            return trimmed;
        } catch (Exception e) {
            return trimmed;
        }
    }

    /**
     * Parses a multi-credential VP token into a map of credential ID to credential strings.
     * Returns empty map if parsing fails or token is not multi-credential format.
     */
    public static Map<String, List<String>> parseMultiCredential(String vpToken, ObjectMapper objectMapper) {
        Map<String, List<String>> result = new LinkedHashMap<>();

        if (vpToken == null || vpToken.isBlank()) {
            return result;
        }

        String trimmed = vpToken.trim();
        if (!trimmed.startsWith("{")) {
            return result;
        }

        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (!node.isObject()) {
                return result;
            }

            for (var entry : node.properties()) {
                String credentialId = entry.getKey();
                JsonNode value = entry.getValue();

                if (value != null && value.isArray()) {
                    List<String> credentials = new ArrayList<>();
                    for (JsonNode element : value) {
                        if (element.isTextual()) {
                            credentials.add(element.asText());
                        }
                    }
                    if (!credentials.isEmpty()) {
                        result.put(credentialId, credentials);
                    }
                }
            }
        } catch (Exception e) {
            // Return empty map on parse failure
        }

        return result;
    }

    /**
     * Checks if the VP token is in multi-credential format.
     */
    public static boolean isMultiCredential(String vpToken, ObjectMapper objectMapper) {
        return detect(vpToken, objectMapper) == Type.MULTI_CREDENTIAL;
    }
}
