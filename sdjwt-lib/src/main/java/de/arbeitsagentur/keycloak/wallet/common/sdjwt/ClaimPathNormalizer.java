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
package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

/**
 * Normalizes JSON paths for claim matching by removing common prefixes
 * used in different credential formats (JSONPath, VC Data Model).
 */
public final class ClaimPathNormalizer {
    /** JSONPath root prefix */
    private static final String JSONPATH_ROOT = "$.";
    /** W3C VC credential subject path */
    private static final String CREDENTIAL_SUBJECT = "credentialSubject.";
    /** W3C VC data model full path */
    private static final String VC_CREDENTIAL_SUBJECT = "vc.credentialSubject.";
    /** Path separator */
    private static final String PATH_SEPARATOR = ".";

    private ClaimPathNormalizer() {
    }

    /**
     * Normalizes a JSON path by stripping common prefixes.
     *
     * @param path the path to normalize (e.g., "$.credentialSubject.name")
     * @return the normalized path (e.g., "name")
     */
    public static String normalize(String path) {
        if (path == null || path.isBlank()) {
            return path;
        }
        String normalized = path;
        if (normalized.startsWith(JSONPATH_ROOT)) {
            normalized = normalized.substring(JSONPATH_ROOT.length());
        }
        if (normalized.startsWith(VC_CREDENTIAL_SUBJECT)) {
            normalized = normalized.substring(VC_CREDENTIAL_SUBJECT.length());
        } else if (normalized.startsWith(CREDENTIAL_SUBJECT)) {
            normalized = normalized.substring(CREDENTIAL_SUBJECT.length());
        }
        return normalized;
    }

    /**
     * Checks if a claim name matches a request path, considering path hierarchies.
     * Handles both exact matches and nested path relationships.
     *
     * @param claimName the actual claim name from the disclosure
     * @param requestName the requested claim name
     * @param requestPath the JSON path from the request (may be null)
     * @return true if the claim matches the request
     */
    public static boolean matches(String claimName, String requestName, String requestPath) {
        if (claimName == null) {
            return false;
        }
        // Direct name match
        if (claimName.equals(requestName)) {
            return true;
        }
        // Match against normalized JSON path
        if (requestPath != null && !requestPath.isBlank()) {
            String normalized = normalize(requestPath);
            if (claimName.equals(normalized)
                    || isPathSuffix(normalized, claimName)
                    || isPathPrefix(claimName, normalized)) {
                return true;
            }
        }
        // Match against request name with path semantics
        if (requestName != null) {
            return isPathSuffix(claimName, requestName) || isPathPrefix(requestName, claimName);
        }
        return false;
    }

    /**
     * Checks if {@code child} is a suffix path of {@code parent}.
     * For example: "address.city" contains suffix "city".
     */
    private static boolean isPathSuffix(String parent, String child) {
        return parent.endsWith(PATH_SEPARATOR + child);
    }

    /**
     * Checks if {@code prefix} is a path prefix of {@code full}.
     * For example: "address" is a prefix of "address.city".
     */
    private static boolean isPathPrefix(String prefix, String full) {
        return full.startsWith(prefix + PATH_SEPARATOR);
    }
}
