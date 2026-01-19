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
package de.arbeitsagentur.keycloak.wallet.common.util;

/**
 * Normalizes JSON paths for credential claims, handling common prefixes.
 */
public final class JsonPathNormalizer {

    private static final String JSONPATH_ROOT = "$.";
    private static final String CREDENTIAL_SUBJECT_PREFIX = "credentialSubject.";
    private static final String VC_CREDENTIAL_SUBJECT_PREFIX = "vc.credentialSubject.";

    private JsonPathNormalizer() {
    }

    /**
     * Normalizes a JSON path by removing common prefixes like "$.", "credentialSubject.", etc.
     *
     * @param path the JSON path to normalize
     * @return the normalized path, or null if input is null/blank
     */
    public static String normalize(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        String normalized = path;
        if (normalized.startsWith(JSONPATH_ROOT)) {
            normalized = normalized.substring(JSONPATH_ROOT.length());
        }
        if (normalized.startsWith(VC_CREDENTIAL_SUBJECT_PREFIX)) {
            normalized = normalized.substring(VC_CREDENTIAL_SUBJECT_PREFIX.length());
        } else if (normalized.startsWith(CREDENTIAL_SUBJECT_PREFIX)) {
            normalized = normalized.substring(CREDENTIAL_SUBJECT_PREFIX.length());
        }
        return normalized;
    }

    /**
     * Extracts the first segment of a path (before the first dot).
     *
     * @param path the path to extract from
     * @return the first segment, or null if no dot found or path is null/blank
     */
    public static String firstSegment(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        int dot = path.indexOf('.');
        return dot > 0 ? path.substring(0, dot) : null;
    }

    /**
     * Builds a credentialSubject JSON path from a claim name.
     *
     * @param claimName the claim name
     * @return the JSON path (e.g., "$.credentialSubject.given_name")
     */
    public static String toCredentialSubjectPath(String claimName) {
        return "$." + CREDENTIAL_SUBJECT_PREFIX + claimName;
    }

    /**
     * Builds a vc.credentialSubject JSON path from a claim name.
     *
     * @param claimName the claim name
     * @return the JSON path (e.g., "$.vc.credentialSubject.given_name")
     */
    public static String toVcCredentialSubjectPath(String claimName) {
        return "$." + VC_CREDENTIAL_SUBJECT_PREFIX + claimName;
    }
}
