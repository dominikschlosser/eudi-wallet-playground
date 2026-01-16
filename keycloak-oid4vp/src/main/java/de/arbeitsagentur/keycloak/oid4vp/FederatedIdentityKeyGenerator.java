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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Generates deterministic lookup keys for federated identities based on credential attributes.
 * The key is a SHA-256 hash of issuer, credential type, and subject, ensuring consistent
 * user matching across sessions.
 */
public final class FederatedIdentityKeyGenerator {

    private FederatedIdentityKeyGenerator() {}

    /**
     * Computes a deterministic lookup key from credential attributes.
     * Uses SHA-256 hash of "issuer\0credentialType\0subject" for uniqueness and privacy.
     */
    public static String computeLookupKey(String issuer, String credentialType, String subject) {
        String combined = issuer + "\0" + credentialType + "\0" + subject;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            // Fallback to plain concatenation (should never happen with SHA-256)
            return combined.replace("\0", ":");
        }
    }
}
