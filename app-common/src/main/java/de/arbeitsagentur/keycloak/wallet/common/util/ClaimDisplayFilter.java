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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Filters credential claims for display purposes, removing technical/reserved claims.
 */
public final class ClaimDisplayFilter {

    /**
     * Reserved JWT and credential claims that should not be displayed to users.
     * Includes standard JWT claims, SD-JWT internal claims, and OIDC claims.
     */
    public static final Set<String> RESERVED_CLAIMS = Set.of(
            // Standard JWT claims
            "iss", "aud", "exp", "nbf", "iat", "jti", "sub",
            // OIDC claims
            "azp", "nonce", "at_hash", "c_hash", "s_hash", "auth_time", "acr", "amr", "sid", "session_state",
            // SD-JWT and credential structure claims
            "cnf", "vct", "_sd_alg", "_sd", "kid", "typ"
    );

    private ClaimDisplayFilter() {
    }

    /**
     * Filters claims for display, removing reserved/technical claims.
     *
     * @param claims the claims to filter
     * @return filtered claims suitable for display
     */
    public static Map<String, Object> filterForDisplay(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> filtered = new LinkedHashMap<>();
        claims.forEach((key, value) -> {
            if (key != null && !isHidden(key)) {
                filtered.put(key, value);
            }
        });
        return filtered;
    }

    /**
     * Checks if a claim key should be hidden from display.
     */
    public static boolean isHidden(String key) {
        if (key == null) {
            return true;
        }
        if (key.startsWith("_")) {
            return true;
        }
        for (String reserved : RESERVED_CLAIMS) {
            if (key.equals(reserved) || key.startsWith(reserved + ".")) {
                return true;
            }
        }
        return false;
    }
}
