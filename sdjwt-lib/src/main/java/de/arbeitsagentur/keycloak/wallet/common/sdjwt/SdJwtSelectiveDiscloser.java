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

import com.authlete.sd.Disclosure;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Filters SD-JWT disclosures to only keep requested claims and rebuilds the token accordingly.
 */
public class SdJwtSelectiveDiscloser {
    private final SdJwtParser sdJwtParser;

    public SdJwtSelectiveDiscloser(SdJwtParser sdJwtParser) {
        this.sdJwtParser = sdJwtParser;
    }

    /**
     * Rebuilds the SD-JWT with only the disclosures that match the requested claims.
     */
    public String filter(String sdJwt,
                         List<ClaimRequest> requests,
                         Set<String> requestedClaims) {
        return sdJwtParser.rebuildForRequestedClaims(sdJwt, requests, requestedClaims);
    }

    /**
     * Filters a separate disclosure list based on requested claims.
     */
    public List<String> filterDisclosures(List<String> disclosures,
                                          List<ClaimRequest> requests,
                                          Set<String> requestedClaims) {
        if (disclosures == null || disclosures.isEmpty() || requestedClaims == null || requestedClaims.isEmpty()) {
            return disclosures == null ? List.of() : new ArrayList<>(disclosures);
        }
        List<String> filtered = new ArrayList<>();
        for (String disclosure : disclosures) {
            String claimName = claimNameFromDisclosure(disclosure);
            if (claimName != null && (requestedClaims.contains(claimName)
                    || matchesAnyRequest(requests, claimName))) {
                filtered.add(disclosure);
            }
        }
        return filtered;
    }

    private boolean matchesAnyRequest(List<ClaimRequest> requests, String claimName) {
        if (requests == null || requests.isEmpty()) {
            return false;
        }
        return requests.stream().anyMatch(r -> matchesClaimName(r, claimName));
    }

    private boolean matchesClaimName(ClaimRequest request, String claimName) {
        if (request == null || claimName == null) {
            return false;
        }
        return ClaimPathNormalizer.matches(claimName, request.name(), request.jsonPath());
    }

    private String claimNameFromDisclosure(String disclosure) {
        try {
            return Disclosure.parse(disclosure).getClaimName();
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Minimal claim request representation used for filtering disclosures.
     */
    public record ClaimRequest(String name, String jsonPath) {
    }
}
