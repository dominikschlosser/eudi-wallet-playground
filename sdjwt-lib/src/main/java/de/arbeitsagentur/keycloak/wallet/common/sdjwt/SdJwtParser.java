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
import com.authlete.sd.SDJWT;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtSelectiveDiscloser.ClaimRequest;
import de.arbeitsagentur.keycloak.wallet.common.util.TokenFormatUtils;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SD-JWT parsing utilities used across issuance and presentation flows.
 */
public class SdJwtParser {
    private final ObjectMapper objectMapper;

    public SdJwtParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public boolean isSdJwt(String raw) {
        return TokenFormatUtils.isSdJwt(raw);
    }

    public SdJwtUtils.SdJwtParts split(String sdJwt) {
        return SdJwtUtils.split(sdJwt);
    }

    public String signedJwt(String sdJwt) {
        try {
            return split(sdJwt).signedJwt();
        } catch (Exception e) {
            return sdJwt;
        }
    }

    public List<String> disclosures(String sdJwt) {
        try {
            return new ArrayList<>(split(sdJwt).disclosures());
        } catch (Exception e) {
            return List.of();
        }
    }

    public Map<String, Object> extractDisclosedClaims(String sdJwt) {
        if (sdJwt == null || sdJwt.isBlank()) {
            return Collections.emptyMap();
        }
        try {
            SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(sdJwt);
            return SdJwtUtils.extractDisclosedClaims(parts, objectMapper);
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    public Map<String, Object> extractDisclosedClaims(SdJwtUtils.SdJwtParts parts) {
        try {
            return SdJwtUtils.extractDisclosedClaims(parts, objectMapper);
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    public Map<String, Object> decodeSubject(String sdJwt) {
        try {
            return SdJwtUtils.extractDisclosedClaims(split(sdJwt), objectMapper);
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    public String extractVct(String sdJwt) {
        if (!isSdJwt(sdJwt)) {
            return null;
        }
        try {
            SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(sdJwt);
            String[] split = parts.signedJwt().split("\\.");
            if (split.length < 2) {
                return null;
            }
            JsonNode node = objectMapper.readTree(Base64.getUrlDecoder().decode(split[1]));
            return node.path("vct").asText(null);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns an SD-JWT string containing the given disclosures (or the original ones if null/empty).
     */
    public String withDisclosures(String sdJwt, List<String> disclosures) {
        SdJwtUtils.SdJwtParts parts = isSdJwt(sdJwt) ? split(sdJwt) : null;
        String signed = parts != null ? parts.signedJwt() : sdJwt;
        String keyBindingJwt = parts != null ? parts.keyBindingJwt() : null;
        List<String> toAppend = (disclosures == null || disclosures.isEmpty())
                ? (parts != null ? parts.disclosures() : List.of())
                : disclosures;
        StringBuilder sb = new StringBuilder(signed == null ? "" : signed);
        for (String disclosure : toAppend) {
            if (disclosure != null && !disclosure.isBlank()) {
                sb.append('~').append(disclosure);
            }
        }
        if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
            sb.append('~').append(keyBindingJwt);
        }
        return sb.toString();
    }

    /**
     * Rebuilds an SD-JWT with only the disclosures matching the requested claims.
     */
    public String rebuildForRequestedClaims(String sdJwt,
                                            List<ClaimRequest> requests,
                                            Set<String> requestedClaims) {
        try {
            SDJWT parsed = SDJWT.parse(sdJwt);
            List<Disclosure> filtered = parsed.getDisclosures().stream()
                    .filter(d -> {
                        if (requestedClaims == null || requestedClaims.isEmpty()) {
                            return true;
                        }
                        String claimName = d.getClaimName();
                        if (claimName == null) {
                            return false;
                        }
                        return requestedClaims.contains(claimName)
                                || requests.stream().anyMatch(r -> matchesClaimName(r, claimName));
                    })
                    .toList();
            return new SDJWT(parsed.getCredentialJwt(), filtered, parsed.getBindingJwt()).toString();
        } catch (Exception e) {
            return sdJwt;
        }
    }

    private boolean matchesClaimName(ClaimRequest request, String claimName) {
        if (request == null || claimName == null) {
            return false;
        }
        return ClaimPathNormalizer.matches(claimName, request.name(), request.jsonPath());
    }
}
