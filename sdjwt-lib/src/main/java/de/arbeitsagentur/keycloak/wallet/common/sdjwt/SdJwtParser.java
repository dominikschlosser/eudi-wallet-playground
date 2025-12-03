package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtSelectiveDiscloser.ClaimRequest;

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
        return raw != null && raw.contains("~");
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
        List<String> toAppend = (disclosures == null || disclosures.isEmpty())
                ? (parts != null ? parts.disclosures() : List.of())
                : disclosures;
        StringBuilder sb = new StringBuilder(signed == null ? "" : signed);
        for (String disclosure : toAppend) {
            if (disclosure != null && !disclosure.isBlank()) {
                sb.append('~').append(disclosure);
            }
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
        if (claimName.equals(request.name())) {
            return true;
        }
        if (request.jsonPath() != null && !request.jsonPath().isBlank()) {
            String normalized = request.jsonPath();
            if (normalized.startsWith("$.")) {
                normalized = normalized.substring(2);
            }
            if (normalized.startsWith("credentialSubject.")) {
                normalized = normalized.substring("credentialSubject.".length());
            } else if (normalized.startsWith("vc.credentialSubject.")) {
                normalized = normalized.substring("vc.credentialSubject.".length());
            }
            if (claimName.equals(normalized) || normalized.endsWith("." + claimName) || normalized.startsWith(claimName + ".")) {
                return true;
            }
        }
        return request.name() != null && (normalizedContains(claimName, request.name()) || (claimName.startsWith(request.name() + ".")));
    }

    private boolean normalizedContains(String full, String tail) {
        return full.equals(tail) || full.endsWith("." + tail);
    }
}
