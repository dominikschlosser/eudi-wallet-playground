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
            return claimName.equals(normalized)
                    || normalized.endsWith("." + claimName)
                    || normalized.startsWith(claimName + ".");
        }
        return request.name() != null && (normalizedContains(claimName, request.name()) || claimName.startsWith(request.name() + "."));
    }

    private boolean normalizedContains(String full, String tail) {
        return full.equals(tail) || full.endsWith("." + tail);
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
