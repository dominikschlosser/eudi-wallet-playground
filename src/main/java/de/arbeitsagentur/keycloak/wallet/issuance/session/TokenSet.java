package de.arbeitsagentur.keycloak.wallet.issuance.session;

import java.time.Instant;

public record TokenSet(
        String accessToken,
        String refreshToken,
        String scope,
        Instant expiresAt,
        String cNonce,
        Instant cNonceExpiresAt
) {
    public boolean needsRefresh() {
        return refreshToken != null && expiresAt != null && Instant.now().isAfter(expiresAt.minusSeconds(5));
    }
}
