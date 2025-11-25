package de.arbeitsagentur.keycloak.wallet.issuance.session;

public record UserProfile(
        String sub,
        String name,
        String email,
        String givenName,
        String familyName
) {
}
