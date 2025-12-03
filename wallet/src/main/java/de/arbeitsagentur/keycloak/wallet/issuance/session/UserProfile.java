package de.arbeitsagentur.keycloak.wallet.issuance.session;

public record UserProfile(
        String sub,
        String username,
        String name,
        String email,
        String givenName,
        String familyName
) {
    public String displayName() {
        if (username != null && !username.isBlank()) {
            return username;
        }
        if (name != null && !name.isBlank()) {
            return name;
        }
        if (email != null && !email.isBlank()) {
            return email;
        }
        return sub;
    }
}
