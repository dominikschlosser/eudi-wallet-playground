package de.arbeitsagentur.keycloak.wallet.issuance.session;

public record PkceSession(String state, String nonce, String codeVerifier) {
}
