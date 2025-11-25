package de.arbeitsagentur.keycloak.wallet.verification.session;

public record VerifierSession(String state,
                              String nonce,
                              String dcqlQuery,
                              String trustListId,
                              String clientMetadata,
                              String clientId,
                              String authType,
                              String attestationJwt) {
}
