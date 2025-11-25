package de.arbeitsagentur.keycloak.wallet.verification.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;

@ConfigurationProperties(prefix = "verifier")
@Validated
public record VerifierProperties(
        Path dcqlQueryFile,
        String defaultDcqlQuery,
        String walletAuthEndpoint,
        String clientId,
        Path encryptionKeyFile
) {
    public String clientId() {
        return clientId != null ? clientId : "wallet-verifier";
    }
}
