package de.arbeitsagentur.keycloak.wallet.issuance.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;

@ConfigurationProperties(prefix = "wallet")
@Validated
public record WalletProperties(
        @NotBlank String keycloakBaseUrl,
        @NotBlank String realm,
        @NotBlank String clientId,
        @NotBlank String clientSecret,
        @NotBlank String walletDid,
        @NotNull Path storageDir,
        @NotNull Path walletKeyFile,
        Path tlsKeyStore,
        String tlsKeyStorePassword,
        String tlsKeyStoreType,
        java.util.List<String> trustedAttestationIssuers,
        Boolean requestUriWalletMetadataEnabled
) {
    public record CredentialOption(String scope, String configurationId, String label) {
    }

    public String issuerMetadataUrl() {
        return "%s/.well-known/openid-credential-issuer/realms/%s".formatted(keycloakBaseUrl, realm);
    }

    public String oidcDiscoveryUrl() {
        return "%s/realms/%s/.well-known/openid-configuration".formatted(keycloakBaseUrl, realm);
    }

    public String tokenEndpoint() {
        return "%s/realms/%s/protocol/openid-connect/token".formatted(keycloakBaseUrl, realm);
    }

    public String userInfoEndpoint() {
        return "%s/realms/%s/protocol/openid-connect/userinfo".formatted(keycloakBaseUrl, realm);
    }

    public String authorizeEndpoint() {
        return "%s/realms/%s/protocol/openid-connect/auth".formatted(keycloakBaseUrl, realm);
    }

    public String nonceEndpoint() {
        return "%s/realms/%s/protocol/oid4vc/nonce".formatted(keycloakBaseUrl, realm);
    }

    public boolean requestUriWalletMetadataEnabledOrDefault() {
        return requestUriWalletMetadataEnabled == null || requestUriWalletMetadataEnabled;
    }
}
