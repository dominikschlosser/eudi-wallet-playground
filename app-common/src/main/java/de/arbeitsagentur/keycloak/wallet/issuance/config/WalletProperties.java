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
package de.arbeitsagentur.keycloak.wallet.issuance.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;
import java.util.List;

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
        Path x509TrustAnchorsPem,
        List<String> trustedAttestationIssuers,
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

    public String issuerUrl() {
        return "%s/realms/%s".formatted(keycloakBaseUrl, realm);
    }

    public String nonceEndpoint() {
        return "%s/realms/%s/protocol/oid4vc/nonce".formatted(keycloakBaseUrl, realm);
    }

    public boolean requestUriWalletMetadataEnabledOrDefault() {
        return requestUriWalletMetadataEnabled == null || requestUriWalletMetadataEnabled;
    }
}
