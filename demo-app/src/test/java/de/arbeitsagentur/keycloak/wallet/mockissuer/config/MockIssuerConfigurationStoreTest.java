package de.arbeitsagentur.keycloak.wallet.mockissuer.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MockIssuerConfigurationStoreTest {

    @TempDir
    Path tempDir;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void addsConfigurationAndPersistsToFile() throws Exception {
        MockIssuerProperties.CredentialConfiguration base = new MockIssuerProperties.CredentialConfiguration(
                "mock-pid-sdjwt", "dc+sd-jwt", "mock-scope", "Mock PID (SD-JWT)", "urn:example:pid:mock",
                List.of(new MockIssuerProperties.ClaimTemplate("given_name", "Given name", "Alice", true))
        );
        Path configurationFile = tempDir.resolve("mock-issuer-configurations.json");
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                Path.of("config/mock-issuer-keys.json"),
                Duration.ofMinutes(5),
                "http://localhost:3000/mock-issuer",
                configurationFile,
                List.of(base)
        );

        WalletProperties walletProps = new WalletProperties(
                "http://localhost:8080",
                "realm",
                "client",
                "secret",
                "did:example:wallet",
                tempDir,
                tempDir.resolve("wallet.jwk"),
                null,
                null,
                null,
                List.of(),
                true
        );

        MockIssuerConfigurationStore store = new MockIssuerConfigurationStore(props, walletProps, objectMapper);
        MockIssuerProperties.CredentialConfiguration created = new MockIssuerProperties.CredentialConfiguration(
                "custom-credential", "dc+sd-jwt", "custom-scope", "Custom Credential", "urn:example:custom",
                List.of(new MockIssuerProperties.ClaimTemplate("email", "Email", "user@example.com", true))
        );

        store.addConfiguration(created);

        assertThat(store.configurations()).extracting(MockIssuerProperties.CredentialConfiguration::id)
                .contains("custom-credential");

        Path userFile = walletProps.storageDir().resolve("mock-issuer/configurations.json");
        JsonNode root = objectMapper.readTree(userFile.toFile());
        JsonNode configsNode = root.isObject() ? root.get("configurations") : root;
        assertThat(configsNode).isNotNull();
        assertThat(configsNode.toString()).contains("custom-credential");
    }
}
