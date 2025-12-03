package de.arbeitsagentur.keycloak.wallet.mockissuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MockIssuerIntegrationTest {

    private static final Path CONFIG_FILE = Path.of("target", "mock-issuer-config-int.json");
    private static final Path DATA_DIR = Path.of("target", "mock-data");
    private static final Path USER_CONFIG_FILE = DATA_DIR.resolve("mock-issuer/configurations.json");

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) throws Exception {
        Files.deleteIfExists(CONFIG_FILE);
        Files.deleteIfExists(USER_CONFIG_FILE);
        Path parent = CONFIG_FILE.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.createDirectories(DATA_DIR);
        registry.add("mock-issuer.configuration-file", () -> CONFIG_FILE.toAbsolutePath().toString());
        registry.add("wallet.storage-dir", () -> DATA_DIR.toAbsolutePath().toString());
    }

    @BeforeEach
    void cleanConfigFile() throws Exception {
        Files.deleteIfExists(CONFIG_FILE);
        Files.createDirectories(CONFIG_FILE.getParent());
        Files.deleteIfExists(USER_CONFIG_FILE);
        Files.createDirectories(USER_CONFIG_FILE.getParent());
    }

    @Test
    void createsCredentialConfigurationViaHttpAndPersistsIt() throws Exception {
        Map<String, Object> payload = Map.of(
                "id", "integration-credential",
                "name", "Integration Credential",
                "scope", "integration-scope",
                "vct", "urn:example:integration",
                "format", "dc+sd-jwt",
                "claims", List.of(
                        Map.of(
                                "name", "email",
                                "label", "Email",
                                "defaultValue", "user@example.com",
                                "required", true
                        )
                )
        );

        @SuppressWarnings("unchecked")
        var created = restTemplate.postForEntity(baseUrl("/mock-issuer/configurations"), payload, Map.class);
        assertThat(created.getStatusCode().is2xxSuccessful())
                .withFailMessage("POST /mock-issuer/configurations returned %s with body %s", created.getStatusCode(), created.getBody())
                .isTrue();
        Map<String, Object> createdBody = (Map<String, Object>) created.getBody();
        assertThat(createdBody).isNotNull();
        assertThat(createdBody).containsEntry("id", "integration-credential");

        JsonNode stored = objectMapper.readTree(USER_CONFIG_FILE.toFile());
        assertThat(stored.toString()).contains("integration-credential");

        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = restTemplate.getForObject(baseUrl("/mock-issuer/.well-known/openid-credential-issuer"), Map.class);
        assertThat(metadata).isNotNull();
        Object configs = metadata.get("credential_configurations_supported");
        assertThat(configs).isInstanceOf(Map.class);
        Map<String, Object> configMap = (Map<String, Object>) configs;
        assertThat(configMap).containsKey("integration-credential");

        Map<String, Object> previewRequest = Map.of(
                "configurationId", "integration-credential",
                "format", "dc+sd-jwt",
                "vct", "urn:example:integration",
                "claims", List.of(Map.of("name", "email", "value", "user@example.com"))
        );
        var preview = restTemplate.postForEntity(baseUrl("/mock-issuer/preview"), previewRequest, Map.class);
        assertThat(preview.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(preview.getBody()).isNotNull();
        assertThat(preview.getBody().get("encoded")).isInstanceOf(String.class);
    }

    private String baseUrl(String path) {
        return "http://localhost:" + port + path;
    }

}
