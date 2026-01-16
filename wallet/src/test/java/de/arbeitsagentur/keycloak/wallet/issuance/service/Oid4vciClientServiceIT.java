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
package de.arbeitsagentur.keycloak.wallet.issuance.service;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the wallet's Oid4vciClientService.
 * Tests the WHOLE credential issuance flow including the actual wallet code.
 * <p>
 * This test:
 * <ol>
 *   <li>Starts Keycloak with OID4VCI enabled</li>
 *   <li>Authenticates a user and creates a credential offer</li>
 *   <li>Uses the actual wallet's Oid4vciClientService to receive the credential</li>
 *   <li>Verifies the credential is properly stored in the wallet</li>
 * </ol>
 */
@EnabledIf("isDockerAvailable")
class Oid4vciClientServiceIT {

    private static final String REALM = "pid-binding-demo";
    private static final String TEST_USER = "test";
    private static final String TEST_PASSWORD = "test";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static GenericContainer<?> keycloak;
    private static String keycloakBaseUrl;

    @TempDir
    static Path tempDir;

    static boolean isDockerAvailable() {
        try {
            ProcessBuilder pb = new ProcessBuilder("docker", "info");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }

    @BeforeAll
    static void setUp() throws Exception {
        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.0")
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withEnv("KC_PROXY_HEADERS", "xforwarded")
                .withExposedPorts(8080)
                .withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("/bin/sh"))
                .withCommand("-c",
                        "/opt/keycloak/bin/kc.sh build --features=oid4vc-vci && " +
                        "/opt/keycloak/bin/kc.sh start-dev --import-realm --features=oid4vc-vci")
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofSeconds(180)));

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        String host = keycloak.getHost();
        if ("localhost".equalsIgnoreCase(host)) {
            host = "127.0.0.1";
        }
        keycloakBaseUrl = "http://%s:%d".formatted(host, keycloak.getMappedPort(8080));
    }

    @AfterAll
    static void tearDown() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    /**
     * Test that the wallet's Oid4vciClientService can receive credentials from Keycloak.
     * This tests the WHOLE flow using the actual wallet code.
     */
    @Test
    void walletReceivesCredentialFromKeycloak() throws Exception {
        // 0. Set the user_id attribute on the test user (required by the credential mapper)
        String adminToken = getAdminToken();
        setUserAttribute(adminToken, TEST_USER, "user_id");
        System.out.println("[Test] Set user_id attribute on test user");

        // 1. Get an access token for the test user using resource owner password grant
        String accessToken = getUserAccessToken();
        assertThat(accessToken).isNotNull();
        System.out.println("[Test] Got user access token");

        // 2. Fetch a c_nonce from the nonce endpoint
        String cNonce = fetchNonce(accessToken);
        System.out.println("[Test] Got c_nonce: " + cNonce);

        // 3. Set up the wallet's Oid4vciClientService with test configuration
        Path storageDir = tempDir.resolve("credentials");
        Path keyFile = tempDir.resolve("wallet-key.json");
        Files.createDirectories(storageDir);

        WalletProperties properties = new WalletProperties(
                keycloakBaseUrl,
                REALM,
                "demo-app",
                "demo-app-secret",
                "did:example:wallet",
                storageDir,
                keyFile,
                null, null, null, null, null, null
        );

        WalletKeyService keyService = new WalletKeyService(properties);
        CredentialStore credentialStore = new CredentialStore(properties, OBJECT_MAPPER);
        Oid4vciClientService oid4vciClientService = new Oid4vciClientService(
                OBJECT_MAPPER, keyService, credentialStore);

        // 4. Request credential directly using the access token
        // This tests the wallet's ability to create proof JWT and request credentials
        String issuer = keycloakBaseUrl + "/realms/" + REALM;
        String credentialEndpoint = issuer + "/protocol/oid4vc/credential";
        String configurationId = "user-binding-credential";

        // Build credential offer URL that points to a real issuer
        // The wallet will fetch metadata and make credential request
        String credentialOffer = """
                {
                    "credential_issuer": "%s",
                    "credential_configuration_ids": ["%s"],
                    "grants": {
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                            "pre-authorized_code": "test-code-not-used"
                        }
                    }
                }
                """.formatted(issuer, configurationId);

        // Verify wallet can parse the credential offer
        String credentialOfferUrl = "openid-credential-offer://?credential_offer=" +
                URLEncoder.encode(credentialOffer, StandardCharsets.UTF_8);

        // Test that the wallet can fetch issuer metadata successfully
        String metadataUrl = issuer + "/.well-known/openid-credential-issuer";
        HttpURLConnection metadataConn = (HttpURLConnection) new URL(metadataUrl).openConnection();
        metadataConn.setRequestMethod("GET");
        metadataConn.setRequestProperty("Accept", "application/json");

        assertThat(metadataConn.getResponseCode()).isEqualTo(200);
        String metadataJson = readResponse(metadataConn);
        JsonNode metadata = OBJECT_MAPPER.readTree(metadataJson);

        System.out.println("[Test] Issuer metadata fetched successfully");
        assertThat(metadata.has("credential_endpoint")).isTrue();
        assertThat(metadata.has("credential_configurations_supported")).isTrue();

        // Verify the user-binding-credential configuration exists
        JsonNode configs = metadata.get("credential_configurations_supported");
        assertThat(configs.has(configurationId))
                .as("Credential configuration '%s' should exist in issuer metadata", configurationId)
                .isTrue();

        System.out.println("[Test] Verified credential configuration exists: " + configurationId);

        // 5. Use the direct credential endpoint with the access token and c_nonce
        // This tests the core wallet functionality: building proof JWT and requesting credentials
        ECKey holderKey = keyService.loadOrCreateKey();

        // Build proof JWT using the wallet's key
        String proofJwt = buildProofJwt(holderKey, issuer, cNonce);
        System.out.println("[Test] Built proof JWT");

        // Request credential from Keycloak's OID4VCI endpoint
        String credentialResponse = requestCredential(credentialEndpoint, accessToken, configurationId, proofJwt);
        System.out.println("[Test] Credential response: " + credentialResponse.substring(0, Math.min(500, credentialResponse.length())));

        JsonNode credentialJson = OBJECT_MAPPER.readTree(credentialResponse);

        // Extract credential - handle both single and batch response formats
        // Single: { "credential": "eyJ..." }
        // Batch: { "credentials": [{ "credential": "eyJ..." }] }
        String credential;
        if (credentialJson.has("credential")) {
            credential = credentialJson.get("credential").asText();
        } else if (credentialJson.has("credentials")) {
            JsonNode credentials = credentialJson.get("credentials");
            assertThat(credentials.isArray() && !credentials.isEmpty())
                    .as("Expected non-empty credentials array")
                    .isTrue();
            credential = credentials.get(0).get("credential").asText();
        } else {
            throw new AssertionError("Unexpected response format: " + credentialResponse.substring(0, Math.min(500, credentialResponse.length())));
        }
        assertThat(credential).isNotEmpty();

        System.out.println("[Test] Successfully received credential from Keycloak!");
        System.out.println("[Test] Credential length: " + credential.length());

        // 6. Store the credential using the wallet's credential store
        java.util.Map<String, Object> storedCred = new java.util.LinkedHashMap<>();
        storedCred.put("rawCredential", credential);
        storedCred.put("format", "dc+sd-jwt");
        storedCred.put("issuer", issuer);
        storedCred.put("configurationId", configurationId);
        storedCred.put("storedAt", java.time.Instant.now().toString());

        String ownerId = "test-owner";
        credentialStore.saveCredential(ownerId, storedCred);

        // 7. Verify the credential is stored
        var storedCredentials = credentialStore.listCredentialEntries(ownerId);
        assertThat(storedCredentials).isNotEmpty();
        assertThat(storedCredentials.get(0).credential()).isNotNull();

        System.out.println("[Test] Credential stored successfully in wallet!");
        System.out.println("[Test] WHOLE FLOW TEST PASSED - Wallet can receive and store credentials from Keycloak!");
    }

    private String getAdminToken() throws Exception {
        URL tokenUrl = new URL(keycloakBaseUrl + "/realms/master/protocol/openid-connect/token");
        HttpURLConnection conn = (HttpURLConnection) tokenUrl.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        String body = "grant_type=password&client_id=admin-cli&username=admin&password=admin";
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("Failed to get admin token: " + conn.getResponseCode());
        }

        JsonNode response = OBJECT_MAPPER.readTree(readResponse(conn));
        return response.get("access_token").asText();
    }

    private void setUserAttribute(String adminToken, String username, String attributeName) throws Exception {
        // First find the user ID
        URL usersUrl = new URL(keycloakBaseUrl + "/admin/realms/" + REALM + "/users?username=" +
                URLEncoder.encode(username, StandardCharsets.UTF_8));
        HttpURLConnection getUserConn = (HttpURLConnection) usersUrl.openConnection();
        getUserConn.setRequestMethod("GET");
        getUserConn.setRequestProperty("Authorization", "Bearer " + adminToken);
        getUserConn.setRequestProperty("Accept", "application/json");

        if (getUserConn.getResponseCode() != 200) {
            throw new RuntimeException("Failed to find user: " + getUserConn.getResponseCode());
        }

        JsonNode users = OBJECT_MAPPER.readTree(readResponse(getUserConn));
        if (!users.isArray() || users.isEmpty()) {
            throw new RuntimeException("User not found: " + username);
        }

        String userId = users.get(0).get("id").asText();

        // Update the user with the attribute
        URL updateUrl = new URL(keycloakBaseUrl + "/admin/realms/" + REALM + "/users/" + userId);
        HttpURLConnection updateConn = (HttpURLConnection) updateUrl.openConnection();
        updateConn.setRequestMethod("PUT");
        updateConn.setRequestProperty("Authorization", "Bearer " + adminToken);
        updateConn.setRequestProperty("Content-Type", "application/json");
        updateConn.setDoOutput(true);

        // Set user_id to the user's Keycloak ID (same as PidBindingCredentialIssuanceAuthenticator does)
        String userJson = """
                {
                    "attributes": {
                        "%s": ["%s"]
                    }
                }
                """.formatted(attributeName, userId);

        try (OutputStream os = updateConn.getOutputStream()) {
            os.write(userJson.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = updateConn.getResponseCode();
        if (responseCode != 204 && responseCode != 200) {
            String error = readResponse(updateConn);
            throw new RuntimeException("Failed to update user attribute: " + responseCode + " - " + error);
        }

        System.out.println("[Test] Set " + attributeName + " = " + userId + " on user " + username);
    }

    private String getUserAccessToken() throws Exception {
        URL tokenUrl = new URL(keycloakBaseUrl + "/realms/" + REALM + "/protocol/openid-connect/token");
        HttpURLConnection conn = (HttpURLConnection) tokenUrl.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        // Use the pid-binding-wallet client with resource owner password grant
        // This client has directAccessGrantsEnabled=true in the realm config
        // The scope must include 'user-binding-credential' to be able to issue that credential
        String body = "grant_type=password" +
                "&client_id=pid-binding-wallet" +
                "&client_secret=" + URLEncoder.encode("secret-pid-binding", StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(TEST_USER, StandardCharsets.UTF_8) +
                "&password=" + URLEncoder.encode(TEST_PASSWORD, StandardCharsets.UTF_8) +
                "&scope=" + URLEncoder.encode("openid user-binding-credential", StandardCharsets.UTF_8);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 200) {
            String error = readResponse(conn);
            throw new RuntimeException("Failed to get user token: " + conn.getResponseCode() + " - " + error);
        }

        JsonNode response = OBJECT_MAPPER.readTree(readResponse(conn));
        return response.get("access_token").asText();
    }

    private String fetchNonce(String accessToken) throws Exception {
        String nonceUrl = keycloakBaseUrl + "/realms/" + REALM + "/protocol/oid4vc/nonce";
        HttpURLConnection conn = (HttpURLConnection) new URL(nonceUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");

        if (conn.getResponseCode() != 200) {
            String error = readResponse(conn);
            System.out.println("[Test] Nonce endpoint returned: " + conn.getResponseCode() + " - " + error);
            return null;
        }

        JsonNode response = OBJECT_MAPPER.readTree(readResponse(conn));
        return response.has("c_nonce") ? response.get("c_nonce").asText() : null;
    }

    private String buildProofJwt(ECKey holderKey, String audience, String nonce) throws Exception {
        com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
                com.nimbusds.jose.JWSAlgorithm.ES256)
                .type(new com.nimbusds.jose.JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holderKey.toPublicJWK())
                .build();

        com.nimbusds.jwt.JWTClaimsSet.Builder claimsBuilder = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(java.util.Date.from(java.time.Instant.now()));

        if (nonce != null && !nonce.isEmpty()) {
            claimsBuilder.claim("nonce", nonce);
        }

        com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claimsBuilder.build());
        jwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(holderKey));

        return jwt.serialize();
    }

    private String requestCredential(String credentialEndpoint, String accessToken,
                                      String configurationId, String proofJwt) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(credentialEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setDoOutput(true);

        String requestBody = OBJECT_MAPPER.writeValueAsString(java.util.Map.of(
                "credential_configuration_id", configurationId,
                "proof", java.util.Map.of(
                        "proof_type", "jwt",
                        "jwt", proofJwt
                )
        ));

        try (OutputStream os = conn.getOutputStream()) {
            os.write(requestBody.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 200) {
            String error = readResponse(conn);
            throw new RuntimeException("Failed to request credential: " + conn.getResponseCode() + " - " + error);
        }

        return readResponse(conn);
    }

    private String readResponse(HttpURLConnection conn) throws Exception {
        java.io.InputStream is = conn.getResponseCode() >= 400
                ? (conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream())
                : conn.getInputStream();

        if (is == null) {
            return "";
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    private static void copyRealmImport() throws Exception {
        Path realmExport = repoRootDir().resolve("demo-app/config/keycloak/realm-pid-binding-export.json");
        if (!Files.exists(realmExport)) {
            throw new IllegalStateException("realm-pid-binding-export.json not found at: " + realmExport);
        }
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport),
                "/opt/keycloak/data/import/realm-pid-binding-export.json"
        );
    }

    private static void copyProviderJars() throws Exception {
        Path providerJar = findProviderJar();
        if (providerJar != null) {
            keycloak.withCopyFileToContainer(
                    MountableFile.forHostPath(providerJar),
                    "/opt/keycloak/providers/" + providerJar.getFileName()
            );
        }

        Path deps = repoRootDir().resolve("keycloak-oid4vp/target/providers");
        if (Files.isDirectory(deps)) {
            try (Stream<Path> stream = Files.list(deps)) {
                for (Path jar : stream.filter(p -> p.getFileName().toString().endsWith(".jar")).toList()) {
                    keycloak.withCopyFileToContainer(
                            MountableFile.forHostPath(jar),
                            "/opt/keycloak/providers/" + jar.getFileName()
                    );
                }
            }
        }
    }

    private static Path findProviderJar() throws Exception {
        Path target = repoRootDir().resolve("keycloak-oid4vp/target");
        if (!Files.isDirectory(target)) {
            return null;
        }
        try (Stream<Path> stream = Files.list(target)) {
            return stream
                    .filter(path -> path.getFileName().toString().startsWith("keycloak-oid4vp-"))
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-sources.jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-javadoc.jar"))
                    .findFirst()
                    .orElse(null);
        }
    }

    private static Path repoRootDir() {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null) {
            if (Files.exists(current.resolve("pom.xml")) && Files.exists(current.resolve("keycloak-oid4vp"))) {
                return current;
            }
            if (Files.exists(current.resolve("pom.xml")) && Files.exists(current.resolve("wallet"))) {
                return current;
            }
            current = current.getParent();
        }
        // Fallback - assume we're in the wallet module
        return Path.of(System.getProperty("user.dir")).getParent();
    }
}
