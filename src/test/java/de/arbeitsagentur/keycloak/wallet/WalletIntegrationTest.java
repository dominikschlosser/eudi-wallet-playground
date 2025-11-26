package de.arbeitsagentur.keycloak.wallet;

import com.authlete.sd.Disclosure;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.net.URLEncodedUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.demo.oid4vp.PresentationService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WalletIntegrationTest {

    private static final String TEST_USERNAME = "test";
    private static final String TEST_PASSWORD = "test";

    private static final Logger KEYCLOAK_LOG = LoggerFactory.getLogger("KeycloakContainer");
    private static final Path REALM_EXPORT = Path.of("config/keycloak/realm-export.json").toAbsolutePath();

    @Container
    static GenericContainer<?> keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withExposedPorts(8080)
            .withCopyFileToContainer(MountableFile.forHostPath(REALM_EXPORT),
                    "/opt/keycloak/data/import/realm-export.json")
            .withCommand("start-dev", "--import-realm", "--features=oid4vc-vci")
            .withLogConsumer(new Slf4jLogConsumer(KEYCLOAK_LOG))
            .waitingFor(Wait.forHttp("/realms/wallet-demo").forPort(8080).withStartupTimeout(Duration.ofSeconds(240)));

    private static Path credentialDir;
    private static Path keyFile;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) throws IOException {
        credentialDir = Files.createTempDirectory("wallet-cred");
        keyFile = credentialDir.resolveSibling("wallet-keys.json");
        registry.add("wallet.keycloak-base-url",
                () -> "http://%s:%d".formatted(keycloak.getHost(), keycloak.getMappedPort(8080)));
        registry.add("wallet.storage-dir", () -> credentialDir.toAbsolutePath().toString());
        registry.add("wallet.wallet-key-file", () -> keyFile.toAbsolutePath().toString());
    }
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService verifierKeyService;
    @Autowired
    WalletKeyService walletKeyService;
    @Autowired
    PresentationService presentationService;
    @Autowired
    CredentialStore credentialStore;
    @LocalServerPort
    int serverPort;

    @AfterEach
    void cleanup() throws IOException {
        if (credentialDir != null && Files.exists(credentialDir)) {
            Files.list(credentialDir).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        }
        Files.deleteIfExists(keyFile);
    }

    @Test
    void endToEndCredentialIssuance() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);

            JsonNode sessionJson;
            try (CloseableHttpResponse sessionResponse = client.execute(
                    new HttpGet(base.resolve("/api/session")), context)) {
                sessionJson = objectMapper.readTree(sessionResponse.getEntity().getContent());
            }
            assertThat(sessionJson.path("authenticated").asBoolean()).isTrue();

            JsonNode credential;
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                String issueBody = issueResponse.getEntity() != null
                        ? new String(issueResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8)
                        : "";
                assertThat(issueResponse.getCode())
                        .withFailMessage("Issuance failed. HTTP %s Body:%n%s", issueResponse.getCode(), issueBody)
                        .isEqualTo(200);
                credential = objectMapper.readTree(issueBody);
            }
            assertThat(credential.path("credentialSubject").path("given_name").asText())
                    .isEqualTo("Alice");
            assertThat(credential.path("credentialSubject").path("birthdate").asText())
                    .isEqualTo("1992-04-12");
            assertThat(credential.path("credentialSubject").path("nationalities").asText())
                    .contains("DE");
            assertThat(credential.path("credentialSubject").path("address.country").asText())
                    .isEqualTo("DE");
            assertThat(credential.path("credentialSubject").path("document_number").asText())
                    .startsWith("DOC-");

            assertThat(Files.list(credentialDir)).isNotEmpty();

            String dcql = fetchDefaultDcqlQuery(client, context, base);
            PresentationForm validForm = initiatePresentationFlow(client, context, base, dcql, "accept",
                    List.of("given_name", "family_name", "birthdate", "country", "nationalities"),
                    List.of("personal_id"), null, false, null, null, null, null, null);
            HttpPost callbackPost = new HttpPost(validForm.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(validForm.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                assertThat(verifierResult.getCode()).isEqualTo(200);
                assertThat(new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8))
                        .contains("Verified credential");
            }

            PresentationForm tamperedForm = initiatePresentationFlow(client, context, base, dcql, "accept",
                    List.of("given_name", "family_name", "birthdate", "country", "nationalities"),
                    List.of("personal_id"), null, false, null, null, null, null, null);
            tamperedForm.fields().put("state", "invalid-state");
            tamperedForm.fields().remove("vp_token");
            HttpPost tamperedPost = new HttpPost(tamperedForm.action());
            tamperedPost.setEntity(new UrlEncodedFormEntity(toParams(tamperedForm.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse tamperedResponse = client.execute(tamperedPost, context)) {
                assertThat(tamperedResponse.getCode()).isEqualTo(400);
                String body = new String(tamperedResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(body).contains("Invalid verifier session");
            }
        }
    }

    @Test
    void presentationCanBeDenied() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            // Add a second credential so each descriptor can use a distinct one.
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "dc+sd-jwt",
                    "credentialSubject", Map.of("given_name", "Alice", "family_name", "Doe", "personal_id", "ID-999"),
                    "rawCredential", "aaa.bbb.ccc~disc-2"
            ));

            String dcql = fetchDefaultDcqlQuery(client, context, base);
            PresentationForm denyForm = initiatePresentationFlow(client, context, base, dcql, "deny",
                    List.of("given_name", "family_name", "birthdate", "country"), List.of("personal_id"), null, false,
                    null, null, null, null, null);
            HttpPost callbackPost = new HttpPost(denyForm.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(denyForm.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                assertThat(verifierResult.getCode()).isEqualTo(400);
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(body).contains("access_denied").contains("User denied presentation");
            }
        }
    }

    @Test
    void pidCredentialPresentsAddressAndNationality() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);

            JsonNode sessionJson;
            try (CloseableHttpResponse sessionResponse = client.execute(
                    new HttpGet(base.resolve("/api/session")), context)) {
                sessionJson = objectMapper.readTree(sessionResponse.getEntity().getContent());
            }
            String userId = sessionJson.path("user").path("sub").asText();
            assertThat(userId).isNotBlank();

            HttpPost issuePid = new HttpPost(base.resolve("/api/issue"));
            issuePid.setEntity(new UrlEncodedFormEntity(
                    List.of(new BasicNameValuePair("credentialConfigurationId", "pid-credential")),
                    StandardCharsets.UTF_8));
            try (CloseableHttpResponse issueResponse = client.execute(issuePid, context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
                JsonNode pidCredential = objectMapper.readTree(issueResponse.getEntity().getContent());
                assertThat(pidCredential.path("credentialSubject").path("nationalities").asText()).contains("DE");
                assertThat(pidCredential.path("credentialSubject").path("address.country").asText()).isEqualTo("DE");
            }
            List<CredentialStore.Entry> creds = credentialStore.listCredentialEntries(userId);
            assertThat(creds).isNotEmpty();

            String dcql = objectMapper.writeValueAsString(Map.of(
                    "credentials", List.of(
                            Map.of(
                                    "id", "pid-proof",
                                    "format", "dc+sd-jwt",
                                    "claims", List.of(
                                            Map.of("path", List.of("given_name")),
                                            Map.of("path", List.of("nationalities")),
                                            Map.of("path", List.of("address", "country"), "value", "DE"),
                                            Map.of("path", List.of("document_number"))
                                    )
                            )
                    )
            ));

            Optional<PresentationService.PresentationBundle> prepared = presentationService.preparePresentations(userId, dcql);
            assertThat(prepared)
                    .withFailMessage("No PID credential matched DCQL. Stored entries: %s", creds)
                    .isPresent();
            PresentationService.PresentationBundle bundle = prepared.get();
            assertThat(bundle.matches()).hasSize(1);
            PresentationService.DescriptorMatch match = bundle.matches().get(0);
            // Ensure PID disclosures contain the requested address and identity data.
            assertThat(match.disclosedClaims())
                    .containsEntry("nationalities", "DE")
                    .containsEntry("document_number", "DOC-123-A")
                    .containsEntry("country", "DE");
        }
    }

    @Test
    void multiCredentialPresentationDefinition() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = objectMapper.writeValueAsString(Map.of(
                    "credentials", List.of(
                            Map.of(
                                    "id", "given-name-primary",
                                    "format", "dc+sd-jwt",
                                    "claims", List.of(
                                            Map.of("path", List.of("given_name"), "value", "Alice")
                                    )
                            ),
                            Map.of(
                                    "id", "given-name-secondary",
                                    "format", "dc+sd-jwt",
                                    "claims", List.of(
                                            Map.of("path", List.of("given_name"))
                                    )
                            )
                    )
            ));
            PresentationForm presentationForm = initiatePresentationFlow(client, context, base, dcql, "accept",
                    List.of("given_name"), List.of("family_name", "document_number"), null, false,
                    null, null, null, null, null);
            HttpPost callbackPost = new HttpPost(presentationForm.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(presentationForm.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Status %s Body:%n%s", verifierResult.getCode(), body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
                assertThat(body).contains("presentation_1");
                assertThat(body).contains("presentation_2");
            }
        }
    }

    @Test
    void nestedClaimDisclosureIsIncludedInVpToken() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = """
                    {
                      "credentials": [{
                        "id": "address-proof",
                        "format": "dc+sd-jwt",
                        "claims": [
                          { "path": ["address", "country"] },
                          { "path": ["given_name"] }
                        ]
                      }]
                    }
                    """;
            PresentationForm presentationForm = initiatePresentationFlow(client, context, base, dcql, "accept",
                    null, null, null, false,
                    null, null, null, null, null);
            String vpTokenValue = presentationForm.fields().get("vp_token");
            assertThat(vpTokenValue).isNotBlank();
            JsonNode vpTokenJson = objectMapper.readTree(vpTokenValue);
            Map.Entry<String, JsonNode> first = vpTokenJson.fields().next();
            JsonNode firstTokenNode = first.getValue();
            String outerToken = firstTokenNode.isArray() ? firstTokenNode.get(0).asText() : firstTokenNode.asText();
            String innerVp = SignedJWT.parse(outerToken).getJWTClaimsSet().getStringClaim("vp_token");
            assertThat(innerVp).isNotBlank();
            List<String> disclosures = Stream.of(innerVp.split("~"))
                    .skip(1)
                    .filter(s -> s != null && !s.isBlank())
                    .toList();
            String signedPart = innerVp.contains("~") ? innerVp.split("~")[0] : innerVp;
            String[] innerParts = signedPart.split("\\.");
            JsonNode subject = objectMapper.createObjectNode();
            if (innerParts.length >= 2) {
                JsonNode payload = objectMapper.readTree(Base64.getUrlDecoder().decode(innerParts[1]));
                subject = payload.path("vc").path("credentialSubject");
                if (subject.isMissingNode()) {
                    subject = payload.path("credentialSubject");
                }
            }
            boolean disclosedCountry = false;
            for (String disclosure : disclosures) {
                try {
                    Disclosure parsed = Disclosure.parse(disclosure);
                    String name = parsed.getClaimName();
                    if ("address.country".equals(name) || "country".equals(name) || "address".equals(name)) {
                        disclosedCountry = true;
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
            if (!disclosures.isEmpty()) {
                assertThat(disclosedCountry).isTrue();
            } else {
                String countryValue = subject.path("address").path("country").asText("");
                if (countryValue.isBlank()) {
                    countryValue = subject.path("address.country").asText(subject.path("country").asText(""));
                }
                assertThat(countryValue).isEqualTo("DE");
            }
        }
    }

    @Test
    void consentShowsAndReturnsDistinctCredentials() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("personal_id", "ID-111", "given_name", "Alice"),
                    "rawCredential", "token-one"
            ));
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("personal_id", "ID-222", "given_name", "Bob"),
                    "rawCredential", "token-two"
            ));

            String dcql = objectMapper.writeValueAsString(Map.of(
                    "credentials", List.of(
                            Map.of(
                                    "id", "primary",
                                    "format", "jwt_vc",
                                    "claims", List.of(Map.of("path", List.of("personal_id"), "value", "ID-111"))
                            ),
                            Map.of(
                                    "id", "secondary",
                                    "format", "jwt_vc",
                                    "claims", List.of(Map.of("path", List.of("personal_id"), "value", "ID-222"))
                            )
                    )
            ));

            HttpPost verifierStart = new HttpPost(base.resolve("/verifier/start"));
            verifierStart.setConfig(requestConfig);
            verifierStart.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("dcqlQuery", dcql)), StandardCharsets.UTF_8));
            URI walletAuth;
            try (CloseableHttpResponse startResponse = client.execute(verifierStart, context)) {
                assertThat(startResponse.getCode()).isEqualTo(302);
                walletAuth = resolveRedirect(base, startResponse.getFirstHeader("Location").getValue());
            }

            HtmlPage consentPage = fetchHtmlFollowingRedirects(client, context, walletAuth);
            String consentText = consentPage.document().text();
            assertThat(consentText).contains("ID-111");
            assertThat(consentText).contains("ID-222");
            Map<String, List<Element>> radioGroups = consentPage.document().select("input[type=radio][name^=selection-]")
                    .stream()
                    .collect(Collectors.groupingBy(input -> input.attr("name"), Collectors.toList()));
            assertThat(radioGroups).isEmpty();

            HttpPost consentPost = new HttpPost(base.resolve("/oid4vp/consent"));
            List<NameValuePair> consentParams = new ArrayList<>();
            consentParams.add(new BasicNameValuePair("decision", "accept"));
            consentPost.setEntity(new UrlEncodedFormEntity(consentParams, StandardCharsets.UTF_8));
            String vpTokenValue;
            try (CloseableHttpResponse consentResponse = client.execute(consentPost, context)) {
                assertThat(consentResponse.getCode()).isEqualTo(200);
                String body = new String(consentResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                Document submitDoc = Jsoup.parse(body);
                Element form = submitDoc.selectFirst("form");
                assertThat(form).isNotNull();
                Map<String, String> fields = new LinkedHashMap<>();
                for (Element input : form.select("input")) {
                    fields.put(input.attr("name"), input.attr("value"));
                }
                vpTokenValue = fields.get("vp_token");
                assertThat(vpTokenValue).isNotBlank();
            }

            JsonNode vpTokenJson = objectMapper.readTree(vpTokenValue);
            Set<String> keys = new HashSet<>();
            vpTokenJson.fieldNames().forEachRemaining(keys::add);
            assertThat(keys).containsExactlyInAnyOrder("primary", "secondary");
            String primaryToken = vpTokenJson.get("primary").get(0).asText();
            String secondaryToken = vpTokenJson.get("secondary").get(0).asText();
            assertThat(primaryToken).isNotEqualTo(secondaryToken);
            assertThat(SignedJWT.parse(primaryToken).getJWTClaimsSet().getStringClaim("vp_token")).isEqualTo("token-one");
            assertThat(SignedJWT.parse(secondaryToken).getJWTClaimsSet().getStringClaim("vp_token")).isEqualTo("token-two");
        }
    }

    @Test
    void defaultSelectionWorksWhenMultipleCandidates() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("given_name", "Alice"),
                    "rawCredential", "token-one"
            ));
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("given_name", "Alice"),
                    "rawCredential", "token-two"
            ));
            String dcql = """
                    {
                      "credentials": [{
                        "id": "any",
                        "format": "jwt_vc",
                        "claims": [{ "path": ["given_name"] }]
                      }]
                    }
                    """;
            HttpPost verifierStart = new HttpPost(base.resolve("/verifier/start"));
            verifierStart.setConfig(requestConfig);
            verifierStart.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("dcqlQuery", dcql)), StandardCharsets.UTF_8));
            URI walletAuth;
            try (CloseableHttpResponse startResponse = client.execute(verifierStart, context)) {
                assertThat(startResponse.getCode()).isEqualTo(302);
                walletAuth = resolveRedirect(base, startResponse.getFirstHeader("Location").getValue());
            }
            HtmlPage consentPage = fetchHtmlFollowingRedirects(client, context, walletAuth);
            Map<String, List<Element>> radioGroups = consentPage.document().select("input[type=radio][name^=selection-]").stream()
                    .collect(Collectors.groupingBy(input -> input.attr("name"), Collectors.toList()));
            List<Element> radios = radioGroups.values().stream().findFirst().orElse(List.of());
            // should still render radios when multiple credentials match a single request
            assertThat(radios).hasSize(2);
            HttpPost consentPost = new HttpPost(base.resolve("/oid4vp/consent"));
            consentPost.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("decision", "accept")), StandardCharsets.UTF_8));
            try (CloseableHttpResponse consentResponse = client.execute(consentPost, context)) {
                String body = new String(consentResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(consentResponse.getCode()).isEqualTo(200);
                Document submitDoc = Jsoup.parse(body);
                Element form = submitDoc.selectFirst("form");
                assertThat(form).isNotNull();
                String vpTokenValue = form.select("input[name=vp_token]").attr("value");
                assertThat(vpTokenValue).isNotBlank();
                JsonNode parsed = objectMapper.readTree(vpTokenValue);
                assertThat(parsed.fieldNames().next()).isEqualTo("any");
            }
        }
    }

    @Test
    void consentListsEachRequestWithCorrectCredentials() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("given_name", "Alice", "personal_id", "ID-111"),
                    "rawCredential", "token-one"
            ));
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("given_name", "Bob", "personal_id", "ID-222"),
                    "rawCredential", "token-two"
            ));
            String dcql = """
                    {
                      "credentials": [
                        { "id": "first", "format": "jwt_vc", "claims": [{ "path": ["personal_id"], "value": "ID-111" }] },
                        { "id": "second", "format": "jwt_vc", "claims": [{ "path": ["personal_id"], "value": "ID-222" }] }
                      ]
                    }
                    """;
            HttpPost verifierStart = new HttpPost(base.resolve("/verifier/start"));
            verifierStart.setConfig(requestConfig);
            verifierStart.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("dcqlQuery", dcql)), StandardCharsets.UTF_8));
            URI walletAuth;
            try (CloseableHttpResponse startResponse = client.execute(verifierStart, context)) {
                assertThat(startResponse.getCode()).isEqualTo(302);
                walletAuth = resolveRedirect(base, startResponse.getFirstHeader("Location").getValue());
            }
            HtmlPage consentPage = fetchHtmlFollowingRedirects(client, context, walletAuth);
            Map<String, List<Element>> radioGroups = consentPage.document().select("input[type=radio][name^=selection-]").stream()
                    .collect(Collectors.groupingBy(input -> input.attr("name"), Collectors.toList()));
            assertThat(radioGroups).isEmpty();
            assertThat(consentPage.document().text()).contains("ID-111").contains("ID-222");
        }
    }

    @Test
    void failingWhenNotEnoughDistinctCredentials() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            credentialStore.saveCredential(TEST_USERNAME, Map.of(
                    "format", "jwt_vc",
                    "credentialSubject", Map.of("given_name", "Alice"),
                    "rawCredential", "token-one"
            ));
            String dcql = """
                    {
                      "credentials": [
                        { "id": "first", "claims": [{ "path": ["given_name"] }] },
                        { "id": "second", "claims": [{ "path": ["given_name"] }] }
                      ]
                    }
                    """;
            HttpPost verifierStart = new HttpPost(base.resolve("/verifier/start"));
            verifierStart.setConfig(requestConfig);
            verifierStart.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("dcqlQuery", dcql)), StandardCharsets.UTF_8));
            URI walletAuth;
            try (CloseableHttpResponse startResponse = client.execute(verifierStart, context)) {
                assertThat(startResponse.getCode()).isEqualTo(302);
                walletAuth = resolveRedirect(base, startResponse.getFirstHeader("Location").getValue());
            }
            HtmlPage document = fetchHtmlFollowingRedirects(client, context, walletAuth);
            HttpPost consentPost = new HttpPost(base.resolve("/oid4vp/consent"));
            consentPost.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("decision", "accept")), StandardCharsets.UTF_8));
            try (CloseableHttpResponse consentResponse = client.execute(consentPost, context)) {
                String body = new String(consentResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(consentResponse.getCode()).isEqualTo(200);
                assertThat(body).contains("No matching credential found");
            }
        }
    }

    @Test
    void encryptedPresentationResponses() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }

            String clientMetadata = objectMapper.writeValueAsString(Map.of(
                    "jwks", objectMapper.readTree(verifierKeyService.publicJwksJson()),
                    "response_encryption_alg", "RSA-OAEP-256",
                    "response_encryption_enc", "A256GCM"
            ));

            String dcql = fetchDefaultDcqlQuery(client, context, base);
            PresentationForm encryptedForm = initiatePresentationFlow(client, context, base, dcql, "accept",
                    List.of("given_name", "birthdate"), List.of("personal_id"), clientMetadata, true,
                    null, null, null, null, null);
            HttpPost callbackPost = new HttpPost(encryptedForm.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(encryptedForm.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                assertThat(verifierResult.getCode()).isEqualTo(200);
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    @Test
    void presentationWithX509HashAuth() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            SelfSignedMaterial cert = generateSelfSignedCert();
            String clientId = "x509_hash:" + cert.hash();
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    clientId, "x509_hash", cert.combinedPem(), null, null);
            List<NameValuePair> params = URLEncodedUtils.parse(walletAuth, StandardCharsets.UTF_8);
            List<String> paramNames = params.stream().map(NameValuePair::getName).toList();
            assertThat(paramNames).contains("client_id").contains("request");
            assertThat(paramNames).doesNotContain("dcql_query", "nonce", "response_mode", "response_uri", "state", "client_metadata", "request_uri");
            PresentationForm form = continuePresentationFlow(client, context, base, walletAuth, "accept",
                    List.of("given_name"), null, false, Map.of(), null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    @Test
    void presentationWithX509HashAutoDerivedClientId() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    null, "x509_hash", null, null, null);
            String clientId = URLEncodedUtils.parse(walletAuth, StandardCharsets.UTF_8).stream()
                    .filter(param -> "client_id".equals(param.getName()))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElse(null);
            assertThat(clientId).isNotBlank();
            assertThat(clientId).startsWith("x509_hash:");
            PresentationForm form = continuePresentationFlow(client, context, base, walletAuth, "accept",
                    List.of("given_name"), null, false, Map.of(), null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    @Test
    void presentationWithX509HashRequestUri() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            SelfSignedMaterial cert = generateSelfSignedCert();
            String clientId = "x509_hash:" + cert.hash();
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    clientId, "x509_hash", cert.combinedPem(), null, null, "request_uri");
            List<String> params = URLEncodedUtils.parse(walletAuth, StandardCharsets.UTF_8).stream()
                    .map(NameValuePair::getName)
                    .toList();
            assertThat(params).contains("client_id").contains("request_uri");
            assertThat(params).doesNotContain("request", "dcql_query", "nonce", "response_mode", "response_uri", "state", "client_metadata");
            PresentationForm form = continuePresentationFlow(client, context, base, walletAuth, "accept",
                    List.of("given_name"), null, false, Map.of(), null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    @Test
    void requestUriResponseIsEncryptedWithWalletNonce() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    null, "plain", null, null, null, "request_uri");
            String requestUri = URLEncodedUtils.parse(walletAuth, StandardCharsets.UTF_8).stream()
                    .filter(param -> "request_uri".equals(param.getName()))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("request_uri missing"));
            HttpPost roRequest = new HttpPost(requestUri);
            List<NameValuePair> form = new ArrayList<>();
            String walletMetadata = buildWalletMetadataForTest();
            String walletNonce = randomWalletNonce();
            form.add(new BasicNameValuePair("wallet_metadata", walletMetadata));
            form.add(new BasicNameValuePair("wallet_nonce", walletNonce));
            roRequest.setEntity(new UrlEncodedFormEntity(form, StandardCharsets.UTF_8));
            try (CloseableHttpResponse roResponse = client.execute(roRequest, context)) {
                assertThat(roResponse.getCode()).isEqualTo(200);
                String body = new String(roResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(body.chars().filter(ch -> ch == '.').count()).isEqualTo(4);
                com.nimbusds.jose.JWEObject jwe = com.nimbusds.jose.JWEObject.parse(body);
                jwe.decrypt(new com.nimbusds.jose.crypto.ECDHDecrypter(walletKeyService.loadOrCreateKey()));
                String requestObject = jwe.getPayload().toString();
                SignedJWT jwt = SignedJWT.parse(requestObject);
                assertThat(jwt.getJWTClaimsSet().getStringClaim("wallet_nonce")).isEqualTo(walletNonce);
            }
        }
    }

    @Test
    void verifierResultShowsKeyBindingJwt() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            PresentationForm form = initiatePresentationFlow(client, context, base, dcql, "accept",
                    List.of("given_name"), null, null, false,
                    null, "plain", null, null, null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                Document doc = Jsoup.parse(body);
                Element kb = doc.selectFirst("#key-binding-jwt");
                assertThat(kb).withFailMessage("key_binding_jwt not shown. Body:%n%s", body).isNotNull();
                assertThat(kb.text()).contains(".");
            }
        }
    }

    @Test
    void presentationWithVerifierAttestationAuth() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            SelfSignedMaterial attestation = generateSelfSignedCert();
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    "verifier.example", "verifier_attestation", null, attestation.combinedPem(), "demo-attestation-issuer");
            List<NameValuePair> params = URLEncodedUtils.parse(walletAuth, StandardCharsets.UTF_8);
            List<String> names = params.stream().map(NameValuePair::getName).toList();
            assertThat(names).contains("client_id").contains("request_uri");
            assertThat(names).doesNotContain("dcql_query", "nonce", "response_mode", "response_uri", "state", "client_metadata", "request");
            PresentationForm form = continuePresentationFlow(client, context, base, walletAuth, "accept",
                    List.of("given_name"), null, false, Map.of(), null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    @Test
    void presentationWithVerifierAttestationRequestUri() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            SelfSignedMaterial attestation = generateSelfSignedCert();
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    "verifier.example", "verifier_attestation", null, attestation.combinedPem(), "demo-attestation-issuer", "request_uri");
            List<String> params = URLEncodedUtils.parse(walletAuth, StandardCharsets.UTF_8).stream()
                    .map(NameValuePair::getName)
                    .toList();
            assertThat(params).contains("client_id").contains("request_uri");
            assertThat(params).doesNotContain("request", "dcql_query", "nonce", "response_mode", "response_uri", "state", "client_metadata");
            PresentationForm form = continuePresentationFlow(client, context, base, walletAuth, "accept",
                    List.of("given_name"), null, false, Map.of(), null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    @Test
    void consentShowsVctBadge() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            PresentationForm form = initiatePresentationFlow(client, context, base, dcql, "accept",
                    List.of("given_name"), null, null, false,
                    null, "plain", null, null, null, Map.of(), "urn:eudi:pid:1");
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                String body = new String(verifierResult.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
            }
        }
    }

    @Test
    void usernameDisplayedInsteadOfSubjectOnWalletAndConsent() throws Exception {
        URI base = URI.create("http://localhost:" + serverPort);
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build();
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            authenticateThroughLogin(client, context, base);
            String sub;
            String username;
            try (CloseableHttpResponse sessionResponse = client.execute(new HttpGet(base.resolve("/api/session")), context)) {
                JsonNode sessionJson = objectMapper.readTree(sessionResponse.getEntity().getContent());
                JsonNode user = sessionJson.path("user");
                sub = user.path("sub").asText();
                username = firstNonBlank(
                        user.path("preferred_username").asText(null),
                        user.path("name").asText(null),
                        user.path("email").asText(null),
                        user.path("sub").asText("test")
                );
            }

            HtmlPage walletPage = fetchHtmlFollowingRedirects(client, context, base);
            Element walletName = walletPage.document().selectFirst(".user-chip .name");
            assertThat(walletName).isNotNull();
            assertThat(walletName.text()).isEqualTo("test");
            if (sub != null && !sub.isBlank()) {
                assertThat(walletName.text()).doesNotContain(sub);
            }

            try (CloseableHttpResponse issueResponse = client.execute(new HttpPost(base.resolve("/api/issue")), context)) {
                assertThat(issueResponse.getCode()).isEqualTo(200);
            }
            String dcql = fetchDefaultDcqlQuery(client, context, base);
            URI walletAuth = startPresentationRequest(client, context, base, dcql, List.of("given_name"), null,
                    null, null, null, null, null);
            HtmlPage consentPage = fetchHtmlFollowingRedirects(client, context, walletAuth);
            Element consentName = consentPage.document().selectFirst(".user-chip .name");
            assertThat(consentName).isNotNull();
            assertThat(consentName.text()).isEqualTo("test");
            if (sub != null && !sub.isBlank()) {
                assertThat(consentName.text()).doesNotContain(sub);
            }

            // Complete the flow to keep the test environment consistent.
            PresentationForm form = continuePresentationFlow(client, context, base, walletAuth, "accept",
                    List.of("given_name"), null, false, Map.of(), null);
            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (CloseableHttpResponse verifierResult = client.execute(callbackPost, context)) {
                assertThat(verifierResult.getCode()).isEqualTo(200);
            }
        }
    }

    private void authenticateThroughLogin(CloseableHttpClient client, HttpClientContext context, URI base) throws Exception {
        for (int attempt = 0; attempt < 2; attempt++) {
            HttpGet startLogin = new HttpGet(base.resolve("/auth/login"));
            try (CloseableHttpResponse loginRedirect = client.execute(startLogin, context)) {
                assertThat(loginRedirect.getCode()).isEqualTo(302);
                URI authorize = resolveRedirect(base, loginRedirect.getFirstHeader("Location").getValue());
                HtmlPage loginPage = fetchHtmlFollowingRedirects(client, context, authorize);
                LoginForm loginForm = extractLoginForm(loginPage.document(), loginPage.uri());
                loginForm.fields().put("username", TEST_USERNAME);
                loginForm.fields().put("password", TEST_PASSWORD);

                HttpPost loginPost = new HttpPost(loginForm.action());
                loginPost.setEntity(new UrlEncodedFormEntity(toParams(loginForm.fields()), StandardCharsets.UTF_8));
                String cookieHeader = buildCookieHeaderFor(loginForm.action(), context.getCookieStore().getCookies());
                if (!cookieHeader.isBlank()) {
                    loginPost.setHeader(HttpHeaders.COOKIE, cookieHeader);
                }
                try (ResponseWithUri loginResult = executeFollowRedirects(client, context, loginPost)) {
                    List<String> cookieNames = context.getCookieStore().getCookies().stream()
                            .map(Cookie::getName)
                            .toList();
                    String body = loginResult.response().getEntity() != null
                            ? new String(loginResult.response().getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8)
                            : "";
                    if (loginResult.response().getCode() == 400 && body.contains("Restart login cookie not found") && attempt == 0) {
                        context.getCookieStore().clear();
                        continue;
                    }
                    assertThat(loginResult.response().getCode())
                            .withFailMessage("Login flow failed. HTTP %s at %s Cookies: %s Body:%n%s",
                                    loginResult.response().getCode(),
                                    loginResult.uri(),
                                    cookieNames,
                                    body)
                            .isEqualTo(200);
                    return;
                }
            }
        }
        throw new IllegalStateException("Login flow did not complete after retries");
    }

    private PresentationForm initiatePresentationFlow(CloseableHttpClient client, HttpClientContext context, URI base,
                                                      String dcqlQuery, String decision,
                                                      List<String> expectedClaims, List<String> forbiddenClaims,
                                                      String clientMetadata, boolean expectEncrypted,
                                                      String walletClientId, String authType,
                                                      String walletClientCert, String attestationCert, String attestationIssuer) throws IOException {
        return initiatePresentationFlow(client, context, base, dcqlQuery, decision, expectedClaims, forbiddenClaims,
                clientMetadata, expectEncrypted, walletClientId, authType, walletClientCert, attestationCert, attestationIssuer, Map.of(), null, null);
    }

    private PresentationForm initiatePresentationFlow(CloseableHttpClient client, HttpClientContext context, URI base,
                                                      String dcqlQuery, String decision,
                                                      List<String> expectedClaims, List<String> forbiddenClaims,
                                                      String clientMetadata, boolean expectEncrypted,
                                                      String walletClientId, String authType,
                                                      String walletClientCert, String attestationCert, String attestationIssuer,
                                                      Map<String, String> selectionOverrides, String expectedVct, String requestObjectMode)
            throws IOException {
        URI walletAuth = startPresentationRequest(client, context, base, dcqlQuery, expectedClaims, clientMetadata,
                walletClientId, authType, walletClientCert, attestationCert, attestationIssuer, requestObjectMode);
        return continuePresentationFlow(client, context, base, walletAuth, decision, expectedClaims, forbiddenClaims, expectEncrypted, selectionOverrides, expectedVct);
    }

    private PresentationForm initiatePresentationFlow(CloseableHttpClient client, HttpClientContext context, URI base,
                                                      String dcqlQuery, String decision,
                                                      List<String> expectedClaims, List<String> forbiddenClaims,
                                                      String clientMetadata, boolean expectEncrypted,
                                                      String walletClientId, String authType,
                                                      String walletClientCert, String attestationCert, String attestationIssuer,
                                                      Map<String, String> selectionOverrides, String expectedVct)
            throws IOException {
        return initiatePresentationFlow(client, context, base, dcqlQuery, decision, expectedClaims, forbiddenClaims,
                clientMetadata, expectEncrypted, walletClientId, authType, walletClientCert, attestationCert, attestationIssuer, selectionOverrides, expectedVct, null);
    }

    private URI startPresentationRequest(CloseableHttpClient client, HttpClientContext context, URI base,
                                         String dcqlQuery, List<String> expectedClaims, String clientMetadata,
                                         String walletClientId, String authType, String walletClientCert,
                                         String attestationCert, String attestationIssuer) throws IOException {
        return startPresentationRequest(client, context, base, dcqlQuery, expectedClaims, clientMetadata,
                walletClientId, authType, walletClientCert, attestationCert, attestationIssuer, null);
    }

    private URI startPresentationRequest(CloseableHttpClient client, HttpClientContext context, URI base,
                                         String dcqlQuery, List<String> expectedClaims, String clientMetadata,
                                         String walletClientId, String authType, String walletClientCert,
                                         String attestationCert, String attestationIssuer, String requestObjectMode) throws IOException {
        HttpPost verifierStart = new HttpPost(base.resolve("/verifier/start"));
        verifierStart.setConfig(RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build());
        List<NameValuePair> startParams = new ArrayList<>();
        startParams.add(new BasicNameValuePair("dcqlQuery", addClaimsToDcql(dcqlQuery, expectedClaims)));
        if (walletClientId != null && !walletClientId.isBlank()) {
            startParams.add(new BasicNameValuePair("walletClientId", walletClientId));
        }
        if (authType != null && !authType.isBlank()) {
            startParams.add(new BasicNameValuePair("authType", authType));
        }
        if (clientMetadata != null && !clientMetadata.isBlank()) {
            startParams.add(new BasicNameValuePair("clientMetadata", clientMetadata));
        }
        if (walletClientCert != null && !walletClientCert.isBlank()) {
            startParams.add(new BasicNameValuePair("walletClientCert", walletClientCert));
        }
        if (attestationCert != null && !attestationCert.isBlank()) {
            startParams.add(new BasicNameValuePair("attestationCert", attestationCert));
        }
        if (attestationIssuer != null && !attestationIssuer.isBlank()) {
            startParams.add(new BasicNameValuePair("attestationIssuer", attestationIssuer));
        }
        if (requestObjectMode != null && !requestObjectMode.isBlank()) {
            startParams.add(new BasicNameValuePair("requestObjectMode", requestObjectMode));
        }
        verifierStart.setEntity(new UrlEncodedFormEntity(startParams, StandardCharsets.UTF_8));
        try (CloseableHttpResponse startResponse = client.execute(verifierStart, context)) {
            assertThat(startResponse.getCode()).isEqualTo(302);
            return resolveRedirect(base, startResponse.getFirstHeader("Location").getValue());
        }
    }

    private PresentationForm continuePresentationFlow(CloseableHttpClient client, HttpClientContext context, URI base,
                                                      URI walletAuth, String decision, List<String> expectedClaims,
                                                      List<String> forbiddenClaims, boolean expectEncrypted,
                                                      Map<String, String> selectionOverrides, String expectedVct) throws IOException {
        HtmlPage document = fetchHtmlFollowingRedirects(client, context, walletAuth);
        Element consentForm = document.document().selectFirst("form[action=\"/oid4vp/consent\"]");
        assertThat(consentForm)
                .withFailMessage("Consent form missing. Body: %s", document.document().text())
                .isNotNull();
        String pageText = document.document().text();
        if (expectedClaims != null) {
            expectedClaims.forEach(claim -> assertThat(pageText).contains(claim));
        }
        if (forbiddenClaims != null) {
            forbiddenClaims.forEach(claim -> assertThat(pageText).doesNotContain(claim));
        }
        if (expectedVct != null && !expectedVct.isBlank()) {
            assertThat(pageText).contains(expectedVct);
            List<Element> candidateCards = document.document().select(".candidate-card");
            List<Element> badges = document.document().select(".candidate-card .badge.secondary");
            assertThat(badges)
                    .withFailMessage("Missing VCT badge in consent screen. Body: %s", pageText)
                    .isNotEmpty();
            assertThat(badges)
                    .withFailMessage("Expected a VCT badge on every candidate card")
                    .hasSize(candidateCards.size());
            assertThat(badges.stream().map(Element::text).toList())
                    .anyMatch(text -> text.contains(expectedVct));
        }

        List<NameValuePair> consentParams = new ArrayList<>();
        consentParams.add(new BasicNameValuePair("decision", decision));
        Map<String, List<Element>> radioGroups = document.document().select("input[type=radio][name^=selection-]")
                .stream()
                .collect(Collectors.groupingBy(input -> input.attr("name"), Collectors.toList()));
        radioGroups.forEach((name, inputs) -> {
            String override = selectionOverrides.get(name);
            Element chosen = null;
            if (override != null) {
                if ("__none__".equals(override)) {
                    return;
                }
                chosen = inputs.stream().filter(i -> override.equals(i.attr("value")) || "__last__".equals(override) && i == inputs.get(inputs.size() - 1)).findFirst().orElse(null);
            }
            if (chosen == null && !inputs.isEmpty()) {
                chosen = inputs.get(0);
            }
            if (chosen != null) {
                consentParams.add(new BasicNameValuePair(name, chosen.attr("value")));
            }
        });
        HttpPost consentPost = new HttpPost(base.resolve("/oid4vp/consent"));
        consentPost.setEntity(new UrlEncodedFormEntity(consentParams, StandardCharsets.UTF_8));
        try (CloseableHttpResponse consentResponse = client.execute(consentPost, context)) {
            assertThat(consentResponse.getCode()).isEqualTo(200);
            String body = new String(consentResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
            Document submitDoc = Jsoup.parse(body);
            Element presentationForm = submitDoc.selectFirst("form");
            assertThat(presentationForm).withFailMessage("Presentation form missing after consent. Body: %s", body).isNotNull();
            Map<String, String> fields = new LinkedHashMap<>();
            for (Element input : presentationForm.select("input")) {
                String name = input.attr("name");
                if (name != null && !name.isBlank()) {
                    fields.put(name, input.attr("value"));
                }
            }
            if (expectEncrypted) {
                String vpTokenValue = fields.get("vp_token");
                assertThat(vpTokenValue).isNotBlank();
                List<String> vpTokens = parseVpTokens(vpTokenValue);
                assertThat(vpTokens)
                        .withFailMessage("Expected encrypted vp_token but got %s", vpTokens)
                        .allMatch(this::looksLikeJwe);
            }
            URI action = resolveRedirect(base, presentationForm.attr("action"));
            return new PresentationForm(action, fields);
        }
    }

    private HtmlPage fetchHtmlFollowingRedirects(CloseableHttpClient client, HttpClientContext context, URI uri)
            throws IOException {
        HttpGet request = new HttpGet(uri);
        try (ResponseWithUri response = executeFollowRedirects(client, context, request)) {
            assertThat(response.response().getCode()).isEqualTo(200);
            return new HtmlPage(
                    response.uri(),
                    Jsoup.parse(response.response().getEntity().getContent(), StandardCharsets.UTF_8.name(), response.uri().toString())
            );
        }
    }

    private LoginForm extractLoginForm(Document loginPage, URI pageUri) {
        Element targetForm = null;
        for (Element form : loginPage.select("form")) {
            Elements inputs = form.select("input");
            boolean hasUsername = inputs.stream().anyMatch(input -> "username".equals(input.attr("name")));
            boolean hasPassword = inputs.stream().anyMatch(input -> "password".equals(input.attr("name")));
            if (hasUsername && hasPassword) {
                targetForm = form;
                break;
            }
        }
        if (targetForm == null) {
            targetForm = loginPage.selectFirst("form");
        }
        assertThat(targetForm).withFailMessage("Login form not found").isNotNull();

        Map<String, String> fields = new LinkedHashMap<>();
        for (Element input : targetForm.select("input")) {
            String name = input.attr("name");
            if (name == null || name.isBlank()) {
                continue;
            }
            fields.put(name, input.attr("value"));
        }
        URI action = resolveRedirect(pageUri, targetForm.attr("action"));
        return new LoginForm(action, fields);
    }

    private String fetchDefaultDcqlQuery(CloseableHttpClient client, HttpClientContext context, URI base)
            throws IOException {
        HttpGet get = new HttpGet(base.resolve("/verifier/default"));
        try (CloseableHttpResponse resp = client.execute(get, context)) {
            assertThat(resp.getCode()).isEqualTo(200);
            JsonNode json = objectMapper.readTree(resp.getEntity().getContent());
            return json.path("dcql_query").asText();
        }
    }

    private ResponseWithUri executeFollowRedirects(CloseableHttpClient client, HttpClientContext context,
                                                   HttpUriRequestBase initial) throws IOException {
        CloseableHttpResponse response = client.execute(initial, context);
        URI current = URI.create(initial.getRequestUri());
        int hops = 0;
        while (isRedirect(response)) {
            if (++hops > 10) {
                response.close();
                throw new IllegalStateException("Too many redirects");
            }
            String location = response.getFirstHeader("Location").getValue();
            response.close();
            URI next = resolveRedirect(current, location);
            response = client.execute(new HttpGet(next), context);
            current = next;
        }
        return new ResponseWithUri(response, current);
    }

    private boolean isRedirect(CloseableHttpResponse response) {
        int code = response.getCode();
        return code >= 300 && code < 400;
    }

    private URI resolveRedirect(URI current, String location) {
        URI candidate = URI.create(location);
        if (candidate.isAbsolute()) {
            return candidate;
        }
        return current.resolve(location);
    }

    private String buildCookieHeaderFor(URI target, List<Cookie> cookies) {
        String host = target.getHost();
        String path = target.getPath();
        return cookies.stream()
                .filter(cookie -> cookieApplies(cookie, host, path))
                .map(cookie -> cookie.getName() + "=" + cookie.getValue())
                .collect(Collectors.joining("; "));
    }

    private boolean cookieApplies(Cookie cookie, String host, String path) {
        String domain = cookie.getDomain();
        if (domain != null && !host.endsWith(domain.replaceFirst("^\\.", ""))) {
            return false;
        }
        String cookiePath = cookie.getPath();
        if (cookiePath != null && !path.startsWith(cookiePath)) {
            return false;
        }
        return true;
    }

    private String addClaimsToDcql(String dcqlQuery, List<String> expectedClaims) {
        if (expectedClaims == null || expectedClaims.isEmpty()) {
            return dcqlQuery;
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQuery);
            if (!root.has("credentials") || !root.get("credentials").isArray() || root.get("credentials").isEmpty()) {
                return dcqlQuery;
            }
            ArrayNode credentials = (ArrayNode) root.get("credentials");
            for (JsonNode credentialNode : credentials) {
                ArrayNode claimsArray;
                if (credentialNode.has("claims") && credentialNode.get("claims").isArray()) {
                    claimsArray = (ArrayNode) credentialNode.get("claims");
                } else {
                    claimsArray = objectMapper.createArrayNode();
                    ((ObjectNode) credentialNode).set("claims", claimsArray);
                }
                addClaimNodes(claimsArray, expectedClaims);
            }
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return dcqlQuery;
        }
    }

    private void addClaimNodes(ArrayNode claimsArray, List<String> claims) {
        Set<String> existing = new HashSet<>();
        claimsArray.forEach(node -> {
            if (node.has("path")) {
                existing.add(node.get("path").toString());
            }
        });
        for (String claim : claims) {
            if (claim == null || claim.isBlank()) {
                continue;
            }
            ArrayNode path = objectMapper.createArrayNode();
            for (String segment : claim.split("\\.")) {
                if (!segment.isBlank()) {
                    path.add(segment.trim());
                }
            }
            if (path.isEmpty()) {
                continue;
            }
            if (existing.contains(path.toString())) {
                continue;
            }
            ObjectNode claimNode = objectMapper.createObjectNode();
            claimNode.set("path", path);
            claimsArray.add(claimNode);
            existing.add(path.toString());
        }
    }

    private List<NameValuePair> toParams(Map<String, String> fields) {
        List<NameValuePair> params = new ArrayList<>();
        fields.forEach((k, v) -> params.add(new BasicNameValuePair(k, v)));
        return params;
    }

    private List<String> parseVpTokens(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        try {
            JsonNode node = objectMapper.readTree(raw);
            List<String> tokens = new ArrayList<>();
            if (node.isObject()) {
                node.fields().forEachRemaining(entry -> {
                    if (entry.getValue().isArray()) {
                        entry.getValue().forEach(v -> tokens.add(v.asText()));
                    } else {
                        tokens.add(entry.getValue().asText());
                    }
                });
            } else if (node.isArray()) {
                node.forEach(v -> tokens.add(v.asText()));
            } else if (node.isTextual()) {
                tokens.add(node.asText());
            }
            tokens.removeIf(String::isBlank);
            if (!tokens.isEmpty()) {
                return tokens;
            }
        } catch (Exception ignored) {
        }
        return List.of(raw);
    }

    private boolean looksLikeJwe(String token) {
        return token != null && token.chars().filter(ch -> ch == '.').count() == 4;
    }

    private String buildWalletMetadataForTest() throws Exception {
        ECKey key = walletKeyService.loadOrCreateKey();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("jwks", new JWKSet(key.toPublicJWK()).toJSONObject(false));
        meta.put("request_object_encryption_alg_values_supported", List.of("ECDH-ES+A256KW"));
        meta.put("request_object_encryption_enc_values_supported", List.of("A256GCM"));
        meta.put("request_object_signing_alg_values_supported", List.of("RS256"));
        return objectMapper.writeValueAsString(meta);
    }

    private String randomWalletNonce() {
        byte[] random = new byte[24];
        new SecureRandom().nextBytes(random);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    private SelfSignedMaterial generateSelfSignedCert() throws Exception {
        String certPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIICtzCCAZ8CFE2J/t7KgLLEDkKeQ3ywB0leFqlYMA0GCSqGSIb3DQEBCwUAMBgx\n" +
                "FjAUBgNVBAMMDVZlcmlmaWVyIFRlc3QwHhcNMjUxMTI1MDAyMTU3WhcNMzUxMTIz\n" +
                "MDAyMTU3WjAYMRYwFAYDVQQDDA1WZXJpZmllciBUZXN0MIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEAxqpcp5JbRPyUVakXtl/ifEvvq0gwfeEn+GrsCwd2\n" +
                "ByASdSdnvRXdPH56qV+7i1TPpVJvVNtpztOwatAFjv7KMu4ZSmqVUQGi3gns+F6P\n" +
                "NdBiYECz9hmIB4Unq1cXZRJwupY8McbGzYBCMT2a50riBb2lb593NUY38hw1Y4By\n" +
                "xK9/rc2i2NbJUCtm9suf2wLAbIsQqAvoBUPdeMzM+2JkbO1O9MisZA5GmlutrvcM\n" +
                "Xw75838cynfCms8Zt5zv7hfv86NGTqxyk+YWdXbui3U8EYRhxh0HTu3fVbroDVIo\n" +
                "bGKgCDbifiM4qyPSOS6YTM9cPcQMoEzi6+n9b8vPlQ+LqwIDAQABMA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQCnjrZgCzO9ajMTsE1mnRdBuotj4M5SO9jKqFShLmZN0NQltv9e\n" +
                "YblCEJWOpeBco7iii77WUltPGh3RWNsOHq7O4mlQElUL7GyOPDKLZAquYgwmPBv9\n" +
                "VsfMhQTB9y0Rd63g/ObapA+UuGyqTsh+WDJwQJZkuus2t1WkNiqUXJvrngyctO8M\n" +
                "9oU65nI5zwRosp6zvZfN/ga6Xlx/qNbitDTnqVmKCemFclzsOSBoJQMmWvPwHpFY\n" +
                "pDXTGOOwZLQ7Gv+69rc/RGz8cbq+UYnBwV3pIkCGrZga995IzL2Ww77YefNoh51G\n" +
                "YSAWH7sSQCwjdQN+bn/sweGQLKGDeGcaHZdy\n" +
                "-----END CERTIFICATE-----";
        String keyPem = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDGqlynkltE/JRV\n" +
                "qRe2X+J8S++rSDB94Sf4auwLB3YHIBJ1J2e9Fd08fnqpX7uLVM+lUm9U22nO07Bq\n" +
                "0AWO/soy7hlKapVRAaLeCez4Xo810GJgQLP2GYgHhSerVxdlEnC6ljwxxsbNgEIx\n" +
                "PZrnSuIFvaVvn3c1RjfyHDVjgHLEr3+tzaLY1slQK2b2y5/bAsBsixCoC+gFQ914\n" +
                "zMz7YmRs7U70yKxkDkaaW62u9wxfDvnzfxzKd8Kazxm3nO/uF+/zo0ZOrHKT5hZ1\n" +
                "du6LdTwRhGHGHQdO7d9VuugNUihsYqAINuJ+IzirI9I5LphMz1w9xAygTOLr6f1v\n" +
                "y8+VD4urAgMBAAECggEADVHMl8okmWL4+ZT/eRFoP3ECe4wB2pRt4UGxW9eoSe64\n" +
                "5zkv57eWV07AaQOwDDXC+DnLvYCDmnqLDPGvo28zlJVJYPCsSgTfa+d2B3ykpz42\n" +
                "fbhI0/YaZXYbMiBLDHbxrzH+sZkWX9WDyE+EIyRufRx5SvaB21csqTWCPfxevqFv\n" +
                "D6aMMjkccgRzLjS2ZqB8ndNwz+bRhlaxVUxSb9DEBV1+A1egkvtBUYqTrIURdE9N\n" +
                "IZ/0dSCHvMRbpG3bbNg4aHe+kKPMxmDlRMV6q+m+kYRVnmfrXXO353JPqwZmoPLP\n" +
                "T5A+5MxhBUI5naeQ/MyxrT1CNOCFdcUO0s7WehCBjQKBgQDlmC+h3nip4ckBRxyR\n" +
                "IkkLGz6lVGKtCm7Kn6FKUoBN0E6ORmoAdM57agGMrYFHCJEp9s9tP+5WCMlJOJ+d\n" +
                "I5QQenZDe1Fbdh9XnKpT/Bz1DH8EMHd89vxwgrBVmazF8deRX+5qV4uYAxZc3QMQ\n" +
                "yza93ADwoC5rhQg/4bDQSocvjwKBgQDdg405k5Iw6SLvGNDeS1LoNUIxyzHtGErA\n" +
                "1zNoasOLIfxYc4vCSufVZYjwOv4LI5FgFheGZRqjWUP+a0jStNy7qhcufdbD38rE\n" +
                "/fw3MzQxgXEAUmbI12Y5RqVdKwKFNjSH9VXycdnnLuPrrlNmyp8WUHqK8/Qyxunc\n" +
                "0yMERAmUJQKBgQCAqHCAv79US28tJSFP/yt5atIHKauGFmORbjSfBm5ZrJJozfKW\n" +
                "wN34cKXfpFbebGGUZ3dDXGD9mzzYqD9hek99kHJ3TEKCA0Z6/RLBr3S2qUMAIPzE\n" +
                "bU926PVRcqVL40MOdviOZPKXw5sjfMI8BfRuHjv0m36Hx+ugiKNhhXIN5wKBgQCr\n" +
                "TCfR9oR+vkr9irs6rBUY7Nabmv6o0rg8GC7w+F7vIQD7hZ72SOau5y3WWEhMZNzu\n" +
                "6SaYD2diGo2yGVTfXG210frLQRTrtAwh+icoqLgb8HVqQk6p0aiDclY+jhwM17YX\n" +
                "zWkBa3mOhXxLrSthuh78KpAZFD4rZhdDZSMXEWY24QKBgQDid1NAeo+x6umLQuz7\n" +
                "Y50wOmUKlRBUUKUKhgX3UEiCoFWSCPlD1DsKIp/zRbc/RhYJ1ok9epR62n+tNQrv\n" +
                "bKhQTdcN0bz4WxDvL9VnSBm8kY5sh1puOuhu0QQBfWcDQ9SHRnUPFLR9HvrWwCzg\n" +
                "TZtheqnf8IG90SI0T/aWyvlGFQ==\n" +
                "-----END PRIVATE KEY-----";
        byte[] der = Base64.getMimeDecoder().decode(certPem.replaceAll("-----[^-]+-----", "").replaceAll("\\s+", ""));
        String hash = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(der));
        String combined = certPem + "\n" + keyPem;
        return new SelfSignedMaterial(certPem, keyPem, combined, hash);
    }

    private String toPem(byte[] data, String type) {
        String base64 = Base64.getEncoder().encodeToString(data);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }

    private record PresentationForm(URI action, Map<String, String> fields) {
    }

    private record LoginForm(URI action, Map<String, String> fields) {
    }

    private record HtmlPage(URI uri, Document document) {
    }

    private record ResponseWithUri(CloseableHttpResponse response, URI uri) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            response.close();
        }
    }

    private record SelfSignedMaterial(String certificatePem, String keyPem, String combinedPem, String hash) {
    }

    private String firstNonBlank(String... candidates) {
        for (String c : candidates) {
            if (c != null && !c.isBlank()) {
                return c;
            }
        }
        return "";
    }

}
