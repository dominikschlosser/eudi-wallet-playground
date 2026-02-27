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
package de.arbeitsagentur.keycloak.oid4vp;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.WaitForSelectorState;
import com.nimbusds.jose.jwk.ECKey;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtCredentialBuilder;
import io.github.dominikschlosser.oid4vc.Credential;
import io.github.dominikschlosser.oid4vc.CredentialFormat;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;


import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for OID4VP Identity Provider flow using the
 * oid4vc-dev Docker wallet ({@code ghcr.io/dominikschlosser/oid4vc-dev}).
 * <p>
 * Networking strategy:
 * <ul>
 *   <li>Keycloak runs in Docker with port mapped to host</li>
 *   <li>Wallet runs in Docker with {@code --add-host localhost:host-gateway}</li>
 *   <li>All Keycloak URLs use {@code localhost:KC_PORT}</li>
 * </ul>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakOid4vpE2eIT {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpE2eIT.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static Network network;
    private static GenericContainer<?> keycloak;
    private static Oid4vcContainer wallet;
    private static Oid4vpTestCallbackServer callback;
    private static KeycloakAdminClient adminClient;

    private static Playwright playwright;
    private static Browser browser;
    private static BrowserContext context;
    private static Page page;

    private static String kcHostUrl;
    private static String callbackUrl;
    private static String savedTrustListJwt;

    @BeforeAll
    static void setUp() throws Exception {
        callback = new Oid4vpTestCallbackServer();
        callbackUrl = callback.localCallbackUrl();

        network = Network.newNetwork();

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.0")
                .withNetwork(network)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withExposedPorts(8080)
                .withCommand("start-dev", "--import-realm")
                .withLogConsumer(frame -> LOG.info("[KC] {}", frame.getUtf8String().stripTrailing()))
                .waitingFor(Wait.forHttp("/realms/wallet-demo").forPort(8080)
                        .withStartupTimeout(Duration.ofSeconds(180)));

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        int kcMappedPort = keycloak.getMappedPort(8080);
        kcHostUrl = "http://localhost:" + kcMappedPort;

        wallet = new Oid4vcContainer("ghcr.io/dominikschlosser/oid4vc-dev:v0.13.3")
                .withHostAccess()
                .withStatusList()
                .withStatusListBaseUrl("http://oid4vc-dev:8085")
                .withNetwork(network)
                .withNetworkAliases("oid4vc-dev");
        wallet.start();

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
        context = browser.newContext();
        // Track SSE readiness: monkey-patch EventSource so tests can wait for the first ping
        // before submitting wallet responses (mirrors real-world QR scan timing).
        context.addInitScript("""
                const OrigES = window.EventSource;
                window.EventSource = function(url) {
                    const es = new OrigES(url);
                    es.addEventListener('ping', () => { window.__oid4vpSseReady = true; });
                    return es;
                };
                window.EventSource.prototype = OrigES.prototype;
                window.__oid4vpSseReady = false;
                """);
        page = context.newPage();

        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, kcHostUrl, "admin", "admin");

        savedTrustListJwt = wallet.client().getTrustList();

        configureIdp(savedTrustListJwt, wallet.getAuthorizeUrl(), buildDefaultDcqlQuery());
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, "wallet-demo", "wallet-mock", callbackUrl);

        LOG.info("Setup complete. KC: {}, Wallet: {}", kcHostUrl, wallet.getBaseUrl());
    }

    @AfterAll
    static void tearDown() {
        if (page != null) page.close();
        if (context != null) context.close();
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
        if (keycloak != null) keycloak.stop();
        if (wallet != null) wallet.stop();
        if (network != null) network.close();
        if (callback != null) callback.close();
    }

    // ===== Tests =====

    @Test
    @Order(1)
    void loginPageShowsWalletIdpButton() {
        clearBrowserSession();

        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);
        page.waitForSelector("#username, a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-oid4vp").count())
                .as("Expected OID4VP IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    @Order(2)
    void firstWalletLoginCreatesNewUser() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        performSameDeviceWalletLogin();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("wallet-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    @Test
    @Order(3)
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        callback.reset();
        clearBrowserSession();

        performSameDeviceWalletLogin();

        page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        assertThat(page.url()).contains("code=");
    }

    @Test
    @Order(4)
    void mdocPresentationFlow() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        configureDcqlQuery(mdocDcqlQuery);

        try {
            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("mdoc-wallet-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(5)
    void sameDeviceFlowMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        configureDcqlQuery(mdocDcqlQuery);

        try {
            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("same-device-mdoc-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(6)
    void newUserViaWalletCanAccessAccountPage() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        performSameDeviceWalletLogin();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("new-wallet-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).as("Should redirect to callback URL").startsWith(callbackUrl);

        String accountUrl = kcHostUrl + "/realms/wallet-demo/account/";
        page.navigate(accountUrl);
        page.waitForLoadState(LoadState.NETWORKIDLE);
        Thread.sleep(2000);

        String bodyText = page.locator("body").textContent().toLowerCase();
        boolean hasForbiddenError = bodyText.contains("forbidden") ||
                bodyText.contains("403") ||
                bodyText.contains("access denied") ||
                bodyText.contains("not allowed");

        assertThat(hasForbiddenError)
                .as("New user should be able to access account page. URL: %s, Body: %s", page.url(), bodyText)
                .isFalse();

        boolean accountPageLoaded = bodyText.contains("account") ||
                bodyText.contains("profile") ||
                bodyText.contains("personal") ||
                page.url().contains("/account");

        assertThat(accountPageLoaded)
                .as("Account page should load successfully. URL: %s", page.url())
                .isTrue();
    }

    @Test
    @Order(7)
    void claimSetsWithSelectiveDisclosure() throws Exception {
        callback.reset();
        clearBrowserSession();

        String claimSetsDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "id": "family", "path": ["family_name"] },
                        { "id": "given", "path": ["given_name"] },
                        { "id": "birth", "path": ["birthdate"] },
                        { "id": "nationalities", "path": ["nationalities"] }
                      ],
                      "claim_sets": [
                        ["family", "given", "birth", "nationalities"],
                        ["family", "given"]
                      ]
                    }
                  ]
                }
                """;
        configureDcqlQuery(claimSetsDcqlQuery);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("claimsets-selective-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(8)
    void optionalClaimNotDisclosedSucceeds() throws Exception {
        callback.reset();
        clearBrowserSession();

        String minimalDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;
        configureDcqlQuery(minimalDcqlQuery);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("optional-claim-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(9)
    void mdocClaimSetsSelectiveDisclosure() throws Exception {
        callback.reset();
        clearBrowserSession();

        String mdocClaimSetsQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "id": "family", "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "id": "given", "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "id": "birth", "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ],
                      "claim_sets": [
                        ["family", "given", "birth"],
                        ["family", "given"]
                      ]
                    }
                  ]
                }
                """;
        configureDcqlQuery(mdocClaimSetsQuery);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("mdoc-claimsets-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(10)
    void germanPidWithoutUniqueIdentifiers() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        performSameDeviceWalletLogin();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("german-pid-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    /**
     * Native wallet simulation: extract wallet URL, submit via API (not browser click),
     * then navigate browser to the redirect_uri returned by the wallet.
     */
    @Test
    @Order(11)
    void sameDeviceNativeWalletFirstLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        assertThat(walletUrl).as("Wallet URL should not be empty").isNotEmpty();

        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        LOG.info("[Test] Native wallet response body: {}", walletResponse.rawBody());

        String redirectUri = walletResponse.redirectUri();

        if (redirectUri != null) {
            LOG.info("[Test] Native wallet redirect_uri: {}", redirectUri);
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        } else {
            // redirect_uri may be absent if the wallet submitted directly to Keycloak's response_uri
            // In that case, wait for SSE or the page to auto-navigate
            LOG.info("[Test] No redirect_uri in wallet response, waiting for page navigation");
        }

        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("/first-broker-login") ||
                                    url.contains("/login-actions/") ||
                                    page.locator("input[name='username']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            throw new AssertionError("Native wallet first login failed. URL: " + page.url(), e);
        }

        if (page.locator("input[name='username']").count() > 0) {
            String firstName = page.locator("input[name='firstName']").first().inputValue();
            String lastName = page.locator("input[name='lastName']").first().inputValue();

            assertThat(firstName).as("firstName should be pre-filled from credential").isNotEmpty();
            assertThat(lastName).as("lastName should be pre-filled from credential").isNotEmpty();

            completeFirstBrokerLoginForm("same-device-native-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    /**
     * Native wallet second login: verifies SSE does NOT race with the wallet redirect.
     */
    @Test
    @Order(12)
    void sameDeviceNativeWalletSecondLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        String loginPageUrl = page.url();

        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        LOG.info("[Test] Native wallet second login response: {}", walletResponse.rawBody());

        String redirectUri = walletResponse.redirectUri();

        if (redirectUri != null) {
            // Wait 3 seconds to verify SSE does NOT navigate the browser
            Thread.sleep(3000);
            assertThat(page.url())
                    .as("SSE should NOT navigate the browser for same-device flow")
                    .isEqualTo(loginPageUrl);

            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) || url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            LOG.warn("[Test] Did not reach callback URL. Current URL: {}", page.url());
        }

        assertThat(page.url())
                .as("Second login should reach callback with auth code")
                .satisfiesAnyOf(
                        url -> assertThat(url).contains("code="),
                        url -> assertThat(url).startsWith(callbackUrl)
                );
    }

    @Test
    @Order(13)
    void crossDeviceFirstLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, "wallet-demo", true);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();

            page.waitForSelector("img[alt='QR Code for wallet login']", new Page.WaitForSelectorOptions()
                    .setState(WaitForSelectorState.VISIBLE)
                    .setTimeout(30000));

            String crossDeviceWalletUrl = (String) page.evaluate(
                    "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");
            assertThat(crossDeviceWalletUrl).as("Cross-device wallet URL should be present").isNotEmpty();

            LOG.info("[Test] Cross-device wallet URL: {}", crossDeviceWalletUrl);

            // Wait for SSE connection to be established before submitting (mirrors real-world
            // timing where the user takes time to scan the QR code with their phone)
            waitForSseConnection();

            // Convert to openid4vp:// URI and submit via wallet API
            String presentationUri = crossDeviceWalletUrl.replaceFirst("^https?://[^?]*", "openid4vp://authorize");
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Cross-device wallet response: {}", walletResponse.rawBody());

            // SSE should navigate the browser automatically
            try {
                page.waitForURL(url ->
                                url.contains("/complete-auth") ||
                                        url.contains("/first-broker-login") ||
                                        url.contains("/login-actions/") ||
                                        page.locator("input[name='username']").count() > 0 ||
                                        url.startsWith(callbackUrl),
                        new Page.WaitForURLOptions().setTimeout(30000));
            } catch (Exception e) {
                throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
            }

            page.waitForLoadState(LoadState.NETWORKIDLE);

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("cross-device-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, "wallet-demo", false);
        }
    }

    @Test
    @Order(14)
    void crossDeviceSecondLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, "wallet-demo", true);

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            page.waitForSelector("img[alt='QR Code for wallet login']", new Page.WaitForSelectorOptions()
                    .setState(WaitForSelectorState.VISIBLE)
                    .setTimeout(30000));

            String crossDeviceWalletUrl = (String) page.evaluate(
                    "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");

            waitForSseConnection();

            String presentationUri = crossDeviceWalletUrl.replaceFirst("^https?://[^?]*", "openid4vp://authorize");
            wallet.acceptPresentationRequest(presentationUri);

            try {
                page.waitForURL(url -> url.startsWith(callbackUrl) || url.contains("code="),
                        new Page.WaitForURLOptions().setTimeout(30000));
            } catch (Exception e) {
                throw new AssertionError("Cross-device second login: SSE did not navigate to callback. URL: " + page.url(), e);
            }

            assertThat(page.url())
                    .as("Second cross-device login should reach callback with auth code")
                    .satisfiesAnyOf(
                            url -> assertThat(url).contains("code="),
                            url -> assertThat(url).startsWith(callbackUrl)
                    );
        } finally {
            Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, "wallet-demo", false);
        }
    }

    @Test
    @Order(15)
    void multiCredentialGermanPidAndUserBinding() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Build a verifier user credential SD-JWT and POST to Docker wallet
        String userCredentialSdJwt = buildVerifierUserCredential("test-user-" + System.currentTimeMillis());
        LOG.info("[Test] Built user credential SD-JWT (first 100 chars): {}",
                userCredentialSdJwt.substring(0, Math.min(100, userCredentialSdJwt.length())));

        wallet.client().importCredential(userCredentialSdJwt);
        LOG.info("[Test] User credential imported to wallet");

        // List credentials to verify the imported credential is recognized
        LOG.info("[Test] Wallet credentials after import: {}", wallet.listCredentials());

        // Configure multi-credential DCQL + skip trust list (credential is signed by mock issuer)
        Oid4vpTestKeycloakSetup.configureMultiCredentialFlow(adminClient, "wallet-demo");
        setIdpConfig("skipTrustListVerification", "true");

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        // Capture keycloak log position before login attempt
        String logsBefore = keycloak.getLogs();
        int logOffset = logsBefore.length();

        try {
            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("multi-cred-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } catch (AssertionError | Exception e) {
            // Capture Keycloak logs after failure for diagnostics
            String allLogs = keycloak.getLogs();
            String newLogs = allLogs.substring(Math.min(logOffset, allLogs.length()));
            // Filter for OID4VP related log lines
            String relevantLogs = java.util.Arrays.stream(newLogs.split("\n"))
                    .filter(line -> line.contains("OID4VP") || line.contains("SD-JWT") || line.contains("multi-credential")
                            || line.contains("user_id") || line.contains("Missing subject") || line.contains("claims"))
                    .reduce("", (a, b) -> a + "\n" + b);
            LOG.error("[Test] Keycloak logs after multi-credential failure:\n{}", relevantLogs);
            // Also print to System.err for surefire capture
            System.err.println("[DIAG] Keycloak OID4VP logs:\n" + relevantLogs);
            throw e;
        } finally {
            setIdpConfig("skipTrustListVerification", "false");
            Oid4vpTestKeycloakSetup.resetToDefaultConfiguration(adminClient, "wallet-demo");
            configureIdp(savedTrustListJwt, wallet.getAuthorizeUrl(), buildDefaultDcqlQuery());
            wallet.client().deleteCredentialsByType("urn:arbeitsagentur:user_credential:1");
        }
    }

    @Test
    @Order(16)
    void walletErrorShowsErrorAndAllowsRetry() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Pre-program the wallet to return an error on next presentation
        wallet.client().setNextError("access_denied", "User denied consent");

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Wallet error response: {}", walletResponse.rawBody());

            // Navigate to redirect_uri which should contain the error
            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            // Should see error page with option to retry
            Thread.sleep(2000);
            String bodyText = page.locator("body").textContent().toLowerCase();
            boolean hasError = bodyText.contains("error") || bodyText.contains("denied") ||
                    bodyText.contains("cancelled") || bodyText.contains("failed");

            assertThat(hasError)
                    .as("Error page should be shown. URL: %s, Body: %s", page.url(),
                            bodyText.substring(0, Math.min(500, bodyText.length())))
                    .isTrue();
        } finally {
            wallet.client().clearNextError();
        }
    }

    @Test
    @Order(17)
    void credentialSetsFullLoginWithMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        // credential_sets: both SD-JWT and mDoc PID options, wallet prefers mDoc
        String credentialSetsDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    },
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ],
                  "credential_sets": [
                    {
                      "options": [["pid_sd_jwt"], ["pid_mdoc"]],
                      "required": true
                    }
                  ]
                }
                """;
        configureDcqlQuery(credentialSetsDcqlQuery);
        wallet.client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("credset-mdoc-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            wallet.client().clearPreferredFormat();
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(18)
    void credentialSetsFullLoginWithSdJwt() throws Exception {
        callback.reset();
        clearBrowserSession();

        // credential_sets: both SD-JWT and mDoc PID options, wallet prefers SD-JWT
        String credentialSetsDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    },
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ],
                  "credential_sets": [
                    {
                      "options": [["pid_sd_jwt"], ["pid_mdoc"]],
                      "required": true
                    }
                  ]
                }
                """;
        configureDcqlQuery(credentialSetsDcqlQuery);
        wallet.client().setPreferredFormat(CredentialFormat.SD_JWT);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("credset-sdjwt-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            wallet.client().clearPreferredFormat();
            configureDcqlQuery(buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(19)
    void sameDeviceFlowUserDenialHandledGracefully() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Pre-program the wallet to simulate user cancellation
        wallet.client().setNextError("user_cancelled", "User cancelled the request");

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] User denial response: {}", walletResponse.rawBody());

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            Thread.sleep(2000);
            String bodyText = page.locator("body").textContent().toLowerCase();

            // Should see error page — the key is that it does NOT crash
            boolean hasErrorOrLogin = bodyText.contains("error") || bodyText.contains("denied") ||
                    bodyText.contains("cancel") || bodyText.contains("login") ||
                    page.locator("a#social-oid4vp").count() > 0;

            assertThat(hasErrorOrLogin)
                    .as("User denial should be handled gracefully. URL: %s, Body: %s", page.url(),
                            bodyText.substring(0, Math.min(500, bodyText.length())))
                    .isTrue();
        } finally {
            wallet.client().clearNextError();
        }
    }

    @Test
    @Order(20)
    void revokedCredentialIsRejected() throws Exception {
        callback.reset();
        clearBrowserSession();

        Credential pid = wallet.client().getCredentialsByType("urn:eudi:pid:de:1").stream().findFirst()
                .or(() -> wallet.client().getCredentialsByType("eu.europa.ec.eudi.pid.1").stream().findFirst())
                .orElseThrow(() -> new AssertionError("No PID credential found in wallet"));

        wallet.client().revokeCredential(pid.id());

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Revoked credential wallet response: {}", walletResponse.rawBody());

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            Thread.sleep(3000);

            assertThat(page.url())
                    .as("Revoked credential should NOT result in successful login (callback with auth code)")
                    .doesNotStartWith(callbackUrl);
        } finally {
            wallet.client().unrevokeCredential(pid.id());
        }
    }

    @Test
    @Order(21)
    void unrevokedCredentialIsAccepted() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        performSameDeviceWalletLogin();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("unrevoked-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    @Test
    @Order(22)
    void emptyTrustListRejectsSdJwt() throws Exception {
        callback.reset();
        clearBrowserSession();

        setIdpConfig("trustListJwt", "");

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Empty trust list wallet response: {}", walletResponse.rawBody());

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            Thread.sleep(3000);

            assertThat(page.url())
                    .as("Empty trust list should reject SD-JWT presentation")
                    .doesNotStartWith(callbackUrl);
        } finally {
            configureIdp(savedTrustListJwt, wallet.getAuthorizeUrl(), buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(23)
    void emptyTrustListRejectsMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ]
                }
                """;
        configureDcqlQuery(mdocDcqlQuery);
        setIdpConfig("trustListJwt", "");

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Empty trust list mDoc response: {}", walletResponse.rawBody());

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            Thread.sleep(3000);

            assertThat(page.url())
                    .as("Empty trust list should reject mDoc presentation")
                    .doesNotStartWith(callbackUrl);
        } finally {
            configureIdp(savedTrustListJwt, wallet.getAuthorizeUrl(), buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(24)
    void correctTrustListAcceptsSdJwtAfterRejection() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        configureIdp(savedTrustListJwt, wallet.getAuthorizeUrl(), buildDefaultDcqlQuery());

        performSameDeviceWalletLogin();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("trustlist-ok-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    // ===== Same-Device Flow Helper =====

    private void performSameDeviceWalletLogin() throws Exception {
        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        assertThat(walletUrl).as("Wallet URL should be present").isNotEmpty();

        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        LOG.info("[Test] Wallet response: {}", walletResponse.rawBody());

        String redirectUri = walletResponse.redirectUri();

        if (redirectUri != null) {
            LOG.info("[Test] Navigating to redirect_uri: {}", redirectUri);
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        } else {
            LOG.warn("[Test] No redirect_uri in wallet response! Body: {}", walletResponse.rawBody());
        }

        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("/first-broker-login") ||
                                    url.contains("/login-actions/") ||
                                    page.locator("input[name='username']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = "";
            try {
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after wallet login. URL: " + page.url() +
                    "\nWallet response: " + walletResponse.rawBody() +
                    "\nRedirect URI: " + redirectUri +
                    "\nPage content: " + bodyText.substring(0, Math.min(1000, bodyText.length())), e);
        }
    }

    private String convertToOpenid4vpUri(String walletUrl) {
        return walletUrl.replace(wallet.getAuthorizeUrl() + "?", "openid4vp://authorize?");
    }

    // ===== Credential Helpers =====

    private String buildVerifierUserCredential(String userId) throws Exception {
        ECKey issuerKey = loadMockIssuerKey();
        SdJwtCredentialBuilder builder = new SdJwtCredentialBuilder(OBJECT_MAPPER, issuerKey, Duration.ofMinutes(30));

        Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("user_id", userId);
        claims.put("linked_at", java.time.Instant.now().toString());

        // Get the wallet's holder binding key from its PID credential
        JsonNode cnf = getWalletHolderBindingKey();

        return builder.build(
                "verifier_user",
                "urn:arbeitsagentur:user_credential:1",
                "https://mock-issuer.example",
                claims,
                cnf
        ).encoded();
    }

    private JsonNode getWalletHolderBindingKey() {
        for (Credential cred : wallet.client().getCredentialsByType("urn:eudi:pid:de:1")) {
            Object cnf = cred.claims().get("cnf");
            if (cnf != null) {
                return OBJECT_MAPPER.valueToTree(cnf);
            }
        }
        LOG.warn("[Test] Could not find wallet holder binding key from PID credentials");
        return null;
    }

    private static ECKey loadMockIssuerKey() throws Exception {
        try (InputStream is = KeycloakOid4vpE2eIT.class.getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).as("mock-issuer-keys.json must be on classpath").isNotNull();
            JsonNode node = OBJECT_MAPPER.readTree(is);
            return ECKey.parse(node.get("privateJwk").toString());
        }
    }

    // ===== Setup Helpers =====

    private static void setIdpConfig(String key, String value) throws Exception {
        var idp = adminClient.getJson("/admin/realms/wallet-demo/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        var config = (java.util.Map<String, String>) idp.get("config");
        config.put(key, value);
        adminClient.putJson("/admin/realms/wallet-demo/identity-provider/instances/oid4vp", idp);
    }

    private static String buildDefaultDcqlQuery() {
        return """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;
    }

    private static void configureIdp(String trustListJwt, String walletAuthorizeUrl, String dcqlQuery) throws Exception {
        var idp = adminClient.getJson("/admin/realms/wallet-demo/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        var config = (java.util.Map<String, String>) idp.get("config");

        config.put("trustListJwt", trustListJwt);
        config.put("dcqlQuery", dcqlQuery);
        config.put("sameDeviceEnabled", "true");
        config.put("sameDeviceWalletUrl", walletAuthorizeUrl);
        config.put("dcApiRequestMode", "signed");
        config.put("userMappingClaim", "family_name");
        config.put("userMappingClaimMdoc", "family_name");

        adminClient.putJson("/admin/realms/wallet-demo/identity-provider/instances/oid4vp", idp);
    }

    private static void configureDcqlQuery(String dcqlQuery) throws Exception {
        var idp = adminClient.getJson("/admin/realms/wallet-demo/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        var config = (java.util.Map<String, String>) idp.get("config");
        config.put("dcqlQuery", dcqlQuery);
        adminClient.putJson("/admin/realms/wallet-demo/identity-provider/instances/oid4vp", idp);
    }

    // ===== Test Helper Methods =====

    /**
     * Wait for the SSE connection to be established and the first server-side poll to execute.
     * This mirrors real-world timing where the user takes several seconds to scan the QR code,
     * ensuring the SSE listener is active before the wallet submits a VP response.
     * <p>
     * The SSE endpoint sends a keepalive ping on its first iteration (i=0), then sleeps 1s
     * between polls. We wait for the browser to receive that first ping, which proves the
     * full SSE pipeline (HTTP connection + server poll loop) is operational.
     */
    private static void waitForSseConnection() {
        page.waitForCondition(() -> {
            Object ready = page.evaluate("() => window.__oid4vpSseReady === true");
            return Boolean.TRUE.equals(ready);
        }, new Page.WaitForConditionOptions().setTimeout(10000));
        LOG.info("[Test] SSE connection established (first ping received)");
    }

    private static void waitForOpenWalletLink() {
        page.waitForSelector("a:has-text('Open Wallet App')", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));
    }

    private void completeFirstBrokerLoginForm(String uniqueUsername) {
        page.waitForLoadState(LoadState.NETWORKIDLE);
        Locator usernameFields = page.locator("input[name='username']");
        if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
            usernameFields.first().fill(uniqueUsername);
        }
        Locator emailFields = page.locator("input[name='email']");
        if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
            emailFields.first().fill(uniqueUsername + "@example.com");
        }
        Locator firstNameFields = page.locator("input[name='firstName']");
        if (firstNameFields.count() > 0 && firstNameFields.first().inputValue().isEmpty()) {
            firstNameFields.first().fill("Test");
        }
        Locator lastNameFields = page.locator("input[name='lastName']");
        if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
            lastNameFields.first().fill("User");
        }

        page.locator("input[type='submit'], button[type='submit']").first().click();
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = "";
            try {
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("First broker login form did not redirect to callback. URL: " + page.url() +
                    "\nPage content: " + bodyText.substring(0, Math.min(2000, bodyText.length())), e);
        }
    }

    private void clearBrowserSession() {
        context.clearCookies();
        try {
            page.navigate(kcHostUrl + "/realms/wallet-demo/",
                    new Page.NavigateOptions().setTimeout(10000));
        } catch (Exception e) {
            LOG.warn("Initial navigation failed: {}", e.getMessage());
            try {
                page.navigate("about:blank");
            } catch (Exception ignored) {
            }
        }
        try {
            page.evaluate("() => { window.localStorage.clear(); window.sessionStorage.clear(); }");
        } catch (Exception ignored) {
        }
        context.clearCookies();
    }

    private URI buildAuthRequestUri() {
        String state = "s-" + System.nanoTime();
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        String codeVerifier = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String codeChallenge;
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            codeChallenge = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String uri = kcHostUrl + "/realms/wallet-demo/protocol/openid-connect/auth"
                + "?client_id=wallet-mock"
                + "&redirect_uri=" + urlEncode(callbackUrl)
                + "&response_type=code"
                + "&scope=openid"
                + "&state=" + urlEncode(state)
                + "&code_challenge=" + urlEncode(codeChallenge)
                + "&code_challenge_method=S256";
        return URI.create(uri);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void copyRealmImport() throws IOException {
        Path realmExport = repoRootDir().resolve("demo-app/config/keycloak/realm-export.json");
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport),
                "/opt/keycloak/data/import/realm-export.json");
    }

    private static void copyProviderJars() throws IOException {
        Path providerJar = findProviderJar();
        keycloak.withCopyFileToContainer(MountableFile.forHostPath(providerJar),
                "/opt/keycloak/providers/" + providerJar.getFileName());

        Path deps = moduleDir().resolve("target/providers").toAbsolutePath();
        if (!Files.isDirectory(deps)) {
            return;
        }
        try (Stream<Path> stream = Files.list(deps)) {
            for (Path jar : stream.filter(p -> p.getFileName().toString().endsWith(".jar")).toList()) {
                keycloak.withCopyFileToContainer(MountableFile.forHostPath(jar),
                        "/opt/keycloak/providers/" + jar.getFileName());
            }
        }
    }

    private static Path findProviderJar() throws IOException {
        Path target = moduleDir().resolve("target");
        try (Stream<Path> stream = Files.list(target)) {
            return stream
                    .filter(path -> path.getFileName().toString().startsWith("keycloak-oid4vp-"))
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-sources.jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-javadoc.jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Provider jar not found in target/"));
        }
    }

    private static Path moduleDir() {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        if ("keycloak-oid4vp".equals(dir.getFileName() != null ? dir.getFileName().toString() : "")) {
            return dir;
        }
        Path child = dir.resolve("keycloak-oid4vp");
        if (Files.isDirectory(child)) {
            return child;
        }
        return dir;
    }

    private static Path repoRootDir() {
        Path module = moduleDir();
        Path parent = module.getParent();
        return parent != null ? parent : module;
    }
}
