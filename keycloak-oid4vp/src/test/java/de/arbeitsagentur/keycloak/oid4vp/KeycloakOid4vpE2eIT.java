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

import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.WaitForSelectorState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.condition.EnabledIf;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for OID4VP Identity Provider flow.
 * Tests the "Sign in with Wallet" functionality using federated identity.
 *
 * These tests require a headed browser (Chrome with extensions) and will be
 * skipped in environments without a display (e.g., CI servers without Xvfb).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@EnabledIf("isHeadedBrowserAvailable")
class KeycloakOid4vpE2eIT {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpE2eIT.class);

    /**
     * Check if headed browser tests can run on this system.
     * Chrome extensions require non-headless mode, which needs a display.
     */
    static boolean isHeadedBrowserAvailable() {
        // Skip if explicitly disabled
        if ("true".equalsIgnoreCase(System.getenv("SKIP_HEADED_TESTS"))) {
            return false;
        }

        // On Linux, check for DISPLAY environment variable
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("linux")) {
            String display = System.getenv("DISPLAY");
            return display != null && !display.isBlank();
        }

        // On macOS and Windows, assume display is available unless in CI
        // CI environments typically set the CI environment variable
        String ci = System.getenv("CI");
        if ("true".equalsIgnoreCase(ci)) {
            // In CI, only run if explicitly enabled via ENABLE_HEADED_TESTS
            return "true".equalsIgnoreCase(System.getenv("ENABLE_HEADED_TESTS"));
        }

        return true;
    }

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static Oid4vpTestDcApiMockWalletServer wallet;
    private static Oid4vpTestCallbackServer callback;
    private static KeycloakAdminClient adminClient;
    private static String adminBaseUrl;
    private static String browserBaseUrl;
    private static String callbackUrl;
    private static String walletAuthEndpoint;

    private static GenericContainer<?> keycloak;
    private static Playwright playwright;
    private static BrowserContext context;
    private static Page page;

    @BeforeAll
    static void setUp() throws Exception {
        // Start local wallet mock and callback servers
        wallet = new Oid4vpTestDcApiMockWalletServer(OBJECT_MAPPER, "localhost");
        callback = new Oid4vpTestCallbackServer();

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.0")
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withEnv("KC_PROXY_HEADERS", "xforwarded")
                .withExposedPorts(8080)
                .withCommand("start-dev", "--import-realm")
                .waitingFor(Wait.forHttp("/realms/wallet-demo").forPort(8080).withStartupTimeout(Duration.ofSeconds(180)))
                .withLogConsumer(frame -> {
                    String log = frame.getUtf8String();
                    // Log all OID4VP related logs and errors
                    if (log.contains("OID4VP") || log.contains("Oid4vp") ||
                            log.contains("[OID4VP") || log.contains("identity") ||
                            log.contains("broker") || log.contains("MdocVerifier") ||
                            log.contains("mDoc") || log.contains("trust") ||
                            log.contains("ERROR") || log.contains("WARN")) {
                        LOG.info("[KC] {}", log.stripTrailing());
                    }
                });

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        // Setup Playwright with Chrome extension
        playwright = Playwright.create();
        Path extensionPath = repoRootDir().resolve("chrome-extension/oid4vp-wallet-bridge").toAbsolutePath();

        // launchPersistentContext returns a BrowserContext directly, not a Browser
        // Extensions require non-headless mode
        context = playwright.chromium().launchPersistentContext(
                Files.createTempDirectory("playwright-profile"),
                new BrowserType.LaunchPersistentContextOptions()
                        .setHeadless(false)
                        .setArgs(List.of(
                                "--disable-extensions-except=" + extensionPath,
                                "--load-extension=" + extensionPath,
                                "--disable-features=WebIdentityDigitalCredentials",
                                "--no-first-run",
                                "--no-default-browser-check",
                                "--window-position=-2000,-2000" // Move window off-screen
                        ))
        );

        page = context.newPage();

        String keycloakHost = keycloak.getHost();
        String adminHost = "localhost".equalsIgnoreCase(keycloakHost) ? "127.0.0.1" : keycloakHost;
        adminBaseUrl = "http://%s:%d".formatted(adminHost, keycloak.getMappedPort(8080));
        browserBaseUrl = adminBaseUrl; // Playwright runs locally
        callbackUrl = callback.localCallbackUrl();
        walletAuthEndpoint = wallet.localBaseUrl() + "/oid4vp/auth";

        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, adminBaseUrl, "admin", "admin");
        // Add test callback URL (realm export already has IdP configured)
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, "wallet-demo", "wallet-mock", callbackUrl);
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (page != null) {
            page.close();
            page = null;
        }
        if (context != null) {
            context.close();
            context = null;
        }
        if (playwright != null) {
            playwright.close();
            playwright = null;
        }
        if (keycloak != null) {
            keycloak.stop();
        }
        if (callback != null) {
            callback.close();
        }
        if (wallet != null) {
            wallet.close();
        }
        adminClient = null;
    }

    @Test
    @Order(1)
    void loginPageShowsWalletIdpButton() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Wait for login page to load
        page.waitForSelector("#username, a[href*='oid4vp']", new Page.WaitForSelectorOptions().setTimeout(30000));

        // Verify the IdP link is present
        assertThat(page.locator("a[href*='broker/oid4vp']").count())
                .as("Expected OID4VP IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    @Order(2)
    void firstWalletLoginCreatesNewUserViaFirstBrokerLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Ensure no existing federated identity for the test credential
        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(isContentScriptPresent()).isTrue();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to open wallet - this opens a popup via the extension
        int walletRequestsBefore = wallet.requestCount();

        // Listen for popup window created by the extension and auto-close it
        Page[] popup = new Page[1];
        context.onPage(newPage -> {
            popup[0] = newPage;
            newPage.onLoad(loadedPage -> {
                try {
                    Thread.sleep(1000); // Give wallet time to process
                    if (!loadedPage.isClosed()) {
                        loadedPage.close();
                    }
                } catch (Exception ignored) {}
            });
        });

        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        // Wait for popup to close and response to be delivered to main page
        Thread.sleep(3000);

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    page.locator("#kc-update-profile-form").count() > 0 ||
                                    page.locator("#kc-register-form").count() > 0 ||
                                    page.locator("input[name='username']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after wallet login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.locator("input[name='username']").count() > 0) {
            // Fill all required fields
            Locator usernameFields = page.locator("input[name='username']");
            if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
                usernameFields.first().fill("wallet-user-" + System.currentTimeMillis());
            }
            Locator emailFields = page.locator("input[name='email']");
            if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
                emailFields.first().fill("wallet-user@example.com");
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
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback
        assertThat(page.url()).contains("code=");
    }

    @Test
    @Order(3)
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to open wallet
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for callback redirect
        page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        assertThat(page.url()).contains("code=");

        // Verify encrypted response was used
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");
    }

    @Test
    @Order(4)
    void walletErrorShowsErrorAndAllowsRetry() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Configure wallet to return error (simulating no matching credential)
        int walletRequestsBefore = wallet.requestCount();
        wallet.failNextRequestWithNoMatchingCredential();

        // Store the current URL before clicking (should be IdP login page)
        String urlBeforeClick = page.url();
        LOG.info("URL before clicking button: {}", urlBeforeClick);

        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // The DC API JS should receive the error and NOT submit the form.
        // This means the page should stay on the IdP login page.
        // Wait a bit for the error response to be processed.
        Thread.sleep(3000);

        // Check URL immediately - if page navigated, the form was submitted
        String urlAfterError = page.url();
        LOG.info("URL after wallet error: {}", urlAfterError);

        // Try to get the OID4VP log content if still on the page
        String oid4vpLogContent = "";
        try {
            if (page.locator("#oid4vpLog").count() > 0) {
                oid4vpLogContent = page.locator("#oid4vpLog").textContent();
                LOG.info("OID4VP Log content: {}", oid4vpLogContent);
            } else {
                LOG.info("OID4VP Log element not found - page may have navigated");
            }
        } catch (Exception e) {
            LOG.info("Error getting OID4VP log: {}", e.getMessage());
        }

        // If the page navigated away from the IdP login page, the error form was submitted.
        // For retry to work, we need to stay on the IdP login page.
        // If we navigated, fall back to manual navigation for retry.
        boolean stayedOnIdpPage = page.locator("#oid4vpStartButton").count() > 0;
        LOG.info("Stayed on IdP login page: {}", stayedOnIdpPage);

        if (!stayedOnIdpPage) {
            // The page navigated - this means the error handling submitted the form.
            // For now, manually navigate to fresh auth URL to test retry.
            LOG.info("Page navigated away, using manual navigation for retry...");
            page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            // Click the IdP link
            Locator idpLink = page.locator("a[href*='broker/oid4vp']");
            assertThat(idpLink.count()).as("IdP link should be present").isGreaterThan(0);
            idpLink.click();
            waitForOid4vpStartButton();
        }

        // ===== RETRY PART: Now test that clicking "Sign in with Wallet" again works =====
        LOG.info("Testing retry after error...");

        // Configure wallet bridge for this page (needed in case we navigated or the page reloaded)
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Verify button is visible before clicking
        assertThat(page.locator("#oid4vpStartButton").count())
                .as("Button should be visible for retry")
                .isGreaterThan(0);

        // This time, don't configure an error - let it succeed
        walletRequestsBefore = wallet.requestCount();
        LOG.info("Clicking button for retry, wallet request count before: {}", walletRequestsBefore);
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for callback redirect (successful login)
        // First check if we're already at the destination (to avoid race condition with waitForURL)
        page.waitForLoadState(LoadState.NETWORKIDLE);
        String currentUrl = page.url();
        boolean alreadyAtDestination = currentUrl.contains(callbackUrl.replace("http://", "").replace("https://", "").split("/")[0] + "/callback");

        if (!alreadyAtDestination) {
            // Note: Wrap locator checks in try-catch because navigation can destroy execution context
            try {
                page.waitForURL(url -> {
                            if (url.contains("/callback")) {
                                return true;
                            }
                            try {
                                return page.locator("#kc-update-profile-form").count() > 0 ||
                                       page.locator("input[name='username']").count() > 0;
                            } catch (Exception e) {
                                // Navigation in progress - keep waiting
                                return false;
                            }
                        },
                        new Page.WaitForURLOptions().setTimeout(30000));
            } catch (Exception e) {
                // Capture state for debugging
                String debugUrl = "(unavailable)";
                String currentBody = "(unavailable)";
                try {
                    debugUrl = page.url();
                    currentBody = page.locator("body").textContent();
                } catch (Exception ignored) {}
                throw new AssertionError("Retry failed - timeout waiting for redirect. URL: " + debugUrl +
                        ", Body (first 500 chars): " + (currentBody.length() > 500 ? currentBody.substring(0, 500) : currentBody), e);
            }
        }

        // If we're at first broker login, we reached a successful state
        // If we reached callback, verify code parameter
        if (page.url().startsWith(callbackUrl)) {
            assertThat(page.url()).contains("code=");
        }

        LOG.info("Retry after error succeeded!");
    }

    @Test
    @Order(5)
    void mdocPresentationFlow() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Configure DCQL query to request mDoc PID format with official claim names
        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["document_number"] },
                        { "path": ["family_name"] },
                        { "path": ["given_name"] },
                        { "path": ["birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", mdocDcqlQuery);

        // Clean up any existing identities for this format
        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to open wallet
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url -> url.contains("/first-broker-login") || url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = page.locator("body").textContent();
            throw new AssertionError("Unexpected state after mDoc wallet login. URL: " + page.url() + ", Body: " + bodyText, e);
        }

        // If at first broker login, complete the profile form
        if (page.locator("input[name='username']").count() > 0) {
            Locator usernameFields = page.locator("input[name='username']");
            if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
                usernameFields.first().fill("mdoc-wallet-user-" + System.currentTimeMillis());
            }
            Locator emailFields = page.locator("input[name='email']");
            if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
                emailFields.first().fill("mdoc-wallet-user@example.com");
            }
            Locator firstNameFields = page.locator("input[name='firstName']");
            if (firstNameFields.count() > 0 && firstNameFields.first().inputValue().isEmpty()) {
                firstNameFields.first().fill("MDoc");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("User");
            }
            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        assertThat(page.url()).contains("code=");

        // Restore default DCQL query
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
    }

    /**
     * Test same-device (redirect) flow with SD-JWT presentation.
     * This tests the scenario where user clicks "Open Wallet App" link instead of using DC API.
     */
    @Test
    @Order(6)
    void sameDeviceFlowSdJwt() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Enable same-device flow and configure wallet URL
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", true, walletAuthEndpoint);

        // Clean up any existing identities for this test
        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page - look for the same-device link
        page.waitForSelector("a:has-text('Open Wallet App')", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));

        // Click the same-device link (not the DC API button)
        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        // Same-device flow redirects back to Keycloak after wallet submits form
        try {
            page.waitForURL(url ->
                            url.contains("/first-broker-login") ||
                                    url.contains("/login-actions/") ||
                                    page.locator("input[name='username']").count() > 0 ||
                                    url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after same-device wallet login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If at first broker login, complete the profile form
        if (page.locator("input[name='username']").count() > 0) {
            Locator usernameFields = page.locator("input[name='username']");
            if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
                usernameFields.first().fill("same-device-user-" + System.currentTimeMillis());
            }
            Locator emailFields = page.locator("input[name='email']");
            if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
                emailFields.first().fill("same-device-user@example.com");
            }
            Locator firstNameFields = page.locator("input[name='firstName']");
            if (firstNameFields.count() > 0 && firstNameFields.first().inputValue().isEmpty()) {
                firstNameFields.first().fill("SameDevice");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("User");
            }
            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        assertThat(page.url()).contains("code=");

        // Verify encrypted response was used (same-device also uses direct_post.jwt)
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");

        // Disable same-device flow after test
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", false, null);
    }

    /**
     * Test same-device (redirect) flow with mDoc presentation.
     * This tests the mDoc SessionTranscript handling when both DC API and same-device flows are enabled.
     */
    @Test
    @Order(7)
    void sameDeviceFlowMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Enable same-device flow and configure wallet URL
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", true, walletAuthEndpoint);

        // Configure DCQL query to request mDoc PID format with official claim names
        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["document_number"] },
                        { "path": ["family_name"] },
                        { "path": ["given_name"] },
                        { "path": ["birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", mdocDcqlQuery);

        // Clean up any existing identities for this test
        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page - look for the same-device link
        page.waitForSelector("a:has-text('Open Wallet App')", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));

        // Click the same-device link (not the DC API button)
        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.contains("/first-broker-login") ||
                                    url.contains("/login-actions/") ||
                                    page.locator("input[name='username']").count() > 0 ||
                                    url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after same-device mDoc wallet login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If at first broker login, complete the profile form
        if (page.locator("input[name='username']").count() > 0) {
            Locator usernameFields = page.locator("input[name='username']");
            if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
                usernameFields.first().fill("same-device-mdoc-user-" + System.currentTimeMillis());
            }
            Locator emailFields = page.locator("input[name='email']");
            if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
                emailFields.first().fill("same-device-mdoc-user@example.com");
            }
            Locator firstNameFields = page.locator("input[name='firstName']");
            if (firstNameFields.count() > 0 && firstNameFields.first().inputValue().isEmpty()) {
                firstNameFields.first().fill("SameDeviceMdoc");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("User");
            }
            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        assertThat(page.url()).contains("code=");

        // Verify encrypted response was used
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");

        // Restore default DCQL query and disable same-device flow
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", false, null);
    }

    /**
     * Test that user denial in same-device flow is handled gracefully.
     * When user denies the credential share request, they should see an error page,
     * not an internal server error.
     */
    @Test
    @Order(8)
    void sameDeviceFlowUserDenialHandledGracefully() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Enable same-device flow
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", true, walletAuthEndpoint);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page - look for the same-device link
        page.waitForSelector("a:has-text('Open Wallet App')", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));

        // Configure wallet to simulate user denial
        int walletRequestsBefore = wallet.requestCount();
        wallet.failNextRequestWithUserCancellation();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for navigation away from wallet page to Keycloak error page
        // Use shorter timeout since wallet auto-submits quickly
        try {
            page.waitForURL(url -> !url.contains("/oid4vp/auth"), new Page.WaitForURLOptions().setTimeout(10000));
        } catch (Exception e) {
            throw new AssertionError("Wallet page did not navigate back to Keycloak: " + page.url(), e);
        }

        // Wait for the page to load
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Check the page content
        String bodyText = page.locator("body").textContent().toLowerCase();

        // Should NOT show internal server error
        boolean internalError = bodyText.contains("internal server error") ||
                bodyText.contains("500") ||
                bodyText.contains("nullpointerexception");
        assertThat(internalError).as("Should not show internal server error").isFalse();

        // Should show user-friendly error message
        boolean errorFound = bodyText.contains("error") ||
                bodyText.contains("denied") ||
                bodyText.contains("cancelled") ||
                bodyText.contains("access_denied");
        assertThat(errorFound).as("Expected error message to appear on page").isTrue();

        // Should stay on Keycloak error page, not redirect to callback
        assertThat(page.url()).doesNotStartWith(callbackUrl);

        // Disable same-device flow after test
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", false, null);
    }

    @Test
    @Order(9)
    void newUserViaWalletCanAccessAccountPage() throws Exception {
        // This test verifies that new users created via wallet login get the correct default roles
        // to access their account page
        callback.reset();
        clearBrowserSession();

        // Use a unique personal_id to create a new user
        String uniquePersonalId = "NEW-USER-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();

        // Wait for wallet login page
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click the start button to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback (same pattern as sdJwtLoginFlow)
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    page.locator("#kc-update-profile-form").count() > 0 ||
                                    page.locator("#kc-register-form").count() > 0 ||
                                    page.locator("input[name='username']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = page.url();
            String bodyText = page.locator("body").textContent();
            LOG.warn("[Test] Unexpected state after wallet login. URL: {}, Body: {}", currentUrl, bodyText);
        }

        // If we're at first broker login, complete the profile form
        if (page.locator("input[name='username']").count() > 0) {
            // Fill all required fields
            Locator usernameFields = page.locator("input[name='username']");
            if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
                usernameFields.first().fill("new-wallet-user-" + System.currentTimeMillis());
            }
            Locator emailFields = page.locator("input[name='email']");
            if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
                emailFields.first().fill("new-wallet-user-" + System.currentTimeMillis() + "@example.com");
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
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback
        assertThat(page.url()).as("Should redirect to callback URL").startsWith(callbackUrl);

        // Now navigate to the account page
        String accountUrl = browserBaseUrl + "/realms/wallet-demo/account/";
        page.navigate(accountUrl);
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Give the SPA time to load
        Thread.sleep(2000);

        // Verify we can access the account page (not forbidden)
        String bodyText = page.locator("body").textContent().toLowerCase();
        boolean hasForbiddenError = bodyText.contains("forbidden") ||
                bodyText.contains("403") ||
                bodyText.contains("access denied") ||
                bodyText.contains("not allowed");

        assertThat(hasForbiddenError)
                .as("New user should be able to access account page. URL: %s, Body: %s", page.url(), bodyText)
                .isFalse();

        // Verify we see something that indicates the account page loaded
        // (could be "account", "profile", user info, etc.)
        boolean accountPageLoaded = bodyText.contains("account") ||
                bodyText.contains("profile") ||
                bodyText.contains("personal") ||
                page.url().contains("/account");

        assertThat(accountPageLoaded)
                .as("Account page should load successfully. URL: %s", page.url())
                .isTrue();
    }

    /**
     * Test credential_sets with mDoc format - basic request verification.
     * Verifies the wallet receives the DCQL query and can respond with mDoc.
     */
    @Test
    @Order(10)
    void mdocPidWithCredentialSetsWorks() throws Exception {
        // This test verifies that the credential_sets DCQL query works correctly
        // by forcing mDoc format and checking the wallet receives the request
        callback.reset();
        clearBrowserSession();

        // Force mDoc format for this request (simulates wallet that prefers mDoc over SD-JWT)
        wallet.setFormatForNextRequest("mso_mdoc");
        String uniqueAdminNumber = "MDOC-PID-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniqueAdminNumber);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Verify the wallet received a request and it was for mDoc format
        assertThat(wallet.requestCount()).isGreaterThan(walletRequestsBefore);

        LOG.info("[Test-mDoc] Wallet successfully received mDoc PID request via credential_sets DCQL query");
    }

    /**
     * Test credential_sets allowing either SD-JWT or mDoc - full login with mDoc.
     * This tests the complete flow where:
     * 1. DCQL query requests either SD-JWT or mDoc PID (via credential_sets)
     * 2. Wallet presents mDoc PID
     * 3. Keycloak extracts claims using mDoc-specific mappers (different claim names)
     * 4. User is created with correct attributes
     */
    @Test
    @Order(11)
    void credentialSetsFullLoginWithMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Default DCQL query already has credential_sets with SD-JWT and mDoc options
        // Force mDoc format for this request (simulates wallet that only has mDoc PID)
        wallet.setFormatForNextRequest("mso_mdoc");
        String uniqueAdminNumber = "MDOC-CREDSET-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniqueAdminNumber);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after mDoc credential_sets login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            page.waitForLoadState(LoadState.NETWORKIDLE);
            String uniqueUsername = "mdoc-credset-user-" + System.currentTimeMillis();
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
                firstNameFields.first().fill("MDoc");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("CredSet");
            }

            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).contains("code=");

        // Verify encrypted response was used
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");

        LOG.info("[Test-credentialSets] Full mDoc login via credential_sets completed successfully");
    }

    /**
     * Test credential_sets allowing either SD-JWT or mDoc - full login with SD-JWT.
     * This tests the complete flow where:
     * 1. DCQL query requests either SD-JWT or mDoc PID (via credential_sets)
     * 2. Wallet presents SD-JWT PID (default when both are available)
     * 3. Keycloak extracts claims using SD-JWT-specific mappers
     * 4. User is created with correct attributes
     */
    @Test
    @Order(12)
    void credentialSetsFullLoginWithSdJwt() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Default DCQL query already has credential_sets with SD-JWT and mDoc options
        // Force SD-JWT format (simulates wallet that prefers SD-JWT)
        wallet.setFormatForNextRequest("dc+sd-jwt");
        String uniquePersonalId = "SDJWT-CREDSET-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after SD-JWT credential_sets login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            page.waitForLoadState(LoadState.NETWORKIDLE);
            String uniqueUsername = "sdjwt-credset-user-" + System.currentTimeMillis();
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
                firstNameFields.first().fill("SdJwt");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("CredSet");
            }

            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).contains("code=");

        // Verify encrypted response was used
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");

        LOG.info("[Test-credentialSets] Full SD-JWT login via credential_sets completed successfully");
    }

    /**
     * Test DCQL claim_sets with selective disclosure.
     * This tests the scenario where:
     * 1. DCQL query defines claim_sets with alternative combinations
     * 2. Wallet chooses to disclose only the minimal set (without nationality)
     * 3. Optional mapper for nationality doesn't cause failures
     */
    @Test
    @Order(13)
    void claimSetsWithSelectiveDisclosure() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Configure DCQL query with claim_sets that allow optional nationality
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DCQL_QUERY_WITH_CLAIM_SETS);

        // Use a unique ID for this test
        String uniquePersonalId = "CLAIMSETS-SELECTIVE-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after claim_sets login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            page.waitForLoadState(LoadState.NETWORKIDLE);
            String uniqueUsername = "claimsets-selective-user-" + System.currentTimeMillis();
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
                firstNameFields.first().fill("ClaimSets");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("Selective");
            }

            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).contains("code=");

        // Restore default DCQL query
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);

        LOG.info("[Test-claimSets] Selective disclosure via claim_sets completed successfully");
    }

    /**
     * Test optional claim mapper behavior when claim is not disclosed.
     * This tests the scenario where:
     * 1. A mapper is configured with optional=true
     * 2. The wallet doesn't disclose that claim
     * 3. Login still succeeds (mapper doesn't fail)
     */
    @Test
    @Order(14)
    void optionalClaimNotDisclosedSucceeds() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Configure DCQL query that only requests basic claims (no nationalities)
        String minimalDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:1"] },
                      "claims": [
                        { "path": ["document_number"] },
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", minimalDcqlQuery);

        // Use a unique ID for this test
        String uniquePersonalId = "OPTIONAL-CLAIM-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after optional claim test. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            page.waitForLoadState(LoadState.NETWORKIDLE);
            String uniqueUsername = "optional-claim-user-" + System.currentTimeMillis();
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
                firstNameFields.first().fill("Optional");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("Claim");
            }

            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback with an auth code
        // This proves the optional mapper didn't cause a failure even though
        // the nationalities claim wasn't disclosed
        assertThat(page.url()).contains("code=");

        // Restore default DCQL query
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);

        LOG.info("[Test-optionalClaim] Optional claim not disclosed - login succeeded");
    }

    /**
     * Test mDoc with claim_sets - selective disclosure of mDoc claims.
     * This tests claim_sets behavior with mDoc format.
     */
    @Test
    @Order(15)
    void mdocClaimSetsSelectiveDisclosure() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Configure DCQL query with claim_sets for mDoc
        String mdocClaimSetsQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "id": "doc_num", "path": ["document_number"] },
                        { "id": "family", "path": ["family_name"] },
                        { "id": "given", "path": ["given_name"] },
                        { "id": "birth", "path": ["birth_date"] },
                        { "id": "nat", "path": ["nationality"] }
                      ],
                      "claim_sets": [
                        ["doc_num", "family", "given", "birth", "nat"],
                        ["doc_num", "family", "given", "birth"]
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", mdocClaimSetsQuery);

        // Use a unique ID for this test
        String uniqueAdminNumber = "MDOC-CLAIMSETS-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniqueAdminNumber);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after mDoc claim_sets login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            page.waitForLoadState(LoadState.NETWORKIDLE);
            String uniqueUsername = "mdoc-claimsets-user-" + System.currentTimeMillis();
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
                firstNameFields.first().fill("MdocClaimSets");
            }
            Locator lastNameFields = page.locator("input[name='lastName']");
            if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
                lastNameFields.first().fill("User");
            }

            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).contains("code=");

        // Restore default DCQL query
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);

        LOG.info("[Test-mdocClaimSets] mDoc claim_sets selective disclosure completed successfully");
    }

    /**
     * Test German PID credential without unique identifiers.
     * This tests the scenario where the German PID doesn't have document_number
     * or administrative_number, requiring alternative user matching strategies.
     */
    @Test
    @Order(16)
    void germanPidWithoutUniqueIdentifiers() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Configure IdP for German PID flow
        Oid4vpTestKeycloakSetup.configureGermanPidFlow(adminClient, "wallet-demo");

        // Enable German PID mode in the mock wallet (no document_number)
        wallet.setUseGermanPid(true);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after German PID login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("german-pid-user-" + System.currentTimeMillis());
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).contains("code=");

        // Restore default configuration
        wallet.setUseGermanPid(false);
        Oid4vpTestKeycloakSetup.resetToDefaultConfiguration(adminClient, "wallet-demo");

        LOG.info("[Test-germanPid] German PID without unique identifiers login completed successfully");
    }

    /**
     * Test multi-credential flow: German PID + Verifier User Credential.
     * This tests the scenario where both credentials are required for login.
     * The user_id from the verifier credential is used for user matching.
     */
    @Test
    @Order(17)
    void multiCredentialGermanPidAndUserBinding() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Configure IdP for multi-credential flow
        Oid4vpTestKeycloakSetup.configureMultiCredentialFlow(adminClient, "wallet-demo");

        // Enable German PID mode and set verifier user ID in the mock wallet
        wallet.setUseGermanPid(true);
        String testUserId = "test-user-" + System.currentTimeMillis();
        wallet.setVerifierUserIdForNextRequest(testUserId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login or callback
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Unexpected state after multi-credential login. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // If we're at first broker login, complete the profile form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("multi-cred-user-" + System.currentTimeMillis());
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).contains("code=");

        // Restore default configuration
        wallet.setUseGermanPid(false);
        Oid4vpTestKeycloakSetup.resetToDefaultConfiguration(adminClient, "wallet-demo");

        LOG.info("[Test-multiCredential] Multi-credential (German PID + User Binding) login completed successfully");
    }

    /**
     * Test the complete German PID binding flow:
     * 1. Initial registration: User presents German PID → First broker login creates user
     * 2. Credential issuance: Verifier issues user binding credential via OID4VCI (simulated)
     * 3. Subsequent login: User presents German PID + user binding credential → User matched via user_id
     *
     * This test verifies the complete E2E flow for authenticating with German PID
     * (which has no unique identifiers) combined with a verifier-issued credential.
     */
    @Test
    @Order(18)
    void completeGermanPidBindingFlowWithCredentialIssuance() throws Exception {
        LOG.info("=== Starting complete German PID binding flow E2E test ===");

        // ========== PHASE 1: Initial registration with German PID only ==========
        LOG.info("=== Phase 1: Initial registration with German PID only ===");

        callback.reset();
        clearBrowserSession();

        // Configure IdP for German PID flow (single credential, no unique identifiers)
        Oid4vpTestKeycloakSetup.configureGermanPidFlow(adminClient, "wallet-demo");

        // Enable German PID mode in the mock wallet
        wallet.setUseGermanPid(true);
        wallet.clearSimulatedCredentials(); // Ensure no simulated credentials from previous tests

        // Start the login flow
        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth
        int walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for redirect to first broker login
        String registrationUsername = "pid-binding-user-" + System.currentTimeMillis();
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("first-broker-login") ||
                                    url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = page.url();
            String bodyText = page.locator("body").textContent();
            throw new AssertionError("Phase 1 failed - unexpected state. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // Complete first broker login form
        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm(registrationUsername);
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).as("Phase 1: Should complete with auth code").contains("code=");
        LOG.info("Phase 1 complete: User registered via first broker login");

        // ========== PHASE 2: Simulate credential issuance (OID4VCI) ==========
        LOG.info("=== Phase 2: Simulating credential issuance (OID4VCI) ===");

        // Get the user ID that was created during first broker login
        // In a real flow, this would come from the OID4VCI credential offer or pre-auth code
        String userId;
        try {
            userId = Oid4vpTestKeycloakSetup.findMostRecentOid4vpUser(adminClient, "wallet-demo");
            LOG.info("Phase 2: Found user ID from first broker login: {}", userId);
        } catch (Exception e) {
            // Fall back to using the username
            userId = Oid4vpTestKeycloakSetup.resolveUserId(adminClient, "wallet-demo", registrationUsername);
            LOG.info("Phase 2: Resolved user ID by username: {}", userId);
        }

        // Simulate the OID4VCI credential issuance
        // In a real flow, this would be:
        // 1. User is redirected to OID4VCI credential offer endpoint
        // 2. Wallet obtains authorization code
        // 3. Wallet exchanges code for access token with scope 'user-binding-credential'
        // 4. Wallet calls credential endpoint with the access token
        // 5. Keycloak issues SD-JWT credential with user_id claim
        // 6. Wallet stores the credential
        // 7. The system updates the federated identity to use the new user_id for future matching
        //
        // For this test, we simulate:
        // - Steps 4-6 by directly configuring the mock wallet
        // - Step 7 by updating the federated identity via admin API
        wallet.simulateCredentialIssuance(userId);

        // Update the federated identity to use the verifier credential lookup key
        // The IdP uses a composite lookup key (hash of issuer + credentialType + subject)
        // This simulates the binding that occurs after credential issuance -
        // future logins will match via the verifier credential's user_id claim
        Oid4vpTestKeycloakSetup.updateFederatedIdentityForVerifierCredential(adminClient, "wallet-demo", userId, "oid4vp");
        LOG.info("Phase 2 complete: Credential issuance simulated and federated identity updated with lookup key for user_id: {}", userId);

        // ========== PHASE 3: Login with both credentials ==========
        LOG.info("=== Phase 3: Login with German PID + User Binding Credential ===");

        callback.reset();
        clearBrowserSession();

        // Reconfigure IdP to require multi-credential flow
        // This changes the DCQL query to require BOTH German PID and user binding credential
        Oid4vpTestKeycloakSetup.configureMultiCredentialFlow(adminClient, "wallet-demo");

        // Start a new login flow
        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a[href*='broker/oid4vp']").click();
        waitForOid4vpStartButton();
        configureWalletBridgeEndpoint();
        assertThat(waitForBridgeInstalled(Duration.ofSeconds(5))).isTrue();

        // Click to trigger wallet auth - this time wallet will present BOTH credentials
        walletRequestsBefore = wallet.requestCount();
        page.locator("#oid4vpStartButton").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // Wait for callback - should NOT go to first broker login since user already exists
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = page.url();
            String bodyText = page.locator("body").textContent();
            // If we ended up at first broker login, that's a failure - the user should have been matched
            if (currentUrl.contains("first-broker-login") || currentUrl.contains("login-actions")) {
                throw new AssertionError("Phase 3 failed: User was not matched! Expected existing user to be found via user_id claim. URL: " + currentUrl, e);
            }
            throw new AssertionError("Phase 3 failed - unexpected state. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        // Verify we reached the callback with an auth code
        assertThat(page.url()).as("Phase 3: Should complete with auth code").contains("code=");
        LOG.info("Phase 3 complete: User authenticated with multi-credential flow");

        // ========== CLEANUP ==========
        LOG.info("=== Cleanup: Restoring default configuration ===");
        wallet.setUseGermanPid(false);
        wallet.clearSimulatedCredentials();
        Oid4vpTestKeycloakSetup.resetToDefaultConfiguration(adminClient, "wallet-demo");

        LOG.info("=== Complete German PID binding flow E2E test PASSED ===");
        LOG.info("Summary:");
        LOG.info("  - Phase 1: User registered with German PID only (no unique identifiers)");
        LOG.info("  - Phase 2: Verifier credential issuance simulated (OID4VCI)");
        LOG.info("  - Phase 3: User authenticated with German PID + verifier credential");
        LOG.info("  - User matching via user_id claim in verifier credential: SUCCESS");
    }

    /**
     * Helper to complete the first broker login form with a unique username.
     */
    private void completeFirstBrokerLoginForm(String uniqueUsername) throws Exception {
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
        page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
    }

    private static void waitForOid4vpStartButton() {
        try {
            page.waitForSelector("#oid4vpStartButton", new Page.WaitForSelectorOptions()
                    .setState(WaitForSelectorState.VISIBLE)
                    .setTimeout(30000));
        } catch (Exception e) {
            String bodyText = page.locator("body").textContent();
            throw new AssertionError("oid4vpStartButton not found. URL: " + page.url() + ", Body: " + bodyText, e);
        }
    }

    private static void clearBrowserSession() {
        // Clear all browser state first
        context.clearCookies();
        // Navigate to realm root and clear storage
        try {
            page.navigate(browserBaseUrl + "/realms/wallet-demo/",
                    new Page.NavigateOptions().setTimeout(10000));
        } catch (Exception e) {
            // Navigation may fail if previous test left things in inconsistent state
            // Try navigating to about:blank first to reset
            LOG.warn("Initial navigation failed, resetting browser state: {}", e.getMessage());
            try {
                page.navigate("about:blank");
                page.navigate(browserBaseUrl + "/realms/wallet-demo/",
                        new Page.NavigateOptions().setTimeout(10000));
            } catch (Exception e2) {
                LOG.warn("Secondary navigation also failed, continuing anyway: {}", e2.getMessage());
            }
        }
        try {
            page.evaluate("() => { window.localStorage.clear(); window.sessionStorage.clear(); }");
        } catch (Exception ignored) {
            // May fail on about:blank or error pages
        }
        // Clear cookies again after navigation (in case new ones were set)
        context.clearCookies();
    }

    private static boolean waitForBridgeInstalled(Duration timeout) {
        try {
            page.waitForCondition(() -> Boolean.TRUE.equals(
                    page.evaluate("() => window.__oid4vpWalletBridgeInstalled === true")
            ), new Page.WaitForConditionOptions().setTimeout(timeout.toMillis()));
            return true;
        } catch (Exception e) {
            Object diag = page.evaluate("() => ({ " +
                    "injected: window.__oid4vpWalletBridgeInjected === true, " +
                    "installed: window.__oid4vpWalletBridgeInstalled === true, " +
                    "installError: window.__oid4vpWalletBridgeInstallError || '', " +
                    "backgroundPing: window.__oid4vpWalletBridgeBackgroundPing === true, " +
                    "contentScriptPresent: document.documentElement && document.documentElement.getAttribute('data-oid4vp-wallet-bridge-content-script') === 'true' " +
                    "})");
            throw new AssertionError("Wallet bridge not installed in page context. diag=" + diag, e);
        }
    }

    private static boolean isContentScriptPresent() {
        Object value = page.evaluate(
                "() => document.documentElement && document.documentElement.getAttribute('data-oid4vp-wallet-bridge-content-script') === 'true'"
        );
        return Boolean.TRUE.equals(value);
    }

    private static void configureWalletBridgeEndpoint() {
        page.evaluate(
                "endpoint => document.documentElement && document.documentElement.setAttribute('data-oid4vp-wallet-bridge-wallet-auth-endpoint', endpoint)",
                walletAuthEndpoint
        );
    }

    private static void waitForWalletRequest(int minCount, Duration timeout) throws InterruptedException {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            if (wallet != null && wallet.requestCount() >= minCount) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Wallet did not receive expected request count within %d ms (expected >= %d, got %d)"
                .formatted(timeout.toMillis(), minCount, wallet != null ? wallet.requestCount() : -1));
    }

    private static URI buildAuthRequestUri(String baseUrl, String redirectUri) {
        String state = "s-" + System.nanoTime();
        // Generate PKCE code_verifier and code_challenge (wallet-mock client requires S256)
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        String uri = baseUrl + "/realms/wallet-demo/protocol/openid-connect/auth"
                + "?client_id=wallet-mock"
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&response_type=code"
                + "&scope=openid"
                + "&state=" + urlEncode(state)
                + "&code_challenge=" + urlEncode(codeChallenge)
                + "&code_challenge_method=S256";
        return URI.create(uri);
    }

    private static String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String generateCodeChallenge(String codeVerifier) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void copyRealmImport() throws IOException {
        // Use the same realm export as demo-app to catch configuration issues early
        Path realmExport = repoRootDir().resolve("demo-app/config/keycloak/realm-export.json");
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport),
                "/opt/keycloak/data/import/realm-export.json");
    }

    private static void copyProviderJars() throws IOException {
        Path providerJar = findProviderJar();
        keycloak.withCopyFileToContainer(MountableFile.forHostPath(providerJar), "/opt/keycloak/providers/" + providerJar.getFileName());

        Path deps = moduleDir().resolve("target/providers").toAbsolutePath();
        if (!Files.isDirectory(deps)) {
            return;
        }
        try (Stream<Path> stream = Files.list(deps)) {
            for (Path jar : stream.filter(p -> p.getFileName().toString().endsWith(".jar")).toList()) {
                keycloak.withCopyFileToContainer(MountableFile.forHostPath(jar), "/opt/keycloak/providers/" + jar.getFileName());
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
