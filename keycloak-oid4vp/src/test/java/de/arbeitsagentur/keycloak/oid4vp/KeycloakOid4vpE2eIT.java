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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for OID4VP Identity Provider flow.
 * Tests the "Sign in with Wallet" functionality using same-device, native wallet, and cross-device flows.
 * <p>
 * All tests run in headless mode and do not require a browser extension.
 * Same-device flow uses redirect to mock wallet, cross-device uses QR code + SSE.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakOid4vpE2eIT {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpE2eIT.class);

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
    private static Browser browser;
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
                    if (log.contains("OID4VP") || log.contains("REQUEST-STORE") || log.contains("REDIRECT-FLOW")
                            || log.contains("ERROR") || log.contains("WARN")) {
                        LOG.info("[KC] {}", log.stripTrailing());
                    }
                });

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        // Setup Playwright in headless mode (no extension needed)
        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
        context = browser.newContext();
        page = context.newPage();

        String keycloakHost = keycloak.getHost();
        String adminHost = "localhost".equalsIgnoreCase(keycloakHost) ? "127.0.0.1" : keycloakHost;
        adminBaseUrl = "http://%s:%d".formatted(adminHost, keycloak.getMappedPort(8080));
        browserBaseUrl = adminBaseUrl;
        callbackUrl = callback.localCallbackUrl();
        walletAuthEndpoint = wallet.localBaseUrl() + "/oid4vp/auth";

        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, adminBaseUrl, "admin", "admin");
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, "wallet-demo", "wallet-mock", callbackUrl);

        // Enable same-device flow for all tests
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", true, walletAuthEndpoint);
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
        if (browser != null) {
            browser.close();
            browser = null;
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

        page.waitForSelector("#username, a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-oid4vp").count())
                .as("Expected OID4VP IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    @Order(2)
    void firstWalletLoginCreatesNewUserViaFirstBrokerLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        waitForFirstBrokerLoginOrCallback();

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

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        assertThat(page.url()).contains("code=");

        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");
    }

    @Test
    @Order(4)
    void walletErrorShowsErrorAndAllowsRetry() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        // Configure wallet to return error (simulating no matching credential)
        int walletRequestsBefore = wallet.requestCount();
        wallet.failNextRequestWithUserCancellation();

        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // In same-device flow, Keycloak returns a JSON error to the wallet (no redirect_uri
        // per OID4VP spec), so the mock wallet returns an error page to the browser.
        // Verify the wallet received and processed the error, then the user would navigate back.
        Thread.sleep(1000); // Give wallet time to process the error
        assertThat(wallet.getLastPostResponseCode()).isGreaterThanOrEqualTo(400);

        // Retry: navigate to fresh auth URL (simulating user going back to login)
        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        try {
            page.waitForURL(url -> url.contains("/callback") || url.contains("first-broker-login") || url.contains("login-actions"),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String debugUrl = "(unavailable)";
            String currentBody = "(unavailable)";
            try {
                debugUrl = page.url();
                currentBody = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Retry failed. URL: " + debugUrl +
                    ", Body: " + (currentBody.length() > 500 ? currentBody.substring(0, 500) : currentBody), e);
        }

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

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "document_number"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", mdocDcqlQuery);

        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("mdoc-wallet-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
    }

    @Test
    @Order(6)
    void sameDeviceFlowMdoc() throws Exception {
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

        try {
            Oid4vpTestKeycloakSetup.removeAllFederatedIdentities(adminClient, "wallet-demo", "test");
        } catch (Exception ignored) {
        }

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("same-device-mdoc-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
    }

    @Test
    @Order(7)
    void newUserViaWalletCanAccessAccountPage() throws Exception {
        callback.reset();
        clearBrowserSession();

        String uniquePersonalId = "NEW-USER-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("new-wallet-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).as("Should redirect to callback URL").startsWith(callbackUrl);

        // Now navigate to the account page
        String accountUrl = browserBaseUrl + "/realms/wallet-demo/account/";
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
    @Order(8)
    void credentialSetsFullLoginWithMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        wallet.setFormatForNextRequest("mso_mdoc");
        String uniqueAdminNumber = "MDOC-CREDSET-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniqueAdminNumber);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("mdoc-credset-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");
    }

    @Test
    @Order(9)
    void credentialSetsFullLoginWithSdJwt() throws Exception {
        callback.reset();
        clearBrowserSession();

        wallet.setFormatForNextRequest("dc+sd-jwt");
        String uniquePersonalId = "SDJWT-CREDSET-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("sdjwt-credset-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
        assertThat(wallet.lastResponseMode()).isEqualToIgnoringCase("direct_post.jwt");
    }

    @Test
    @Order(10)
    void claimSetsWithSelectiveDisclosure() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DCQL_QUERY_WITH_CLAIM_SETS);

        String uniquePersonalId = "CLAIMSETS-SELECTIVE-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("claimsets-selective-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
    }

    @Test
    @Order(11)
    void optionalClaimNotDisclosedSucceeds() throws Exception {
        callback.reset();
        clearBrowserSession();

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

        String uniquePersonalId = "OPTIONAL-CLAIM-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniquePersonalId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("optional-claim-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
    }

    @Test
    @Order(12)
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

        String uniqueAdminNumber = "MDOC-CLAIMSETS-" + System.currentTimeMillis();
        wallet.setPersonalIdForNextRequest(uniqueAdminNumber);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("mdoc-claimsets-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo",
                Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
    }

    @Test
    @Order(13)
    void germanPidWithoutUniqueIdentifiers() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureGermanPidFlow(adminClient, "wallet-demo");
        wallet.setUseGermanPid(true);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("german-pid-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");

        wallet.setUseGermanPid(false);
        Oid4vpTestKeycloakSetup.resetToDefaultConfiguration(adminClient, "wallet-demo");
    }

    @Test
    @Order(14)
    void multiCredentialGermanPidAndUserBinding() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureMultiCredentialFlow(adminClient, "wallet-demo");
        wallet.setUseGermanPid(true);
        String testUserId = "test-user-" + System.currentTimeMillis();
        wallet.setVerifierUserIdForNextRequest(testUserId);

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        waitForFirstBrokerLoginOrCallback();

        if (page.url().contains("first-broker-login") || page.url().contains("login-actions")) {
            completeFirstBrokerLoginForm("multi-cred-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");

        wallet.setUseGermanPid(false);
        Oid4vpTestKeycloakSetup.resetToDefaultConfiguration(adminClient, "wallet-demo");
    }

    @Test
    @Order(15)
    void sameDeviceFlowUserDenialHandledGracefully() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        waitForOpenWalletLink();

        int walletRequestsBefore = wallet.requestCount();
        wallet.failNextRequestWithUserCancellation();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(10));

        // In same-device flow, Keycloak returns a JSON error (no redirect_uri per OID4VP spec).
        // The mock wallet cannot redirect the browser back, so it returns an error page.
        // Verify the wallet received the error and user was NOT authenticated.
        Thread.sleep(1000); // Give wallet time to process the error
        assertThat(wallet.getLastPostResponseCode()).isGreaterThanOrEqualTo(400);
        assertThat(page.url()).doesNotStartWith(callbackUrl);
    }

    /**
     * Test same-device flow: first login with native wallet simulation.
     * Browser extracts wallet URL, calls wallet via HTTP (simulating native app),
     * then navigates to the complete-auth URL.
     */
    @Test
    @Order(16)
    void sameDeviceNativeWalletFirstLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        wallet.setUseGermanPid(false);
        wallet.clearSimulatedCredentials();

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        assertThat(walletUrl)
                .as("Wallet URL should not be empty. Page URL: %s", page.url())
                .isNotEmpty();

        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpResponse<String> walletResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(walletUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        LOG.info("[Test] Wallet response status: {}, body length: {}", walletResponse.statusCode(), walletResponse.body().length());

        String redirectUri;
        if (walletResponse.statusCode() == 302 || walletResponse.statusCode() == 303) {
            redirectUri = walletResponse.headers().firstValue("Location").orElse(null);
            LOG.info("[Test] Wallet returned redirect to: {}", redirectUri);
        } else {
            LOG.warn("[Test] Unexpected wallet response status: {}", walletResponse.statusCode());
            redirectUri = null;
        }

        assertThat(redirectUri)
                .as("Wallet should return redirect to complete-auth URL")
                .isNotNull()
                .isNotEmpty();

        assertThat(redirectUri)
                .as("Redirect should go through the complete-auth endpoint")
                .contains("complete-auth?state=");

        page.navigate(redirectUri);
        page.waitForLoadState(LoadState.NETWORKIDLE);

        assertThat(page.locator("input[name='firstName']").count())
                .as("First-broker-login form should be visible. Current URL: " + page.url())
                .isGreaterThan(0);

        String firstName = page.locator("input[name='firstName']").first().inputValue();
        String lastName = page.locator("input[name='lastName']").first().inputValue();

        assertThat(firstName).as("firstName should be pre-filled from credential").isNotEmpty();
        assertThat(lastName).as("lastName should be pre-filled from credential").isNotEmpty();

        Locator usernameFields = page.locator("input[name='username']");
        if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
            usernameFields.first().fill("same-device-native-" + System.currentTimeMillis());
        }
        Locator emailFields = page.locator("input[name='email']");
        if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
            emailFields.first().fill("same-device-native@example.com");
        }

        page.locator("input[type='submit'], button[type='submit']").first().click();
        page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));

        assertThat(page.url()).contains("code=");
    }

    /**
     * Test same-device flow: second login (existing user) with native wallet.
     * Verifies SSE does NOT race with the wallet redirect for same-device.
     */
    @Test
    @Order(17)
    void sameDeviceNativeWalletSecondLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        String loginPageUrl = page.url();

        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpResponse<String> walletResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(walletUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(walletResponse.statusCode()).as("Wallet should return 302 redirect").isIn(302, 303);

        String redirectUri = walletResponse.headers().firstValue("Location").orElse(null);
        assertThat(redirectUri).as("Wallet redirect should contain complete-auth URL").isNotNull().isNotEmpty();

        // Wait 3 seconds to verify SSE does NOT navigate the browser
        Thread.sleep(3000);
        assertThat(page.url())
                .as("SSE should NOT navigate the browser for same-device flow")
                .isEqualTo(loginPageUrl);

        page.navigate(redirectUri);
        page.waitForLoadState(LoadState.NETWORKIDLE);

        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) || url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            LOG.warn("[Test] Did not reach callback URL. Current URL: {}, Body: {}",
                    page.url(), page.locator("body").textContent());
        }

        assertThat(page.url())
                .as("Second login should reach callback with auth code")
                .satisfiesAnyOf(
                        url -> assertThat(url).contains("code="),
                        url -> assertThat(url).startsWith(callbackUrl)
                );
    }

    /**
     * Test cross-device flow: first login (new user) via QR code.
     */
    @Test
    @Order(18)
    void crossDeviceFirstLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        wallet.setUseGermanPid(false);
        wallet.clearSimulatedCredentials();

        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, "wallet-demo", Oid4vpTestKeycloakSetup.DEFAULT_DCQL_QUERY);
        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, "wallet-demo", true);

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, "wallet-demo");

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();

        page.waitForSelector("img[alt='QR Code for wallet login']", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));

        String crossDeviceWalletUrl = (String) page.evaluate(
                "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");
        assertThat(crossDeviceWalletUrl).as("Cross-device wallet URL should be present").isNotEmpty();

        String walletQuery = crossDeviceWalletUrl.contains("?")
                ? crossDeviceWalletUrl.substring(crossDeviceWalletUrl.indexOf("?"))
                : "";
        String mockWalletUrl = wallet.localBaseUrl() + "/oid4vp/auth" + walletQuery;

        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpResponse<String> walletResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(mockWalletUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(walletResponse.statusCode())
                .as("Cross-device wallet should return 200. Body: " + walletResponse.body())
                .isEqualTo(200);

        try {
            page.waitForURL(url ->
                            url.contains("/complete-auth") ||
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
            throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + currentUrl +
                    ", Body: " + bodyText, e);
        }

        page.waitForLoadState(LoadState.NETWORKIDLE);

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("cross-device-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    /**
     * Test cross-device flow: second login (existing user).
     */
    @Test
    @Order(19)
    void crossDeviceSecondLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        page.navigate(buildAuthRequestUri(browserBaseUrl, callbackUrl).toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        page.waitForSelector("img[alt='QR Code for wallet login']", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));

        String crossDeviceWalletUrl = (String) page.evaluate(
                "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");

        String walletQuery = crossDeviceWalletUrl.contains("?")
                ? crossDeviceWalletUrl.substring(crossDeviceWalletUrl.indexOf("?"))
                : "";
        String mockWalletUrl = wallet.localBaseUrl() + "/oid4vp/auth" + walletQuery;

        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpResponse<String> walletResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(mockWalletUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(walletResponse.statusCode()).as("Cross-device wallet should return 200").isEqualTo(200);

        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) || url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Cross-device second login: SSE did not navigate to callback. URL: " +
                    currentUrl + ", Body: " + bodyText, e);
        }

        assertThat(page.url())
                .as("Second cross-device login should reach callback with auth code")
                .satisfiesAnyOf(
                        url -> assertThat(url).contains("code="),
                        url -> assertThat(url).startsWith(callbackUrl)
                );

        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, "wallet-demo", false, null);
        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, "wallet-demo", false);
    }

    // ===== Helper Methods =====

    private static void waitForOpenWalletLink() {
        page.waitForSelector("a:has-text('Open Wallet App')", new Page.WaitForSelectorOptions()
                .setState(WaitForSelectorState.VISIBLE)
                .setTimeout(30000));
    }

    private static void waitForFirstBrokerLoginOrCallback() {
        try {
            page.waitForURL(url ->
                            url.startsWith(callbackUrl) ||
                                    url.contains("/first-broker-login") ||
                                    url.contains("/login-actions/") ||
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
    }

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

    private static void clearBrowserSession() {
        context.clearCookies();
        try {
            page.navigate(browserBaseUrl + "/realms/wallet-demo/",
                    new Page.NavigateOptions().setTimeout(10000));
        } catch (Exception e) {
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
        }
        context.clearCookies();
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
