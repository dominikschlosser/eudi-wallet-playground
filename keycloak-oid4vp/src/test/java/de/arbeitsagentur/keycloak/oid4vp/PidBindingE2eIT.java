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
import com.microsoft.playwright.options.WaitUntilState;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for the German PID Binding Identity Provider.
 * Tests the two-phase authentication flow:
 * <ol>
 *   <li>First-time users: PID only -> username/password -> credential issuance</li>
 *   <li>Returning users: PID + ba-login-credential -> direct login</li>
 * </ol>
 * <p>
 * All tests run in headless mode using the same-device (redirect) flow.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PidBindingE2eIT {

    private static final Logger LOG = LoggerFactory.getLogger(PidBindingE2eIT.class);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String REALM = "pid-binding-demo";
    private static final String CLIENT_ID = "demo-app";
    private static final String IDP_ALIAS = "german-pid";
    private static final String TEST_USER = "test";
    private static final String TEST_PASSWORD = "test";

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

    // Store the user ID from the first login
    private static String issuedUserId;
    // OID4VCI client for receiving credentials
    private static Oid4vciTestClient oid4vciClient;
    // The actual credential issued via OID4VCI
    private static String issuedCredential;

    @BeforeAll
    static void setUp() throws Exception {
        wallet = new Oid4vpTestDcApiMockWalletServer(OBJECT_MAPPER, "localhost");
        callback = new Oid4vpTestCallbackServer();

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.0")
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withEnv("KC_PROXY_HEADERS", "xforwarded")
                .withExposedPorts(8080)
                // Run build first to properly discover providers, then start-dev
                .withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("/bin/sh"))
                .withCommand("-c",
                        "/opt/keycloak/bin/kc.sh build --features=oid4vc-vci && " +
                        "/opt/keycloak/bin/kc.sh start-dev --import-realm --features=oid4vc-vci")
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofSeconds(180)))
                .withLogConsumer(frame -> {
                    String log = frame.getUtf8String();
                    if (log.contains("PID") || log.contains("pid") ||
                            log.contains("binding") || log.contains("ERROR") ||
                            log.contains("WARN") || log.contains("OID4VP") ||
                            log.contains("VERIFIER") || log.contains("x5c") ||
                            log.contains("OID4VCI") || log.contains("oid4vc") ||
                            log.contains("credential-offer") || log.contains("CREDENTIAL") ||
                            log.contains("Keycloak") || log.contains("quarkus")) {
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
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, REALM, CLIENT_ID, callbackUrl);

        // Configure wallet for German PID mode (no unique identifiers)
        wallet.setUseGermanPid(true);

        // Enable same-device flow for the german-pid IdP
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, REALM, IDP_ALIAS, true, walletAuthEndpoint);

        // Initialize OID4VCI client for credential issuance
        oid4vciClient = new Oid4vciTestClient(OBJECT_MAPPER);

        // Share the holder key between OID4VCI client and mock wallet
        wallet.setHolderKey(oid4vciClient.getHolderKey());
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
    void loginPageShowsGermanPidIdpButton() throws Exception {
        callback.reset();
        clearBrowserSession();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.waitForSelector("#username, a[href*='german-pid']", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-german-pid").count())
                .as("Expected German PID IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    @Order(2)
    void firstTimeUserWithPidOnlyRequiresUsernamePassword() throws Exception {
        callback.reset();
        clearBrowserSession();
        wallet.clearSimulatedCredentials();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Click the IdP link
        page.locator("a#social-german-pid").click();

        // Wait for wallet login page with same-device link
        waitForOpenWalletLink();

        // Click to start wallet flow via same-device redirect
        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        // Wait for redirect to first broker login (username/password form)
        try {
            page.waitForURL(url ->
                            url.contains("first-broker-login") ||
                                    url.contains("login-actions") ||
                                    page.locator("input[name='username']").count() > 0 ||
                                    page.locator("input[name='password']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = "(unavailable)";
            String bodyText = "(unavailable)";
            try {
                currentUrl = page.url();
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {}
            throw new AssertionError("Expected first-broker-login flow. URL: " + currentUrl + ", Body: " + bodyText, e);
        }

        page.waitForLoadState(LoadState.NETWORKIDLE);
        LOG.info("[Test] First broker login page URL: {}", page.url());

        // Handle Review Profile step if present
        if (page.locator("input[name='firstName']").count() > 0) {
            LOG.info("[Test] Review Profile page detected, filling profile info");
            page.locator("input[name='firstName']").fill("Test");
            page.locator("input[name='lastName']").fill("User");
            if (page.locator("input[name='email']").count() > 0) {
                page.locator("input[name='email']").fill("test@example.com");
            }
            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForLoadState(LoadState.NETWORKIDLE);
            LOG.info("[Test] After review profile, URL: {}", page.url());
        }

        // Handle "Add to existing account" step if present
        Locator addToExistingLink = page.locator("a:has-text('Add to existing account'), a:has-text('Link'), a[id*='link'], #linkAccount");
        if (addToExistingLink.count() > 0) {
            LOG.info("[Test] 'Add to existing account' link detected, clicking");
            addToExistingLink.first().click();
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        // Now we should see the username/password form
        boolean hasUsernameField = page.locator("input[name='username']").count() > 0;
        boolean hasPasswordField = page.locator("input[name='password']").count() > 0;

        assertThat(hasUsernameField || hasPasswordField)
                .as("Expected username/password form for first-time PID user. URL: " + page.url())
                .isTrue();

        // Fill in the credentials to link the account
        if (hasUsernameField) {
            page.locator("input[name='username']").fill(TEST_USER);
        }
        if (hasPasswordField) {
            page.locator("input[name='password']").fill(TEST_PASSWORD);
        }

        page.locator("input[type='submit'], button[type='submit']").first().click();
        page.waitForLoadState(LoadState.NETWORKIDLE);

        LOG.info("[Test] After username/password submission, URL: {}", page.url());

        // Check if we're on the credential issuance page
        boolean hasCredentialIssuancePage = page.locator("text=Issuing Login Credential").count() > 0 ||
                page.locator("text=Account Linked Successfully").count() > 0 ||
                page.locator("text=Issuing Login Credential to Your Wallet").count() > 0 ||
                page.locator("button[name='skip']").count() > 0;

        String pageContent = page.locator("body").textContent();
        LOG.info("[Test] Page content after login: {}", pageContent.substring(0, Math.min(1000, pageContent.length())));

        assertThat(hasCredentialIssuancePage)
                .as("Credential issuance page must be shown after username/password authentication. URL: %s, Content: %s",
                        page.url(), pageContent.substring(0, Math.min(500, pageContent.length())))
                .isTrue();

        assertThat(page.locator("button[name='skip']").count())
                .as("Should have 'Skip' button")
                .isGreaterThan(0);

        assertThat(page.locator("button[name='continue']").count())
                .as("Should have 'Continue' button")
                .isGreaterThan(0);

        // Verify the same-device wallet link OR QR code section is present
        Locator sameDeviceLink = page.locator("a:has-text('Open Wallet')");
        boolean hasSameDeviceLink = sameDeviceLink.count() > 0;

        Locator qrCodeSection = page.locator("#qrcode");
        boolean hasQrCode = qrCodeSection.count() > 0;

        assertThat(hasSameDeviceLink || hasQrCode)
                .as("Should have either same-device wallet link or QR code for credential issuance")
                .isTrue();

        // Extract the credential offer URL from the same-device link
        String credentialOfferUrl = null;
        if (hasSameDeviceLink) {
            String sameDeviceUrl = sameDeviceLink.getAttribute("href");
            LOG.info("[Test] Same-device wallet URL: {}", sameDeviceUrl);

            if (sameDeviceUrl != null && sameDeviceUrl.contains("credentialOffer=")) {
                int startIdx = sameDeviceUrl.indexOf("credentialOffer=") + "credentialOffer=".length();
                String encodedOffer = sameDeviceUrl.substring(startIdx);
                credentialOfferUrl = java.net.URLDecoder.decode(encodedOffer, java.nio.charset.StandardCharsets.UTF_8);
            }
        }

        LOG.info("[Test] Credential offer URL: {}", credentialOfferUrl);
        assertThat(credentialOfferUrl)
                .as("Credential offer URL should start with openid-credential-offer://")
                .isNotNull()
                .startsWith("openid-credential-offer://");

        // Call the OID4VCI endpoint to receive the credential
        LOG.info("[Test] Issuing credential via OID4VCI...");
        issuedCredential = oid4vciClient.receiveCredential(credentialOfferUrl);
        LOG.info("[Test] Successfully received credential via OID4VCI! Length: {}", issuedCredential.length());
        wallet.storeIssuedCredential(issuedCredential);

        // Click continue - user indicates they've added the credential to their wallet
        page.locator("button[name='continue']").click();

        // Wait for successful login (callback with code)
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) && url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(10000));
        } catch (Exception e) {
            throw new AssertionError("First broker login did not complete. URL: " + page.url() +
                    ", Body: " + page.locator("body").textContent().substring(0, Math.min(500, page.locator("body").textContent().length())), e);
        }

        assertThat(page.url()).contains("code=");
        LOG.info("[Test] First-time user successfully authenticated via username/password");

        // Get the user ID to verify the credential contains the correct user_id claim
        issuedUserId = Oid4vpTestKeycloakSetup.resolveUserId(adminClient, REALM, TEST_USER);
        LOG.info("[Test] Resolved Keycloak user ID: {}", issuedUserId);

        // Verify the federated identity was created with the correct lookup key
        var federatedIdentity = Oid4vpTestKeycloakSetup.getFederatedIdentity(
                adminClient, REALM, issuedUserId, IDP_ALIAS);

        assertThat(federatedIdentity)
                .as("Federated identity should exist after first login")
                .isNotNull();

        String actualLookupKey = String.valueOf(federatedIdentity.get("userId"));
        String expectedLookupKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(adminBaseUrl, REALM, issuedUserId);

        LOG.info("[Test] Expected lookup key: {}", expectedLookupKey);
        LOG.info("[Test] Actual lookup key:   {}", actualLookupKey);

        assertThat(actualLookupKey)
                .as("Federated identity MUST have the correct lookup key")
                .isEqualTo(expectedLookupKey);
    }

    @Test
    @Order(3)
    void returningUserWithBothCredentialsGetsDirectLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        assertThat(issuedUserId).as("User ID should be set from previous test").isNotNull();
        assertThat(issuedCredential).as("Credential should have been issued via OID4VCI in previous test").isNotNull();
        assertThat(wallet.hasIssuedCredential()).as("Wallet should have the issued credential").isTrue();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();

        waitForOpenWalletLink();

        // Click to start wallet flow - wallet presents PID + ba-login-credential
        int walletRequestsBefore = wallet.requestCount();
        long startTime = System.currentTimeMillis();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        // For returning users, we should go directly to callback WITHOUT any login form
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(15000));
        } catch (Exception e) {
            String currentUrl = page.url();
            String bodyText = page.locator("body").textContent();

            boolean hasLoginForm = page.locator("input[name='username']").count() > 0 ||
                    page.locator("input[name='password']").count() > 0;

            var identity = Oid4vpTestKeycloakSetup.getFederatedIdentity(adminClient, REALM, issuedUserId, IDP_ALIAS);
            String actualKey = identity != null ? String.valueOf(identity.get("userId")) : "NOT FOUND";
            String expectedKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(adminBaseUrl, REALM, issuedUserId);

            throw new AssertionError(
                    "RETURNING USER SHOULD GET DIRECT LOGIN without username/password!\n" +
                            "Has login form: " + hasLoginForm + "\n" +
                            "Expected lookup key: " + expectedKey + "\n" +
                            "Actual lookup key:   " + actualKey + "\n" +
                            "URL: " + currentUrl, e);
        }

        long duration = System.currentTimeMillis() - startTime;

        assertThat(page.url()).contains("code=");

        LOG.info("[Test] SUCCESS: Returning user got DIRECT LOGIN in {}ms", duration);

        wallet.clearSimulatedCredentials();
    }

    @Test
    @Order(4)
    void dcqlQueryHasCorrectStructureAndNestedClaimPaths() throws Exception {
        callback.reset();
        clearBrowserSession();
        wallet.clearSimulatedCredentials();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();

        waitForOpenWalletLink();

        // Click to start - we want to inspect the DCQL query sent to the wallet
        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        // Verify we received a request with a DCQL query
        String dcqlRaw = wallet.lastDcqlQuery();
        assertThat(dcqlRaw).as("Wallet should have received a DCQL query").isNotNull();
        LOG.info("[Test] Received DCQL query: {}", dcqlRaw);

        tools.jackson.databind.JsonNode dcql = OBJECT_MAPPER.readTree(dcqlRaw);

        // Verify credential structure: should have german_pid and ba_login_credential
        tools.jackson.databind.JsonNode credentials = dcql.get("credentials");
        assertThat(credentials).as("DCQL must have credentials array").isNotNull();
        assertThat(credentials.size()).as("Should request 2 credentials (PID + login)").isEqualTo(2);

        // Find PID credential by id
        tools.jackson.databind.JsonNode pidCred = null;
        tools.jackson.databind.JsonNode loginCred = null;
        for (var cred : credentials) {
            String id = cred.get("id").asText();
            if ("german_pid".equals(id)) pidCred = cred;
            if ("ba_login_credential".equals(id)) loginCred = cred;
        }
        assertThat(pidCred).as("Should have german_pid credential").isNotNull();
        assertThat(loginCred).as("Should have ba_login_credential credential").isNotNull();

        // Verify PID credential has correct format and type
        assertThat(pidCred.get("format").asText()).isEqualTo("dc+sd-jwt");
        assertThat(pidCred.get("meta").get("vct_values").get(0).asText()).isEqualTo("urn:eudi:pid:de:1");

        // Verify nested claim paths are correctly split
        tools.jackson.databind.JsonNode pidClaims = pidCred.get("claims");
        assertThat(pidClaims).as("PID credential should have claims").isNotNull();

        boolean foundStreetAddress = false;
        boolean foundLocality = false;
        for (var claim : pidClaims) {
            tools.jackson.databind.JsonNode path = claim.get("path");
            if (path.size() == 2 && "address".equals(path.get(0).asText()) && "street_address".equals(path.get(1).asText())) {
                foundStreetAddress = true;
            }
            if (path.size() == 2 && "address".equals(path.get(0).asText()) && "locality".equals(path.get(1).asText())) {
                foundLocality = true;
            }
            // Verify NO path contains a slash in a single element (the old bug)
            if (path.size() == 1) {
                assertThat(path.get(0).asText())
                        .as("Single-element claim path must not contain '/'")
                        .doesNotContain("/");
            }
        }
        assertThat(foundStreetAddress)
                .as("DCQL must contain path [\"address\", \"street_address\"]")
                .isTrue();
        assertThat(foundLocality)
                .as("DCQL must contain path [\"address\", \"locality\"]")
                .isTrue();

        // Verify credential_sets allows PID+login or PID-only
        tools.jackson.databind.JsonNode credentialSets = dcql.get("credential_sets");
        assertThat(credentialSets).as("Should have credential_sets").isNotNull();
        assertThat(credentialSets.size()).isGreaterThan(0);

        LOG.info("[Test] DCQL query structure and nested claim paths verified successfully");
    }

    @Test
    @Order(5)
    void reissuanceFlowForUserWhoLostCredential() throws Exception {
        callback.reset();
        clearBrowserSession();

        wallet.clearSimulatedCredentials();
        assertThat(wallet.hasIssuedCredential()).as("Wallet should have no credential").isFalse();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();

        waitForOpenWalletLink();

        // Click to start wallet flow - wallet will only present PID (no credential)
        int walletRequestsBefore = wallet.requestCount();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        // Since user has no credential, they should be directed to first-broker-login
        try {
            page.waitForURL(url ->
                            url.contains("first-broker-login") ||
                                    url.contains("login-actions") ||
                                    page.locator("input[name='username']").count() > 0 ||
                                    page.locator("input[name='password']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String currentUrl = page.url();
            if (currentUrl.contains("code=")) {
                LOG.info("[Test] Re-issuance: User was directly authenticated");
                return;
            }
            throw new AssertionError("Expected first-broker-login flow for re-issuance. URL: " + currentUrl, e);
        }

        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Handle any intermediate steps
        if (page.locator("a:has-text('Add to existing account'), a:has-text('Link')").count() > 0) {
            page.locator("a:has-text('Add to existing account'), a:has-text('Link')").first().click();
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        // Fill in credentials for re-authentication
        boolean hasUsernameField = page.locator("input[name='username']").count() > 0;
        boolean hasPasswordField = page.locator("input[name='password']").count() > 0;

        assertThat(hasUsernameField || hasPasswordField)
                .as("Expected username/password form for re-issuance flow. URL: " + page.url())
                .isTrue();

        if (hasUsernameField) {
            page.locator("input[name='username']").fill(TEST_USER);
        }
        if (hasPasswordField) {
            page.locator("input[name='password']").fill(TEST_PASSWORD);
        }

        page.locator("input[type='submit'], button[type='submit']").first().click();
        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Should see credential issuance page again
        boolean hasCredentialIssuancePage = page.locator("text=Issuing Login Credential").count() > 0 ||
                page.locator("text=Account Linked Successfully").count() > 0 ||
                page.locator("button[name='skip']").count() > 0 ||
                page.locator("button[name='continue']").count() > 0;

        assertThat(hasCredentialIssuancePage)
                .as("Credential issuance page must be shown for re-issuance. URL: %s", page.url())
                .isTrue();

        // Get the new credential offer URL
        Locator sameDeviceLink = page.locator("a:has-text('Open Wallet')");
        String credentialOfferUrl = null;
        if (sameDeviceLink.count() > 0) {
            String sameDeviceUrl = sameDeviceLink.getAttribute("href");
            if (sameDeviceUrl != null && sameDeviceUrl.contains("credentialOffer=")) {
                int startIdx = sameDeviceUrl.indexOf("credentialOffer=") + "credentialOffer=".length();
                String encodedOffer = sameDeviceUrl.substring(startIdx);
                credentialOfferUrl = java.net.URLDecoder.decode(encodedOffer, java.nio.charset.StandardCharsets.UTF_8);
            }
        }

        assertThat(credentialOfferUrl).as("New credential offer URL should be present").isNotNull();

        // Issue the new credential
        String newCredential = oid4vciClient.receiveCredential(credentialOfferUrl);
        LOG.info("[Test] Re-issuance: Successfully received new credential! Length: {}", newCredential.length());
        wallet.storeIssuedCredential(newCredential);

        // Click continue
        page.locator("button[name='continue']").click();

        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) && url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(10000));
        } catch (Exception e) {
            throw new AssertionError("Re-issuance flow did not complete. URL: " + page.url(), e);
        }

        assertThat(page.url()).contains("code=");

        // Verify the federated identity was correctly overridden
        var reissuedIdentity = Oid4vpTestKeycloakSetup.getFederatedIdentity(
                adminClient, REALM, issuedUserId, IDP_ALIAS);

        assertThat(reissuedIdentity)
                .as("Federated identity should still exist after re-issuance")
                .isNotNull();

        String actualKey = String.valueOf(reissuedIdentity.get("userId"));
        String expectedKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(adminBaseUrl, REALM, issuedUserId);

        assertThat(actualKey)
                .as("Federated identity must have the correct lookup key after re-issuance")
                .isEqualTo(expectedKey);
    }

    @Test
    @Order(6)
    void directLoginWorksAfterReissuance() throws Exception {
        callback.reset();
        clearBrowserSession();

        assertThat(issuedUserId).as("User ID should be set from test 2").isNotNull();
        assertThat(wallet.hasIssuedCredential())
                .as("Wallet should have the re-issued credential from test 5")
                .isTrue();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();

        waitForOpenWalletLink();

        // Start wallet flow — wallet presents PID + re-issued ba-login-credential
        int walletRequestsBefore = wallet.requestCount();
        long startTime = System.currentTimeMillis();
        page.locator("a:has-text('Open Wallet App')").click();
        waitForWalletRequest(walletRequestsBefore + 1, Duration.ofSeconds(15));

        // Returning user with re-issued credential should get DIRECT LOGIN
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(15000));
        } catch (Exception e) {
            String currentUrl = page.url();
            boolean hasLoginForm = page.locator("input[name='username']").count() > 0 ||
                    page.locator("input[name='password']").count() > 0;

            var identity = Oid4vpTestKeycloakSetup.getFederatedIdentity(adminClient, REALM, issuedUserId, IDP_ALIAS);
            String actualKey = identity != null ? String.valueOf(identity.get("userId")) : "NOT FOUND";
            String expectedKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(adminBaseUrl, REALM, issuedUserId);

            throw new AssertionError(
                    "DIRECT LOGIN WITH RE-ISSUED CREDENTIAL FAILED!\n" +
                            "Has login form: " + hasLoginForm + "\n" +
                            "Expected lookup key: " + expectedKey + "\n" +
                            "Actual lookup key:   " + actualKey + "\n" +
                            "URL: " + currentUrl, e);
        }

        long duration = System.currentTimeMillis() - startTime;

        assertThat(page.url()).contains("code=");
        LOG.info("[Test] SUCCESS: Direct login with re-issued credential in {}ms", duration);

        wallet.clearSimulatedCredentials();
    }

    // ========== Helper Methods ==========

    private URI buildAuthRequestUri() {
        String state = "s-" + System.nanoTime();
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        return URI.create("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256"
                .formatted(browserBaseUrl, REALM, CLIENT_ID,
                        URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8),
                        URLEncoder.encode(state, StandardCharsets.UTF_8),
                        URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8)));
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

    private void clearBrowserSession() throws InterruptedException {
        context.clearCookies();
        Thread.sleep(100);
    }

    private void safeNavigate(String url) {
        try {
            page.navigate(url, new Page.NavigateOptions().setWaitUntil(WaitUntilState.COMMIT));
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("interrupted by another navigation")) {
                LOG.debug("Navigation to {} was redirected (expected behavior)", url);
            } else {
                throw e;
            }
        }
    }

    private void waitForOpenWalletLink() {
        try {
            page.waitForSelector("a:has-text('Open Wallet App')", new Page.WaitForSelectorOptions()
                    .setState(WaitForSelectorState.VISIBLE)
                    .setTimeout(30000));
        } catch (Exception e) {
            String bodyText = page.locator("body").textContent();
            throw new AssertionError("'Open Wallet App' link not found. URL: " + page.url() +
                    ", Body: " + bodyText.substring(0, Math.min(2000, bodyText.length())), e);
        }
    }

    private void waitForWalletRequest(int expectedCount, Duration timeout) throws InterruptedException {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            if (wallet.requestCount() >= expectedCount) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Wallet did not receive expected request count: " + expectedCount +
                " (current: " + wallet.requestCount() + ")");
    }

    private static Path repoRootDir() {
        Path current = Path.of(System.getProperty("user.dir"));
        while (current != null) {
            if (Files.exists(current.resolve("pom.xml")) && Files.exists(current.resolve("keycloak-oid4vp"))) {
                return current;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("Could not find repository root");
    }

    private static void copyRealmImport() throws IOException {
        Path realmExport = repoRootDir().resolve("demo-app/config/keycloak/realm-pid-binding-export.json");
        if (!Files.exists(realmExport)) {
            throw new IllegalStateException("realm-pid-binding-export.json not found at: " + realmExport);
        }
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport),
                "/opt/keycloak/data/import/realm-pid-binding-export.json"
        );
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
        throw new IllegalStateException("Cannot determine module directory from: " + dir);
    }
}
