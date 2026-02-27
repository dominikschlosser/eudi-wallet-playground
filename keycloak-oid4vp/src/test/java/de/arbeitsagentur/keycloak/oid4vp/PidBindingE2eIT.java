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
import io.github.dominikschlosser.oid4vc.Credential;
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
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for the German PID Binding Identity Provider
 * using the oid4vc-dev Docker wallet ({@code ghcr.io/dominikschlosser/oid4vc-dev}).
 * <p>
 * Tests the two-phase authentication flow:
 * <ol>
 *   <li>First-time users: PID only -> username/password -> credential issuance via OID4VCI</li>
 *   <li>Returning users: PID + ba-login-credential -> direct login</li>
 * </ol>
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

    // Store the user ID from the first login
    private static String issuedUserId;

    @BeforeAll
    static void setUp() throws Exception {
        callback = new Oid4vpTestCallbackServer();
        callbackUrl = callback.localCallbackUrl();

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.0")
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withEnv("KC_PROXY_HEADERS", "xforwarded")
                .withExposedPorts(8080)
                .withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("/bin/sh"))
                .withCommand("-c",
                        "/opt/keycloak/bin/kc.sh build --features=oid4vc-vci && " +
                        "/opt/keycloak/bin/kc.sh start-dev --import-realm --features=oid4vc-vci")
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofSeconds(180)))
                .withLogConsumer(frame -> LOG.info("[KC] {}", frame.getUtf8String().stripTrailing()));

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        int kcMappedPort = keycloak.getMappedPort(8080);
        kcHostUrl = "http://localhost:" + kcMappedPort;

        wallet = new Oid4vcContainer("ghcr.io/dominikschlosser/oid4vc-dev:v0.13.3")
                .withHostAccess()
                .withLogConsumer(frame -> LOG.info("[OID4VC] {}", frame.getUtf8String().stripTrailing()));
        wallet.start();

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
        context = browser.newContext();
        page = context.newPage();

        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, kcHostUrl, "admin", "admin");
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, REALM, CLIENT_ID, callbackUrl);

        // Configure IdP with wallet trust list and same-device wallet URL
        configureIdpForDockerWallet(wallet.client().getTrustList(), wallet.getAuthorizeUrl());

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
        if (callback != null) callback.close();
    }

    @Test
    @Order(1)
    void loginPageShowsGermanPidIdpButton() {
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

        // Delete all non-PID credentials from the wallet to simulate PID-only
        deleteAllNonPidCredentials();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();
        waitForOpenWalletLink();

        // Extract wallet URL and submit via API
        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        // Wait for first broker login (username/password form)
        try {
            page.waitForURL(url ->
                            url.contains("first-broker-login") ||
                                    url.contains("login-actions") ||
                                    page.locator("input[name='username']").count() > 0 ||
                                    page.locator("input[name='password']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            throw new AssertionError("Expected first-broker-login flow. URL: " + page.url(), e);
        }

        page.waitForLoadState(LoadState.NETWORKIDLE);
        LOG.info("[Test] First broker login page URL: {}", page.url());

        // Handle Review Profile step if present
        if (page.locator("input[name='firstName']").count() > 0 &&
                page.locator("input[name='password']").count() == 0) {
            LOG.info("[Test] Review Profile page detected, filling profile info");
            page.locator("input[name='firstName']").fill("Test");
            page.locator("input[name='lastName']").fill("User");
            if (page.locator("input[name='email']").count() > 0) {
                page.locator("input[name='email']").fill("test@example.com");
            }
            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForLoadState(LoadState.NETWORKIDLE);
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
                .as("Credential issuance page must be shown after username/password authentication. URL: %s",
                        page.url())
                .isTrue();

        assertThat(page.locator("button[name='skip']").count())
                .as("Should have 'Skip' button")
                .isGreaterThan(0);

        assertThat(page.locator("button[name='continue']").count())
                .as("Should have 'Continue' button")
                .isGreaterThan(0);

        // Extract the credential offer URL from the same-device link
        Locator sameDeviceLink = page.locator("a:has-text('Open Wallet')");
        assertThat(sameDeviceLink.count()).as("Should have same-device wallet link").isGreaterThan(0);

        String sameDeviceUrl = sameDeviceLink.getAttribute("href");
        LOG.info("[Test] Same-device wallet URL: {}", sameDeviceUrl);

        String credentialOfferUrl = null;
        if (sameDeviceUrl != null && sameDeviceUrl.contains("credentialOffer=")) {
            int startIdx = sameDeviceUrl.indexOf("credentialOffer=") + "credentialOffer=".length();
            String encodedOffer = sameDeviceUrl.substring(startIdx);
            credentialOfferUrl = URLDecoder.decode(encodedOffer, StandardCharsets.UTF_8);
        }

        assertThat(credentialOfferUrl)
                .as("Credential offer URL should start with openid-credential-offer://")
                .isNotNull()
                .startsWith("openid-credential-offer://");

        // Accept the credential offer via wallet API
        LOG.info("[Test] Accepting credential offer via wallet API...");
        wallet.acceptCredentialOffer(credentialOfferUrl);
        LOG.info("[Test] Credential offer accepted");

        // Click continue
        page.locator("button[name='continue']").click();

        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) && url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(10000));
        } catch (Exception e) {
            throw new AssertionError("First broker login did not complete. URL: " + page.url(), e);
        }

        assertThat(page.url()).contains("code=");
        LOG.info("[Test] First-time user successfully authenticated via username/password");

        issuedUserId = Oid4vpTestKeycloakSetup.resolveUserId(adminClient, REALM, TEST_USER);
        LOG.info("[Test] Resolved Keycloak user ID: {}", issuedUserId);

        // Verify the federated identity was created with the correct lookup key
        var federatedIdentity = Oid4vpTestKeycloakSetup.getFederatedIdentity(
                adminClient, REALM, issuedUserId, IDP_ALIAS);

        assertThat(federatedIdentity)
                .as("Federated identity should exist after first login")
                .isNotNull();

        String actualLookupKey = String.valueOf(federatedIdentity.get("userId"));
        String expectedLookupKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(kcHostUrl, REALM, issuedUserId);

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

        // Verify wallet has the ba-login-credential
        assertThat(wallet.client().hasCredentialWithType("urn:arbeitsagentur:user_credential:1"))
                .as("Wallet should have the ba-login-credential from previous test. Wallet credentials: %s", wallet.listCredentials())
                .isTrue();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        String presentationUri = convertToOpenid4vpUri(walletUrl);

        long startTime = System.currentTimeMillis();
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        // Returning users should go directly to callback WITHOUT any login form
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(15000));
        } catch (Exception e) {
            boolean hasLoginForm = page.locator("input[name='username']").count() > 0 ||
                    page.locator("input[name='password']").count() > 0;

            var identity = Oid4vpTestKeycloakSetup.getFederatedIdentity(adminClient, REALM, issuedUserId, IDP_ALIAS);
            String actualKey = identity != null ? String.valueOf(identity.get("userId")) : "NOT FOUND";
            String expectedKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(kcHostUrl, REALM, issuedUserId);

            throw new AssertionError(
                    "RETURNING USER SHOULD GET DIRECT LOGIN without username/password!\n" +
                            "Has login form: " + hasLoginForm + "\n" +
                            "Expected lookup key: " + expectedKey + "\n" +
                            "Actual lookup key:   " + actualKey + "\n" +
                            "URL: " + page.url(), e);
        }

        long duration = System.currentTimeMillis() - startTime;

        assertThat(page.url()).contains("code=");
        LOG.info("[Test] SUCCESS: Returning user got DIRECT LOGIN in {}ms", duration);
    }

    @Test
    @Order(4)
    void dcqlQueryHasCorrectStructureAndNestedClaimPaths() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Delete all non-PID credentials so wallet only has PID
        deleteAllNonPidCredentials();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();
        waitForOpenWalletLink();

        // Extract the wallet URL to get the request_uri parameter
        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        assertThat(walletUrl).as("Wallet URL should be present").isNotEmpty();

        // Parse the wallet URL to extract request_uri
        URI walletUri = URI.create(walletUrl);
        String query = walletUri.getQuery();
        String requestUri = null;
        for (String param : query.split("&")) {
            if (param.startsWith("request_uri=")) {
                requestUri = URLDecoder.decode(param.substring("request_uri=".length()), StandardCharsets.UTF_8);
                break;
            }
        }

        assertThat(requestUri).as("request_uri parameter should be present in wallet URL").isNotNull();

        // Fetch the request JWT from the request_uri
        HttpResponse<String> jwtResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create(requestUri))
                        .timeout(Duration.ofSeconds(10))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(jwtResponse.statusCode()).as("Request URI fetch should succeed").isEqualTo(200);

        String jwt = jwtResponse.body().strip();
        // Decode JWT payload (second part)
        String[] jwtParts = jwt.split("\\.");
        assertThat(jwtParts.length).as("JWT should have 3 parts").isGreaterThanOrEqualTo(3);

        String payloadJson = new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);
        JsonNode payload = OBJECT_MAPPER.readTree(payloadJson);

        JsonNode dcql = payload.get("dcql_query");
        assertThat(dcql).as("JWT payload must contain dcql_query").isNotNull();

        LOG.info("[Test] Decoded DCQL query: {}", dcql);

        // Verify credential structure: should have german_pid and ba_login_credential
        JsonNode credentials = dcql.get("credentials");
        assertThat(credentials).as("DCQL must have credentials array").isNotNull();
        assertThat(credentials.size()).as("Should request 2 credentials (PID + login)").isEqualTo(2);

        JsonNode pidCred = null;
        JsonNode loginCred = null;
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
        JsonNode pidClaims = pidCred.get("claims");
        assertThat(pidClaims).as("PID credential should have claims").isNotNull();

        boolean foundStreetAddress = false;
        boolean foundLocality = false;
        for (var claim : pidClaims) {
            JsonNode path = claim.get("path");
            if (path.size() == 2 && "address".equals(path.get(0).asText()) && "street_address".equals(path.get(1).asText())) {
                foundStreetAddress = true;
            }
            if (path.size() == 2 && "address".equals(path.get(0).asText()) && "locality".equals(path.get(1).asText())) {
                foundLocality = true;
            }
            // Verify NO path contains a slash in a single element
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

        // Verify credential_sets
        JsonNode credentialSets = dcql.get("credential_sets");
        assertThat(credentialSets).as("Should have credential_sets").isNotNull();
        assertThat(credentialSets.size()).isGreaterThan(0);

        LOG.info("[Test] DCQL query structure and nested claim paths verified successfully");
    }

    @Test
    @Order(5)
    void reissuanceFlowForUserWhoLostCredential() throws Exception {
        callback.reset();
        clearBrowserSession();

        // Delete the ba-login-credential from the wallet (simulate lost credential)
        deleteAllNonPidCredentials();
        assertThat(wallet.client().hasCredentialWithType("urn:arbeitsagentur:user_credential:1"))
                .as("Wallet should NOT have ba-login-credential after deletion")
                .isFalse();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        // Since user has no ba-login-credential, they should be directed to first-broker-login
        try {
            page.waitForURL(url ->
                            url.contains("first-broker-login") ||
                                    url.contains("login-actions") ||
                                    page.locator("input[name='username']").count() > 0 ||
                                    page.locator("input[name='password']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            if (page.url().contains("code=")) {
                LOG.info("[Test] Re-issuance: User was directly authenticated");
                return;
            }
            throw new AssertionError("Expected first-broker-login flow for re-issuance. URL: " + page.url(), e);
        }

        page.waitForLoadState(LoadState.NETWORKIDLE);

        // Handle "Add to existing account" step if present
        if (page.locator("a:has-text('Add to existing account'), a:has-text('Link')").count() > 0) {
            page.locator("a:has-text('Add to existing account'), a:has-text('Link')").first().click();
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

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
                credentialOfferUrl = URLDecoder.decode(encodedOffer, StandardCharsets.UTF_8);
            }
        }

        assertThat(credentialOfferUrl).as("New credential offer URL should be present").isNotNull();

        // Accept the new credential via wallet API
        wallet.acceptCredentialOffer(credentialOfferUrl);
        LOG.info("[Test] Re-issuance: credential offer accepted");

        // Click continue
        page.locator("button[name='continue']").click();

        try {
            page.waitForURL(url -> url.startsWith(callbackUrl) && url.contains("code="),
                    new Page.WaitForURLOptions().setTimeout(10000));
        } catch (Exception e) {
            throw new AssertionError("Re-issuance flow did not complete. URL: " + page.url(), e);
        }

        assertThat(page.url()).contains("code=");

        // Verify the federated identity was correctly maintained
        var reissuedIdentity = Oid4vpTestKeycloakSetup.getFederatedIdentity(
                adminClient, REALM, issuedUserId, IDP_ALIAS);

        assertThat(reissuedIdentity)
                .as("Federated identity should still exist after re-issuance")
                .isNotNull();

        String actualKey = String.valueOf(reissuedIdentity.get("userId"));
        String expectedKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(kcHostUrl, REALM, issuedUserId);

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
        assertThat(wallet.client().hasCredentialWithType("urn:arbeitsagentur:user_credential:1"))
                .as("Wallet should have the re-issued ba-login-credential from test 5")
                .isTrue();

        safeNavigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-german-pid").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        String presentationUri = convertToOpenid4vpUri(walletUrl);

        long startTime = System.currentTimeMillis();
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        // Returning user with re-issued credential should get DIRECT LOGIN
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl),
                    new Page.WaitForURLOptions().setTimeout(15000));
        } catch (Exception e) {
            boolean hasLoginForm = page.locator("input[name='username']").count() > 0 ||
                    page.locator("input[name='password']").count() > 0;

            var identity = Oid4vpTestKeycloakSetup.getFederatedIdentity(adminClient, REALM, issuedUserId, IDP_ALIAS);
            String actualKey = identity != null ? String.valueOf(identity.get("userId")) : "NOT FOUND";
            String expectedKey = Oid4vpTestKeycloakSetup.computeExpectedLookupKey(kcHostUrl, REALM, issuedUserId);

            throw new AssertionError(
                    "DIRECT LOGIN WITH RE-ISSUED CREDENTIAL FAILED!\n" +
                            "Has login form: " + hasLoginForm + "\n" +
                            "Expected lookup key: " + expectedKey + "\n" +
                            "Actual lookup key:   " + actualKey + "\n" +
                            "URL: " + page.url(), e);
        }

        long duration = System.currentTimeMillis() - startTime;

        assertThat(page.url()).contains("code=");
        LOG.info("[Test] SUCCESS: Direct login with re-issued credential in {}ms", duration);
    }

    // ===== Wallet Helpers =====

    private void deleteAllNonPidCredentials() {
        for (Credential cred : wallet.listCredentials()) {
            String type = cred.type();
            boolean isPid = type != null && (type.contains("pid") ||
                    type.equals("urn:eudi:pid:de:1") || type.equals("eu.europa.ec.eudi.pid.1"));
            if (!isPid) {
                LOG.info("[Test] Deleting non-PID credential: id={}, type={}", cred.id(), type);
                wallet.client().deleteCredential(cred.id());
            }
        }
    }

    private String convertToOpenid4vpUri(String walletUrl) {
        return walletUrl.replace(wallet.getAuthorizeUrl() + "?", "openid4vp://authorize?");
    }

    // ===== Setup Helpers =====

    private static void configureIdpForDockerWallet(String trustListJwt, String walletAuthorizeUrl) throws Exception {
        var idp = adminClient.getJson("/admin/realms/" + REALM + "/identity-provider/instances/" + IDP_ALIAS);
        @SuppressWarnings("unchecked")
        var config = (java.util.Map<String, String>) idp.get("config");

        config.put("trustListJwt", trustListJwt);
        config.put("sameDeviceEnabled", "true");
        config.put("sameDeviceWalletUrl", walletAuthorizeUrl);
        config.put("dcApiRequestMode", "signed");

        adminClient.putJson("/admin/realms/" + REALM + "/identity-provider/instances/" + IDP_ALIAS, idp);
    }

    // ===== Test Helper Methods =====

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

    private URI buildAuthRequestUri() {
        String state = "s-" + System.nanoTime();
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String codeChallenge;
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return URI.create("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256"
                .formatted(kcHostUrl, REALM, CLIENT_ID,
                        URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8),
                        URLEncoder.encode(state, StandardCharsets.UTF_8),
                        URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8)));
    }

    private void clearBrowserSession() {
        context.clearCookies();
        try {
            page.navigate(kcHostUrl + "/realms/" + REALM + "/",
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
        throw new IllegalStateException("Cannot determine module directory from: " + dir);
    }

    private static Path repoRootDir() {
        Path module = moduleDir();
        Path parent = module.getParent();
        return parent != null ? parent : module;
    }
}
