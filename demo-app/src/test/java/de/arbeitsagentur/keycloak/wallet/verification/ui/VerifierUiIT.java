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
package de.arbeitsagentur.keycloak.wallet.verification.ui;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.ConsoleMessage;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Playwright-based integration test for the verifier UI.
 * Boots the Spring app on a random port, opens the verifier page in a headless
 * browser, and verifies: no JS errors on load, sandbox defaults button works,
 * DCQL mode toggle works.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerifierUiIT {

    @LocalServerPort
    int port;

    private static Playwright playwright;
    private static Browser browser;
    private static Path sandboxCertFile;
    private static Path sandboxVerifierInfoFile;

    @BeforeAll
    static void setUp() throws Exception {
        // Generate sandbox test fixtures (self-signed EC cert + key)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=Test Verifier, C=DE");
        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 86400000),
                new Date(System.currentTimeMillis() + 365L * 86400000),
                subject, keyPair.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "test.example.com")));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        String certPem = toPem(cert.getEncoded(), "CERTIFICATE");
        String keyPem = toPem(keyPair.getPrivate().getEncoded(), "PRIVATE KEY");

        Path tempDir = Files.createTempDirectory("verifier-ui-it");
        sandboxCertFile = tempDir.resolve("sandbox-combined.pem");
        Files.writeString(sandboxCertFile, certPem + "\n" + keyPem);

        sandboxVerifierInfoFile = tempDir.resolve("sandbox-verifier-info.json");
        Files.writeString(sandboxVerifierInfoFile,
                "[{\"format\":\"registration_cert\",\"data\":\"eyJ0ZXN0IjoianVzdC1hLXRlc3QifQ\"}]");

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
    }

    @AfterAll
    static void tearDown() {
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
    }

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) throws Exception {
        // setUp() runs before @DynamicPropertySource, but static fields are set
        // Force setUp to run early by calling it if not yet done
        if (sandboxCertFile == null) {
            setUp();
        }
        registry.add("verifier.client-cert-file", () -> sandboxCertFile.toAbsolutePath().toString());
        registry.add("verifier.sandbox-verifier-info-file", () -> sandboxVerifierInfoFile.toAbsolutePath().toString());
    }

    @Test
    void verifierPageLoadsWithoutJsErrors() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            assertThat(page.title()).isEqualTo("Verifier Demo");
            assertThat(errors)
                    .as("JavaScript console errors on verifier page load")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    @Test
    void sandboxDefaultsButtonPopulatesForm() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            // Sandbox buttons should be visible since we configured the cert file
            var sandboxBothBtn = page.locator("#sandbox-both");
            assertThat(sandboxBothBtn.isVisible())
                    .as("Sandbox Both button should be visible")
                    .isTrue();

            // Click sandbox button and wait for the async fetch + form update
            sandboxBothBtn.click();
            page.waitForTimeout(2000);

            // Auth type should be set to x509_san_dns
            String authType = page.locator("#authType").inputValue();
            assertThat(authType).isEqualTo("x509_san_dns");

            // Client ID should contain the SAN-derived value
            String clientId = page.locator("#walletClientId").inputValue();
            assertThat(clientId).startsWith("x509_san_dns:");

            // In sandbox mode, the editable cert textarea is hidden and the read-only sandbox display is shown
            assertThat(page.locator("#x509-editable").isVisible())
                    .as("Editable cert section should be hidden in sandbox mode")
                    .isFalse();
            assertThat(page.locator("#x509-sandbox").isVisible())
                    .as("Sandbox cert display should be visible")
                    .isTrue();
            String sandboxCert = page.locator("#sandboxCertDisplay").inputValue();
            assertThat(sandboxCert).contains("BEGIN CERTIFICATE");
            assertThat(sandboxCert).as("Private key must not be sent to browser").doesNotContain("PRIVATE KEY");
            // useSandboxKey hidden field should be set
            String useSandboxKey = page.locator("#useSandboxKey").inputValue();
            assertThat(useSandboxKey).isEqualTo("true");

            // Response mode should be direct_post.jwt (HAIP encrypted response)
            String responseMode = page.locator("#responseMode").inputValue();
            assertThat(responseMode).isEqualTo("direct_post.jwt");

            // Encryption should be enabled — toggle state shows "On"
            String encryptionState = page.locator("#encryption-state").textContent();
            assertThat(encryptionState).isEqualTo("On");

            // Client metadata should contain HAIP encryption parameters
            String clientMetadata = page.locator("#clientMetadata").inputValue();
            assertThat(clientMetadata).contains("ECDH-ES");
            assertThat(clientMetadata).contains("jwks");

            // credential_sets should be present in the generated DCQL (enables SD-JWT OR mDoc selection)
            String dcqlPreview = page.locator("#dcql-builder-preview").textContent();
            assertThat(dcqlPreview).contains("credential_sets");
            assertThat(dcqlPreview).contains("pid_sd_jwt");
            assertThat(dcqlPreview).contains("pid_mdoc");

            // Verify full request object preview structure
            var mapper = new tools.jackson.databind.ObjectMapper();
            var requestObj = mapper.readTree(dcqlPreview);

            // Top-level request object fields
            assertThat(requestObj.has("client_id")).as("Preview should have client_id").isTrue();
            assertThat(requestObj.get("client_id").asText()).startsWith("x509_san_dns:");
            assertThat(requestObj.get("response_type").asText()).isEqualTo("vp_token");
            assertThat(requestObj.get("response_mode").asText()).isEqualTo("direct_post.jwt");
            assertThat(requestObj.has("dcql_query")).as("Preview should have dcql_query").isTrue();
            assertThat(requestObj.has("client_metadata")).as("Preview should have client_metadata when encrypted").isTrue();

            // Verify DCQL structure inside request object matches registration certificate
            var dcqlJson = requestObj.get("dcql_query");
            var credentials = dcqlJson.get("credentials");
            assertThat(credentials.isArray()).isTrue();
            assertThat(credentials.size()).isEqualTo(2);

            // SD-JWT credential: meta.vct_values present, simple claim paths
            var sdJwt = credentials.get(0);
            assertThat(sdJwt.get("format").asText()).isEqualTo("dc+sd-jwt");
            assertThat(sdJwt.get("meta").get("vct_values").get(0).asText()).isEqualTo("urn:eudi:pid:de:1");
            // SD-JWT address claims: nested paths like ["address", "street_address"]
            var sdJwtClaims = sdJwt.get("claims");
            boolean foundSdJwtStreetAddress = false;
            boolean foundSdJwtLocality = false;
            for (var claim : sdJwtClaims) {
                var path = claim.get("path");
                if (path.size() == 2 && "address".equals(path.get(0).asText()) && "street_address".equals(path.get(1).asText())) {
                    foundSdJwtStreetAddress = true;
                }
                if (path.size() == 2 && "address".equals(path.get(0).asText()) && "locality".equals(path.get(1).asText())) {
                    foundSdJwtLocality = true;
                }
            }
            assertThat(foundSdJwtStreetAddress).as("SD-JWT should have ['address', 'street_address'] path").isTrue();
            assertThat(foundSdJwtLocality).as("SD-JWT should have ['address', 'locality'] path").isTrue();

            // mDoc credential: meta.doctype_value present, paths match registration cert
            var mdoc = credentials.get(1);
            assertThat(mdoc.get("format").asText()).isEqualTo("mso_mdoc");
            assertThat(mdoc.get("meta").get("doctype_value").asText()).isEqualTo("eu.europa.ec.eudi.pid.1");
            // mDoc claims: paths must be exactly 2 elements [namespace, element_identifier]
            var mdocClaims = mdoc.get("claims");
            boolean foundMdocGivenName = false;
            boolean foundMdocStreetAddress = false;
            boolean foundMdocLocality = false;
            for (var claim : mdocClaims) {
                var path = claim.get("path");
                if (path.size() == 2
                        && "eu.europa.ec.eudi.pid.1".equals(path.get(0).asText())
                        && "given_name".equals(path.get(1).asText())) {
                    foundMdocGivenName = true;
                }
                if (path.size() == 2
                        && "eu.europa.ec.eudi.pid.1".equals(path.get(0).asText())
                        && "resident_street".equals(path.get(1).asText())) {
                    foundMdocStreetAddress = true;
                }
                if (path.size() == 2
                        && "eu.europa.ec.eudi.pid.1".equals(path.get(0).asText())
                        && "resident_city".equals(path.get(1).asText())) {
                    foundMdocLocality = true;
                }
            }
            assertThat(foundMdocGivenName).as("mDoc should have 2-element path ['eu.europa.ec.eudi.pid.1','given_name']").isTrue();
            assertThat(foundMdocStreetAddress).as("mDoc should have 2-element path ['eu.europa.ec.eudi.pid.1','resident_street']").isTrue();
            assertThat(foundMdocLocality).as("mDoc should have 2-element path ['eu.europa.ec.eudi.pid.1','resident_city']").isTrue();

            // credential_sets panel should be visible in builder mode
            assertThat(page.locator("#credential-sets-panel").isVisible())
                    .as("credential_sets panel should be visible after sandbox defaults")
                    .isTrue();

            // Client binding preview should show the sandbox certificate, not the self-signed default
            String bindingSource = page.locator("#binding-x509-source").textContent();
            assertThat(bindingSource).as("Binding should show sandbox cert source").contains("Sandbox");
            String bindingCert = page.locator("#binding-x509-cert").inputValue();
            assertThat(bindingCert)
                    .as("Binding preview should show the sandbox certificate, not the default self-signed one")
                    .contains("BEGIN CERTIFICATE");

            // --- Toggle back: sandbox buttons hidden, mock button visible ---
            var sandboxMockBtn = page.locator("#sandbox-mock");
            assertThat(sandboxMockBtn.isVisible())
                    .as("Mock defaults button should be visible after activating sandbox")
                    .isTrue();
            assertThat(sandboxBothBtn.isVisible())
                    .as("Sandbox Both button should be hidden in sandbox mode")
                    .isFalse();

            sandboxMockBtn.click();
            page.waitForTimeout(1000);

            // Auth type should be back to plain
            assertThat(page.locator("#authType").inputValue()).isEqualTo("plain");

            // Sandbox key flag should be reset
            assertThat(page.locator("#useSandboxKey").inputValue()).isEqualTo("false");
            // Editable cert textarea should be empty (mock mode doesn't prefill cert)
            assertThat(page.locator("#walletClientCert").inputValue()).isEmpty();
            // Sandbox cert display should be cleared
            assertThat(page.locator("#sandboxCertDisplay").inputValue()).isEmpty();

            // Response mode should be back to direct_post
            assertThat(page.locator("#responseMode").inputValue()).isEqualTo("direct_post");

            // Encryption should be disabled
            assertThat(page.locator("#encryption-state").textContent()).isEqualTo("Off");

            // Sandbox buttons should be visible again
            assertThat(sandboxBothBtn.isVisible())
                    .as("Sandbox Both button should be visible after mock reset")
                    .isTrue();
            assertThat(sandboxMockBtn.isVisible())
                    .as("Mock button should be hidden after mock reset")
                    .isFalse();

            assertThat(errors)
                    .as("JavaScript console errors after toggling sandbox defaults")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    @Test
    void sandboxDefaultsEndpointNeverExposesPrivateKey() throws Exception {
        // Directly fetch the sandbox-defaults JSON endpoint and verify no private key material leaks
        var url = new java.net.URI("http://localhost:" + port + "/verifier/sandbox-defaults");
        var connection = (java.net.HttpURLConnection) url.toURL().openConnection();
        connection.setRequestMethod("GET");
        assertThat(connection.getResponseCode()).isEqualTo(200);

        String body;
        try (var in = connection.getInputStream()) {
            body = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }

        var mapper = new tools.jackson.databind.ObjectMapper();
        var json = mapper.readTree(body);

        // The response must contain certificate data (for display)
        String walletClientCert = json.get("walletClientCert").asText();
        assertThat(walletClientCert)
                .as("sandbox-defaults should include the certificate chain")
                .contains("BEGIN CERTIFICATE");

        // The response must NEVER contain any private key material
        assertThat(walletClientCert)
                .as("sandbox-defaults must not expose PKCS8 private key")
                .doesNotContain("BEGIN PRIVATE KEY");
        assertThat(walletClientCert)
                .as("sandbox-defaults must not expose RSA private key")
                .doesNotContain("BEGIN RSA PRIVATE KEY");
        assertThat(walletClientCert)
                .as("sandbox-defaults must not expose EC private key")
                .doesNotContain("BEGIN EC PRIVATE KEY");

        // Also verify the full JSON body doesn't leak private keys in any field
        String fullBody = body;
        assertThat(fullBody).doesNotContain("PRIVATE KEY");
    }

    @Test
    void dcqlModeToggleWorks() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            // Default mode is builder — builder panel visible, raw panel hidden
            assertThat(page.locator("#dcql-builder-panel").isVisible()).isTrue();
            assertThat(page.locator("#dcql-raw-panel").isVisible()).isFalse();

            // Click raw mode
            page.locator("#dcql-mode-raw").click();
            assertThat(page.locator("#dcql-builder-panel").isVisible()).isFalse();
            assertThat(page.locator("#dcql-raw-panel").isVisible()).isTrue();

            // Click builder mode
            page.locator("#dcql-mode-builder").click();
            assertThat(page.locator("#dcql-builder-panel").isVisible()).isTrue();
            assertThat(page.locator("#dcql-raw-panel").isVisible()).isFalse();

            assertThat(errors)
                    .as("JavaScript console errors during DCQL mode toggle")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    @Test
    void mdocFormatShowsNamespaceAndElementFields() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            // Default format is dc+sd-jwt — should show "Claim path" labels
            assertThat(page.locator("#dcql-descriptors").textContent()).contains("Claim path");

            // Switch format to mso_mdoc
            page.locator("[data-field='format-select']").first().selectOption("mso_mdoc");
            page.waitForTimeout(300);

            // Should now show "Namespace" and "Element identifier" labels instead of "Claim path"
            String descriptorText = page.locator("#dcql-descriptors").textContent();
            assertThat(descriptorText)
                    .as("mDoc format should show Namespace field")
                    .contains("Namespace");
            assertThat(descriptorText)
                    .as("mDoc format should show Element identifier field")
                    .contains("Element identifier");

            // Should NOT show "Claim path" for mDoc
            // (The label might still appear in other places, so check the claim rows specifically)
            var claimRows = page.locator("#dcql-descriptors .claim-row");
            for (int i = 0; i < claimRows.count(); i++) {
                String rowText = claimRows.nth(i).textContent();
                assertThat(rowText)
                        .as("mDoc claim row should not have 'Claim path' label")
                        .doesNotContain("Claim path");
            }

            // Switch back to dc+sd-jwt — should show "Claim path" again
            page.locator("[data-field='format-select']").first().selectOption("dc+sd-jwt");
            page.waitForTimeout(300);

            var sdJwtClaimRows = page.locator("#dcql-descriptors .claim-row");
            for (int i = 0; i < sdJwtClaimRows.count(); i++) {
                String rowText = sdJwtClaimRows.nth(i).textContent();
                assertThat(rowText)
                        .as("SD-JWT claim row should have 'Claim path' label")
                        .contains("Claim path");
                assertThat(rowText)
                        .as("SD-JWT claim row should not have 'Namespace' label")
                        .doesNotContain("Namespace");
            }

            assertThat(errors)
                    .as("JavaScript console errors during format switching")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    @Test
    void mdocQuickAddButtonsUseMdocClaimNames() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            // Switch to mso_mdoc format
            page.locator("[data-field='format-select']").first().selectOption("mso_mdoc");
            page.waitForTimeout(300);

            // Quick-add buttons should show mdoc claim names
            String buttonsText = page.locator("#dcql-descriptors").textContent();
            assertThat(buttonsText)
                    .as("mDoc should have birth_date button (not birthdate)")
                    .contains("birth_date");
            assertThat(buttonsText)
                    .as("mDoc should have birth_place button (not place_of_birth)")
                    .contains("birth_place");
            assertThat(buttonsText)
                    .as("mDoc should have age_over_18 button (not age_equal_or_over)")
                    .contains("age_over_18");

            // SD-JWT specific names should NOT appear as quick-add buttons
            // Check that 'birthdate' (without underscore) does not appear as a button
            var addButtons = page.locator("#dcql-descriptors [data-action='add-claim']");
            boolean hasBirthdateButton = false;
            boolean hasPlaceOfBirthButton = false;
            for (int i = 0; i < addButtons.count(); i++) {
                String claim = addButtons.nth(i).getAttribute("data-claim");
                if ("birthdate".equals(claim)) hasBirthdateButton = true;
                if ("place_of_birth".equals(claim)) hasPlaceOfBirthButton = true;
            }
            assertThat(hasBirthdateButton)
                    .as("mDoc should NOT have 'birthdate' quick-add button")
                    .isFalse();
            assertThat(hasPlaceOfBirthButton)
                    .as("mDoc should NOT have 'place_of_birth' quick-add button")
                    .isFalse();

            // Switch back to SD-JWT and verify opposite
            page.locator("[data-field='format-select']").first().selectOption("dc+sd-jwt");
            page.waitForTimeout(300);

            var sdJwtButtons = page.locator("#dcql-descriptors [data-action='add-claim']");
            boolean hasBirthDateButton = false;
            boolean hasBirthPlaceButton = false;
            for (int i = 0; i < sdJwtButtons.count(); i++) {
                String claim = sdJwtButtons.nth(i).getAttribute("data-claim");
                if ("birth_date".equals(claim)) hasBirthDateButton = true;
                if ("birth_place".equals(claim)) hasBirthPlaceButton = true;
            }
            assertThat(hasBirthDateButton)
                    .as("SD-JWT should NOT have 'birth_date' quick-add button")
                    .isFalse();
            assertThat(hasBirthPlaceButton)
                    .as("SD-JWT should NOT have 'birth_place' quick-add button")
                    .isFalse();

            assertThat(errors)
                    .as("JavaScript console errors during quick-add button check")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    @Test
    void mdocBuilderGeneratesCorrectDcqlPaths() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            // Switch to mso_mdoc format
            page.locator("[data-field='format-select']").first().selectOption("mso_mdoc");
            page.waitForTimeout(300);

            // Click a quick-add button (e.g. birth_date)
            page.locator("[data-action='add-claim'][data-claim='birth_date']").first().click();
            page.waitForTimeout(1000);

            // Read the preview (builder initializes on page load so it should be valid JSON)
            String preview = page.locator("#dcql-builder-preview").textContent();
            var mapper = new tools.jackson.databind.ObjectMapper();
            var previewJson = mapper.readTree(preview);
            var dcql = previewJson.get("dcql_query");
            var credentials = dcql.get("credentials");
            var cred = credentials.get(0);

            assertThat(cred.get("format").asText()).isEqualTo("mso_mdoc");

            // Find the birth_date claim
            boolean foundBirthDate = false;
            for (var claim : cred.get("claims")) {
                var path = claim.get("path");
                if (path.size() == 2 && "birth_date".equals(path.get(1).asText())) {
                    assertThat(path.get(0).asText())
                            .as("mDoc claim namespace should be eu.europa.ec.eudi.pid.1")
                            .isEqualTo("eu.europa.ec.eudi.pid.1");
                    foundBirthDate = true;
                }
            }
            assertThat(foundBirthDate)
                    .as("DCQL should contain birth_date with [namespace, element] path")
                    .isTrue();

            // All mDoc claims should have exactly 2-element paths
            for (var claim : cred.get("claims")) {
                var path = claim.get("path");
                assertThat(path.size())
                        .as("mDoc claim path should have exactly 2 elements: " + path)
                        .isEqualTo(2);
            }

            assertThat(errors)
                    .as("JavaScript console errors during mDoc DCQL generation")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    @Test
    void sdJwtNestedClaimPathsGenerateMultiElementArrays() {
        List<String> errors = new ArrayList<>();
        Page page = browser.newPage();
        try {
            page.onConsoleMessage(msg -> {
                if ("error".equals(msg.type())) {
                    errors.add(msg.text());
                }
            });
            page.navigate("http://localhost:" + port + "/verifier");
            page.waitForLoadState();

            // Default format is dc+sd-jwt — click the "address/street_address" quick-add button
            page.locator("[data-action='add-claim'][data-claim='address/street_address']").first().click();
            page.waitForTimeout(500);

            // Read the preview
            String preview = page.locator("#dcql-builder-preview").textContent();
            var mapper = new tools.jackson.databind.ObjectMapper();
            var previewJson = mapper.readTree(preview);
            var dcql = previewJson.get("dcql_query");
            var cred = dcql.get("credentials").get(0);

            // Find the address/street_address claim — should be ["address", "street_address"]
            boolean found = false;
            for (var claim : cred.get("claims")) {
                var path = claim.get("path");
                if (path.size() == 2
                        && "address".equals(path.get(0).asText())
                        && "street_address".equals(path.get(1).asText())) {
                    found = true;
                }
            }
            assertThat(found)
                    .as("DCQL should contain ['address','street_address'] 2-element path")
                    .isTrue();

            assertThat(errors)
                    .as("JavaScript console errors during nested path generation")
                    .isEmpty();
        } finally {
            page.close();
        }
    }

    private static String toPem(byte[] der, String type) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }
}
