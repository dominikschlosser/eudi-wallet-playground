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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocCredentialBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocDeviceResponseBuilder;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtCredentialBuilder;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URLEncodedUtils;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

final class Oid4vpTestDcApiMockWalletServer implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Oid4vpTestDcApiMockWalletServer.class);

    // EUDI PID credential types
    private static final String PID_VCT_SD_JWT = "urn:eudi:pid:1";
    private static final String PID_DOCTYPE_MDOC = "eu.europa.ec.eudi.pid.1";

    // German PID (realistic - no unique identifiers)
    private static final String GERMAN_PID_VCT = "urn:eudi:pid:de:1";

    // Verifier-issued user credential (for user matching after initial registration)
    private static final String VERIFIER_USER_CREDENTIAL_VCT = "urn:arbeitsagentur:user_credential:1";

    // Default PID claim values
    private static final String DEFAULT_FAMILY_NAME = "Mustermann";
    private static final String DEFAULT_GIVEN_NAME = "Erika";
    private static final String DEFAULT_BIRTHDATE = "1984-01-26";
    private static final String DEFAULT_PERSONAL_ADMIN_NUMBER = "PAN-DE-123456789";
    private static final String DEFAULT_PERSONAL_ADMIN_NUMBER_MDOC = "PAN-DE-MDOC-456"; // Different for mDoc to avoid username conflicts
    private static final String ERROR_ACCESS_DENIED = "access_denied";
    private static final String ERROR_DESCRIPTION_NO_MATCHING_CREDENTIAL = "No credential matches the DCQL query";

    private final ObjectMapper objectMapper;
    private final String containerHost;
    private final HttpServer server;
    private final int port;
    private final SdJwtParser sdJwtParser;
    private final SdJwtCredentialBuilder sdJwtCredentialBuilder;
    private final MdocCredentialBuilder mdocCredentialBuilder;
    private final MdocDeviceResponseBuilder mdocDeviceResponseBuilder;
    private final ECKey issuerKey;
    private ECKey holderKey; // Can be replaced with external key for OID4VCI flow
    private final AtomicInteger requestCount = new AtomicInteger();
    private volatile String lastResponseUri;
    private volatile String lastResponseMode;
    private volatile String lastClientId;
    private volatile String lastNonce;
    private final AtomicReference<String> nextErrorCode = new AtomicReference<>();
    private final AtomicReference<String> nextErrorDescription = new AtomicReference<>();
    private final AtomicReference<String> nextPersonalId = new AtomicReference<>();
    private final AtomicReference<String> nextFormat = new AtomicReference<>(); // Force specific format: "dc+sd-jwt" or "mso_mdoc"
    private final AtomicReference<String> nextVerifierUserId = new AtomicReference<>(); // User ID for verifier credential
    private volatile boolean useGermanPid = false; // Use German PID (no identifiers) instead of default PID
    private volatile String lastPostResponseBody; // Diagnostic: last VP token POST response body
    private volatile int lastPostResponseCode; // Diagnostic: last VP token POST response code
    private volatile String lastDcqlQuery; // Last DCQL query received from Keycloak

    Oid4vpTestDcApiMockWalletServer(ObjectMapper objectMapper, String containerHost) throws Exception {
        this.objectMapper = objectMapper;
        this.containerHost = containerHost;
        this.sdJwtParser = new SdJwtParser(objectMapper);

        this.issuerKey = loadIssuerKey();
        this.sdJwtCredentialBuilder = new SdJwtCredentialBuilder(objectMapper, issuerKey, Duration.ofMinutes(5));
        this.mdocCredentialBuilder = new MdocCredentialBuilder(issuerKey, Duration.ofMinutes(5))
                .issuerCertificateChain(List.of(loadIssuerCertificate()));
        this.mdocDeviceResponseBuilder = new MdocDeviceResponseBuilder();
        this.holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder").generate();

        this.server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
        this.port = server.getAddress().getPort();
        server.createContext("/oid4vp/auth", this::handleAuth);
        server.start();
    }

    int requestCount() {
        return requestCount.get();
    }

    String containerBaseUrl() {
        return "http://%s:%d".formatted(containerHost, port);
    }

    String localBaseUrl() {
        return "http://localhost:%d".formatted(port);
    }

    String lastResponseUri() {
        return lastResponseUri;
    }

    String lastResponseMode() {
        return lastResponseMode;
    }

    String lastClientId() {
        return lastClientId;
    }

    String lastNonce() {
        return lastNonce;
    }

    String lastDcqlQuery() {
        return lastDcqlQuery;
    }

    void failNextRequestWithNoMatchingCredential() {
        nextErrorCode.set(ERROR_ACCESS_DENIED);
        nextErrorDescription.set(ERROR_DESCRIPTION_NO_MATCHING_CREDENTIAL);
    }

    /**
     * Simulate user denying/cancelling the credential share request.
     */
    void failNextRequestWithUserCancellation() {
        nextErrorCode.set(ERROR_ACCESS_DENIED);
        nextErrorDescription.set("User denied the credential request");
    }

    /**
     * Set a custom personal_id for the next request (for testing new user creation).
     */
    void setPersonalIdForNextRequest(String personalId) {
        nextPersonalId.set(personalId);
    }

    /**
     * Force a specific credential format for the next request.
     * @param format "dc+sd-jwt" or "mso_mdoc", or null to auto-detect from DCQL query
     */
    void setFormatForNextRequest(String format) {
        nextFormat.set(format);
    }

    /**
     * Set a verifier user ID for the next request (for multi-credential flow testing).
     * This will cause the wallet to include a verifier-issued credential with this user_id.
     */
    void setVerifierUserIdForNextRequest(String userId) {
        nextVerifierUserId.set(userId);
    }

    /**
     * Enable/disable German PID mode (credential without unique identifiers).
     * When enabled, the wallet will use urn:eudi:pid:de:1 instead of urn:eudi:pid:1.
     */
    void setUseGermanPid(boolean useGermanPid) {
        this.useGermanPid = useGermanPid;
    }

    /** Diagnostic: get the last VP token POST response body from the endpoint. */
    String getLastPostResponseBody() {
        return lastPostResponseBody;
    }

    /** Diagnostic: get the last VP token POST response code from the endpoint. */
    int getLastPostResponseCode() {
        return lastPostResponseCode;
    }

    /**
     * Simulate receiving a verifier-issued user credential via OID4VCI.
     * This simulates what would happen after the user goes through the OID4VCI flow
     * to obtain a user binding credential from the verifier.
     *
     * After calling this method, the mock wallet will include this credential
     * in multi-credential responses.
     *
     * @param userId The user ID to include in the credential (typically the Keycloak user ID)
     */
    void simulateCredentialIssuance(String userId) {
        LOG.info("[MockWallet] Simulating credential issuance for user_id: {}", userId);
        // Set the verifier user ID so it's included in subsequent multi-credential responses
        this.nextVerifierUserId.set(userId);
    }

    /**
     * Clear any simulated credentials (reset to initial state).
     */
    void clearSimulatedCredentials() {
        LOG.info("[MockWallet] Clearing simulated credentials");
        this.nextVerifierUserId.set(null);
        this.issuedUserCredential.set(null);
    }

    // Storage for actually issued credentials via OID4VCI
    private final AtomicReference<String> issuedUserCredential = new AtomicReference<>();

    /**
     * Store a credential that was issued via OID4VCI.
     * This credential will be presented in subsequent multi-credential responses.
     *
     * @param sdJwtCredential The issued SD-JWT credential (without key binding JWT)
     */
    void storeIssuedCredential(String sdJwtCredential) {
        LOG.info("[MockWallet] Storing issued credential (length: {})", sdJwtCredential != null ? sdJwtCredential.length() : 0);
        this.issuedUserCredential.set(sdJwtCredential);
    }

    /**
     * Check if the wallet has an issued credential stored.
     */
    boolean hasIssuedCredential() {
        return this.issuedUserCredential.get() != null;
    }

    /**
     * Get the stored issued credential.
     */
    String getIssuedCredential() {
        return this.issuedUserCredential.get();
    }

    /**
     * Set the holder key to use for credential presentations.
     * This allows sharing the key with an OID4VCI client so that
     * credentials issued via OID4VCI can be properly presented with key binding.
     *
     * @param holderKey The EC key to use for holder proof
     */
    void setHolderKey(ECKey holderKey) {
        LOG.info("[MockWallet] Setting external holder key: {}", holderKey.getKeyID());
        this.holderKey = holderKey;
    }

    /**
     * Get the current holder key (public part only).
     */
    ECKey getHolderPublicKey() {
        return this.holderKey.toPublicJWK();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handleAuth(HttpExchange exchange) throws IOException {
        LOG.info("[MockWallet] handleAuth called, method={}", exchange.getRequestMethod());
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        int count = requestCount.incrementAndGet();
        LOG.info("[MockWallet] Request #{} received: {}", count, exchange.getRequestURI());

        Map<String, String> params = new LinkedHashMap<>();
        for (NameValuePair pair : URLEncodedUtils.parse(exchange.getRequestURI(), StandardCharsets.UTF_8)) {
            params.put(pair.getName(), pair.getValue());
        }

        // Keep the original response_uri from URL params for form submission (the actual Keycloak endpoint)
        String formActionUri = params.get("response_uri");
        if (formActionUri == null || formActionUri.isBlank()) {
            formActionUri = params.get("redirect_uri");
        }

        // If a request_uri is present (same-device flow), fetch the request object from that URL
        String requestUri = params.get("request_uri");
        String requestJwt = params.get("request");
        if (requestUri != null && !requestUri.isBlank() && (requestJwt == null || requestJwt.isBlank())) {
            LOG.info("[MockWallet] Fetching request object from request_uri: {}", requestUri);
            try {
                requestJwt = fetchRequestObject(requestUri);
                LOG.info("[MockWallet] Fetched request JWT, length: {}", requestJwt != null ? requestJwt.length() : 0);
            } catch (Exception e) {
                LOG.error("[MockWallet] Failed to fetch request object from {}: {}", requestUri, e.getMessage());
                exchange.sendResponseHeaders(400, -1);
                return;
            }
        }

        // If a signed request JWT is present, parse it to extract parameters
        // Note: JWT response_uri is used for SessionTranscript (for mDoc verification)
        String sessionTranscriptResponseUri = null;
        if (requestJwt != null && !requestJwt.isBlank()) {
            try {
                JsonNode jwtClaims = parseJwtPayload(requestJwt);
                if (jwtClaims.has("state")) params.putIfAbsent("state", jwtClaims.get("state").asText());
                if (jwtClaims.has("nonce")) params.putIfAbsent("nonce", jwtClaims.get("nonce").asText());
                if (jwtClaims.has("client_id")) params.putIfAbsent("client_id", jwtClaims.get("client_id").asText());
                if (jwtClaims.has("response_mode")) params.putIfAbsent("response_mode", jwtClaims.get("response_mode").asText());
                // response_uri from JWT is used for SessionTranscript
                if (jwtClaims.has("response_uri")) sessionTranscriptResponseUri = jwtClaims.get("response_uri").asText();
                if (jwtClaims.has("dcql_query")) params.putIfAbsent("dcql_query", jwtClaims.get("dcql_query").toString());
                if (jwtClaims.has("client_metadata")) params.putIfAbsent("client_metadata", jwtClaims.get("client_metadata").toString());
            } catch (Exception e) {
                LOG.error("[MockWallet] Failed to parse request JWT: {}", e.getMessage());
                exchange.sendResponseHeaders(400, -1);
                return;
            }
        }

        // For same-device flow, formActionUri may not be in URL params - use JWT response_uri
        if ((formActionUri == null || formActionUri.isBlank()) && sessionTranscriptResponseUri != null) {
            formActionUri = sessionTranscriptResponseUri;
        }

        // For SessionTranscript, prefer JWT response_uri, fall back to URL param
        String responseUri = (sessionTranscriptResponseUri != null && !sessionTranscriptResponseUri.isBlank())
                ? sessionTranscriptResponseUri
                : formActionUri;
        String state = params.get("state");
        String nonce = params.get("nonce");
        String clientId = params.get("client_id");
        String responseMode = params.getOrDefault("response_mode", "");
        String clientMetadata = params.get("client_metadata");
        if (responseUri == null || responseUri.isBlank() || state == null || state.isBlank() || nonce == null || nonce.isBlank()) {
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        this.lastNonce = nonce;
        this.lastResponseMode = responseMode;
        this.lastResponseUri = responseUri;
        this.lastClientId = clientId;
        this.lastDcqlQuery = params.get("dcql_query");

        String errorCode = nextErrorCode.getAndSet(null);
        String errorDesc = nextErrorDescription.getAndSet(null);
        if (errorCode == null && !canSatisfyDcqlQuery(params.get("dcql_query"))) {
            errorCode = ERROR_ACCESS_DENIED;
            errorDesc = ERROR_DESCRIPTION_NO_MATCHING_CREDENTIAL;
        }

        String audience = clientId != null && !clientId.isBlank() ? clientId : responseUri;
        boolean encrypted = "direct_post.jwt".equalsIgnoreCase(responseMode);
        // Use forced format if set, otherwise detect from DCQL query
        String forcedFormat = nextFormat.getAndSet(null);
        String requestedFormat = forcedFormat != null ? forcedFormat : detectRequestedFormat(params.get("dcql_query"));
        LOG.info("[MockWallet] Using format: {} (forced: {})", requestedFormat, forcedFormat != null);
        JWK handoverJwk = extractHandoverJwk(clientMetadata);

        // Check if multi-credential response is required
        String dcqlQuery = params.get("dcql_query");
        boolean multiCredential = isMultiCredentialRequired(dcqlQuery);
        String verifierUserId = nextVerifierUserId.getAndSet(null);
        boolean hasIssuedCredential = issuedUserCredential.get() != null;
        LOG.info("[MockWallet] Multi-credential mode: {}, verifierUserId: {}, hasIssuedCredential: {}",
                multiCredential, verifierUserId, hasIssuedCredential);

        Map<String, String> fields = new LinkedHashMap<>();
        if (encrypted) {
            try {
                String payload;
                if (errorCode != null && !errorCode.isBlank()) {
                    payload = objectMapper.writeValueAsString(Map.of(
                            "error", errorCode,
                            "error_description", errorDesc != null ? errorDesc : "",
                            "state", state
                    ));
                } else if (multiCredential && (verifierUserId != null || hasIssuedCredential)) {
                    // Build multi-credential VP token
                    Map<String, List<String>> vpTokenMap = buildMultiCredentialVpToken(dcqlQuery, nonce, audience, verifierUserId);
                    payload = objectMapper.writeValueAsString(Map.of("vp_token", vpTokenMap, "state", state));
                    LOG.info("[MockWallet] Built multi-credential encrypted response with {} credentials", vpTokenMap.size());
                } else {
                    String vpToken = buildPresentation(requestedFormat, nonce, audience, responseUri, handoverJwk, dcqlQuery);
                    String vpTokenParam = objectMapper.writeValueAsString(Map.of("pid", List.of(vpToken)));
                    payload = objectMapper.writeValueAsString(Map.of("vp_token", objectMapper.readTree(vpTokenParam), "state", state));
                }
                String encryptedResponse = encryptResponse(payload, clientMetadata);
                fields.put("response", encryptedResponse);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
                return;
            }
        } else if (errorCode != null && !errorCode.isBlank()) {
            fields.put("state", state);
            fields.put("error", errorCode);
            if (errorDesc != null && !errorDesc.isBlank()) {
                fields.put("error_description", errorDesc);
            }
        } else if (multiCredential && (verifierUserId != null || hasIssuedCredential)) {
            // Build multi-credential VP token
            Map<String, List<String>> vpTokenMap = buildMultiCredentialVpToken(dcqlQuery, nonce, audience, verifierUserId);
            fields.put("state", state);
            fields.put("vp_token", objectMapper.writeValueAsString(vpTokenMap));
            LOG.info("[MockWallet] Built multi-credential response with {} credentials", vpTokenMap.size());
        } else {
            String vpToken = buildPresentation(requestedFormat, nonce, audience, responseUri, handoverJwk, dcqlQuery);
            String vpTokenParam = objectMapper.writeValueAsString(Map.of("pid", List.of(vpToken)));
            fields.put("state", state);
            fields.put("vp_token", vpTokenParam);
        }

        // Use formActionUri for the actual form submission, not responseUri (which is for SessionTranscript)
        String actualFormAction = (formActionUri != null && !formActionUri.isBlank()) ? formActionUri : responseUri;
        boolean isNativeWalletFlow = requestUri != null && !requestUri.isBlank();
        if (encrypted && isNativeWalletFlow) {
            // Real wallets using direct_post.jwt do NOT send state externally.
            // State is only inside the encrypted JWE payload.
            fields.remove("state");
            LOG.info("[MockWallet] Encrypted native wallet flow: state only inside JWE, not sent externally");
        } else if (state != null && !state.isBlank()) {
            // Append state to query string like real wallets do
            String encodedState = URLEncoder.encode(state, StandardCharsets.UTF_8);
            actualFormAction = actualFormAction + (actualFormAction.contains("?") ? "&" : "?") + "state=" + encodedState;
            // Remove state from form body since it's now in URL
            fields.remove("state");
        }
        LOG.info("[MockWallet] formAction={}, responseMode={}, encrypted={}", actualFormAction, responseMode, encrypted);
        LOG.info("[MockWallet] state={}, nonce={}", state, nonce);

        // Native wallet flow: both same-device and cross-device use request_uri,
        // meaning the wallet fetches the request object JWT and POSTs the VP token server-side.
        // Distinguish by checking if response_uri contains flow=cross_device.
        boolean isCrossDeviceFlow = actualFormAction.contains("flow=cross_device");
        if (isNativeWalletFlow) {
            if (isCrossDeviceFlow) {
                // Cross-device: POST VP token server-side, expect {} response (no redirect_uri).
                LOG.info("[MockWallet] Cross-device flow: POSTing VP token server-side to {}", actualFormAction);
                try {
                    String responseBody = postVpTokenRaw(actualFormAction, fields);
                    LOG.info("[MockWallet] Cross-device response: {}", responseBody);
                    // Verify the endpoint returned empty JSON (no redirect_uri for cross-device)
                    if (responseBody != null && responseBody.contains("redirect_uri")) {
                        throw new IOException("Cross-device flow received redirect_uri, expected empty JSON: " + responseBody);
                    }
                    // Return 200 OK to the test (nothing more for cross-device wallet to do)
                    byte[] okBytes = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(200, okBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(okBytes);
                    }
                } catch (Exception e) {
                    LOG.error("[MockWallet] Cross-device POST failed: {}", e.getMessage(), e);
                    byte[] errBytes = ("{\"error\":\"post_failed\",\"detail\":\"" + htmlAttr(e.getMessage()) + "\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(500, errBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(errBytes);
                    }
                }
            } else {
                // Same-device: POST VP token server-side, expect redirect_uri in response.
                LOG.info("[MockWallet] Same-device flow: POSTing VP token server-side to {}", actualFormAction);
                try {
                    String redirectUri = postVpTokenAndGetRedirect(actualFormAction, fields);
                    if (redirectUri != null && !redirectUri.isBlank()) {
                        LOG.info("[MockWallet] Same-device: opening redirect_uri in browser: {}", redirectUri);
                        exchange.getResponseHeaders().add("Location", redirectUri);
                        exchange.sendResponseHeaders(302, -1);
                    } else {
                        LOG.error("[MockWallet] Same-device: no redirect_uri in response! Body: {}", lastPostResponseBody);
                        byte[] errBytes = ("{\"error\":\"no_redirect_uri\",\"detail\":\"" + htmlAttr(lastPostResponseBody) + "\"}")
                                .getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
                        exchange.sendResponseHeaders(400, errBytes.length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(errBytes);
                        }
                    }
                } catch (Exception e) {
                    LOG.error("[MockWallet] Same-device POST failed: {}", e.getMessage(), e);
                    byte[] errBytes = ("{\"error\":\"post_failed\",\"detail\":\"" + htmlAttr(e.getMessage()) + "\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(500, errBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(errBytes);
                    }
                }
            }
            return;
        }

        // DC API / popup flow: return HTML with auto-submit form (browser submits with cookies)
        String html = buildDirectPostHtml(actualFormAction, fields);
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        // Allow the popup to access window.opener (cross-origin)
        exchange.getResponseHeaders().add("Cross-Origin-Opener-Policy", "unsafe-none");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String buildDirectPostHtml(String responseUri, Map<String, String> fields) {
        StringBuilder inputs = new StringBuilder();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            String name = entry.getKey();
            if (name == null || name.isBlank()) {
                continue;
            }
            String value = entry.getValue() != null ? entry.getValue() : "";
            inputs.append("<input type=\"hidden\" name=\"")
                    .append(htmlAttr(name))
                    .append("\" value=\"")
                    .append(htmlAttr(value))
                    .append("\"/>");
        }

        return """
                <!doctype html>
                <html>
                  <head><meta charset="utf-8"><title>Mock Wallet</title></head>
                  <body>
                    <p id="status">Submitting response...</p>
                    <form id="responseForm" method="post" action="%s">%s</form>
                    <script>
                      (function() {
                        var status = document.getElementById('status');
                        var form = document.getElementById('responseForm');
                        var formData = {};
                        var inputs = form.querySelectorAll('input');
                        for (var i = 0; i < inputs.length; i++) {
                          formData[inputs[i].name] = inputs[i].value;
                        }

                        status.textContent = 'opener=' + (window.opener ? 'yes' : 'no') + ', formAction=' + form.action.substring(0, 50);

                        // Try to notify opener via postMessage (for extension bridge flow)
                        if (window.opener) {
                          try {
                            console.log('[Mock Wallet] Sending postMessage to opener');
                            window.opener.postMessage({
                              type: 'oid4vp_wallet_response',
                              responseUri: form.action,
                              data: formData
                            }, '*');
                            status.textContent += ' | postMessage sent';
                          } catch (e) {
                            console.error('[Mock Wallet] postMessage failed:', e);
                            status.textContent += ' | postMessage error: ' + e.message;
                          }
                        } else {
                          status.textContent += ' | no opener!';
                        }

                        // Auto-submit after a delay as fallback
                        // The extension content script should intercept this, or webRequest will catch it
                        setTimeout(function() {
                          console.log('[Mock Wallet] Auto-submit triggered');
                          status.textContent += ' | submitting...';
                          form.submit();
                        }, 500);
                      })();
                    </script>
                  </body>
                </html>
                """.formatted(htmlAttr(responseUri), inputs.toString());
    }

    private String encryptResponse(String jsonPayload, String clientMetadataJson) throws Exception {
        if (clientMetadataJson == null || clientMetadataJson.isBlank()) {
            throw new IllegalStateException("Missing client_metadata");
        }
        JsonNode meta = objectMapper.readTree(clientMetadataJson);
        JsonNode jwksNode = meta.get("jwks");
        if (jwksNode == null || jwksNode.isMissingNode()) {
            throw new IllegalStateException("client_metadata.jwks missing");
        }
        JWKSet set = JWKSet.parse(jwksNode.toString());
        JWK jwk = set.getKeys().stream()
                .filter(k -> k.getAlgorithm() != null)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No suitable encryption key found"));

        JWEAlgorithm jweAlg = JWEAlgorithm.parse(jwk.getAlgorithm().getName());
        EncryptionMethod jweEnc = EncryptionMethod.A128GCM;
        // OID4VP 1.0: encrypted_response_enc_values_supported declares supported content encryption methods
        JsonNode encValues = meta.get("encrypted_response_enc_values_supported");
        if (encValues != null && encValues.isArray() && !encValues.isEmpty()) {
            String enc = encValues.get(0).asText(null);
            if (enc != null && !enc.isBlank()) {
                jweEnc = EncryptionMethod.parse(enc);
            }
        }
        JWEHeader.Builder header = new JWEHeader.Builder(jweAlg, jweEnc);
        if (jwk.getKeyID() != null && !jwk.getKeyID().isBlank()) {
            header.keyID(jwk.getKeyID());
        }
        JWEObject jwe = new JWEObject(header.build(), new Payload(jsonPayload));
        if (jwk instanceof RSAKey rsaKey) {
            jwe.encrypt(new RSAEncrypter(rsaKey));
        } else if (jwk instanceof ECKey ecKey) {
            jwe.encrypt(new ECDHEncrypter(ecKey));
        } else {
            throw new IllegalStateException("Unsupported encryption key type: " + jwk.getKeyType());
        }
        return jwe.serialize();
    }

    /**
     * Detect the requested credential format from a DCQL query.
     * When credential_sets are present (allowing multiple credential types),
     * prefer SD-JWT format as default, but respect the credential_sets options.
     */
    private String detectRequestedFormat(String dcqlQueryRaw) {
        if (dcqlQueryRaw == null || dcqlQueryRaw.isBlank()) {
            return "dc+sd-jwt";
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQueryRaw);
            JsonNode credentials = root.get("credentials");
            if (credentials == null || !credentials.isArray() || credentials.isEmpty()) {
                return "dc+sd-jwt";
            }

            // Build a map of credential ID to format
            Map<String, String> credentialIdToFormat = new LinkedHashMap<>();
            for (JsonNode credentialRequest : credentials) {
                if (!credentialRequest.isObject()) {
                    continue;
                }
                String id = credentialRequest.has("id") ? credentialRequest.get("id").asText() : null;
                String format = credentialRequest.has("format") ? credentialRequest.get("format").asText() : null;
                if (id != null && format != null) {
                    credentialIdToFormat.put(id, format);
                }
            }

            // Check for credential_sets to determine which credential(s) are acceptable
            JsonNode credentialSets = root.get("credential_sets");
            if (credentialSets != null && credentialSets.isArray() && !credentialSets.isEmpty()) {
                // credential_sets present - need to pick from the options
                for (JsonNode credentialSet : credentialSets) {
                    JsonNode options = credentialSet.get("options");
                    if (options == null || !options.isArray()) {
                        continue;
                    }
                    // Each option is an array of credential IDs that together satisfy this set
                    // For "optional" mode (our default), each option contains one credential ID
                    // Pick the first option we can satisfy (prefer SD-JWT if available)
                    String preferredFormat = null;
                    for (JsonNode option : options) {
                        if (!option.isArray() || option.isEmpty()) {
                            continue;
                        }
                        // Get the credential ID from this option
                        String credId = option.get(0).asText();
                        String format = credentialIdToFormat.get(credId);
                        if (format != null) {
                            // Prefer SD-JWT, but remember any valid format
                            if ("dc+sd-jwt".equals(format)) {
                                return format; // Prefer SD-JWT
                            }
                            if (preferredFormat == null) {
                                preferredFormat = format;
                            }
                        }
                    }
                    if (preferredFormat != null) {
                        return preferredFormat;
                    }
                }
            }

            // No credential_sets or couldn't find a matching format - fall back to first credential
            for (JsonNode credentialRequest : credentials) {
                if (!credentialRequest.isObject()) {
                    continue;
                }
                JsonNode format = credentialRequest.get("format");
                if (format != null && format.isTextual()) {
                    return format.asText();
                }
            }
        } catch (Exception ignored) {
        }
        return "dc+sd-jwt";
    }

    private JWK extractHandoverJwk(String clientMetadataRaw) {
        if (clientMetadataRaw == null || clientMetadataRaw.isBlank()) {
            return null;
        }
        try {
            JsonNode metadata = objectMapper.readTree(clientMetadataRaw);
            JsonNode jwksNode = metadata.get("jwks");
            if (jwksNode == null || !jwksNode.isObject()) {
                return null;
            }
            JWKSet jwks = JWKSet.parse(objectMapper.writeValueAsString(jwksNode));
            // Return first key in JWKS - this is the key Keycloak uses for response encryption
            // and whose thumbprint should be included in mDoc SessionTranscript
            return jwks.getKeys().isEmpty() ? null : jwks.getKeys().get(0);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Fetch a request object JWT from a request_uri (used in same-device/redirect flow).
     */
    private String fetchRequestObject(String requestUri) throws IOException {
        LOG.info("[MockWallet] Fetching request object from: {}", requestUri);
        java.net.URL url = new java.net.URL(requestUri);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/oauth-authz-req+jwt");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new IOException("Failed to fetch request object: HTTP " + responseCode);
        }

        try (java.io.InputStream is = conn.getInputStream();
             java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    /**
     * POST VP token to the Keycloak endpoint server-side (simulating a native wallet app).
     * Enforces real wallet behavior:
     * - Does NOT send any cookies (native wallet app has no browser session)
     * - Rejects non-JSON responses (real wallets crash on HTML)
     * - For same-device: expects JSON with redirect_uri
     * Returns the redirect_uri from the JSON response, or null if not present.
     */
    private String postVpTokenAndGetRedirect(String formAction, Map<String, String> fields) throws IOException {
        String responseBody = postVpTokenRaw(formAction, fields);

        if (responseBody != null && !responseBody.isBlank()) {
            JsonNode json = objectMapper.readTree(responseBody);
            if (json.has("redirect_uri")) {
                return json.get("redirect_uri").asText();
            }
        }

        return null;
    }

    /**
     * Low-level POST to Keycloak endpoint, simulating a native wallet app.
     * Enforces real wallet constraints:
     * - No cookies sent
     * - Response must be JSON (rejects HTML, redirects)
     * Returns the raw JSON response body.
     */
    private String postVpTokenRaw(String formAction, Map<String, String> fields) throws IOException {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (!body.isEmpty()) body.append("&");
            body.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                .append("=")
                .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }

        java.net.URL url = new java.net.URL(formAction);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        // Real wallet: explicitly do NOT send cookies
        conn.setRequestProperty("Cookie", "");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setInstanceFollowRedirects(false);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        lastPostResponseCode = responseCode;
        String contentType = conn.getContentType();
        LOG.info("[MockWallet] POST {} → status={}, content-type={}", formAction, responseCode, contentType);

        // Real wallet enforcement: reject redirects (wallet is not a browser)
        if (responseCode == 302 || responseCode == 303) {
            String location = conn.getHeaderField("Location");
            lastPostResponseBody = "REDIRECT: " + location;
            throw new IOException("Wallet received redirect (status " + responseCode + ") instead of JSON. " +
                    "Location: " + location + ". Endpoints MUST return JSON to wallets, never redirects.");
        }

        // Read response body
        String responseBody;
        java.io.InputStream stream = (responseCode >= 200 && responseCode < 300)
                ? conn.getInputStream() : conn.getErrorStream();
        if (stream != null) {
            responseBody = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            responseBody = "";
        }
        lastPostResponseBody = responseBody;
        LOG.info("[MockWallet] POST response body (first 500): {}",
                responseBody.substring(0, Math.min(500, responseBody.length())));

        // Real wallet enforcement: reject HTML responses
        if (contentType != null && contentType.contains("text/html")) {
            throw new IOException("Wallet received HTML instead of JSON. Status: " + responseCode +
                    ", Body: " + responseBody.substring(0, Math.min(200, responseBody.length())) +
                    ". Endpoints MUST return JSON to wallets, never HTML.");
        }

        return responseBody;
    }

    private String buildPresentation(String format, String nonce, String audience, String responseUri, JWK handoverJwk, String dcqlQuery) {
        Set<String> requestedClaims = extractRequestedClaims(dcqlQuery, format);
        if ("mso_mdoc".equalsIgnoreCase(format)) {
            return buildMdocPresentation(nonce, audience, responseUri, handoverJwk, requestedClaims);
        }
        // Check if German PID mode is enabled - if so, use the German PID builder
        if (useGermanPid) {
            LOG.info("[MockWallet] Using German PID (no unique identifiers) for single credential response");
            return buildGermanPidPresentation(nonce, audience);
        }
        return buildSdJwtPresentation(nonce, audience, requestedClaims);
    }

    private String buildMdocPresentation(String nonce, String audience, String responseUri, JWK handoverJwk, Set<String> requestedClaims) {
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));
        String adminNumber = nextPersonalId.getAndSet(null);
        if (adminNumber == null) {
            adminNumber = DEFAULT_PERSONAL_ADMIN_NUMBER_MDOC;
        }
        // Build EUDI PID mDoc claims according to the official spec
        // Only include claims that are requested (or all if no specific claims requested)
        Map<String, Object> allClaims = new LinkedHashMap<>();
        allClaims.put("family_name", DEFAULT_FAMILY_NAME);
        allClaims.put("given_name", DEFAULT_GIVEN_NAME);
        allClaims.put("birth_date", DEFAULT_BIRTHDATE);
        allClaims.put("administrative_number", adminNumber);
        allClaims.put("document_number", "DOC-" + adminNumber);
        allClaims.put("nationality", "DE");
        allClaims.put("birth_place", "Berlin");
        allClaims.put("birth_country", "DE");
        allClaims.put("issuing_country", "DE");
        allClaims.put("issuing_authority", "Test Issuer");

        Map<String, Object> claims;
        if (requestedClaims == null || requestedClaims.isEmpty()) {
            claims = allClaims;
        } else {
            claims = new LinkedHashMap<>();
            for (String claimName : requestedClaims) {
                if (allClaims.containsKey(claimName)) {
                    claims.put(claimName, allClaims.get(claimName));
                }
            }
            LOG.info("[MockWallet] mDoc filtered claims: {} (from requested: {})", claims.keySet(), requestedClaims);
        }

        String issuerSigned = mdocCredentialBuilder.build("pid", PID_DOCTYPE_MDOC, "https://issuer.example", claims, cnf).encoded();
        String deviceResponse = mdocDeviceResponseBuilder.buildDeviceResponse(issuerSigned, holderKey, audience, nonce, responseUri, handoverJwk);
        LOG.info("[MockWallet] Built mDoc, issuerSigned length={}, deviceResponse length={}", issuerSigned.length(), deviceResponse.length());
        LOG.info("[MockWallet] handoverJwk={}", handoverJwk != null ? handoverJwk.getKeyID() : "null");
        return deviceResponse;
    }

    private String buildSdJwtPresentation(String nonce, String audience, Set<String> requestedClaims) {
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));
        String personalAdminNumber = nextPersonalId.getAndSet(null);
        if (personalAdminNumber == null) {
            personalAdminNumber = DEFAULT_PERSONAL_ADMIN_NUMBER;
        }
        // Build EUDI PID claims according to the official spec
        // Only include claims that are requested (or all if no specific claims requested)
        Map<String, Object> allClaims = new LinkedHashMap<>();
        allClaims.put("family_name", DEFAULT_FAMILY_NAME);
        allClaims.put("given_name", DEFAULT_GIVEN_NAME);
        allClaims.put("birthdate", DEFAULT_BIRTHDATE);
        allClaims.put("personal_administrative_number", personalAdminNumber);
        allClaims.put("document_number", "DOC-" + personalAdminNumber);
        allClaims.put("nationalities", List.of("DE"));
        allClaims.put("place_of_birth.locality", "Berlin");
        allClaims.put("place_of_birth.country", "DE");
        allClaims.put("issuing_country", "DE");
        allClaims.put("issuing_authority", "Test Issuer");

        Map<String, Object> claims;
        if (requestedClaims == null || requestedClaims.isEmpty()) {
            claims = allClaims;
        } else {
            claims = new LinkedHashMap<>();
            for (String claimName : requestedClaims) {
                // Handle nested claims like "place_of_birth" which map to "place_of_birth.locality" etc.
                if (allClaims.containsKey(claimName)) {
                    claims.put(claimName, allClaims.get(claimName));
                } else if ("place_of_birth".equals(claimName)) {
                    // Special handling for nested claim
                    claims.put("place_of_birth.locality", allClaims.get("place_of_birth.locality"));
                    claims.put("place_of_birth.country", allClaims.get("place_of_birth.country"));
                }
            }
            LOG.info("[MockWallet] SD-JWT filtered claims: {} (from requested: {})", claims.keySet(), requestedClaims);
        }

        String sdJwt = sdJwtCredentialBuilder.build("pid", PID_VCT_SD_JWT, "https://issuer.example", claims, cnf).encoded();

        SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwt);
        String sdHash;
        try {
            sdHash = SdJwtUtils.computeSdHash(parts, objectMapper);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute sd_hash", e);
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .keyID(holderKey.getKeyID())
                .build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .build();
        SignedJWT kbJwt = new SignedJWT(header, claimsSet);
        try {
            kbJwt.sign(new ECDSASigner(holderKey));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign kb+jwt", e);
        }

        String rebuilt = parts.signedJwt();
        if (parts.disclosures() != null) {
            for (String disclosure : parts.disclosures()) {
                if (disclosure != null && !disclosure.isBlank()) {
                    rebuilt = rebuilt + "~" + disclosure;
                }
            }
        }
        return rebuilt + "~" + kbJwt.serialize();
    }

    private ECKey loadIssuerKey() throws Exception {
        try (var is = Oid4vpTestDcApiMockWalletServer.class.getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).isNotNull();
            JsonNode node = objectMapper.readTree(is);
            ECKey key = ECKey.parse(node.get("privateJwk").toString());
            LOG.info("[MockWallet] Loaded issuer key: x={}, y={}", key.getX(), key.getY());
            return key;
        }
    }

    /**
     * Load the issuer X.509 certificate matching the mock-issuer key.
     * This certificate is the same one in the test trust list.
     */
    private static java.security.cert.X509Certificate loadIssuerCertificate() throws Exception {
        // This is the mock-issuer self-signed certificate from the test trust list.
        String certBase64 = "MIIBgTCCASegAwIBAgIUBjEaIhGcW5pPX7vCtXbqMyql7ewwCgYIKoZIzj0EAwIw"
                + "FjEUMBIGA1UEAwwLbW9jay1pc3N1ZXIwHhcNMjUxMjAxMDkzOTI2WhcNMzUxMTI5"
                + "MDkzOTI2WjAWMRQwEgYDVQQDDAttb2NrLWlzc3VlcjBZMBMGByqGSM49AgEGCCqG"
                + "SM49AwEHA0IABCSGo02fNJ4ilyIJVsnR90UMvBEhbDxpvIN/X+Rq4y9qjCA35Inb"
                + "wm5jF0toypoov4aagJGaRkwzmvOy1JMlamKjUzBRMB0GA1UdDgQWBBR2mOx26507"
                + "8nBXsMCf07e99RBlDDAfBgNVHSMEGDAWgBR2mOx265078nBXsRCf07e99RBlDDAP"
                + "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDc1Evb58VWAGTNgiad"
                + "stQmCL6YL3ChASt/VLhgA/ogbAIgK5DjLQuY0dVDTaDccEC9s/uaKu+z5u28ZtQj"
                + "VK65zFU=";
        byte[] certBytes = java.util.Base64.getDecoder().decode(certBase64);
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        return (java.security.cert.X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(certBytes));
    }

    /**
     * Build a German PID SD-JWT presentation (without unique identifiers like document_number).
     * This simulates the real German PID which doesn't have globally unique identifiers.
     */
    private String buildGermanPidPresentation(String nonce, String audience) {
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));

        // German PID claims - NO document_number, NO administrative_number
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("family_name", DEFAULT_FAMILY_NAME);
        claims.put("given_name", DEFAULT_GIVEN_NAME);
        claims.put("birthdate", DEFAULT_BIRTHDATE);
        claims.put("place_of_birth.locality", "Berlin");
        claims.put("place_of_birth.country", "DE");
        claims.put("nationalities", List.of("DE"));
        claims.put("issuing_country", "DE");
        claims.put("issuing_authority", "Bundesdruckerei");

        // Use mock-issuer URL to ensure credential is trusted by the same trust list
        String sdJwt = sdJwtCredentialBuilder.build("german_pid", GERMAN_PID_VCT, "https://mock-issuer.example", claims, cnf).encoded();

        SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwt);
        String sdHash;
        try {
            sdHash = SdJwtUtils.computeSdHash(parts, objectMapper);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute sd_hash", e);
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .keyID(holderKey.getKeyID())
                .build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .build();
        SignedJWT kbJwt = new SignedJWT(header, claimsSet);
        try {
            kbJwt.sign(new ECDSASigner(holderKey));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign kb+jwt", e);
        }

        String rebuilt = parts.signedJwt();
        if (parts.disclosures() != null) {
            for (String disclosure : parts.disclosures()) {
                if (disclosure != null && !disclosure.isBlank()) {
                    rebuilt = rebuilt + "~" + disclosure;
                }
            }
        }
        return rebuilt + "~" + kbJwt.serialize();
    }

    /**
     * Build a verifier-issued user credential SD-JWT presentation.
     * This is the credential issued by the verifier after initial registration,
     * containing only the user_id for subsequent matching.
     */
    private String buildVerifierUserCredentialPresentation(String nonce, String audience, String userId) {
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));

        // Verifier user credential claims - just user_id and linked_at
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("user_id", userId);
        claims.put("linked_at", Instant.now().toString());

        // Use mock-issuer URL to ensure credential is trusted by the same trust list as PID credentials
        String sdJwt = sdJwtCredentialBuilder.build("verifier_user", VERIFIER_USER_CREDENTIAL_VCT, "https://mock-issuer.example", claims, cnf).encoded();

        SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwt);
        String sdHash;
        try {
            sdHash = SdJwtUtils.computeSdHash(parts, objectMapper);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute sd_hash", e);
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .keyID(holderKey.getKeyID())
                .build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .build();
        SignedJWT kbJwt = new SignedJWT(header, claimsSet);
        try {
            kbJwt.sign(new ECDSASigner(holderKey));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign kb+jwt", e);
        }

        String rebuilt = parts.signedJwt();
        if (parts.disclosures() != null) {
            for (String disclosure : parts.disclosures()) {
                if (disclosure != null && !disclosure.isBlank()) {
                    rebuilt = rebuilt + "~" + disclosure;
                }
            }
        }
        return rebuilt + "~" + kbJwt.serialize();
    }

    /**
     * Add key binding JWT to an existing SD-JWT credential.
     * This is used for credentials issued via OID4VCI that need to be presented with proof of possession.
     *
     * @param sdJwtCredential The SD-JWT credential (issuer JWT + disclosures, no key binding)
     * @param nonce The nonce for key binding
     * @param audience The audience for the presentation
     * @return The credential with key binding JWT appended
     */
    private String addKeyBindingToCredential(String sdJwtCredential, String nonce, String audience) {
        try {
            // Parse the SD-JWT to get its parts
            SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwtCredential);

            // Compute the sd_hash
            String sdHash = SdJwtUtils.computeSdHash(parts, objectMapper);

            // Build the key binding JWT
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("kb+jwt"))
                    .keyID(holderKey.getKeyID())
                    .build();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .claim("nonce", nonce)
                    .claim("sd_hash", sdHash)
                    .build();
            SignedJWT kbJwt = new SignedJWT(header, claimsSet);
            kbJwt.sign(new ECDSASigner(holderKey));

            // Rebuild the credential with key binding
            String rebuilt = parts.signedJwt();
            if (parts.disclosures() != null) {
                for (String disclosure : parts.disclosures()) {
                    if (disclosure != null && !disclosure.isBlank()) {
                        rebuilt = rebuilt + "~" + disclosure;
                    }
                }
            }
            return rebuilt + "~" + kbJwt.serialize();
        } catch (Exception e) {
            LOG.error("[MockWallet] Failed to add key binding to credential: {}", e.getMessage(), e);
            throw new IllegalStateException("Failed to add key binding to credential", e);
        }
    }

    /**
     * Build a multi-credential VP token for DCQL queries that require multiple credentials.
     * Returns a map of credential ID to list of credentials (OID4VP format).
     *
     * @param dcqlQuery The DCQL query JSON
     * @param nonce The nonce for key binding
     * @param audience The audience for the presentation
     * @param userId The user ID for the verifier credential (if requested)
     * @return A map that can be serialized to JSON for vp_token
     */
    private Map<String, List<String>> buildMultiCredentialVpToken(String dcqlQuery, String nonce, String audience, String userId) {
        Map<String, List<String>> vpToken = new LinkedHashMap<>();

        try {
            JsonNode root = objectMapper.readTree(dcqlQuery);
            JsonNode credentials = root.get("credentials");
            if (credentials == null || !credentials.isArray()) {
                return vpToken;
            }

            for (JsonNode credentialRequest : credentials) {
                String credId = credentialRequest.has("id") ? credentialRequest.get("id").asText() : null;
                if (credId == null) continue;

                JsonNode meta = credentialRequest.get("meta");
                String vct = null;
                if (meta != null && meta.has("vct_values") && meta.get("vct_values").isArray()) {
                    vct = meta.get("vct_values").get(0).asText();
                }

                if (vct == null) continue;

                String credential = null;
                if (vct.equals(GERMAN_PID_VCT)) {
                    credential = buildGermanPidPresentation(nonce, audience);
                    LOG.info("[MockWallet] Built German PID credential for id: {}", credId);
                } else if (vct.equals(VERIFIER_USER_CREDENTIAL_VCT)) {
                    // Check if we have a real OID4VCI-issued credential stored
                    String storedCredential = issuedUserCredential.get();
                    if (storedCredential != null && !storedCredential.isBlank()) {
                        credential = addKeyBindingToCredential(storedCredential, nonce, audience);
                        LOG.info("[MockWallet] Using stored OID4VCI-issued credential with key binding for id: {}", credId);
                    } else if (userId != null) {
                        credential = buildVerifierUserCredentialPresentation(nonce, audience, userId);
                        LOG.info("[MockWallet] Built simulated verifier user credential for id: {}", credId);
                    } else {
                        LOG.warn("[MockWallet] No stored credential and no userId for verifier user credential");
                    }
                } else if (vct.equals(PID_VCT_SD_JWT)) {
                    // Use the standard PID builder
                    Set<String> requestedClaims = extractRequestedClaims(dcqlQuery, "dc+sd-jwt");
                    credential = buildSdJwtPresentation(nonce, audience, requestedClaims);
                    LOG.info("[MockWallet] Built standard PID credential for id: {}", credId);
                }

                if (credential != null) {
                    vpToken.put(credId, List.of(credential));
                }
            }
        } catch (Exception e) {
            LOG.error("[MockWallet] Error building multi-credential VP token: {}", e.getMessage());
        }

        return vpToken;
    }

    /**
     * Check if the DCQL query requires multiple credentials (all mandatory).
     */
    private boolean isMultiCredentialRequired(String dcqlQueryRaw) {
        if (dcqlQueryRaw == null || dcqlQueryRaw.isBlank()) {
            return false;
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQueryRaw);
            JsonNode credentialSets = root.get("credential_sets");
            if (credentialSets == null || !credentialSets.isArray() || credentialSets.isEmpty()) {
                return false;
            }
            // Check if any option requires multiple credentials
            for (JsonNode credentialSet : credentialSets) {
                JsonNode options = credentialSet.get("options");
                if (options != null && options.isArray()) {
                    for (JsonNode option : options) {
                        if (option.isArray() && option.size() > 1) {
                            return true; // Found an option requiring multiple credentials
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOG.error("[MockWallet] Error checking multi-credential requirement: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Check if the mock wallet can satisfy the DCQL query.
     * For credential_sets with "optional" mode (default), we only need to satisfy ONE option.
     * Each option specifies which credential IDs must be presented together.
     */
    private boolean canSatisfyDcqlQuery(String dcqlQueryRaw) {
        if (dcqlQueryRaw == null || dcqlQueryRaw.isBlank()) {
            return true;
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQueryRaw);
            JsonNode credentials = root.get("credentials");
            if (credentials == null || !credentials.isArray() || credentials.isEmpty()) {
                return true;
            }

            // Build a map of credential ID to whether we can satisfy it
            Map<String, Boolean> credentialSatisfaction = new LinkedHashMap<>();
            for (JsonNode credentialRequest : credentials) {
                if (!credentialRequest.isObject()) {
                    continue;
                }
                String credId = credentialRequest.has("id") ? credentialRequest.get("id").asText() : null;
                boolean canSatisfy = canSatisfyCredentialRequest(credentialRequest);
                if (credId != null) {
                    credentialSatisfaction.put(credId, canSatisfy);
                }
            }

            // Check credential_sets - if present, we only need to satisfy ONE option
            JsonNode credentialSets = root.get("credential_sets");
            if (credentialSets != null && credentialSets.isArray() && !credentialSets.isEmpty()) {
                for (JsonNode credentialSet : credentialSets) {
                    JsonNode options = credentialSet.get("options");
                    if (options == null || !options.isArray()) {
                        continue;
                    }
                    // For "optional" mode, each option is independent - we need to satisfy any ONE option
                    for (JsonNode option : options) {
                        if (!option.isArray()) {
                            continue;
                        }
                        // Check if ALL credentials in this option can be satisfied
                        boolean optionSatisfied = true;
                        for (JsonNode credIdNode : option) {
                            String credId = credIdNode.asText();
                            Boolean canSatisfy = credentialSatisfaction.get(credId);
                            if (canSatisfy == null || !canSatisfy) {
                                optionSatisfied = false;
                                break;
                            }
                        }
                        if (optionSatisfied) {
                            return true; // Found an option we can satisfy
                        }
                    }
                }
                // If credential_sets is present, we MUST satisfy at least one option
                return false;
            }

            // No credential_sets - original behavior: satisfy ANY one credential
            return credentialSatisfaction.values().stream().anyMatch(v -> v);
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Check if we can satisfy a single credential request (all claims supported).
     */
    private boolean canSatisfyCredentialRequest(JsonNode credentialRequest) {
        // First check if this is a credential type we support
        JsonNode meta = credentialRequest.get("meta");
        if (meta != null) {
            JsonNode vctValues = meta.get("vct_values");
            if (vctValues != null && vctValues.isArray()) {
                for (JsonNode vct : vctValues) {
                    String vctStr = vct.asText();
                    // Support standard PID, German PID, and verifier user credential
                    if (PID_VCT_SD_JWT.equals(vctStr) ||
                        GERMAN_PID_VCT.equals(vctStr) ||
                        VERIFIER_USER_CREDENTIAL_VCT.equals(vctStr)) {
                        return true;
                    }
                }
            }
            JsonNode doctype = meta.get("doctype_value");
            if (doctype != null && PID_DOCTYPE_MDOC.equals(doctype.asText())) {
                return true;
            }
        }

        JsonNode claims = credentialRequest.get("claims");
        if (claims == null || !claims.isArray()) {
            return true; // No claims required, can satisfy
        }

        // List of claims we support in the mock wallet
        Set<String> supportedClaims = Set.of(
                // SD-JWT claims
                "family_name", "given_name", "birthdate", "personal_administrative_number", "document_number",
                "nationalities", "place_of_birth", "issuing_country", "issuing_authority",
                // mDoc claims
                "birth_date", "administrative_number", "nationality", "birth_place", "birth_country",
                // Verifier user credential claims
                "user_id", "linked_at",
                // Legacy claim for backward compatibility
                "personal_id"
        );

        for (JsonNode claim : claims) {
            if (!claim.isObject()) {
                return false;
            }
            JsonNode path = claim.get("path");
            if (path == null || !path.isArray() || path.isEmpty()) {
                return false;
            }
            // Use the last element of the path as the claim name
            // mDoc paths are 2-element: ["eu.europa.ec.eudi.pid.1", "document_number"]
            // SD-JWT paths are 1-element: ["document_number"]
            String name = path.get(path.size() - 1).asText("");
            if (!supportedClaims.contains(name)) {
                return false;
            }
        }
        return true;
    }

    private JsonNode parseJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        String payload = parts[1];
        // Add padding if needed
        int padding = (4 - payload.length() % 4) % 4;
        payload = payload + "=".repeat(padding);
        byte[] decoded = Base64.getUrlDecoder().decode(payload);
        return objectMapper.readTree(new String(decoded, StandardCharsets.UTF_8));
    }

    /**
     * Build the Keycloak IdP login page URL from the form action URL (response_uri).
     * The formActionUri looks like: http://HOST/realms/REALM/broker/ALIAS/endpoint?tab_id=...&session_code=...&client_data=...
     * The login page URL is: http://HOST/realms/REALM/broker/ALIAS/login?tab_id=...&session_code=...&client_data=...
     */
    private String buildKeycloakLoginPageUrl(String formActionUri) {
        try {
            java.net.URI uri = java.net.URI.create(formActionUri);
            String path = uri.getPath();
            // Replace /endpoint with /login in the path
            int endpointIdx = path.indexOf("/endpoint");
            if (endpointIdx < 0) return null;
            String loginPath = path.substring(0, endpointIdx) + "/login";
            // Build URL with tab_id, session_code, client_data from query params
            String query = uri.getQuery();
            if (query == null) return null;
            // Extract tab_id, session_code, client_data from query
            Map<String, String> params = new LinkedHashMap<>();
            for (String param : query.split("&")) {
                String[] kv = param.split("=", 2);
                if (kv.length == 2) {
                    params.put(kv[0], kv[1]);
                }
            }
            StringBuilder url = new StringBuilder();
            url.append(uri.getScheme()).append("://").append(uri.getAuthority()).append(loginPath);
            url.append("?tab_id=").append(params.getOrDefault("tab_id", ""));
            if (params.containsKey("client_data")) {
                url.append("&client_data=").append(params.get("client_data"));
            }
            if (params.containsKey("session_code")) {
                url.append("&session_code=").append(params.get("session_code"));
            }
            return url.toString();
        } catch (Exception e) {
            LOG.warn("[MockWallet] Failed to build login page URL from {}: {}", formActionUri, e.getMessage());
            return null;
        }
    }

    private static String htmlAttr(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    /**
     * Extract the set of claim names that should be disclosed based on the DCQL query.
     * Supports claim_sets to determine which combination of claims to disclose.
     *
     * @param dcqlQueryRaw The raw DCQL query JSON string
     * @param format The credential format ("dc+sd-jwt" or "mso_mdoc")
     * @return Set of claim names to disclose, or null if all available claims should be disclosed
     */
    private Set<String> extractRequestedClaims(String dcqlQueryRaw, String format) {
        if (dcqlQueryRaw == null || dcqlQueryRaw.isBlank()) {
            return null; // No query = disclose all available claims
        }
        try {
            JsonNode root = objectMapper.readTree(dcqlQueryRaw);
            JsonNode credentials = root.get("credentials");
            if (credentials == null || !credentials.isArray() || credentials.isEmpty()) {
                return null;
            }

            // Find the credential request matching the format
            JsonNode matchingCredential = null;
            for (JsonNode credentialRequest : credentials) {
                if (!credentialRequest.isObject()) {
                    continue;
                }
                String credFormat = credentialRequest.has("format") ? credentialRequest.get("format").asText() : null;
                if (format.equals(credFormat)) {
                    matchingCredential = credentialRequest;
                    break;
                }
            }

            if (matchingCredential == null) {
                return null;
            }

            JsonNode claims = matchingCredential.get("claims");
            if (claims == null || !claims.isArray()) {
                return null; // No claims specified = disclose all
            }

            // Build a map of claim ID to claim name for use with claim_sets
            Map<String, String> claimIdToName = new LinkedHashMap<>();
            List<String> allClaimNames = new ArrayList<>();
            for (JsonNode claim : claims) {
                if (!claim.isObject()) {
                    continue;
                }
                JsonNode path = claim.get("path");
                if (path == null || !path.isArray() || path.isEmpty()) {
                    continue;
                }
                // Use the last element of the path as the claim name
                // mDoc paths are 2-element: ["eu.europa.ec.eudi.pid.1", "document_number"]
                String claimName = path.get(path.size() - 1).asText("");
                allClaimNames.add(claimName);

                // If claim has an ID, map it for claim_sets lookup
                if (claim.has("id")) {
                    claimIdToName.put(claim.get("id").asText(), claimName);
                }
            }

            // Check for claim_sets - if present, determine which claims to include
            JsonNode claimSets = matchingCredential.get("claim_sets");
            if (claimSets != null && claimSets.isArray() && !claimSets.isEmpty()) {
                // claim_sets specifies alternative combinations of claims
                // Each element is an array of claim IDs that form one valid combination
                // The wallet should return the first combination it can satisfy

                Set<String> availableClaims = getAvailableClaimsForFormat(format);

                for (JsonNode claimSet : claimSets) {
                    if (!claimSet.isArray()) {
                        continue;
                    }
                    // Check if we can satisfy all claims in this set
                    Set<String> claimNamesInSet = new HashSet<>();
                    boolean canSatisfy = true;
                    for (JsonNode claimIdNode : claimSet) {
                        String claimId = claimIdNode.asText();
                        String claimName = claimIdToName.get(claimId);
                        if (claimName == null) {
                            // Claim ID not found in claims array - might be the claim name itself
                            claimName = claimId;
                        }
                        if (!availableClaims.contains(claimName)) {
                            canSatisfy = false;
                            break;
                        }
                        claimNamesInSet.add(claimName);
                    }
                    if (canSatisfy && !claimNamesInSet.isEmpty()) {
                        LOG.info("[MockWallet] Using claim_set with claims: {}", claimNamesInSet);
                        return claimNamesInSet;
                    }
                }

                // No claim_set could be satisfied - return all requested claims and let validation fail
                LOG.warn("[MockWallet] No claim_set could be satisfied, returning all requested claims");
            }

            // No claim_sets or couldn't satisfy any - return all requested claims
            return new HashSet<>(allClaimNames);
        } catch (Exception e) {
            LOG.error("[MockWallet] Error parsing DCQL query for claims: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Get the set of claim names available for a given format.
     */
    private Set<String> getAvailableClaimsForFormat(String format) {
        if ("mso_mdoc".equalsIgnoreCase(format)) {
            return Set.of(
                    "family_name", "given_name", "birth_date", "administrative_number", "document_number",
                    "nationality", "birth_place", "birth_country", "issuing_country", "issuing_authority"
            );
        }
        // SD-JWT
        return Set.of(
                "family_name", "given_name", "birthdate", "personal_administrative_number", "document_number",
                "nationalities", "place_of_birth", "issuing_country", "issuing_authority"
        );
    }
}
