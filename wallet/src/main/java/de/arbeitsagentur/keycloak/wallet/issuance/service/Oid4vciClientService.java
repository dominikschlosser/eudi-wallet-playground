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

import com.nimbusds.jose.jwk.ECKey;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.util.CredentialOfferUrlParser;
import de.arbeitsagentur.keycloak.wallet.common.util.ProofJwtBuilder;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OID4VCI client service for receiving credentials from external issuers.
 * This handles the standard OID4VCI pre-authorized code flow.
 */
@Service
public class Oid4vciClientService {
    private static final Logger LOG = LoggerFactory.getLogger(Oid4vciClientService.class);

    private final ObjectMapper objectMapper;
    private final WalletKeyService walletKeyService;
    private final CredentialStore credentialStore;

    public Oid4vciClientService(ObjectMapper objectMapper,
                                WalletKeyService walletKeyService,
                                CredentialStore credentialStore) {
        this.objectMapper = objectMapper;
        this.walletKeyService = walletKeyService;
        this.credentialStore = credentialStore;
    }

    /**
     * Process a credential offer and store the received credential.
     *
     * @param credentialOfferInput The credential offer - can be:
     *   - openid-credential-offer://... URL
     *   - Credential offer JSON
     *   - Credential offer URI
     * @param ownerId The owner ID for storing the credential
     * @return Information about the received credential
     */
    public CredentialReceiveResult receiveCredential(String credentialOfferInput, String ownerId) throws Exception {
        LOG.info("[OID4VCI] Processing credential offer for owner: {}", ownerId);

        // Parse the credential offer
        CredentialOffer offer = parseCredentialOffer(credentialOfferInput);
        LOG.info("[OID4VCI] Parsed offer - issuer: {}, configId: {}", offer.issuerUrl, offer.configurationId);

        // Fetch issuer metadata
        JsonNode metadata = fetchIssuerMetadata(offer.issuerUrl);
        String tokenEndpoint = metadata.has("token_endpoint")
                ? metadata.get("token_endpoint").asText()
                : offer.issuerUrl + "/protocol/openid-connect/token";
        String credentialEndpoint = metadata.get("credential_endpoint").asText();

        // Exchange pre-authorized code for access token
        JsonNode tokenResponse = exchangePreAuthorizedCode(tokenEndpoint, offer.preAuthorizedCode, offer.clientId);
        String accessToken = tokenResponse.get("access_token").asText();
        String cNonce = tokenResponse.has("c_nonce") ? tokenResponse.get("c_nonce").asText() : null;

        // Check for nonce endpoint (Keycloak 26+)
        if (cNonce == null && metadata.has("nonce_endpoint")) {
            String nonceEndpoint = metadata.get("nonce_endpoint").asText();
            cNonce = fetchNonce(nonceEndpoint, accessToken);
        }

        // Request the credential
        JsonNode credentialResponse = requestCredential(
                credentialEndpoint, offer.issuerUrl, accessToken, offer.configurationId, cNonce);

        // Extract and store the credential
        String credential = extractCredentialFromResponse(credentialResponse);
        Map<String, Object> storedCredential = buildStoredCredential(credential, offer);
        credentialStore.saveCredential(ownerId, storedCredential);

        LOG.info("[OID4VCI] Successfully received and stored credential (length: {})", credential.length());
        return new CredentialReceiveResult(credential, offer.configurationId, offer.issuerUrl);
    }

    private CredentialOffer parseCredentialOffer(String input) throws Exception {
        if (!StringUtils.hasText(input)) {
            throw new IllegalArgumentException("Empty credential offer");
        }

        CredentialOfferUrlParser.ParseResult parsed = CredentialOfferUrlParser.parse(input);
        if (parsed == null) {
            throw new IllegalArgumentException("Could not parse credential offer from: " + input);
        }

        String offerJson = parsed.offerJson();
        if (offerJson == null && parsed.hasOfferUri()) {
            offerJson = fetchCredentialOfferJson(parsed.offerUri());
        }

        if (offerJson == null) {
            throw new IllegalArgumentException("Could not parse credential offer from: " + input);
        }

        JsonNode offer = objectMapper.readTree(offerJson);
        String issuerUrl = offer.get("credential_issuer").asText();
        String preAuthorizedCode = extractPreAuthorizedCode(offer);
        String configurationId = extractConfigurationId(offer);

        if (preAuthorizedCode == null) {
            throw new IllegalArgumentException("No pre-authorized code in credential offer");
        }

        return new CredentialOffer(issuerUrl, preAuthorizedCode, configurationId, "pid-binding-wallet");
    }

    private String fetchCredentialOfferJson(String offerUri) throws Exception {
        LOG.info("[OID4VCI] Fetching credential offer from: {}", offerUri);
        return httpGet(offerUri, null, "fetch credential offer");
    }

    private JsonNode fetchIssuerMetadata(String issuerUrl) throws Exception {
        String metadataUrl = issuerUrl + "/.well-known/openid-credential-issuer";
        LOG.info("[OID4VCI] Fetching issuer metadata from: {}", metadataUrl);
        return objectMapper.readTree(httpGet(metadataUrl, null, "fetch issuer metadata"));
    }

    private JsonNode exchangePreAuthorizedCode(String tokenEndpoint, String preAuthorizedCode, String clientId) throws Exception {
        LOG.info("[OID4VCI] Exchanging pre-authorized code at: {}", tokenEndpoint);
        String body = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:pre-authorized_code", StandardCharsets.UTF_8)
                + "&pre-authorized_code=" + URLEncoder.encode(preAuthorizedCode, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        return objectMapper.readTree(httpPost(tokenEndpoint, body, "application/x-www-form-urlencoded", null, "exchange pre-authorized code"));
    }

    private String fetchNonce(String nonceEndpoint, String accessToken) throws Exception {
        LOG.info("[OID4VCI] Fetching nonce from: {}", nonceEndpoint);
        try {
            String response = httpPost(nonceEndpoint, null, null, accessToken, "fetch nonce");
            JsonNode node = objectMapper.readTree(response);
            return node.has("c_nonce") ? node.get("c_nonce").asText() : null;
        } catch (Exception e) {
            LOG.warn("[OID4VCI] Nonce endpoint failed: {}", e.getMessage());
            return null;
        }
    }

    private JsonNode requestCredential(String credentialEndpoint, String issuerUrl,
                                        String accessToken, String configurationId, String cNonce) throws Exception {
        LOG.info("[OID4VCI] Requesting credential from: {}", credentialEndpoint);
        ECKey holderKey = walletKeyService.loadOrCreateKey();
        String proofJwt = buildProofJwt(holderKey, issuerUrl, cNonce);

        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("credential_configuration_id", configurationId);
        requestBody.put("proof", Map.of("proof_type", "jwt", "jwt", proofJwt));

        String body = objectMapper.writeValueAsString(requestBody);
        return objectMapper.readTree(httpPost(credentialEndpoint, body, "application/json", accessToken, "request credential"));
    }

    // --- HTTP helpers ---

    private static final int HTTP_TIMEOUT_MS = 10000;

    private String httpGet(String url, String bearerToken, String operation) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");
        if (bearerToken != null) {
            conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
        conn.setConnectTimeout(HTTP_TIMEOUT_MS);
        conn.setReadTimeout(HTTP_TIMEOUT_MS);

        return handleResponse(conn, operation);
    }

    private String httpPost(String url, String body, String contentType, String bearerToken, String operation) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Accept", "application/json");
        if (contentType != null) {
            conn.setRequestProperty("Content-Type", contentType);
        }
        if (bearerToken != null) {
            conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
        conn.setConnectTimeout(HTTP_TIMEOUT_MS);
        conn.setReadTimeout(HTTP_TIMEOUT_MS);

        if (body != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }

        return handleResponse(conn, operation);
    }

    private String handleResponse(HttpURLConnection conn, String operation) throws Exception {
        int responseCode = conn.getResponseCode();
        String response = readResponse(conn);
        if (responseCode != 200) {
            throw new RuntimeException("Failed to " + operation + ": HTTP " + responseCode + " - " + response);
        }
        return response;
    }

    private String buildProofJwt(ECKey holderKey, String audience, String nonce) {
        return ProofJwtBuilder.withKey(holderKey)
                .audience(audience)
                .nonce(nonce)
                .expiration(java.time.Duration.ZERO)  // No expiration for this use case
                .build();
    }

    private String extractCredentialFromResponse(JsonNode response) {
        // Try "credential" field first
        if (response.has("credential")) {
            JsonNode credNode = response.get("credential");
            if (credNode.isTextual()) {
                return credNode.asText();
            }
        }

        // Try "credentials" array
        if (response.has("credentials")) {
            JsonNode credentials = response.get("credentials");
            if (credentials.isArray() && !credentials.isEmpty()) {
                JsonNode first = credentials.get(0);
                if (first.isTextual()) {
                    return first.asText();
                }
                if (first.isObject() && first.has("credential")) {
                    return first.get("credential").asText();
                }
            }
        }

        throw new RuntimeException("Could not extract credential from response: " + response);
    }

    private String extractPreAuthorizedCode(JsonNode offer) {
        JsonNode grants = offer.get("grants");
        if (grants == null) {
            return null;
        }
        JsonNode preAuthGrant = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        if (preAuthGrant != null && preAuthGrant.has("pre-authorized_code")) {
            return preAuthGrant.get("pre-authorized_code").asText();
        }
        return null;
    }

    private String extractConfigurationId(JsonNode offer) {
        JsonNode ids = offer.get("credential_configuration_ids");
        if (ids != null && ids.isArray() && !ids.isEmpty()) {
            return ids.get(0).asText();
        }
        // Fallback to old format
        JsonNode credentials = offer.get("credentials");
        if (credentials != null && credentials.isArray() && !credentials.isEmpty()) {
            return credentials.get(0).asText();
        }
        return "default";
    }

    private Map<String, Object> buildStoredCredential(String credential, CredentialOffer offer) {
        Map<String, Object> stored = new LinkedHashMap<>();
        stored.put("rawCredential", credential);
        stored.put("format", "dc+sd-jwt");
        stored.put("issuer", offer.issuerUrl);
        stored.put("configurationId", offer.configurationId);
        stored.put("storedAt", Instant.now().toString());
        return stored;
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

    private record CredentialOffer(String issuerUrl, String preAuthorizedCode, String configurationId, String clientId) {}

    public record CredentialReceiveResult(String credential, String configurationId, String issuerUrl) {}
}
