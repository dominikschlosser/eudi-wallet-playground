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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
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
import java.util.Date;
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

        String trimmed = input.trim();
        String offerJson = null;
        String offerUri = null;

        // Parse openid-credential-offer:// URL
        if (trimmed.startsWith("openid-credential-offer://")) {
            String query = trimmed.substring("openid-credential-offer://".length());
            if (query.startsWith("?")) {
                query = query.substring(1);
            }
            for (String param : query.split("&")) {
                String[] parts = param.split("=", 2);
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
                    if ("credential_offer".equals(key)) {
                        offerJson = value;
                    } else if ("credential_offer_uri".equals(key)) {
                        offerUri = value;
                    }
                }
            }
        } else if (trimmed.startsWith("{")) {
            offerJson = trimmed;
        } else if (trimmed.startsWith("http")) {
            offerUri = trimmed;
        }

        // Fetch offer from URI if needed
        if (offerJson == null && offerUri != null) {
            offerJson = fetchCredentialOfferJson(offerUri);
        }

        if (offerJson == null) {
            throw new IllegalArgumentException("Could not parse credential offer from: " + input);
        }

        // Parse the offer JSON
        JsonNode offer = objectMapper.readTree(offerJson);

        String issuerUrl = offer.get("credential_issuer").asText();
        String preAuthorizedCode = extractPreAuthorizedCode(offer);
        String configurationId = extractConfigurationId(offer);

        if (preAuthorizedCode == null) {
            throw new IllegalArgumentException("No pre-authorized code in credential offer");
        }

        // Default client ID for OID4VCI - some issuers require this
        String clientId = "pid-binding-wallet";

        return new CredentialOffer(issuerUrl, preAuthorizedCode, configurationId, clientId);
    }

    private String fetchCredentialOfferJson(String offerUri) throws Exception {
        LOG.info("[OID4VCI] Fetching credential offer from: {}", offerUri);

        HttpURLConnection conn = (HttpURLConnection) new URL(offerUri).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String error = readResponse(conn);
            throw new RuntimeException("Failed to fetch credential offer: HTTP " + responseCode + " - " + error);
        }

        return readResponse(conn);
    }

    private JsonNode fetchIssuerMetadata(String issuerUrl) throws Exception {
        String metadataUrl = issuerUrl + "/.well-known/openid-credential-issuer";
        LOG.info("[OID4VCI] Fetching issuer metadata from: {}", metadataUrl);

        HttpURLConnection conn = (HttpURLConnection) new URL(metadataUrl).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String error = readResponse(conn);
            throw new RuntimeException("Failed to fetch issuer metadata: HTTP " + responseCode + " - " + error);
        }

        return objectMapper.readTree(readResponse(conn));
    }

    private JsonNode exchangePreAuthorizedCode(String tokenEndpoint, String preAuthorizedCode, String clientId) throws Exception {
        LOG.info("[OID4VCI] Exchanging pre-authorized code at: {}", tokenEndpoint);

        String body = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:pre-authorized_code", StandardCharsets.UTF_8)
                + "&pre-authorized_code=" + URLEncoder.encode(preAuthorizedCode, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(tokenEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String error = readResponse(conn);
            throw new RuntimeException("Failed to exchange pre-authorized code: HTTP " + responseCode + " - " + error);
        }

        return objectMapper.readTree(readResponse(conn));
    }

    private String fetchNonce(String nonceEndpoint, String accessToken) throws Exception {
        LOG.info("[OID4VCI] Fetching nonce from: {}", nonceEndpoint);

        HttpURLConnection conn = (HttpURLConnection) new URL(nonceEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            LOG.warn("[OID4VCI] Nonce endpoint returned: HTTP {}", responseCode);
            return null;
        }

        JsonNode response = objectMapper.readTree(readResponse(conn));
        return response.has("c_nonce") ? response.get("c_nonce").asText() : null;
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

        HttpURLConnection conn = (HttpURLConnection) new URL(credentialEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        String response = readResponse(conn);

        if (responseCode != 200) {
            throw new RuntimeException("Failed to request credential: HTTP " + responseCode + " - " + response);
        }

        return objectMapper.readTree(response);
    }

    private String buildProofJwt(ECKey holderKey, String audience, String nonce) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holderKey.toPublicJWK())
                .build();

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(Instant.now()));

        if (nonce != null && !nonce.isEmpty()) {
            claimsBuilder.claim("nonce", nonce);
        }

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(holderKey));

        return jwt.serialize();
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
