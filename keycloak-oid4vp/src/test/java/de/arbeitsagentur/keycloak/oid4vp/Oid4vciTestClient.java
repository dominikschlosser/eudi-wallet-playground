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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OID4VCI client for testing credential issuance.
 * This client simulates what a real wallet would do when receiving an openid-credential-offer:// URL.
 */
final class Oid4vciTestClient {
    private static final Logger LOG = LoggerFactory.getLogger(Oid4vciTestClient.class);

    private final ObjectMapper objectMapper;
    private final ECKey holderKey;

    Oid4vciTestClient(ObjectMapper objectMapper) throws Exception {
        this.objectMapper = objectMapper;
        this.holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder-" + UUID.randomUUID()).generate();
    }

    /**
     * Parse an openid-credential-offer:// URL and extract the credential_offer_uri.
     */
    String extractCredentialOfferUri(String openidCredentialOfferUrl) {
        if (openidCredentialOfferUrl == null || !openidCredentialOfferUrl.startsWith("openid-credential-offer://")) {
            throw new IllegalArgumentException("Invalid openid-credential-offer URL: " + openidCredentialOfferUrl);
        }

        // Parse the URL parameters
        String query = openidCredentialOfferUrl.substring("openid-credential-offer://".length());
        if (query.startsWith("?")) {
            query = query.substring(1);
        }

        for (String param : query.split("&")) {
            String[] parts = param.split("=", 2);
            if (parts.length == 2 && "credential_offer_uri".equals(parts[0])) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }

        throw new IllegalArgumentException("No credential_offer_uri found in URL: " + openidCredentialOfferUrl);
    }

    /**
     * Fetch the credential offer from the issuer.
     *
     * @param credentialOfferUri The URI to fetch the offer from
     * @return The credential offer JSON
     */
    JsonNode fetchCredentialOffer(String credentialOfferUri) throws Exception {
        LOG.info("[OID4VCI] Fetching credential offer from: {}", credentialOfferUri);

        HttpURLConnection conn = (HttpURLConnection) new URL(credentialOfferUri).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        LOG.info("[OID4VCI] Credential offer response code: {}", responseCode);

        if (responseCode != 200) {
            String error = readResponse(conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream());
            throw new RuntimeException("Failed to fetch credential offer: HTTP " + responseCode + " - " + error);
        }

        String response = readResponse(conn.getInputStream());
        LOG.info("[OID4VCI] Credential offer: {}", response);
        return objectMapper.readTree(response);
    }

    /**
     * Fetch a nonce from the nonce endpoint (Keycloak 26+).
     */
    String fetchNonce(String nonceEndpoint, String accessToken) throws Exception {
        LOG.info("[OID4VCI] Fetching nonce from: {}", nonceEndpoint);

        HttpURLConnection conn = (HttpURLConnection) new URL(nonceEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String error = readResponse(conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream());
            LOG.warn("[OID4VCI] Nonce endpoint returned: HTTP {} - {}", responseCode, error);
            return null;
        }

        String response = readResponse(conn.getInputStream());
        LOG.info("[OID4VCI] Nonce response: {}", response);
        JsonNode nonceResponse = objectMapper.readTree(response);
        return nonceResponse.has("c_nonce") ? nonceResponse.get("c_nonce").asText() : null;
    }

    /**
     * Get the credential issuer metadata from the /.well-known/openid-credential-issuer endpoint.
     */
    JsonNode fetchIssuerMetadata(String issuerUrl) throws Exception {
        String metadataUrl = issuerUrl + "/.well-known/openid-credential-issuer";
        LOG.info("[OID4VCI] Fetching issuer metadata from: {}", metadataUrl);

        HttpURLConnection conn = (HttpURLConnection) new URL(metadataUrl).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String error = readResponse(conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream());
            throw new RuntimeException("Failed to fetch issuer metadata: HTTP " + responseCode + " - " + error);
        }

        String response = readResponse(conn.getInputStream());
        LOG.info("[OID4VCI] Issuer metadata: {}", response.substring(0, Math.min(500, response.length())) + "...");
        return objectMapper.readTree(response);
    }

    /**
     * Exchange a pre-authorized code for an access token.
     * Uses "pid-binding-wallet" as the client_id - this must match the client stored in the credential offer.
     */
    JsonNode exchangePreAuthorizedCode(String tokenEndpoint, String preAuthorizedCode) throws Exception {
        LOG.info("[OID4VCI] Exchanging pre-authorized code at: {}", tokenEndpoint);

        // For OID4VCI pre-authorized code grant, we need to specify a client_id.
        // Using "pid-binding-wallet" which has oid4vci.enabled=true and matches the credential offer.
        String body = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:pre-authorized_code", StandardCharsets.UTF_8)
                + "&pre-authorized_code=" + URLEncoder.encode(preAuthorizedCode, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode("pid-binding-wallet", StandardCharsets.UTF_8);

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
        LOG.info("[OID4VCI] Token response code: {}", responseCode);

        if (responseCode != 200) {
            String error = readResponse(conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream());
            throw new RuntimeException("Failed to exchange pre-authorized code: HTTP " + responseCode + " - " + error);
        }

        String response = readResponse(conn.getInputStream());
        LOG.info("[OID4VCI] Token response: {}", response);
        return objectMapper.readTree(response);
    }

    /**
     * Request a credential from the credential endpoint.
     *
     * @param credentialEndpoint The credential endpoint URL
     * @param issuerUrl The credential issuer URL (used as audience in proof JWT)
     * @param accessToken The access token
     * @param credentialConfigurationId The credential configuration ID
     * @param cNonce The c_nonce from token response (used in proof JWT)
     */
    JsonNode requestCredential(String credentialEndpoint, String issuerUrl, String accessToken, String credentialConfigurationId, String cNonce) throws Exception {
        LOG.info("[OID4VCI] Requesting credential from: {}", credentialEndpoint);

        // Build proof JWT (audience is the issuer URL per OID4VCI spec)
        String proofJwt = buildProofJwt(issuerUrl, cNonce);

        // Build request body
        // Use credential_configuration_id for direct lookup (not credential_identifier which requires offer state)
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("credential_configuration_id", credentialConfigurationId);
        requestBody.put("proof", Map.of(
                "proof_type", "jwt",
                "jwt", proofJwt
        ));

        String body = objectMapper.writeValueAsString(requestBody);
        LOG.info("[OID4VCI] Credential request body: {}", body);

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
        LOG.info("[OID4VCI] Credential response code: {}", responseCode);

        String response = readResponse(responseCode >= 400
                ? (conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream())
                : conn.getInputStream());
        LOG.info("[OID4VCI] Credential response: {}", response);

        if (responseCode != 200) {
            throw new RuntimeException("Failed to request credential: HTTP " + responseCode + " - " + response);
        }

        return objectMapper.readTree(response);
    }

    /**
     * Build a proof JWT for the credential request.
     */
    private String buildProofJwt(String audience, String nonce) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holderKey.toPublicJWK())
                .build();

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(Instant.now()));

        // Only include nonce if provided (Keycloak 26+ may use nonce endpoint instead)
        if (nonce != null && !nonce.isEmpty()) {
            claimsBuilder.claim("nonce", nonce);
        }

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(holderKey));

        LOG.info("[OID4VCI] Built proof JWT with audience: {}, nonce: {}", audience, nonce);
        return jwt.serialize();
    }

    /**
     * Perform the complete OID4VCI flow to receive a credential.
     *
     * @param openidCredentialOfferUrl The openid-credential-offer:// URL
     * @return The issued credential (SD-JWT)
     */
    String receiveCredential(String openidCredentialOfferUrl) throws Exception {
        LOG.info("[OID4VCI] Starting credential issuance flow");

        // 1. Extract credential offer URI
        String credentialOfferUri = extractCredentialOfferUri(openidCredentialOfferUrl);

        // 2. Fetch credential offer
        JsonNode offer = fetchCredentialOffer(credentialOfferUri);

        // 3. Get issuer URL and configuration ID
        String issuerUrl = offer.get("credential_issuer").asText();
        JsonNode credentialConfigIds = offer.get("credential_configuration_ids");
        String credentialConfigId = credentialConfigIds.isArray() && !credentialConfigIds.isEmpty()
                ? credentialConfigIds.get(0).asText()
                : offer.get("credentials").get(0).asText();

        // 4. Get pre-authorized code
        JsonNode grants = offer.get("grants");
        if (grants == null || !grants.has("urn:ietf:params:oauth:grant-type:pre-authorized_code")) {
            throw new RuntimeException("No pre-authorized code grant in offer");
        }
        String preAuthorizedCode = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .get("pre-authorized_code").asText();

        // 5. Fetch issuer metadata
        JsonNode metadata = fetchIssuerMetadata(issuerUrl);
        String tokenEndpoint = metadata.has("token_endpoint")
                ? metadata.get("token_endpoint").asText()
                : issuerUrl + "/protocol/openid-connect/token";
        String credentialEndpoint = metadata.get("credential_endpoint").asText();

        // 6. Exchange pre-authorized code for access token
        JsonNode tokenResponse = exchangePreAuthorizedCode(tokenEndpoint, preAuthorizedCode);
        LOG.info("[OID4VCI] Full token response: {}", tokenResponse);
        String accessToken = tokenResponse.get("access_token").asText();
        String cNonce = tokenResponse.has("c_nonce") ? tokenResponse.get("c_nonce").asText() : null;
        LOG.info("[OID4VCI] c_nonce from token response: {}", cNonce);

        // Check for nonce endpoint in metadata (Keycloak 26+)
        if (cNonce == null && metadata.has("nonce_endpoint")) {
            String nonceEndpoint = metadata.get("nonce_endpoint").asText();
            LOG.info("[OID4VCI] Fetching nonce from nonce endpoint: {}", nonceEndpoint);
            cNonce = fetchNonce(nonceEndpoint, accessToken);
            LOG.info("[OID4VCI] c_nonce from nonce endpoint: {}", cNonce);
        }

        // 7. Request credential (issuerUrl is used as audience in proof JWT)
        JsonNode credentialResponse = requestCredential(credentialEndpoint, issuerUrl, accessToken, credentialConfigId, cNonce);
        LOG.info("[OID4VCI] Credential response: {}", credentialResponse);

        // Handle various response formats from OID4VCI
        // - "credential": "eyJ..." (simple string)
        // - "credential": { ... } (object, get string value)
        // - "credentials": [ "eyJ..." ] (array of strings)
        // - "credentials": [ { "credential": "eyJ..." } ] (array of objects)
        String credential = extractCredentialFromResponse(credentialResponse);
        LOG.info("[OID4VCI] Received credential (length: {})", credential.length());
        return credential;
    }

    /**
     * Extract credential string from various response formats.
     */
    private String extractCredentialFromResponse(JsonNode response) {
        // Try "credential" field first
        if (response.has("credential")) {
            JsonNode credNode = response.get("credential");
            if (credNode.isTextual()) {
                return credNode.asText();
            }
            // If it's an object, look for nested "credential" or first value
            if (credNode.isObject()) {
                if (credNode.has("credential")) {
                    return credNode.get("credential").asText();
                }
                // Return first string value - use propertyNames()
                for (String name : credNode.propertyNames()) {
                    JsonNode value = credNode.get(name);
                    if (value.isTextual()) {
                        return value.asText();
                    }
                }
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

    /**
     * Get the holder's public key (for verification purposes).
     */
    ECKey getHolderPublicKey() {
        return holderKey.toPublicJWK();
    }

    /**
     * Get the holder's full key pair (including private key).
     * This is used to share the key with the mock wallet so that
     * credentials issued via OID4VCI can be properly presented.
     */
    ECKey getHolderKey() {
        return holderKey;
    }

    private String readResponse(java.io.InputStream is) throws Exception {
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
}
