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

import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.common.util.ProofJwtBuilder;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;

@Service
public class CredentialService {
    // Issuer metadata JSON paths
    private static final String METADATA_CREDENTIAL_ISSUER = "credential_issuer";
    private static final String METADATA_CREDENTIAL_ENDPOINT = "credential_endpoint";
    private static final String METADATA_CONFIGURATIONS_SUPPORTED = "credential_configurations_supported";
    private static final String METADATA_NONCE_ENDPOINT = "nonce_endpoint";

    // Credential response JSON paths
    private static final String RESPONSE_CREDENTIALS = "credentials";
    private static final String RESPONSE_CREDENTIAL = "credential";
    private static final String RESPONSE_FORMAT = "format";
    private static final String RESPONSE_DISCLOSURES = "disclosures";
    private static final String RESPONSE_C_NONCE = "c_nonce";
    private static final String RESPONSE_C_NONCE_EXPIRES_IN = "c_nonce_expires_in";

    private final RestTemplate restTemplate;
    private final WalletProperties properties;
    private final WalletKeyService walletKeyService;
    private final CredentialStore credentialStore;
    private final ObjectMapper objectMapper;
    private final CredentialMetadataService credentialMetadataService;
    private final DebugLogService debugLogService;
    private final SdJwtParser sdJwtParser;
    private final MdocParser mdocParser;

    public CredentialService(RestTemplate restTemplate, WalletProperties properties,
                             WalletKeyService walletKeyService,
                             CredentialStore credentialStore,
                             ObjectMapper objectMapper,
                             CredentialMetadataService credentialMetadataService,
                             DebugLogService debugLogService) {
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.walletKeyService = walletKeyService;
        this.credentialStore = credentialStore;
        this.objectMapper = objectMapper;
        this.credentialMetadataService = credentialMetadataService;
        this.debugLogService = debugLogService;
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.mdocParser = new MdocParser();
    }

    public Map<String, Object> issueCredential(String userId, String accessToken, String nonce,
                                               String credentialConfigurationId) {
        if (accessToken == null) {
            throw new IllegalArgumentException("Missing access token");
        }
        JsonNode metadata = credentialMetadataService.metadata();
        if (metadata == null) {
            throw new IllegalStateException("Issuer metadata not available");
        }
        String issuerIdentifier = metadata.path(METADATA_CREDENTIAL_ISSUER).asText(properties.issuerMetadataUrl());
        String credentialEndpoint = metadata.path(METADATA_CREDENTIAL_ENDPOINT).asText(null);
        if (credentialEndpoint == null || credentialEndpoint.isBlank()) {
            throw new IllegalStateException("Issuer metadata missing credential endpoint");
        }
        String configurationId = credentialConfigurationId != null && !credentialConfigurationId.isBlank()
                ? credentialConfigurationId
                : credentialMetadataService.defaultCredentialConfigurationId();
        JsonNode supportedConfigurations = metadata.path(METADATA_CONFIGURATIONS_SUPPORTED);
        if (!supportedConfigurations.has(configurationId)) {
            throw new IllegalArgumentException("Unsupported credential configuration id: " + configurationId);
        }
        NonceInfo nonceInfo = resolveNonce(accessToken, metadata, nonce);
        String proofJwt = buildProofJwt(issuerIdentifier, nonceInfo.nonce());
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("credential_configuration_id", configurationId);
        requestBody.put("proofs", Map.of("jwt", new String[]{proofJwt}));
        JsonNode credDef = supportedConfigurations.path(configurationId).path("credential_definition");
        if (!credDef.isMissingNode()) {
            requestBody.put("credential_definition", objectMapper.convertValue(credDef, Map.class));
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<JsonNode> response = restTemplate.exchange(credentialEndpoint, HttpMethod.POST,
                requestEntity,
                JsonNode.class);
        JsonNode body = response.getBody();
        String group = "Credential " + configurationId;
        logIssuance(group, "Credential",
                "Credential endpoint",
                "POST",
                credentialEndpoint,
                headers.toSingleValueMap(),
                prettyJson(objectMapper.convertValue(requestBody, JsonNode.class)),
                response.getStatusCode().value(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(body),
                "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7",
                decodeJwt(body));
        Map<String, Object> stored = parseCredentialResponse(body);
        credentialStore.saveCredential(userId, stored);
        stored.put("nonceSource", nonceInfo.source());
        stored.put("cNonce", body.path(RESPONSE_C_NONCE).asText(null));
        stored.put("cNonceExpiresIn", body.path(RESPONSE_C_NONCE_EXPIRES_IN).asInt(-1));
        return stored;
    }

    private Map<String, Object> parseCredentialResponse(JsonNode body) {
        Map<String, Object> stored = new HashMap<>();
        stored.put("storedAt", Instant.now().toString());
        JsonNode responseNode = body.has("response") ? body.get("response") : body;
        stored.put("response", responseNode);

        JsonNode credentialsNode = responseNode.path(RESPONSE_CREDENTIALS);
        if (!credentialsNode.isArray() || credentialsNode.isEmpty()) {
            return stored;
        }

        JsonNode first = credentialsNode.get(0);
        stored.put(RESPONSE_FORMAT, first.path(RESPONSE_FORMAT).asText(body.path(RESPONSE_FORMAT).asText(null)));

        String rawCredential = first.path(RESPONSE_CREDENTIAL).asText(null);
        if (rawCredential != null) {
            stored.put("rawCredential", rawCredential);
            stored.put("credentialSubject", decodeCredentialSubject(rawCredential));
            addSdJwtPartsIfApplicable(stored, rawCredential);
        }

        if (first.has(RESPONSE_DISCLOSURES)) {
            stored.put(RESPONSE_DISCLOSURES, objectMapper.convertValue(first.get(RESPONSE_DISCLOSURES), Object.class));
        }
        return stored;
    }

    private void addSdJwtPartsIfApplicable(Map<String, Object> stored, String rawCredential) {
        if (!sdJwtParser.isSdJwt(rawCredential)) {
            return;
        }
        var parts = sdJwtParser.split(rawCredential);
        stored.put("sdJwt", Map.of(
                "signedJwt", parts.signedJwt(),
                "disclosures", parts.disclosures()
        ));
    }

    private Map<String, Object> decodeCredentialSubject(String jwt) {
        if (sdJwtParser.isSdJwt(jwt)) {
            return decodeSdJwtSubject(sdJwtParser.split(jwt));
        }
        if (mdocParser.isMdoc(jwt)) {
            return mdocParser.extractClaims(jwt);
        }
        return decodeJwtSubject(jwt);
    }

    private Map<String, Object> decodeJwtSubject(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return Map.of();
        }
        byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
        try {
            JsonNode node = objectMapper.readTree(decoded);
            JsonNode subject = node.path("vc").path("credentialSubject");
            if (subject.isMissingNode()) {
                subject = node.path("credentialSubject");
            }
            return objectMapper.convertValue(subject, Map.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private Map<String, Object> decodeSdJwtSubject(SdJwtUtils.SdJwtParts parts) {
        return sdJwtParser.extractDisclosedClaims(parts);
    }

    private String buildProofJwt(String audience, String nonce) {
        ECKey key = walletKeyService.loadOrCreateKey();
        return ProofJwtBuilder.withKey(key)
                .audience(audience)
                .nonce(nonce)
                .issuer(properties.walletDid())
                .build();
    }

    private NonceInfo resolveNonce(String accessToken, JsonNode metadata, String providedNonce) {
        if (providedNonce != null && !providedNonce.isBlank()) {
            return new NonceInfo(providedNonce, "session");
        }
        JsonNode nonceEndpointNode = metadata.get(METADATA_NONCE_ENDPOINT);
        if (nonceEndpointNode == null) {
            throw new IllegalStateException("Issuer metadata missing nonce endpoint");
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        ResponseEntity<JsonNode> response = restTemplate.exchange(nonceEndpointNode.asText(), HttpMethod.POST,
                new HttpEntity<>(headers),
                JsonNode.class);
        JsonNode body = response.getBody();
        String group = "Credential " + configurationIdFromResponse(body);
        logIssuance(group, "Nonce",
                "Nonce endpoint",
                "POST",
                nonceEndpointNode.asText(),
                headers.toSingleValueMap(),
                "",
                response.getStatusCode().value(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(body),
                "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1",
                null);
        String cNonce = body.path(RESPONSE_C_NONCE).asText(null);
        if (cNonce == null) {
            throw new IllegalStateException("Issuer response missing c_nonce");
        }
        return new NonceInfo(cNonce, "issuer");
    }

    private record NonceInfo(String nonce, String source) {
    }

    public List<WalletProperties.CredentialOption> getAvailableCredentialOptions() {
        return credentialMetadataService.availableCredentials();
    }

    private void logIssuance(String group, String subgroup, String title, String method, String url,
                             Map<String, String> requestHeaders, String requestBody, Integer status,
                             Map<String, String> responseHeaders, String responseBody, String specLink,
                             String decoded) {
        debugLogService.addIssuance(group, subgroup, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded);
    }

    private String prettyJson(JsonNode node) {
        try {
            return node == null ? "" : objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(node);
        } catch (Exception e) {
            return String.valueOf(node);
        }
    }

    private String decodeJwt(JsonNode responseBody) {
        if (responseBody == null) {
            return "";
        }
        String token = responseBody.path("access_token").asText(null);
        if (token == null || !token.contains(".")) {
            return "";
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return "";
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(payload));
        } catch (Exception e) {
            return "";
        }
    }

    private String configurationIdFromResponse(JsonNode body) {
        if (body == null) {
            return "";
        }
        JsonNode response = body.has("response") ? body.get("response") : body;
        JsonNode credentials = response.path(RESPONSE_CREDENTIALS);
        if (credentials.isArray() && !credentials.isEmpty()) {
            return credentials.get(0).path("credential_configuration_id").asText("");
        }
        return "";
    }
}
