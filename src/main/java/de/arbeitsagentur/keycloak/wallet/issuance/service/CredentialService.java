package de.arbeitsagentur.keycloak.wallet.issuance.service;

import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CredentialService {
    private final RestTemplate restTemplate;
    private final WalletProperties properties;
    private final WalletKeyService walletKeyService;
    private final CredentialStore credentialStore;
    private final ObjectMapper objectMapper;
    private final CredentialMetadataService credentialMetadataService;
    private final DebugLogService debugLogService;

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
        String issuerIdentifier = metadata.path("credential_issuer").asText(properties.issuerMetadataUrl());
        String credentialEndpoint = metadata.path("credential_endpoint").asText();
        if (credentialEndpoint == null || credentialEndpoint.isBlank()) {
            throw new IllegalStateException("Issuer metadata missing credential endpoint");
        }
        String configurationId = credentialConfigurationId != null && !credentialConfigurationId.isBlank()
                ? credentialConfigurationId
                : credentialMetadataService.defaultCredentialConfigurationId();
        JsonNode supportedConfigurations = metadata.path("credential_configurations_supported");
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
                response.getStatusCodeValue(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(body),
                "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7",
                decodeJwt(body));
        Map<String, Object> stored = new HashMap<>();
        stored.put("storedAt", Instant.now().toString());
        JsonNode responseNode = body.has("response") ? body.get("response") : body;
        JsonNode credentialsNode = responseNode.path("credentials");
        if (credentialsNode.isArray() && !credentialsNode.isEmpty()) {
            JsonNode first = credentialsNode.get(0);
            String rawCredential = first.path("credential").asText(null);
            stored.put("format", first.path("format").asText(body.path("format").asText(null)));
            if (rawCredential != null) {
                stored.put("rawCredential", rawCredential);
                if (rawCredential.contains("~")) {
                    SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(rawCredential);
                    stored.put("sdJwt", Map.of(
                            "signedJwt", parts.signedJwt(),
                            "disclosures", parts.disclosures()
                    ));
                    stored.put("credentialSubject", decodeSdJwtSubject(parts));
                } else {
                    stored.put("credentialSubject", decodeJwtSubject(rawCredential));
                }
            }
            if (first.has("disclosures")) {
                stored.put("disclosures", objectMapper.convertValue(first.get("disclosures"), Object.class));
            }
        }
        stored.put("response", responseNode);
        credentialStore.saveCredential(userId, stored);
        stored.put("nonceSource", nonceInfo.source());
        stored.put("cNonce", body.path("c_nonce").asText(null));
        stored.put("cNonceExpiresIn", body.path("c_nonce_expires_in").asInt(-1));
        return stored;
    }

    private Map<String, Object> decodeCredentialSubject(String jwt) {
        if (jwt != null && jwt.contains("~")) {
            return decodeSdJwtSubject(SdJwtUtils.split(jwt));
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
        try {
            return SdJwtUtils.extractDisclosedClaims(parts, objectMapper);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private String buildProofJwt(String audience, String nonce) {
        try {
            ECKey key = walletKeyService.loadOrCreateKey();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .jwk(key.toPublicJWK())
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    header,
                    new com.nimbusds.jwt.JWTClaimsSet.Builder()
                            .issuer(properties.walletDid())
                            .audience(audience)
                            .issueTime(new Date())
                            .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                            .claim("nonce", nonce)
                            .build()
            );
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign proof JWT", e);
        }
    }

    private NonceInfo resolveNonce(String accessToken, JsonNode metadata, String providedNonce) {
        if (providedNonce != null && !providedNonce.isBlank()) {
            return new NonceInfo(providedNonce, "session");
        }
        JsonNode nonceEndpointNode = metadata.get("nonce_endpoint");
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
                response.getStatusCodeValue(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(body),
                "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1",
                null);
        return new NonceInfo(body.path("c_nonce").asText(), "issuer");
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
        if (response.path("credentials").isArray() && !response.path("credentials").isEmpty()) {
            return response.path("credentials").get(0).path("credential_configuration_id").asText("");
        }
        return "";
    }
}
