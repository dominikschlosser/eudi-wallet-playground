package de.arbeitsagentur.keycloak.wallet.issuance.oidc;

import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import de.arbeitsagentur.keycloak.wallet.issuance.service.CredentialMetadataService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.TokenSet;
import de.arbeitsagentur.keycloak.wallet.issuance.session.UserProfile;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Component
public class OidcClient {
    private final RestTemplate restTemplate;
    private final WalletProperties properties;
    private final ObjectMapper objectMapper;
    private final CredentialMetadataService credentialMetadataService;
    private final DebugLogService debugLogService;

    public OidcClient(RestTemplate restTemplate, WalletProperties properties, ObjectMapper objectMapper,
                      CredentialMetadataService credentialMetadataService, DebugLogService debugLogService) {
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.credentialMetadataService = credentialMetadataService;
        this.debugLogService = debugLogService;
    }

    public URI buildAuthorizationUrl(String state, String nonce, String codeChallenge, URI redirectUri) {
        String scope = combineScopes();
        String authorizationDetails = buildAuthorizationDetailsArray();
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(properties.authorizeEndpoint())
                .queryParam("client_id", qp(properties.clientId()))
                .queryParam("response_type", qp("code"))
                .queryParam("scope", qp(scope))
                .queryParam("state", qp(state))
                .queryParam("nonce", qp(nonce))
                .queryParam("redirect_uri", qp(redirectUri.toString()))
                .queryParam("code_challenge", qp(codeChallenge))
                .queryParam("code_challenge_method", qp("S256"));
        if (authorizationDetails != null) {
            builder.queryParam("authorization_details", qp(authorizationDetails));
        } else {
            throw new IllegalStateException("Unable to build authorization_details from issuer metadata");
        }
        return builder
                .build(true)
                .toUri();
    }


    public TokenSet exchangeCode(String code, String codeVerifier, URI redirectUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", properties.clientId());
        body.add("client_secret", properties.clientSecret());
        body.add("code", code);
        body.add("code_verifier", codeVerifier);
        body.add("redirect_uri", redirectUri.toString());
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<JsonNode> response = restTemplate.postForEntity(properties.tokenEndpoint(), request, JsonNode.class);
        logIssuance("Token endpoint (authorization_code)",
                "POST",
                properties.tokenEndpoint(),
                headers.toSingleValueMap(),
                formEncode(body),
                response.getStatusCodeValue(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(response.getBody()),
                "https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint",
                decodeJwt(response.getBody() != null ? response.getBody().path("access_token").asText(null) : null),
                "OIDC Login");
        JsonNode json = response.getBody();
        return parseTokenSet(json);
    }

    public TokenSet refreshTokens(TokenSet existing) {
        if (existing.refreshToken() == null) {
            return existing;
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", properties.clientId());
        body.add("client_secret", properties.clientSecret());
        body.add("refresh_token", existing.refreshToken());
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<JsonNode> response = restTemplate.postForEntity(properties.tokenEndpoint(), request, JsonNode.class);
        logIssuance("Token endpoint (refresh_token)",
                "POST",
                properties.tokenEndpoint(),
                headers.toSingleValueMap(),
                formEncode(body),
                response.getStatusCodeValue(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(response.getBody()),
                "https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint",
                decodeJwt(response.getBody() != null ? response.getBody().path("access_token").asText(null) : null),
                "OIDC Login");
        return parseTokenSet(response.getBody());
    }

    private TokenSet parseTokenSet(JsonNode json) {
        Instant expiresAt = json.has("expires_in") ? Instant.now().plusSeconds(json.get("expires_in").asLong()) : null;
        Instant cNonceExp = json.has("c_nonce_expires_in")
                ? Instant.now().plusSeconds(json.get("c_nonce_expires_in").asLong())
                : null;
        return new TokenSet(
                json.path("access_token").asText(),
                json.path("refresh_token").asText(null),
                json.path("scope").asText(null),
                expiresAt,
                json.path("c_nonce").asText(null),
                cNonceExp
        );
    }

    public UserProfile fetchUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(properties.userInfoEndpoint(), HttpMethod.GET, request, Map.class);
        logIssuance("UserInfo endpoint",
                "GET",
                properties.userInfoEndpoint(),
                headers.toSingleValueMap(),
                "",
                response.getStatusCodeValue(),
                response.getHeaders().toSingleValueMap(),
                prettyJson(response.getBody()),
                "https://openid.net/specs/openid-connect-core-1_0.html#UserInfo",
                null,
                "OIDC Login");
        Map<String, Object> body = response.getBody();
        String full = ("%s %s".formatted(body.getOrDefault("given_name", ""), body.getOrDefault("family_name", ""))).trim();
        String name = firstNonBlank(
                (String) body.get("preferred_username"),
                (String) body.get("username"),
                (String) body.get("name"),
                full,
                (String) body.get("email"),
                (String) body.get("sub")
        );
        return new UserProfile(
                (String) body.get("sub"),
                name,
                (String) body.get("email"),
                (String) body.get("given_name"),
                (String) body.get("family_name")
        );
    }

    private String firstNonBlank(String... candidates) {
        for (String c : candidates) {
            if (c != null && !c.isBlank()) {
                return c;
            }
        }
        return "";
    }

    private String qp(String value) {
        return UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }

    public String buildAuthorizationDetails(String credentialConfigurationId) {
        try {
            ObjectNode descriptor = objectMapper.createObjectNode();
            descriptor.put("type", "openid_credential");
            descriptor.put("format", "dc+sd-jwt");
            descriptor.put("credential_configuration_id", credentialConfigurationId);
            ArrayNode arr = objectMapper.createArrayNode();
            arr.add(descriptor);
            return objectMapper.writeValueAsString(arr);
        } catch (Exception e) {
            return null;
        }
    }

    private String buildAuthorizationDetailsArray() {
        ArrayNode arr = objectMapper.createArrayNode();
        try {
            for (var opt : credentialMetadataService.availableCredentials()) {
                addDescriptor(arr, opt.configurationId());
            }
        } catch (Exception e) {
            addDescriptor(arr, safeDefaultConfigurationId());
        }
        if (arr.isEmpty()) {
            addDescriptor(arr, safeDefaultConfigurationId());
        }
        if (arr.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(arr);
        } catch (Exception e) {
            return null;
        }
    }

    private void addDescriptor(ArrayNode arr, String configId) {
        if (configId == null || configId.isBlank()) {
            return;
        }
        ObjectNode descriptor = objectMapper.createObjectNode();
        descriptor.put("type", "openid_credential");
        descriptor.put("format", "dc+sd-jwt");
        descriptor.put("credential_configuration_id", configId);
        arr.add(descriptor);
    }

    private String combineScopes() {
        StringBuilder sb = new StringBuilder("openid");
        Set<String> scopes = new LinkedHashSet<>();
        try {
            for (var opt : credentialMetadataService.availableCredentials()) {
                if (opt.scope() != null && !opt.scope().isBlank()) {
                    scopes.add(opt.scope());
                }
            }
        } catch (Exception e) {
            String defaultId = safeDefaultConfigurationId();
            String scope = defaultId != null ? credentialMetadataService.scopeFor(defaultId) : null;
            if (scope != null && !scope.isBlank()) {
                scopes.add(scope);
            }
        }
        scopes.forEach(scope -> sb.append(" ").append(scope));
        return sb.toString().trim().replaceAll("\\s+", " ");
    }

    private String safeDefaultConfigurationId() {
        try {
            return credentialMetadataService.defaultCredentialConfigurationId();
        } catch (Exception e) {
            return null;
        }
    }

    private void logIssuance(String title, String method, String url, Map<String, String> requestHeaders,
                             String requestBody, Integer status, Map<String, String> responseHeaders,
                             String responseBody, String specLink,
                             String decoded, String group) {
        debugLogService.addIssuance(group, null, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded);
    }

    private String decodeJwt(String token) {
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

    private String formEncode(MultiValueMap<String, String> body) {
        StringBuilder sb = new StringBuilder();
        body.forEach((k, values) -> {
            for (String v : values) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(k).append("=").append(v);
            }
        });
        return sb.toString();
    }

    private String prettyJson(Object value) {
        try {
            return value == null ? "" : objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }
}
