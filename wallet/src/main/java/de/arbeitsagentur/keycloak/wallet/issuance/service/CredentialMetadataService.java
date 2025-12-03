package de.arbeitsagentur.keycloak.wallet.issuance.service;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class CredentialMetadataService {
    private final RestTemplate restTemplate;
    private final WalletProperties properties;
    private final ObjectMapper objectMapper;
    private final DebugLogService debugLogService;
    private final AtomicReference<JsonNode> metadataCache = new AtomicReference<>();

    public CredentialMetadataService(RestTemplate restTemplate, WalletProperties properties,
                                     ObjectMapper objectMapper, DebugLogService debugLogService) {
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.debugLogService = debugLogService;
    }

    public JsonNode metadata() {
        JsonNode cached = metadataCache.get();
        if (cached != null) {
            return cached;
        }
        ResponseEntity<JsonNode> response = restTemplate.getForEntity(properties.issuerMetadataUrl(), JsonNode.class);
        metadataCache.compareAndSet(null, response.getBody());
        try {
            debugLogService.addIssuance("Global", "Metadata", "Issuer metadata",
                    "GET",
                    properties.issuerMetadataUrl(),
                    Map.of(),
                    "",
                    response.getStatusCodeValue(),
                    response.getHeaders().toSingleValueMap(),
                    response.getBody() != null ? objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(response.getBody()) : "",
                    "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-openid-provider-metadata",
                    null);
        } catch (Exception ignored) {
        }
        return metadataCache.get();
    }

    public List<WalletProperties.CredentialOption> availableCredentials() {
        JsonNode metadata = metadata();
        if (metadata == null) {
            throw new IllegalStateException("Issuer metadata not available");
        }
        List<WalletProperties.CredentialOption> options = extractCredentialOptions(metadata);
        if (options.isEmpty()) {
            throw new IllegalStateException("Issuer metadata missing credential configurations");
        }
        return options;
    }

    public String defaultCredentialConfigurationId() {
        JsonNode metadata = metadata();
        if (metadata == null) {
            throw new IllegalStateException("Issuer metadata not available");
        }
        List<WalletProperties.CredentialOption> options = extractCredentialOptions(metadata);
        if (options.isEmpty()) {
            throw new IllegalStateException("Issuer metadata missing credential configurations");
        }
        for (WalletProperties.CredentialOption option : options) {
            if (looksLikePid(option)) {
                return option.configurationId();
            }
            if (looksLikeIdentity(option)) {
                return option.configurationId();
            }
        }
        return options.get(0).configurationId();
    }

    public String scopeFor(String configurationId) {
        try {
            JsonNode metadata = metadata();
            if (metadata == null || configurationId == null || configurationId.isBlank()) {
                return null;
            }
            JsonNode scope = metadata.path("credential_configurations_supported")
                    .path(configurationId)
                    .path("scope");
            return scope.isMissingNode() ? null : scope.asText(null);
        } catch (Exception e) {
            return null;
        }
    }

    private List<WalletProperties.CredentialOption> extractCredentialOptions(JsonNode metadata) {
        Map<String, WalletProperties.CredentialOption> options = new LinkedHashMap<>();
        JsonNode configs = metadata.path("credential_configurations_supported");
        if (configs.isObject()) {
            configs.fields().forEachRemaining(entry -> {
                String id = entry.getKey();
                JsonNode cfg = entry.getValue();
                String scope = cfg.path("scope").asText(null);
                String label = extractLabel(cfg, id);
                addOption(options, scope, id, label);
            });
        }
        return new ArrayList<>(options.values());
    }

    private void addOption(Map<String, WalletProperties.CredentialOption> target, String scope, String configurationId,
                           String label) {
        if (configurationId == null || configurationId.isBlank()) {
            return;
        }
        String name = label != null && !label.isBlank() ? label : configurationId;
        target.putIfAbsent(configurationId, new WalletProperties.CredentialOption(scope, configurationId, name));
    }

    private String extractLabel(JsonNode cfg, String defaultLabel) {
        JsonNode display = cfg.path("display");
        if (display.isObject()) {
            JsonNode name = display.path("name");
            if (name.isTextual() && !name.asText().isBlank()) {
                return name.asText();
            }
        }
        return defaultLabel;
    }

    private boolean looksLikeIdentity(WalletProperties.CredentialOption option) {
        String id = option.configurationId() != null ? option.configurationId().toLowerCase() : "";
        String label = option.label() != null ? option.label().toLowerCase() : "";
        return id.contains("identity") || label.contains("identity");
    }

    private boolean looksLikePid(WalletProperties.CredentialOption option) {
        String id = option.configurationId() != null ? option.configurationId().toLowerCase() : "";
        String label = option.label() != null ? option.label().toLowerCase() : "";
        return id.contains("pid") || label.contains("pid");
    }
}
