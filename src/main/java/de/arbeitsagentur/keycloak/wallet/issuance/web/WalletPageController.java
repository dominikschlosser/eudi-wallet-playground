package de.arbeitsagentur.keycloak.wallet.issuance.web;

import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.issuance.oidc.OidcClient;
import de.arbeitsagentur.keycloak.wallet.issuance.service.CredentialService;
import de.arbeitsagentur.keycloak.wallet.issuance.service.MockIssuerFlowService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.SessionService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.TokenSet;
import de.arbeitsagentur.keycloak.wallet.issuance.session.WalletSession;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerConfigurationStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Controller
public class WalletPageController {
    private final SessionService sessionService;
    private final CredentialStore credentialStore;
    private final CredentialService credentialService;
    private final OidcClient oidcClient;
    private final ObjectMapper objectMapper;
    private final DebugLogService debugLogService;
    private final MockIssuerFlowService mockIssuerFlowService;
    private final MockIssuerConfigurationStore mockIssuerConfigurationStore;

    public WalletPageController(SessionService sessionService,
                                CredentialStore credentialStore,
                                CredentialService credentialService,
                                OidcClient oidcClient,
                                ObjectMapper objectMapper,
                                DebugLogService debugLogService,
                                MockIssuerFlowService mockIssuerFlowService,
                                MockIssuerConfigurationStore mockIssuerConfigurationStore) {
        this.sessionService = sessionService;
        this.credentialStore = credentialStore;
        this.credentialService = credentialService;
        this.oidcClient = oidcClient;
        this.objectMapper = objectMapper;
        this.debugLogService = debugLogService;
        this.mockIssuerFlowService = mockIssuerFlowService;
        this.mockIssuerConfigurationStore = mockIssuerConfigurationStore;
    }

    @GetMapping({"/", "/wallet"})
    public String wallet(Model model, HttpSession httpSession) {
        WalletSession session = sessionService.getSession(httpSession);
        IssuerAvailability issuerAvailability = resolveIssuerAvailability();
        model.addAttribute("session", session);
        model.addAttribute("authenticated", session.isAuthenticated());
        model.addAttribute("keycloakAvailable", issuerAvailability.available());
        model.addAttribute("keycloakError", issuerAvailability.error());
        model.addAttribute("credentialOptions", issuerAvailability.options());
        model.addAttribute("mockCredentialOptions", mockCredentialOptions());
        model.addAttribute("userName", session.getUserProfile() != null ? session.getUserProfile().displayName() : null);
        model.addAttribute("userEmail", session.getUserProfile() != null ? session.getUserProfile().email() : null);
        model.addAttribute("credentials", loadDisplayCredentials(session));
        model.addAttribute("issuanceDebug", debugLogService.issuance());
        model.addAttribute("issuanceDebugGrouped", groupBy(debugLogService.issuance()));
        return "wallet";
    }

    @PostMapping("/issue")
    public String issue(@org.springframework.web.bind.annotation.RequestParam(
            value = "credentialConfigurationId", required = false) String configId,
                        HttpSession httpSession, Model model) {
        WalletSession session = sessionService.getSession(httpSession);
        if (!session.isAuthenticated()) {
            model.addAttribute("error", "Not authenticated");
            return wallet(model, httpSession);
        }
        TokenSet tokens = session.getTokenSet();
        if (tokens != null && tokens.needsRefresh()) {
            tokens = oidcClient.refreshTokens(tokens);
            session.setTokenSet(tokens);
        }
        if (tokens == null) {
            model.addAttribute("error", "Missing tokens");
            return wallet(model, httpSession);
        }
        try {
            credentialService.issueCredential(
                    session.getUserProfile().sub(),
                    tokens.accessToken(),
                    tokens.cNonce(),
                    configId
            );
            model.addAttribute("message", "Credential issued");
        } catch (Exception e) {
            model.addAttribute("error", "Credential issuance failed: " + e.getMessage());
        }
        return wallet(model, httpSession);
    }

    @PostMapping("/mock-issue")
    public String mockIssue(HttpSession httpSession, HttpServletRequest request, Model model) {
        WalletSession session = sessionService.getSession(httpSession);
        String configurationId = request.getParameter("configurationId");
        String credentialOffer = request.getParameter("credentialOffer");
        try {
            mockIssuerFlowService.issueWithMockIssuer(
                    CredentialStore.MOCK_ISSUER_OWNER,
                    request,
                    null,
                    configurationId,
                    null,
                    credentialOffer
            );
            model.addAttribute("message", "Mock issuer credential issued");
        } catch (Exception e) {
            model.addAttribute("error", "Mock issuance failed: " + e.getMessage());
        }
        return wallet(model, httpSession);
    }

    @PostMapping("/credentials/delete")
    public String deleteCredential(@org.springframework.web.bind.annotation.RequestParam("file") String file,
                                   HttpSession httpSession,
                                   Model model) {
        WalletSession session = sessionService.getSession(httpSession);
        boolean deleted = credentialStore.deleteCredential(session.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER), file);
        if (!deleted) {
            model.addAttribute("error", "Credential not found");
        } else {
            model.addAttribute("message", "Deleted credential " + file);
        }
        return wallet(model, httpSession);
    }

    private List<DisplayCredential> loadDisplayCredentials(WalletSession session) {
        List<DisplayCredential> result = new ArrayList<>();
        List<CredentialStore.Entry> entries = credentialStore.listCredentialEntries(
                session.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER)
        );
        for (CredentialStore.Entry entry : entries) {
            Map<String, Object> map = objectMapper.convertValue(entry.credential(), Map.class);
            String raw = map.containsKey("rawCredential") ? String.valueOf(map.get("rawCredential")) : null;
            String format = String.valueOf(map.getOrDefault("format",
                    raw != null && raw.contains("~") ? "SD-JWT" : "JWT"));
            Map<String, Object> claims = filterDisplayClaims(extractClaims(map, raw));
            String vct = extractVct(map, raw);
            List<String> disclosures = extractDisclosures(map);
            String storedAt = map.getOrDefault("storedAt", "").toString();
            result.add(new DisplayCredential(entry.fileName(), format, vct, raw, storedAt, claims, disclosures));
        }
        return result;
    }

    private List<CredentialOption> credentialOptions() {
        List<CredentialOption> options = new ArrayList<>();
        for (var opt : credentialService.getAvailableCredentialOptions()) {
            String label = opt.label() != null && !opt.label().isBlank() ? opt.label() : opt.configurationId();
            options.add(new CredentialOption(opt.configurationId(), opt.scope(), label));
        }
        return options;
    }

    private List<CredentialOption> mockCredentialOptions() {
        List<CredentialOption> options = new ArrayList<>();
        mockIssuerConfigurationStore.configurations().forEach(cfg -> {
            String label = cfg.name() != null && !cfg.name().isBlank() ? cfg.name() : cfg.id();
            options.add(new CredentialOption(cfg.id(), cfg.scope(), label));
        });
        return options;
    }

    private Map<String, Object> extractClaims(Map<String, Object> map, String raw) {
        Object existing = map.get("credentialSubject");
        if (existing instanceof Map<?, ?> ready) {
            return (Map<String, Object>) ready;
        }
        if (raw == null) {
            return Collections.emptyMap();
        }
        try {
            if (raw.contains("~")) {
                SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(raw);
                return SdJwtUtils.extractDisclosedClaims(parts, objectMapper);
            }
            String[] parts = raw.split("\\.");
            if (parts.length < 2) {
                return Collections.emptyMap();
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            JsonNode subject = node.path("vc").path("credentialSubject");
            if (subject.isMissingNode()) {
                subject = node.path("credentialSubject");
            }
            return objectMapper.convertValue(subject, Map.class);
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    private List<String> extractDisclosures(Map<String, Object> map) {
        Object disclosureValue = map.get("disclosures");
        if (disclosureValue instanceof List<?> list) {
            List<String> disclosures = new ArrayList<>();
            for (Object entry : list) {
                if (entry != null) {
                    disclosures.add(entry.toString());
                }
            }
            return disclosures;
        }
        return Collections.emptyList();
    }

    private Map<String, Object> filterDisplayClaims(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            return Collections.emptyMap();
        }
        Set<String> reserved = Set.of(
                "iss", "aud", "exp", "nbf", "iat", "jti", "sub",
                "cnf", "vct", "nonce", "_sd_alg", "_sd", "typ", "kid"
        );
        Map<String, Object> filtered = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            String key = entry.getKey();
            if (key == null || reserved.contains(key) || key.startsWith("_")) {
                continue;
            }
            filtered.put(key, entry.getValue());
        }
        return filtered;
    }

    private String extractVct(Map<String, Object> map, String raw) {
        Object existing = map.get("vct");
        if (existing != null) {
            return existing.toString();
        }
        if (raw == null) {
            return null;
        }
        try {
            if (raw.contains("~")) {
                SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(raw);
                JsonNode node = objectMapper.readTree(Base64.getUrlDecoder().decode(parts.signedJwt().split("\\.")[1]));
                return node.path("vct").asText(null);
            }
            String[] parts = raw.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            return node.path("vct").asText(null);
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Map<String, List<de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService.DebugEntry>>> groupBy(
            List<de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService.DebugEntry> entries) {
        Map<String, Map<String, List<de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService.DebugEntry>>> grouped = new LinkedHashMap<>();
        for (var entry : entries) {
            grouped.computeIfAbsent(entry.group(), k -> new LinkedHashMap<>())
                    .computeIfAbsent(entry.subgroup() == null ? "" : entry.subgroup(), k -> new ArrayList<>())
                    .add(entry);
        }
        return grouped;
    }

    private IssuerAvailability resolveIssuerAvailability() {
        try {
            return new IssuerAvailability(true, credentialOptions(), null);
        } catch (Exception e) {
            return new IssuerAvailability(false, List.of(), e.getMessage());
        }
    }

    public record DisplayCredential(String fileName,
                                    String format,
                                    String vct,
                                    String rawCredential,
                                    String storedAt,
                                    Map<String, Object> claims,
                                    List<String> disclosures) {
        public String prettyFormat() {
            String normalized = format == null ? "" : format.trim();
            if (normalized.isBlank() || "unknown format".equalsIgnoreCase(normalized) || "null".equalsIgnoreCase(normalized)) {
                if (rawCredential != null && rawCredential.contains("~")) {
                    return "SD-JWT";
                }
                if (!disclosures.isEmpty()) {
                    return "SD-JWT";
                }
                return "JWT";
            }
            if (normalized.equalsIgnoreCase("dc+sd-jwt") || normalized.equalsIgnoreCase("sd-jwt") || normalized.equalsIgnoreCase("dc_sd_jwt")) {
                return "SD-JWT";
            }
            return normalized;
        }
    }

    public record CredentialOption(String configurationId, String scope, String label) {
    }

    private record IssuerAvailability(boolean available, List<CredentialOption> options, String error) {
    }
}
