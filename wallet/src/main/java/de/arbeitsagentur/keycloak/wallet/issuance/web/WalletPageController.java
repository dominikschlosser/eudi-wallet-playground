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
package de.arbeitsagentur.keycloak.wallet.issuance.web;

import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.common.util.ClaimDisplayFilter;
import de.arbeitsagentur.keycloak.wallet.issuance.oidc.OidcClient;
import de.arbeitsagentur.keycloak.wallet.issuance.service.CredentialService;
import de.arbeitsagentur.keycloak.wallet.issuance.service.MockIssuerFlowService;
import de.arbeitsagentur.keycloak.wallet.issuance.service.Oid4vciClientService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.SessionService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.TokenSet;
import de.arbeitsagentur.keycloak.wallet.issuance.session.WalletSession;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerConfigurationStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService.DebugEntry;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
public class WalletPageController {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(WalletPageController.class);

    private final SessionService sessionService;
    private final CredentialStore credentialStore;
    private final CredentialService credentialService;
    private final OidcClient oidcClient;
    private final ObjectMapper objectMapper;
    private final MdocParser mdocParser;
    private final SdJwtParser sdJwtParser;
    private final DebugLogService debugLogService;
    private final MockIssuerFlowService mockIssuerFlowService;
    private final MockIssuerConfigurationStore mockIssuerConfigurationStore;
    private final Oid4vciClientService oid4vciClientService;

    public WalletPageController(SessionService sessionService,
                                CredentialStore credentialStore,
                                CredentialService credentialService,
                                OidcClient oidcClient,
                                ObjectMapper objectMapper,
                                DebugLogService debugLogService,
                                MockIssuerFlowService mockIssuerFlowService,
                                MockIssuerConfigurationStore mockIssuerConfigurationStore,
                                Oid4vciClientService oid4vciClientService) {
        this.sessionService = sessionService;
        this.credentialStore = credentialStore;
        this.credentialService = credentialService;
        this.oidcClient = oidcClient;
        this.objectMapper = objectMapper;
        this.mdocParser = new MdocParser();
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.debugLogService = debugLogService;
        this.mockIssuerFlowService = mockIssuerFlowService;
        this.mockIssuerConfigurationStore = mockIssuerConfigurationStore;
        this.oid4vciClientService = oid4vciClientService;
    }

    @GetMapping({"/", "/wallet"})
    public String wallet(Model model, HttpSession httpSession,
                         @RequestParam(value = "credentialOffer", required = false) String credentialOffer) {
        WalletSession session = sessionService.getSession(httpSession);

        // Handle credential offer if present (OID4VCI same-device flow)
        if (credentialOffer != null && !credentialOffer.isBlank()) {
            LOG.info("[Wallet] Received credential offer: {}", credentialOffer.substring(0, Math.min(100, credentialOffer.length())) + "...");
            try {
                String ownerId = session.isAuthenticated() && session.getUserProfile() != null
                        ? session.getUserProfile().sub()
                        : CredentialStore.MOCK_ISSUER_OWNER;
                Oid4vciClientService.CredentialReceiveResult result = oid4vciClientService.receiveCredential(credentialOffer, ownerId);
                model.addAttribute("message", "Credential received successfully from " + result.issuerUrl());
                LOG.info("[Wallet] Successfully received credential: configId={}, issuer={}",
                        result.configurationId(), result.issuerUrl());
            } catch (Exception e) {
                LOG.error("[Wallet] Failed to receive credential", e);
                model.addAttribute("error", "Failed to receive credential: " + e.getMessage());
            }
        }

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
    public String issue(@RequestParam(
            value = "credentialConfigurationId", required = false) String configId,
                        HttpSession httpSession, Model model) {
        WalletSession session = sessionService.getSession(httpSession);
        if (!session.isAuthenticated()) {
            model.addAttribute("error", "Not authenticated");
            return wallet(model, httpSession, null);
        }
        TokenSet tokens = session.getTokenSet();
        if (tokens != null && tokens.needsRefresh()) {
            tokens = oidcClient.refreshTokens(tokens);
            if (tokens == null) {
                // Token refresh failed - clear session
                session.setTokenSet(null);
                session.setUserProfile(null);
                model.addAttribute("error", "Session expired. Please sign in again.");
                return wallet(model, httpSession, null);
            }
            session.setTokenSet(tokens);
        }
        if (tokens == null) {
            model.addAttribute("error", "Missing tokens");
            return wallet(model, httpSession, null);
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
        return wallet(model, httpSession, null);
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
        return wallet(model, httpSession, null);
    }

    @PostMapping("/credentials/delete")
    public String deleteCredential(@RequestParam("file") String file,
                                   HttpSession httpSession,
                                   Model model) {
        WalletSession session = sessionService.getSession(httpSession);
        boolean deleted = credentialStore.deleteCredential(session.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER), file);
        if (!deleted) {
            model.addAttribute("error", "Credential not found");
        } else {
            model.addAttribute("message", "Deleted credential " + file);
        }
        return wallet(model, httpSession, null);
    }

    private List<DisplayCredential> loadDisplayCredentials(WalletSession session) {
        List<DisplayCredential> result = new ArrayList<>();
        List<CredentialStore.Entry> entries = credentialStore.listCredentialEntries(
                session.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER)
        );
        for (CredentialStore.Entry entry : entries) {
            Map<String, Object> map = objectMapper.convertValue(entry.credential(), Map.class);
            String raw = map.containsKey("rawCredential") ? String.valueOf(map.get("rawCredential")) : null;
            List<String> disclosures = extractDisclosures(map);
            String format = detectFormat(map.get("format"), raw, disclosures);
            Map<String, Object> claims = filterDisplayClaims(extractClaims(map, raw));
            String vct = extractVct(map, raw);
            String storedAt = map.getOrDefault("storedAt", "").toString();
            String mdocDecoded = "mso_mdoc".equalsIgnoreCase(format) ? decodeMdoc(raw) : null;
            boolean sdJwtLike = sdJwtParser.isSdJwt(raw) || (disclosures != null && !disclosures.isEmpty());
            result.add(new DisplayCredential(entry.fileName(), format, vct, raw, storedAt, claims, disclosures, mdocDecoded, sdJwtLike));
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
            if (sdJwtParser.isSdJwt(raw)) {
                return sdJwtParser.extractDisclosedClaims(raw);
            }
            if (mdocParser.isMdoc(raw)) {
                return mdocParser.extractClaims(raw);
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

    private String detectFormat(Object declared, String raw, List<String> disclosures) {
        if (declared instanceof String s && !s.isBlank()) {
            return s;
        }
        if (raw != null && sdJwtParser.isSdJwt(raw)) {
            return "dc+sd-jwt";
        }
        if (disclosures != null && !disclosures.isEmpty()) {
            return "dc+sd-jwt";
        }
        if (raw != null && mdocParser.isMdoc(raw) && raw.length() > 32) {
            return "mso_mdoc";
        }
        if (raw != null) {
            return "jwt_vc";
        }
        return "unknown format";
    }

    private Map<String, Object> filterDisplayClaims(Map<String, Object> claims) {
        return ClaimDisplayFilter.filterForDisplay(claims);
    }

    private String decodeMdoc(String raw) {
        if (!mdocParser.isMdoc(raw)) {
            return null;
        }
        try {
            return mdocParser.prettyPrint(raw);
        } catch (Exception e) {
            return null;
        }
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
            if (sdJwtParser.isSdJwt(raw)) {
                return sdJwtParser.extractVct(raw);
            }
            if (mdocParser.isMdoc(raw)) {
                return mdocParser.extractDocType(raw);
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

    private Map<String, Map<String, List<DebugEntry>>> groupBy(
            List<DebugEntry> entries) {
        Map<String, Map<String, List<DebugEntry>>> grouped = new LinkedHashMap<>();
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
                                    List<String> disclosures,
                                    String mdocDecoded,
                                    boolean sdJwtLike) {
        public String prettyFormat() {
            String normalized = format == null ? "" : format.trim();
            if (normalized.isBlank() || "unknown format".equalsIgnoreCase(normalized) || "null".equalsIgnoreCase(normalized)) {
                if (sdJwtLike) {
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
            if (normalized.equalsIgnoreCase("mso_mdoc")) {
                return "mDoc";
            }
            return normalized;
        }
    }

    public record CredentialOption(String configurationId, String scope, String label) {
    }

    private record IssuerAvailability(boolean available, List<CredentialOption> options, String error) {
    }
}
