package de.arbeitsagentur.keycloak.wallet.verification.web;

import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.DcqlService;
import de.arbeitsagentur.keycloak.wallet.verification.service.PresentationVerificationService;
import de.arbeitsagentur.keycloak.wallet.verification.service.TokenViewService;
import de.arbeitsagentur.keycloak.wallet.verification.service.TrustListService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierAuthService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierCryptoService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSession;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSessionService;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/verifier")
public class VerifierController {
    private final DcqlService dcqlService;
    private final VerifierSessionService verifierSessionService;
    private final TrustListService trustListService;
    private final PresentationVerificationService verificationService;
    private final VerifierKeyService verifierKeyService;
    private final VerifierAuthService verifierAuthService;
    private final VerifierCryptoService verifierCryptoService;
    private final TokenViewService tokenViewService;
    private final ObjectMapper objectMapper;
    private final VerifierProperties properties;
    private final DebugLogService debugLogService;

    public VerifierController(DcqlService dcqlService,
                              VerifierSessionService verifierSessionService,
                              TrustListService trustListService,
                              PresentationVerificationService verificationService,
                              VerifierKeyService verifierKeyService,
                              VerifierAuthService verifierAuthService,
                              VerifierCryptoService verifierCryptoService,
                              TokenViewService tokenViewService,
                              ObjectMapper objectMapper,
                              VerifierProperties properties,
                              DebugLogService debugLogService) {
        this.dcqlService = dcqlService;
        this.verifierSessionService = verifierSessionService;
        this.trustListService = trustListService;
        this.verificationService = verificationService;
        this.verifierKeyService = verifierKeyService;
        this.verifierAuthService = verifierAuthService;
        this.verifierCryptoService = verifierCryptoService;
        this.tokenViewService = tokenViewService;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.debugLogService = debugLogService;
    }

    @GetMapping
    public String verifierPage(Model model) {
        String defaultDcql = pretty(dcqlService.defaultDcqlQuery());
        model.addAttribute("defaultDcqlQuery", defaultDcql);
        String defaultWalletAuth = properties.walletAuthEndpoint();
        if (defaultWalletAuth == null || defaultWalletAuth.isBlank()) {
            defaultWalletAuth = ServletUriComponentsBuilder.fromCurrentContextPath()
                    .path("/oid4vp/auth")
                    .build()
                    .toUriString();
        }
        model.addAttribute("defaultWalletAuthEndpoint", defaultWalletAuth);
        model.addAttribute("defaultWalletClientId", properties.clientId());
        model.addAttribute("defaultClientMetadata", defaultClientMetadata());
        VerifierCryptoService.X509Material defaultX509 = verifierCryptoService.resolveX509Material(null);
        model.addAttribute("defaultX509ClientId", verifierCryptoService.deriveX509ClientId(null, defaultX509.certificatePem()));
        model.addAttribute("defaultX509Cert", defaultX509.certificatePem());
        model.addAttribute("defaultX509Source", defaultX509.source());
        model.addAttribute("verificationDebug", debugLogService.verification());
        model.addAttribute("trustLists", trustListService.options());
        model.addAttribute("defaultTrustList", trustListService.defaultTrustListId());
        model.addAttribute("verificationDebugGrouped", groupBy(debugLogService.verification()));
        return "verifier";
    }

    @GetMapping("/default")
    @ResponseBody
    public Map<String, String> defaultDcqlQuery() {
        String dcql = dcqlService.defaultDcqlQuery();
        return Map.of("dcql_query", dcql);
    }

    @PostMapping("/start")
    public ResponseEntity<Void> startVerification(@RequestParam(name = "dcqlQuery", required = false)
                                                  String dcqlQuery,
                                                  @RequestParam(name = "dcql_query", required = false)
                                                  String dcqlQueryAlt,
                                                  @RequestParam(name = "walletAuthEndpoint", required = false)
                                                  String walletAuthEndpoint,
                                                  @RequestParam(name = "walletClientId", required = false)
                                                  String walletClientId,
                                                  @RequestParam(name = "authType", required = false, defaultValue = "plain")
                                                  String authType,
                                                  @RequestParam(name = "clientMetadata", required = false)
                                                  String clientMetadata,
                                                  @RequestParam(name = "walletClientCert", required = false)
                                                  String walletClientCert,
                                                  @RequestParam(name = "attestationCert", required = false)
                                                  String attestationCert,
                                                  @RequestParam(name = "attestationIssuer", required = false)
                                                  String attestationIssuer,
                                                  @RequestParam(name = "responseType", required = false)
                                                  String responseType,
                                                  @RequestParam(name = "trustList", required = false)
                                                  String trustList,
                                                  HttpServletRequest request) {
        String providedDcql = dcqlQuery != null && !dcqlQuery.isBlank()
                ? dcqlQuery
                : dcqlQueryAlt;
        String effectiveClientId = walletClientId != null && !walletClientId.isBlank()
                ? walletClientId
                : properties.clientId();
        VerifierCryptoService.X509Material x509Material = null;
        if ("x509_hash".equalsIgnoreCase(authType)) {
            x509Material = verifierCryptoService.resolveX509Material(walletClientCert);
            walletClientCert = x509Material.combinedPem();
            effectiveClientId = verifierCryptoService.deriveX509ClientId(effectiveClientId, x509Material.certificatePem());
        }
        if ("verifier_attestation".equalsIgnoreCase(authType)
                && (effectiveClientId == null || !effectiveClientId.startsWith("verifier_attestation:"))) {
            effectiveClientId = "verifier_attestation:" + (effectiveClientId == null ? "verifier" : effectiveClientId);
        }
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String resolvedDcql = resolveDcqlQuery(providedDcql);
        if ("x509_hash".equalsIgnoreCase(authType) && x509Material != null) {
            debugLogService.addVerification(
                    state,
                    "Authorization",
                    "x509_hash client binding",
                    "INFO",
                    "x509_hash",
                    Map.of("client_id", effectiveClientId),
                    x509Material.certificatePem(),
                    null,
                    Map.of("certificate_source", x509Material.source()),
                    "",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3",
                    null);
        }
        verifierSessionService.saveSession(request.getSession(),
                new VerifierSession(state, nonce, resolvedDcql,
                        trustList != null && !trustList.isBlank() ? trustList : trustListService.defaultTrustListId(),
                        clientMetadata,
                        effectiveClientId,
                        authType,
                        null));
        UriComponentsBuilder baseUri = baseUri(request);
        URI callback = baseUri.cloneBuilder()
                .path("/verifier/callback")
                .build()
                .toUri();
        VerifierAuthService.WalletAuthRequest walletAuth = verifierAuthService.buildWalletAuthorizationUrl(
                callback,
                state,
                nonce,
                resolvedDcql,
                walletAuthEndpoint,
                effectiveClientId,
                authType,
                clientMetadata,
                walletClientCert,
                attestationCert,
                attestationIssuer,
                responseType,
                baseUri
        );
        debugLogService.addVerification(
                state,
                "Authorization",
                "Authorization request to wallet",
                "GET",
                walletAuth.uri().toString(),
                Map.of(),
                "",
                302,
                Map.of("Location", walletAuth.uri().toString()),
                "state=" + state + "\nnonce=" + nonce + "\ntrust_list=" + (trustList != null ? trustList : trustListService.defaultTrustListId()),
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#vp_token_request",
                null);
        if ("verifier_attestation".equalsIgnoreCase(authType) && walletAuth.attestationJwt() != null && !walletAuth.attestationJwt().isBlank()) {
            debugLogService.addVerification(
                    state,
                    "Authorization",
                    "Verifier attestation (wallet client authentication)",
                    "JWT",
                    "verifier_attestation",
                    Map.of(),
                    walletAuth.attestationJwt(),
                    null,
                    Map.of(),
                    "",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#verifier_attestation_jwt",
                    tokenViewService.decodeJwtLike(walletAuth.attestationJwt()));
            verifierSessionService.saveSession(request.getSession(),
                    new VerifierSession(state, nonce, resolvedDcql,
                            trustList != null && !trustList.isBlank() ? trustList : trustListService.defaultTrustListId(),
                            clientMetadata,
                            effectiveClientId,
                            authType,
                            walletAuth.attestationJwt()));
        }
        return ResponseEntity.status(302).location(walletAuth.uri()).build();
    }

    @PostMapping(value = "/callback")
    public ModelAndView handleCallback(@RequestParam("state") String state,
                                       @RequestParam(name = "vp_token", required = false) String vpToken,
                                       @RequestParam(name = "id_token", required = false) String idToken,
                                       @RequestParam(name = "key_binding", required = false) String keyBindingToken,
                                       @RequestParam(name = "key_binding_jwt", required = false) String keyBindingTokenAlt,
                                       @RequestParam(name = "dpop", required = false) String dpopToken,
                                       @RequestParam(name = "dpop_token", required = false) String dpopTokenAlt,
                                       @RequestParam(name = "nonce", required = false) String responseNonce,
                                       @RequestParam(name = "error", required = false) String error,
                                       @RequestParam(name = "error_description", required = false) String errorDescription,
                                       HttpSession httpSession) {
        VerificationSteps steps = new VerificationSteps();
        String vpTokenRaw = vpToken;
        String keyBindingJwt = firstNonBlank(keyBindingTokenAlt, keyBindingToken);
        String effectiveDpop = firstNonBlank(dpopToken, dpopTokenAlt);
        String callbackRequestBody = formBody(state, vpTokenRaw, idToken, responseNonce, error, errorDescription, keyBindingJwt, effectiveDpop);
        VerifierSession verifierSession = verifierSessionService.getSession(httpSession);
        if (verifierSession == null || !verifierSession.state().equals(state)) {
            steps.add("Verifier session and state validation failed",
                    "Verifier session not found or state mismatch.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            logCallback(state, "direct_post callback (invalid session)",
                    "POST",
                    "/verifier/callback",
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    callbackRequestBody,
                    HttpStatus.BAD_REQUEST.value(),
                    Map.of(),
                    "vp_token length=%d".formatted(vpToken != null ? vpToken.length() : 0),
                    null, vpTokenRaw, keyBindingJwt, effectiveDpop);
            return resultView("Invalid verifier session", false, steps.titles(), parseVpTokens(vpTokenRaw), vpTokenRaw, idToken, Map.of(), steps.details());
        }
        if (error != null && !error.isBlank()) {
            String viewMessage = errorDescription != null ? errorDescription : "Presentation denied";
            if (error != null && !error.isBlank() && !viewMessage.contains(error)) {
                viewMessage = viewMessage + " (" + error + ")";
            }
            steps.add("Wallet returned error: " + error,
                    "Wallet returned error: " + error,
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            logCallback(state, "direct_post callback (error)",
                    "POST",
                    "/verifier/callback",
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    callbackRequestBody,
                    HttpStatus.BAD_REQUEST.value(),
                    Map.of(),
                    "error=%s\nerror_description=%s".formatted(error, errorDescription),
                    null, vpTokenRaw, keyBindingJwt, effectiveDpop);
            return resultView(viewMessage, false, steps.titles(), parseVpTokens(vpTokenRaw), vpTokenRaw, idToken, Map.of(), steps.details());
        }
        try {
            List<VpTokenEntry> vpTokens = extractVpTokens(vpTokenRaw);
            if (vpTokens.isEmpty()) {
                steps.add("vp_token missing or empty",
                        "Wallet response did not include a vp_token.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
                logCallback(state, "direct_post callback (missing vp_token)",
                        "POST",
                        "/verifier/callback",
                        Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        callbackRequestBody,
                        HttpStatus.BAD_REQUEST.value(),
                        Map.of(),
                        "vp_token length=0",
                        null, vpTokenRaw, keyBindingJwt, effectiveDpop);
                return resultView("Missing vp_token", false, steps.titles(), List.of(), vpTokenRaw, idToken, Map.of(), steps.details());
            }
            if (verifierSession.authType() != null && !verifierSession.authType().isBlank()) {
                steps.add("Wallet client authentication",
                        "Wallet authenticated using " + verifierSession.authType(),
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3");
            }
            List<Map<String, Object>> payloads = verificationService.verifyPresentations(
                    vpTokens.stream().map(VpTokenEntry::token).toList(),
                    verifierSession.nonce(),
                    responseNonce,
                    verifierSession.trustListId(),
                    verifierSession.clientId(),
                    steps);
            steps.add("Presentation verified successfully (%d token%s)".formatted(payloads.size(), payloads.size() == 1 ? "" : "s"),
                    "All verification checks passed for the presented credential(s).",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            debugLogService.addVerification(
                    verifierSession.state(),
                    "direct_post",
                    "direct_post callback",
                    "POST",
                    "/verifier/callback",
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    formBody(state, vpTokenRaw, idToken, responseNonce, error, errorDescription, keyBindingJwt, effectiveDpop),
                    HttpStatus.OK.value(),
                    Map.of(),
                    "vp_token length=%d\nkey_binding len=%s".formatted(
                            vpTokenRaw != null ? vpTokenRaw.length() : 0,
                            keyBindingJwt != null ? keyBindingJwt.length() : 0),
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6",
                    tokenViewService.assembleDecodedForDebug(
                            tokensToJson(vpTokens.stream().map(VpTokenEntry::token).toList()),
                            keyBindingJwt,
                            effectiveDpop));
            Map<String, Object> combined = new LinkedHashMap<>();
            String kbFromPayload = null;
            for (int i = 0; i < payloads.size(); i++) {
                combined.put("presentation_" + (i + 1), payloads.get(i));
                Object kb = payloads.get(i).get("key_binding_jwt");
                if (kbFromPayload == null && kb instanceof String s && !s.isBlank()) {
                    kbFromPayload = s;
                }
            }
            if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
                combined.put("key_binding_jwt", keyBindingJwt);
            } else if (kbFromPayload != null && !kbFromPayload.isBlank()) {
                combined.put("key_binding_jwt", kbFromPayload);
            }
            if (effectiveDpop != null && !effectiveDpop.isBlank()) {
                combined.put("dpop_token", effectiveDpop);
            }
            return resultView("Verified credential(s)", true, steps.titles(), vpTokens.stream().map(VpTokenEntry::token).toList(), vpTokenRaw, idToken, combined,
                    steps.details());
        } catch (Exception e) {
            steps.add("Verification failed: " + e.getMessage(),
                    "Verification failed: " + e.getMessage(),
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            logCallback(state, "direct_post callback (error)",
                    "POST",
                    "/verifier/callback",
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    callbackRequestBody,
                    HttpStatus.BAD_REQUEST.value(),
                    Map.of(),
                    e.getMessage(),
                    parseVpTokens(vpTokenRaw), vpTokenRaw, keyBindingJwt, effectiveDpop);
            return resultView("Unable to verify credential: " + e.getMessage(), false, steps.titles(), parseVpTokens(vpTokenRaw), vpTokenRaw, idToken,
                    Map.of(), steps.details());
        }
    }

    private ModelAndView resultView(String message, boolean success, List<String> steps, List<String> vpTokens, String vpTokenRaw,
                                    String idToken, Map<String, Object> payload, List<VerificationSteps.StepDetail> stepDetails) {
        ModelAndView mv = new ModelAndView("verifier-result");
        mv.addObject("title", success ? "Presentation Verified" : "Verification Error");
        mv.addObject("message", message);
        mv.addObject("steps", steps);
        mv.addObject("stepDetails", stepDetails);
        List<String> tokens = vpTokens == null ? List.of() : vpTokens;
        mv.addObject("vpTokens", tokenViewService.presentableTokens(tokens));
        mv.addObject("vpTokensRawList", tokens);
        mv.addObject("hasEncryptedVpToken", tokenViewService.hasEncryptedToken(tokens));
        mv.addObject("vpTokenRaw", vpTokenRaw);
        mv.addObject("vpTokenRawDisplay", tokenViewService.presentableToken(vpTokenRaw));
        mv.addObject("idToken", idToken);
        mv.addObject("claims", payload);
        mv.addObject("keyBindingJwt", payload.getOrDefault("key_binding_jwt", null));
        mv.addObject("dpopToken", payload.getOrDefault("dpop_token", null));
        mv.addObject("verificationDebug", debugLogService.verification());
        try {
            mv.addObject("claimsJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload));
        } catch (Exception ignored) {
            mv.addObject("claimsJson", "{}");
        }
        mv.setStatus(success ? HttpStatus.OK : HttpStatus.BAD_REQUEST);
        mv.addObject("verificationDebug", debugLogService.verification());
        mv.addObject("verificationDebugGrouped", groupBy(debugLogService.verification()));
        return mv;
    }

    private String qp(String value) {
        return value == null ? null : UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }

    private String resolveDcqlQuery(String provided) {
        if (provided != null && !provided.isBlank()) {
            return minify(provided);
        }
        String configured = dcqlService.defaultDcqlQuery();
        if (configured != null && !configured.isBlank()) {
            return minify(configured);
        }
        throw new IllegalStateException("Missing dcql_query");
    }

    private String defaultClientMetadata() {
        try {
            String jwks = verifierKeyService.publicJwksJson();
            JsonNode node = objectMapper.readTree(jwks);
            ObjectNode meta = objectMapper.createObjectNode();
            meta.set("jwks", node);
            meta.put("response_encryption_alg", "RSA-OAEP-256");
            meta.put("response_encryption_enc", "A256GCM");
            return objectMapper.writeValueAsString(meta);
        } catch (Exception e) {
            return "";
        }
    }

    private String pretty(String json) {
        if (json == null || json.isBlank()) {
            return "";
        }
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(objectMapper.readTree(json));
        } catch (Exception e) {
            return json;
        }
    }

    private String minify(String json) {
        if (json == null || json.isBlank()) {
            return json;
        }
        try {
            return objectMapper.writeValueAsString(objectMapper.readTree(json));
        } catch (Exception e) {
            return json;
        }
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
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

    private List<VpTokenEntry> extractVpTokens(String vpTokenRaw) {
        if (vpTokenRaw == null || vpTokenRaw.isBlank()) {
            return List.of();
        }
        List<VpTokenEntry> entries = new ArrayList<>();
        try {
            com.fasterxml.jackson.core.JsonParser parser = objectMapper.createParser(vpTokenRaw);
            JsonNode node = objectMapper.readTree(parser);
            if (parser.nextToken() != null) {
                throw new IllegalArgumentException("Trailing content in vp_token");
            }
            if (node.isObject()) {
                node.fields().forEachRemaining(field -> {
                    String queryId = field.getKey();
                    JsonNode value = field.getValue();
                    if (value.isArray()) {
                        value.forEach(item -> entries.add(new VpTokenEntry(queryId, asTokenString(item))));
                    } else {
                        entries.add(new VpTokenEntry(queryId, asTokenString(value)));
                    }
                });
            } else if (node.isArray()) {
                node.forEach(item -> entries.add(new VpTokenEntry(null, asTokenString(item))));
            } else if (node.isTextual()) {
                entries.add(new VpTokenEntry(null, node.asText()));
            }
        } catch (Exception e) {
            return List.of();
        }
        entries.removeIf(entry -> entry.token() == null || entry.token().isBlank());
        return entries;
    }

    private record VpTokenEntry(String queryId, String token) {
    }

    private String asTokenString(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return "";
        }
        if (node.isTextual() || node.isValueNode()) {
            return node.asText();
        }
        return node.toString();
    }

    private String tokensToJson(List<String> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return "";
        }
        if (tokens.size() == 1) {
            return tokens.get(0);
        }
        try {
            return objectMapper.writeValueAsString(tokens);
        } catch (Exception e) {
            return String.join(",", tokens);
        }
    }

    private String formBody(String state, String vpToken, String idToken, String responseNonce,
                            String error, String errorDescription, String keyBindingToken, String dpopToken) {
        StringBuilder sb = new StringBuilder();
        appendForm(sb, "state", state);
        appendForm(sb, "vp_token", vpToken);
        appendForm(sb, "id_token", idToken);
        appendForm(sb, "nonce", responseNonce);
        appendForm(sb, "key_binding_jwt", keyBindingToken);
        appendForm(sb, "dpop", dpopToken);
        appendForm(sb, "error", error);
        appendForm(sb, "error_description", errorDescription);
        return sb.toString();
    }

    private void appendForm(StringBuilder sb, String key, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        if (sb.length() > 0) {
            sb.append("\n");
        }
        sb.append(key).append("=").append(value);
    }

    private List<String> parseVpTokens(String vpTokenRaw) {
        return extractVpTokens(vpTokenRaw).stream()
                .map(VpTokenEntry::token)
                .toList();
    }

    private void logCallback(String state, String title, String method, String url, Map<String, String> requestHeaders,
                             String requestBody, Integer status, Map<String, String> responseHeaders, String responseBody,
                             List<String> vpTokens, String vpTokenRaw, String keyBindingToken, String dpopToken) {
        String tokensForDebug = tokensToJson(vpTokens);
        if (tokensForDebug.isBlank()) {
            tokensForDebug = vpTokenRaw;
        }
        debugLogService.addVerification(
                state,
                "direct_post",
                title,
                method,
                url,
                requestHeaders,
                requestBody,
                status,
                responseHeaders,
                responseBody,
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6",
                tokenViewService.assembleDecodedForDebug(tokensForDebug, keyBindingToken, dpopToken));
    }

    private UriComponentsBuilder baseUri(HttpServletRequest request) {
        String scheme = firstHeaderValue(request, "X-Forwarded-Proto");
        if (scheme == null || scheme.isBlank()) {
            scheme = request.getScheme();
        }
        String hostHeader = firstHeaderValue(request, "X-Forwarded-Host");
        String host = null;
        Integer port = null;
        if (hostHeader != null && !hostHeader.isBlank()) {
            String[] hostParts = hostHeader.split(",", 2)[0].trim().split(":", 2);
            host = hostParts[0];
            if (hostParts.length > 1) {
                try {
                    port = Integer.parseInt(hostParts[1]);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        String portHeader = firstHeaderValue(request, "X-Forwarded-Port");
        if (port == null && portHeader != null && !portHeader.isBlank()) {
            try {
                port = Integer.parseInt(portHeader.split(",", 2)[0].trim());
            } catch (NumberFormatException ignored) {
            }
        }
        if (host == null || host.isBlank()) {
            host = request.getServerName();
        }
        if (port == null) {
            port = request.getServerPort();
        }
        UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                .scheme(scheme)
                .host(host);
        if (!((scheme.equalsIgnoreCase("http") && port == 80) || (scheme.equalsIgnoreCase("https") && port == 443))) {
            builder.port(port);
        }
        return builder;
    }

    private String firstHeaderValue(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        if (value == null) {
            return null;
        }
        int comma = value.indexOf(',');
        if (comma >= 0) {
            return value.substring(0, comma).trim();
        }
        return value.trim();
    }
}
