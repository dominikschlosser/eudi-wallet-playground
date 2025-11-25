package de.arbeitsagentur.keycloak.wallet.verification.web;

import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.DcqlService;
import de.arbeitsagentur.keycloak.wallet.verification.service.PresentationVerificationService;
import de.arbeitsagentur.keycloak.wallet.verification.service.TrustListService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSession;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSessionService;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/verifier")
public class VerifierController {
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    private final DcqlService dcqlService;
    private final VerifierSessionService verifierSessionService;
    private final TrustListService trustListService;
    private final PresentationVerificationService verificationService;
    private final VerifierKeyService verifierKeyService;
    private final ObjectMapper objectMapper;
    private final VerifierProperties properties;
    private final DebugLogService debugLogService;

    public VerifierController(DcqlService dcqlService,
                              VerifierSessionService verifierSessionService,
                              TrustListService trustListService,
                              PresentationVerificationService verificationService,
                              VerifierKeyService verifierKeyService,
                              ObjectMapper objectMapper,
                              VerifierProperties properties,
                              DebugLogService debugLogService) {
        this.dcqlService = dcqlService;
        this.verifierSessionService = verifierSessionService;
        this.trustListService = trustListService;
        this.verificationService = verificationService;
        this.verifierKeyService = verifierKeyService;
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
        X509Material defaultX509 = resolveX509Material(null);
        model.addAttribute("defaultX509ClientId", deriveX509ClientId(null, defaultX509.certificatePem()));
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
        X509Material x509Material = null;
        if ("x509_hash".equalsIgnoreCase(authType)) {
            x509Material = resolveX509Material(walletClientCert);
            walletClientCert = x509Material.combinedPem();
            effectiveClientId = deriveX509ClientId(effectiveClientId, x509Material.certificatePem());
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
        WalletAuthRequest walletAuth = buildWalletAuthorizationUrl(
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
                    decodeJwtLike(walletAuth.attestationJwt()));
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

    private WalletAuthRequest buildWalletAuthorizationUrl(URI callback, String state, String nonce,
                                                          String dcqlQuery,
                                                          String walletAuthOverride,
                                                          String effectiveClientId,
                                                          String authType,
                                                          String clientMetadata,
                                                          String walletClientCert,
                                                          String attestationCert,
                                                          String attestationIssuer,
                                                          String responseTypeOverride,
                                                          UriComponentsBuilder baseUri) {
        UriComponentsBuilder builder;
        String effectiveWalletAuth = walletAuthOverride != null && !walletAuthOverride.isBlank()
                ? walletAuthOverride
                : properties.walletAuthEndpoint();
        String attestationValue = null;
        String effectiveResponseType = responseTypeOverride != null && !responseTypeOverride.isBlank()
                ? responseTypeOverride
                : "vp_token";
        if (effectiveWalletAuth != null && !effectiveWalletAuth.isBlank()) {
            builder = UriComponentsBuilder.fromUriString(effectiveWalletAuth)
                    .queryParam("response_type", qp(effectiveResponseType));
        } else {
            builder = baseUri.cloneBuilder().path("/oid4vp/auth");
        }
        boolean includeClientCertParam = true;
        UriComponentsBuilder populated = builder
                .queryParam("client_id", qp(effectiveClientId))
                .queryParam("nonce", qp(nonce))
                .queryParam("response_mode", qp("direct_post"))
                .queryParam("response_uri", qp(callback.toString()))
                .queryParam("state", qp(state))
                .queryParam("dcql_query", qp(dcqlQuery));
        if ("x509_hash".equalsIgnoreCase(authType) && walletClientCert != null && walletClientCert.contains("PRIVATE KEY")) {
            try {
                RSAKey popKey = parseAttestationKey(walletClientCert);
                List<com.nimbusds.jose.util.Base64> x5c = extractCertChain(walletClientCert);
                String requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType, dcqlQuery, clientMetadata, null, x5c, popKey);
                populated.queryParam("request", qp(requestObject));
                includeClientCertParam = false;
            } catch (Exception ignored) {
                includeClientCertParam = true;
            }
        }
        if ("verifier_attestation".equalsIgnoreCase(authType)) {
            RSAKey verifierKey = verifierKeyService.loadOrCreateKey();
            RSAKey attestationKey = verifierKey;
            if (attestationCert != null && !attestationCert.isBlank()) {
                attestationKey = parseAttestationKey(attestationCert);
            }
            attestationValue = createVerifierAttestation(effectiveClientId, attestationIssuer, attestationKey, callback.toString());
            String requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType, dcqlQuery, clientMetadata, attestationValue, null, attestationKey);
            populated.queryParam("request", qp(requestObject));
        }
        if (clientMetadata != null && !clientMetadata.isBlank()) {
            populated.queryParam("client_metadata", qp(clientMetadata));
        }
        if (includeClientCertParam && walletClientCert != null && !walletClientCert.isBlank()) {
            populated.queryParam("client_cert", qp(walletClientCert));
        }
        return new WalletAuthRequest(populated.build(true).toUri(), authType != null && authType.equalsIgnoreCase("verifier_attestation") ? attestationValue : null);
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
                    assembleDecodedForDebug(tokensToJson(vpTokens.stream().map(VpTokenEntry::token).toList()), keyBindingJwt));
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
        mv.addObject("vpTokens", presentableTokens(tokens));
        mv.addObject("vpTokensRawList", tokens);
        mv.addObject("hasEncryptedVpToken", hasEncryptedToken(tokens));
        mv.addObject("vpTokenRaw", vpTokenRaw);
        mv.addObject("vpTokenRawDisplay", presentableToken(vpTokenRaw));
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

    private record WalletAuthRequest(URI uri, String attestationJwt) {
    }

    private String decodeJwtLike(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        try {
            JsonNode node = null;
            try {
                node = objectMapper.readTree(token);
            } catch (Exception ignored) {
            }
            if (node != null && node.isArray() && node.size() > 0) {
                token = node.get(0).asText();
            }
            if (token.contains("~")) {
                String signed = token.split("~")[0];
                token = signed;
            }
            if (!token.contains(".")) {
                return "";
            }
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return "";
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(payload));
        } catch (Exception e) {
            return "";
        }
    }

    private String assembleDecodedForDebug(String vpTokensJson, String keyBindingToken) {
        StringBuilder sb = new StringBuilder();
        String vpDecoded = decodeJwtLike(vpTokensJson);
        if (vpDecoded != null && !vpDecoded.isBlank()) {
            sb.append("vp_token:\n").append(vpDecoded);
        }
        String kbDecoded = decodeJwtLike(keyBindingToken);
        if (kbDecoded != null && !kbDecoded.isBlank()) {
            if (!sb.isEmpty()) {
                sb.append("\n\n");
            }
            sb.append("key_binding_jwt:\n").append(kbDecoded);
        }
        return sb.toString();
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
        StringBuilder decoded = new StringBuilder();
        String vpDecoded = decodeJwtLike(tokensForDebug);
        if (vpDecoded != null && !vpDecoded.isBlank()) {
            decoded.append("vp_token:\n").append(vpDecoded);
        }
        String kbDecoded = decodeJwtLike(keyBindingToken);
        if (kbDecoded != null && !kbDecoded.isBlank()) {
            if (!decoded.isEmpty()) {
                decoded.append("\n\n");
            }
            decoded.append("key_binding_jwt:\n").append(kbDecoded);
        }
        String dpopDecoded = decodeJwtLike(dpopToken);
        if (dpopDecoded != null && !dpopDecoded.isBlank()) {
            if (!decoded.isEmpty()) {
                decoded.append("\n\n");
            }
            decoded.append("dpop:\n").append(dpopDecoded);
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
                decoded.toString());
    }

    private List<String> decryptTokensForView(List<String> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return List.of();
        }
        List<String> decrypted = new ArrayList<>(tokens.size());
        for (String token : tokens) {
            decrypted.add(decryptTokenForView(token));
        }
        return decrypted;
    }

    private boolean hasEncryptedToken(List<String> tokens) {
        return tokens != null && tokens.stream().anyMatch(this::isEncryptedJwe);
    }

    private String decryptTokenForView(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        if (!isEncryptedJwe(token)) {
            return token;
        }
        try {
            return verifierKeyService.decrypt(token);
        } catch (Exception e) {
            return token;
        }
    }

    private String presentableToken(String token) {
        String decrypted = decryptTokenForView(token);
        String embedded = extractEmbeddedVpToken(decrypted);
        if (embedded != null && !embedded.isBlank()) {
            return embedded;
        }
        return decrypted == null ? "" : decrypted;
    }

    private List<String> presentableTokens(List<String> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>(tokens.size());
        for (String token : tokens) {
            result.add(presentableToken(token));
        }
        return result;
    }

    private String extractEmbeddedVpToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        if (!token.contains(".")) {
            return null;
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            JsonNode vp = node.path("vp_token");
            if (vp.isMissingNode() || vp.isNull()) {
                return null;
            }
            if (vp.isTextual()) {
                return vp.asText();
            }
            if (vp.isArray() && vp.size() > 0) {
                JsonNode first = vp.get(0);
                return first.isTextual() ? first.asText() : first.toString();
            }
            if (vp.isObject()) {
                return vp.toString();
            }
            return vp.asText(null);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isEncryptedJwe(String token) {
        if (token == null) {
            return false;
        }
        return token.chars().filter(c -> c == '.').count() == 4;
    }

    private RSAKey parseAttestationKey(String pem) {
        try {
            String privBase64 = extractPemBlock(pem, "PRIVATE KEY");
            String certBase64 = extractPemBlock(pem, "CERTIFICATE");
            if (privBase64 == null) {
                throw new IllegalStateException("Attestation certificate must include a private key (PKCS8)");
            }
            byte[] privBytes = Base64.getMimeDecoder().decode(privBase64);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);
            java.security.PublicKey publicKey = null;
            if (certBase64 != null) {
                byte[] certBytes = Base64.getMimeDecoder().decode(certBase64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
                publicKey = cert.getPublicKey();
            }
            if (publicKey == null) {
                publicKey = kf.generatePublic(new java.security.spec.RSAPublicKeySpec(
                        ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getModulus(),
                        ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getPublicExponent()
                ));
            }
            return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) publicKey)
                    .privateKey(privateKey)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse attestation certificate/key", e);
        }
    }

    private List<com.nimbusds.jose.util.Base64> extractCertChain(String pem) {
        if (pem == null || pem.isBlank()) {
            return List.of();
        }
        List<com.nimbusds.jose.util.Base64> chain = new ArrayList<>();
        int idx = 0;
        while (true) {
            int start = pem.indexOf("-----BEGIN CERTIFICATE-----", idx);
            if (start < 0) {
                break;
            }
            int end = pem.indexOf("-----END CERTIFICATE-----", start);
            if (end < 0) {
                break;
            }
            String body = pem.substring(start + "-----BEGIN CERTIFICATE-----".length(), end)
                    .replaceAll("\\s+", "")
                    .replace(' ', '+');
            try {
                chain.add(com.nimbusds.jose.util.Base64.encode(java.util.Base64.getDecoder().decode(body)));
            } catch (Exception ignored) {
            }
            idx = end + "-----END CERTIFICATE-----".length();
        }
        return chain;
    }

    private String extractPemBlock(String pem, String type) {
        if (pem == null) {
            return null;
        }
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start >= 0 && stop > start) {
            String body = pem.substring(start + begin.length(), stop);
            return body.replaceAll("\\s+", "");
        }
        return null;
    }

    private String createVerifierAttestation(String clientIdWithPrefix, String issuerOverride, RSAKey signerKey, String responseUri) {
        try {
            String issuer = issuerOverride != null && !issuerOverride.isBlank() ? issuerOverride : "demo-attestation-issuer";
            String baseClientId = clientIdWithPrefix.startsWith("verifier_attestation:")
                    ? clientIdWithPrefix.substring("verifier_attestation:".length())
                    : clientIdWithPrefix;
            String kid = signerKey.getKeyID();
            if (kid == null || kid.isBlank()) {
                kid = com.nimbusds.jose.util.Base64URL.encode(signerKey.toRSAPublicKey().getEncoded()).toString();
                signerKey = new RSAKey.Builder(signerKey.toRSAPublicKey())
                        .privateKey(signerKey.toRSAPrivateKey())
                        .keyID(kid)
                        .build();
            }
            JWSHeader header = new JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .type(com.nimbusds.jose.JOSEObjectType.JWT)
                    .jwk(signerKey.toPublicJWK())
                    .build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(baseClientId)
                    .issueTime(new java.util.Date())
                    .expirationTime(java.util.Date.from(java.time.Instant.now().plusSeconds(600)))
                    .claim("cnf", Map.of("jwk", signerKey.toPublicJWK().toJSONObject()))
                    .claim("redirect_uris", responseUri != null && !responseUri.isBlank() ? java.util.List.of(responseUri) : java.util.List.of())
                    .build();
            SignedJWT att = new SignedJWT(header, claims);
            att.sign(new com.nimbusds.jose.crypto.RSASSASigner(signerKey));
            return att.serialize();
        } catch (Exception e) {
            return null;
        }
    }

    private String buildRequestObject(String responseUri, String state, String nonce,
                                      String clientId, String responseType, String dcqlQuery,
                                      String clientMetadata, String attestationJwt,
                                      List<com.nimbusds.jose.util.Base64> x5c,
                                      RSAKey signerKey) {
        try {
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .type(new com.nimbusds.jose.JOSEObjectType("oauth-authz-req+jwt"))
                    .jwk(signerKey.toPublicJWK());
            if (attestationJwt != null && !attestationJwt.isBlank()) {
                headerBuilder.customParam("jwt", attestationJwt);
            }
            if (x5c != null && !x5c.isEmpty()) {
                headerBuilder.x509CertChain(x5c);
            }
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .claim("client_id", clientId)
                    .claim("response_type", responseType)
                    .claim("response_mode", "direct_post")
                    .claim("response_uri", responseUri)
                    .claim("state", state)
                    .claim("nonce", nonce)
                    .claim("dcql_query", dcqlQuery);
            if (clientMetadata != null && !clientMetadata.isBlank()) {
                try {
                    claims.claim("client_metadata", objectMapper.readTree(clientMetadata));
                } catch (Exception e) {
                    claims.claim("client_metadata", clientMetadata);
                }
            }
            claims.expirationTime(java.util.Date.from(java.time.Instant.now().plusSeconds(600)));
            SignedJWT jwt = new SignedJWT(headerBuilder.build(), claims.build());
            jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signerKey));
            return jwt.serialize();
        } catch (Exception e) {
            return null;
        }
    }

    private record VpTokenEntry(String queryId, String token) {
    }

    private String deriveX509ClientId(String existingClientId, String certificatePem) {
        String firstCert = extractPemBlock(certificatePem, "CERTIFICATE");
        if (firstCert == null || firstCert.isBlank()) {
            throw new IllegalStateException("No certificate found in client_cert");
        }
        try {
            byte[] der = Base64.getMimeDecoder().decode(firstCert);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            String computed = "x509_hash:" + hash;
            if (existingClientId != null && existingClientId.startsWith("x509_hash:") && !existingClientId.equals(computed)) {
                throw new IllegalStateException("client_id hash does not match client_cert");
            }
            return computed;
        } catch (Exception e) {
            throw new IllegalStateException("Invalid client_cert for x509_hash client authentication", e);
        }
    }

    private X509Material resolveX509Material(String providedPem) {
        if (providedPem != null && !providedPem.isBlank()) {
            String certBlock = extractPemBlock(providedPem, "CERTIFICATE");
            if (certBlock == null || certBlock.isBlank()) {
                throw new IllegalStateException("No certificate found in client_cert");
            }
            String normalizedCert = toPem(Base64.getMimeDecoder().decode(certBlock), "CERTIFICATE");
            String combined = providedPem.contains("CERTIFICATE") ? providedPem : normalizedCert;
            return new X509Material(normalizedCert, null, combined, "client_cert");
        }
        RSAKey verifierKey = verifierKeyService.loadOrCreateKey();
        X509Certificate certificate = selfSignedCertificate(verifierKey);
        try {
            String certPem = toPem(certificate.getEncoded(), "CERTIFICATE");
            String keyPem = toPem(verifierKey.toRSAPrivateKey().getEncoded(), "PRIVATE KEY");
            String combined = certPem + "\n" + keyPem;
            return new X509Material(certPem, keyPem, combined, "verifier_self_signed");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to prepare verifier x509 material", e);
        }
    }

    private X509Certificate selfSignedCertificate(RSAKey key) {
        try {
            Date from = Date.from(java.time.Instant.parse("2024-01-01T00:00:00Z"));
            Date to = Date.from(java.time.Instant.parse("2045-01-01T00:00:00Z"));
            byte[] pubDigest = MessageDigest.getInstance("SHA-256").digest(key.toRSAPublicKey().getEncoded());
            BigInteger serial = new BigInteger(1, pubDigest);
            org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=Verifier Demo");
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BC_PROVIDER)
                    .build(key.toRSAPrivateKey());
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    serial,
                    from,
                    to,
                    subject,
                    key.toRSAPublicKey()
            );
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(holder);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate verifier x509 certificate", e);
        }
    }

    private String toPem(byte[] der, String type) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }

    private record X509Material(String certificatePem, String keyPem, String combinedPem, String source) {
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
