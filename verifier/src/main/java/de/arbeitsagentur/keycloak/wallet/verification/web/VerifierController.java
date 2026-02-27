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
package de.arbeitsagentur.keycloak.wallet.verification.web;

import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.DcqlService;
import de.arbeitsagentur.keycloak.wallet.verification.service.PresentationVerificationService;
import de.arbeitsagentur.keycloak.wallet.verification.service.TokenViewService;
import de.arbeitsagentur.keycloak.wallet.verification.service.TrustListService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierAuthService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierCryptoService;
import de.arbeitsagentur.keycloak.wallet.verification.service.RequestObjectService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerificationResultStore;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSession;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSessionService;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSessionStateStore;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService.DebugEntry;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/verifier")
public class VerifierController {
    private static final Logger LOG = LoggerFactory.getLogger(VerifierController.class);

    private final DcqlService dcqlService;
    private final VerifierSessionService verifierSessionService;
    private final TrustListService trustListService;
    private final PresentationVerificationService verificationService;
    private final VerifierKeyService verifierKeyService;
    private final VerifierAuthService verifierAuthService;
    private final VerifierCryptoService verifierCryptoService;
    private final TokenViewService tokenViewService;
    private final RequestObjectService requestObjectService;
    private final ObjectMapper objectMapper;
    private final VerifierProperties properties;
    private final DebugLogService debugLogService;
    private final URI publicBaseUri;
    private final VerifierSessionStateStore verifierSessionStateStore;
    private final VerificationResultStore verificationResultStore;

    public VerifierController(DcqlService dcqlService,
                              VerifierSessionService verifierSessionService,
                              VerifierSessionStateStore verifierSessionStateStore,
                              TrustListService trustListService,
                              PresentationVerificationService verificationService,
                              VerifierKeyService verifierKeyService,
                              VerifierAuthService verifierAuthService,
                              VerifierCryptoService verifierCryptoService,
                              TokenViewService tokenViewService,
                              RequestObjectService requestObjectService,
                              ObjectMapper objectMapper,
                              VerifierProperties properties,
                              DebugLogService debugLogService,
                              VerificationResultStore verificationResultStore,
                              @Value("${wallet.public-base-url:}") String publicBaseUrl) {
        this.dcqlService = dcqlService;
        this.verifierSessionService = verifierSessionService;
        this.verifierSessionStateStore = verifierSessionStateStore;
        this.trustListService = trustListService;
        this.verificationService = verificationService;
        this.verifierKeyService = verifierKeyService;
        this.verifierAuthService = verifierAuthService;
        this.verifierCryptoService = verifierCryptoService;
        this.tokenViewService = tokenViewService;
        this.requestObjectService = requestObjectService;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.debugLogService = debugLogService;
        this.verificationResultStore = verificationResultStore;
        this.publicBaseUri = parsePublicBase(publicBaseUrl);
    }

    @GetMapping
    public String verifierPage(Model model, HttpServletRequest request) {
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
        model.addAttribute("defaultClientMetadata", defaultClientMetadata());
        VerifierCryptoService.X509Material defaultX509 = verifierCryptoService.resolveX509Material(null);
        model.addAttribute("defaultX509ClientId", verifierCryptoService.deriveX509ClientId(null, defaultX509.certificatePem()));
        String defaultX509SanClientId;
        try {
            defaultX509SanClientId = verifierCryptoService.deriveX509SanClientId(null, defaultX509.certificatePem());
        } catch (Exception e) {
            defaultX509SanClientId = "";
        }
        model.addAttribute("defaultX509SanClientId", defaultX509SanClientId);
        model.addAttribute("defaultX509Cert", defaultX509.certificatePem());
        model.addAttribute("defaultX509Source", defaultX509.source());
        model.addAttribute("defaultWalletAudience", "https://self-issued.me/v2");

        model.addAttribute("defaultAuthType", "plain");
        model.addAttribute("defaultResponseMode", "direct_post");
        model.addAttribute("defaultRequestObjectMode", "request");
        model.addAttribute("defaultRequestUriMethod", "post");
        model.addAttribute("prefillClientMetadata", "");
        model.addAttribute("defaultWalletClientId", properties.clientId());

        model.addAttribute("verificationDebug", debugLogService.verification());
        model.addAttribute("trustLists", trustListService.options());
        model.addAttribute("defaultTrustList", trustListService.defaultTrustListId());
        model.addAttribute("verificationDebugGrouped", groupBy(debugLogService.verification()));
        model.addAttribute("sandboxAvailable", isSandboxAvailable());
        return "verifier";
    }

    @GetMapping("/default")
    @ResponseBody
    public Map<String, String> defaultDcqlQuery() {
        String dcql = dcqlService.defaultDcqlQuery();
        return Map.of("dcql_query", dcql);
    }

    @GetMapping("/mock-defaults")
    @ResponseBody
    public Map<String, Object> mockDefaults(HttpServletRequest request) {
        String defaultWalletAuth = properties.walletAuthEndpoint();
        if (defaultWalletAuth == null || defaultWalletAuth.isBlank()) {
            defaultWalletAuth = ServletUriComponentsBuilder.fromCurrentRequest()
                    .replacePath("/oid4vp/auth")
                    .build()
                    .toUriString();
        }
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("authType", "plain");
        defaults.put("requestObjectMode", "request");
        defaults.put("requestUriMethod", "post");
        defaults.put("responseType", "vp_token");
        defaults.put("responseMode", "direct_post");
        defaults.put("walletAuthEndpoint", defaultWalletAuth);
        defaults.put("walletAudience", "https://self-issued.me/v2");
        defaults.put("clientId", properties.clientId());
        defaults.put("walletClientCert", "");
        defaults.put("clientMetadata", "");
        defaults.put("verifierInfo", "");
        defaults.put("dcqlQuery", pretty(dcqlService.defaultDcqlQuery()));
        defaults.put("trustListId", trustListService.defaultTrustListId());
        return defaults;
    }

    @GetMapping("/sandbox-defaults")
    @ResponseBody
    public Map<String, Object> sandboxDefaults() {
        if (!isSandboxAvailable()) {
            return Map.of("available", false);
        }
        VerifierCryptoService.X509Material material = verifierCryptoService.loadSandboxMaterial();
        if (material == null) {
            return Map.of("available", false);
        }
        String clientIdSanDns;
        try {
            clientIdSanDns = verifierCryptoService.deriveX509SanClientId(null, material.certificatePem());
        } catch (Exception e) {
            clientIdSanDns = "";
        }
        String clientIdHash = verifierCryptoService.deriveX509ClientId(null, material.certificatePem());
        String verifierInfo = readFileIfExists(properties.sandboxVerifierInfoFilePath());
        String walletAuthEndpoint = properties.sandboxWalletAuthEndpoint() != null
                && !properties.sandboxWalletAuthEndpoint().isBlank()
                ? properties.sandboxWalletAuthEndpoint() : "openid4vp://";
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("available", true);
        defaults.put("authType", "x509_san_dns");
        defaults.put("requestObjectMode", "request_uri");
        defaults.put("requestUriMethod", "get");
        defaults.put("responseType", "vp_token");
        defaults.put("responseMode", "direct_post.jwt");
        defaults.put("walletAuthEndpoint", walletAuthEndpoint);
        defaults.put("walletAudience", "https://self-issued.me/v2");
        defaults.put("clientId", clientIdSanDns);
        defaults.put("clientIdHash", clientIdHash);
        // Send only the certificate chain to the browser — never the private key
        defaults.put("walletClientCert", stripPrivateKey(material.combinedPem()));
        defaults.put("clientMetadata", defaultClientMetadata());
        defaults.put("verifierInfo", verifierInfo);
        // Build three DCQL variants matching the registration certificate claims.
        // SD-JWT: nested address/* paths for selective disclosure of address sub-fields; "nationalities" (plural, array).
        // mDoc: resident_* element identifiers and "nationality" (singular) as defined in EU PID mDoc namespace.
        // Note: BMI PID uses "birthdate" (no underscore), not "birth_date".
        String sdJwtOnly = """
                {"credentials":[{"id":"pid_sd_jwt","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["birthdate"]},{"path":["nationalities",null]},{"path":["address","street_address"]},{"path":["address","locality"]}]}]}""";
        String mdocOnly = """
                {"credentials":[{"id":"pid_mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","given_name"]},{"path":["eu.europa.ec.eudi.pid.1","family_name"]},{"path":["eu.europa.ec.eudi.pid.1","birth_date"]},{"path":["eu.europa.ec.eudi.pid.1","nationality"]},{"path":["eu.europa.ec.eudi.pid.1","resident_street"]},{"path":["eu.europa.ec.eudi.pid.1","resident_city"]},{"path":["eu.europa.ec.eudi.pid.1","resident_postal_code"]},{"path":["eu.europa.ec.eudi.pid.1","resident_country"]}]}]}""";
        String both = """
                {"credentials":[{"id":"pid_sd_jwt","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["birthdate"]},{"path":["nationalities",null]},{"path":["address","street_address"]},{"path":["address","locality"]}]},{"id":"pid_mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","given_name"]},{"path":["eu.europa.ec.eudi.pid.1","family_name"]},{"path":["eu.europa.ec.eudi.pid.1","birth_date"]},{"path":["eu.europa.ec.eudi.pid.1","nationality"]},{"path":["eu.europa.ec.eudi.pid.1","resident_street"]},{"path":["eu.europa.ec.eudi.pid.1","resident_city"]},{"path":["eu.europa.ec.eudi.pid.1","resident_postal_code"]},{"path":["eu.europa.ec.eudi.pid.1","resident_country"]}]}],"credential_sets":[{"options":[["pid_sd_jwt"],["pid_mdoc"]]}]}""";
        // Allow env override via sandboxDcqlQuery for backward compat
        String dcqlOverride = properties.sandboxDcqlQuery();
        defaults.put("dcqlSdJwt", pretty(sdJwtOnly));
        defaults.put("dcqlMdoc", pretty(mdocOnly));
        defaults.put("dcqlBoth", pretty(both));
        defaults.put("dcqlQuery", dcqlOverride != null ? pretty(dcqlOverride) : pretty(both));
        // Prefer pid-provider trust list for sandbox,
        // fall back to default if BMI trust lists are not loaded.
        String sandboxTrustList = trustListService.options().stream()
                .map(TrustListService.TrustListOption::id)
                .filter(id -> id.equals("pid-provider"))
                .findFirst()
                .orElse(trustListService.defaultTrustListId());
        defaults.put("trustListId", sandboxTrustList);
        return defaults;
    }

    private boolean isSandboxAvailable() {
        java.nio.file.Path certFile = properties.clientCertFilePath();
        return certFile != null && Files.exists(certFile);
    }

    private static String stripPrivateKey(String pem) {
        if (pem == null) return "";
        return pem.replaceAll("-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----", "").strip();
    }

    private String readFileIfExists(java.nio.file.Path path) {
        if (path == null || !Files.exists(path)) {
            return "";
        }
        try {
            return Files.readString(path).strip();
        } catch (Exception e) {
            LOG.warn("Failed to read file {}: {}", path, e.getMessage());
            return "";
        }
    }

    @GetMapping(value = "/request-object/{id}", produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<String> requestObject(@PathVariable("id") String id, HttpServletRequest request) {
        return handleRequestObject(id, null, null, request);
    }

    @PostMapping(value = "/request-object/{id}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<String> requestObjectPost(@PathVariable("id") String id,
                                                    @RequestParam(name = "wallet_metadata", required = false) String walletMetadata,
                                                    @RequestParam(name = "wallet_nonce", required = false) String walletNonce,
                                                    HttpServletRequest request) {
        return handleRequestObject(id, walletMetadata, walletNonce, request);
    }

    private ResponseEntity<String> handleRequestObject(String id, String walletMetadata, String walletNonce, HttpServletRequest request) {
        JsonNode walletMeta = parseWalletMetadata(walletMetadata);
        RequestObjectService.SigningRequest signingRequest = determineSigningRequest(walletMeta);
        LOG.info("request_uri {} {} wallet_nonce={} signing_alg={} encryption_requested={} body={} headers={}",
                request.getMethod(),
                request.getRequestURI(),
                walletNonce != null && !walletNonce.isBlank(),
                signingRequest != null ? signingRequest.alg() : "none",
                walletMeta != null && walletMeta.has("jwks"),
                walletRequestLog(walletMetadata, walletNonce),
                request.getHeaderNames() != null ? Collections.list(request.getHeaderNames()).stream().collect(Collectors.toMap(h -> h, request::getHeader)) : Map.of());
        RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(id, walletNonce, signingRequest);
        if (resolved == null || resolved.serialized() == null || resolved.serialized().isBlank()) {
            LOG.info("request_uri {} not found or expired", id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("request object not found or expired");
        }
        JWK encryptionKey = selectEncryptionKey(walletMeta);
        EncryptionPreferences prefs = extractEncryptionPreferences(walletMeta);
        EncryptionResult encryption = encryptRequestObject(resolved.serialized(), encryptionKey, prefs.alg(), prefs.enc());
        String payload = encryption.payload();
        String state = extractState(resolved.claims());
        String decoded = buildDecodedForLog(resolved.serialized(), encryption);
        String responseSummary = "signed=%s wallet_nonce_applied=%s encrypted=%s".formatted(
                resolved.signed(), resolved.walletNonceApplied(), encryption.encrypted());
        LOG.info("request_uri {} response signed={} encrypted={} state={} payload={}",
                request.getRequestURI(),
                resolved.signed(),
                encryption.encrypted(),
                state,
                payload);
        debugLogService.addVerification(
                state,
                "Authorization",
                "request_uri retrieval",
                request.getMethod(),
                request.getRequestURI(),
                Map.of(),
                walletRequestLog(walletMetadata, walletNonce),
                HttpStatus.OK.value(),
                Map.of("Content-Type", "application/oauth-authz-req+jwt"),
                responseSummary + "\n" + payload,
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-parameter",
                decoded
        );
        return ResponseEntity.ok()
                .contentType(MediaType.valueOf("application/oauth-authz-req+jwt"))
                .body(payload);
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
                                                  @RequestParam(name = "responseMode", required = false)
                                                  String responseMode,
                                                  @RequestParam(name = "requestObjectMode", required = false)
                                                  String requestObjectMode,
                                                  @RequestParam(name = "requestUriMethod", required = false)
                                                  String requestUriMethod,
                                                  @RequestParam(name = "walletAudience", required = false)
                                                  String walletAudience,
                                                  @RequestParam(name = "verifierInfo", required = false)
                                                  String verifierInfo,
                                                  @RequestParam(name = "trustList", required = false)
                                                  String trustList,
                                                  @RequestParam(name = "useSandboxKey", required = false, defaultValue = "false")
                                                  boolean useSandboxKey,
                                                  HttpServletRequest request) {
        String providedDcql = dcqlQuery != null && !dcqlQuery.isBlank()
                ? dcqlQuery
                : dcqlQueryAlt;
        String effectiveClientId = walletClientId != null && !walletClientId.isBlank()
                ? walletClientId
                : properties.clientId();
        String resolvedDcql = resolveDcqlQuery(providedDcql);
        boolean responseModeExplicit = responseMode != null && !responseMode.isBlank();
        String effectiveResponseMode = responseModeExplicit ? responseMode : "direct_post";
        if (!responseModeExplicit && requestsEncryptedResponse(clientMetadata)) {
            effectiveResponseMode = "direct_post.jwt";
        }
        String effectiveRequestUriMethod = requestUriMethod != null && !requestUriMethod.isBlank() ? requestUriMethod : "post";
        VerifierCryptoService.X509Material x509Material = null;
        if ("x509_hash".equalsIgnoreCase(authType) || "x509_san_dns".equalsIgnoreCase(authType)) {
            if (useSandboxKey && isSandboxAvailable()) {
                x509Material = verifierCryptoService.loadSandboxMaterial();
            } else {
                x509Material = verifierCryptoService.resolveX509Material(walletClientCert);
            }
            walletClientCert = x509Material.combinedPem();
            if ("x509_hash".equalsIgnoreCase(authType)) {
                effectiveClientId = verifierCryptoService.deriveX509ClientId(effectiveClientId, x509Material.certificatePem());
            } else {
                effectiveClientId = verifierCryptoService.deriveX509SanClientId(effectiveClientId, x509Material.certificatePem());
            }
            walletClientId = effectiveClientId;
        }
        if ("verifier_attestation".equalsIgnoreCase(authType)
                && (effectiveClientId == null || !effectiveClientId.startsWith("verifier_attestation:"))) {
            effectiveClientId = "verifier_attestation:" + (effectiveClientId == null ? "verifier" : effectiveClientId);
        }
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        if ((("x509_hash".equalsIgnoreCase(authType) || "x509_san_dns".equalsIgnoreCase(authType)) && x509Material != null)) {
            debugLogService.addVerification(
                    state,
                    "Authorization",
                    authType + " client binding",
                    "INFO",
                    authType,
                    Map.of("client_id", effectiveClientId, "response_mode", effectiveResponseMode),
                    x509Material.certificatePem(),
                    null,
                    Map.of("certificate_source", x509Material.source()),
                    "",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3",
                    null);
        }
        HttpSession servletSession = request.getSession();
        List<String> trustedIssuerJwks = List.of();

        // Compute callback URI before creating session - this is the response_uri used in authorization request
        // and must be stored for consistent mDoc SessionTranscript verification
        UriComponentsBuilder baseUri = baseUri(request);
        URI callback = baseUri.cloneBuilder().path("/verifier/callback").build().toUri();
        String responseUri = callback.toString();

        VerifierSession verifierSession = new VerifierSession(state, nonce, resolvedDcql, effectiveResponseMode,
                trustList != null && !trustList.isBlank() ? trustList : trustListService.defaultTrustListId(),
                clientMetadata,
                effectiveClientId,
                authType,
                null,
                trustedIssuerJwks,
                responseUri);
        verifierSessionService.saveSession(servletSession, verifierSession);
        verifierSessionStateStore.put(verifierSession);
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
                effectiveResponseMode,
                requestObjectMode,
                effectiveRequestUriMethod,
                walletAudience,
                verifierInfo,
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
                "state=" + state + "\nnonce=" + nonce + "\ntrust_list=" + (trustList != null ? trustList : trustListService.defaultTrustListId()) + "\nrequest_mode=" + (walletAuth.usedRequestUri() ? "request_uri" : "request")
                        + "\nresponse_mode=" + effectiveResponseMode,
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
            VerifierSession updatedSession = new VerifierSession(state, nonce, resolvedDcql, effectiveResponseMode,
                    trustList != null && !trustList.isBlank() ? trustList : trustListService.defaultTrustListId(),
                    clientMetadata,
                    effectiveClientId,
                    authType,
                    walletAuth.attestationJwt(),
                    trustedIssuerJwks,
                    responseUri);
            verifierSessionService.saveSession(servletSession, updatedSession);
            verifierSessionStateStore.put(updatedSession);
        }
        return ResponseEntity.status(302).location(walletAuth.uri()).build();
    }

    private boolean requestsEncryptedResponse(String clientMetadataJson) {
        if (clientMetadataJson == null || clientMetadataJson.isBlank()) {
            return false;
        }
        try {
            JsonNode node = objectMapper.readTree(clientMetadataJson);
            JsonNode jwks = node.get("jwks");
            if (jwks == null || jwks.isNull()) {
                return false;
            }
            if (jwks.has("keys") && jwks.get("keys").isArray()) {
                return !jwks.get("keys").isEmpty();
            }
            // allow non-JWKS shapes if present; encryption key selection will validate later
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @PostMapping(value = "/callback", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, String>> handleCallback(@RequestParam(name = "state", required = false) String state,
                                       @RequestParam(name = "vp_token", required = false) String vpToken,
                                       @RequestParam(name = "response", required = false) String encryptedResponse,
                                       @RequestParam(name = "id_token", required = false) String idToken,
                                       @RequestParam(name = "key_binding", required = false) String keyBindingToken,
                                       @RequestParam(name = "key_binding_jwt", required = false) String keyBindingTokenAlt,
                                       @RequestParam(name = "dpop", required = false) String dpopToken,
                                       @RequestParam(name = "dpop_token", required = false) String dpopTokenAlt,
                                       @RequestParam(name = "nonce", required = false) String responseNonce,
                                       @RequestParam(name = "error", required = false) String error,
                                       @RequestParam(name = "error_description", required = false) String errorDescription,
                                       HttpServletRequest request,
                                       HttpSession httpSession) {
        LOG.info("direct_post callback received state={} error={}", state, error);
        VerificationSteps steps = new VerificationSteps();
        String vpTokenRaw = vpToken;
        String keyBindingJwt = firstNonBlank(keyBindingTokenAlt, keyBindingToken);
        String effectiveDpop = firstNonBlank(dpopToken, dpopTokenAlt);
        String mdocGeneratedNonce = null;
        if (encryptedResponse != null && !encryptedResponse.isBlank()) {
            steps.add("Processing response (direct_post.jwt)",
                    "Response parameter contained a JWT/JWE; decode it to extract vp_token, state, nonce, and errors.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1");
            ParsedResponseFields parsed = decodeEncryptedResponse(encryptedResponse, steps);
            if (parsed == null) {
                storeResult(state, "Unable to decode response", false, steps, List.of(), vpTokenRaw, idToken, Map.of());
                return callbackErrorResponse("Unable to decode response");
            }
            state = firstNonBlank(state, parsed.state());
            vpTokenRaw = firstNonBlank(vpTokenRaw, parsed.vpToken());
            idToken = firstNonBlank(idToken, parsed.idToken());
            responseNonce = firstNonBlank(responseNonce, parsed.nonce());
            error = firstNonBlank(error, parsed.error());
            errorDescription = firstNonBlank(errorDescription, parsed.errorDescription());
            keyBindingJwt = firstNonBlank(keyBindingJwt, parsed.keyBindingJwt());
            mdocGeneratedNonce = parsed.mdocGeneratedNonce();
        }
        String callbackRequestBody = (encryptedResponse != null && !encryptedResponse.isBlank() ? "response=" + encryptedResponse + "\n" : "")
                + formBody(state, vpTokenRaw, idToken, responseNonce, error, errorDescription, keyBindingJwt, effectiveDpop);
        LOG.info("direct_post callback request body:\n{}", callbackRequestBody);
        VerifierSession verifierSession = verifierSessionService.getSession(httpSession);
        if (verifierSession == null || state == null || state.isBlank() || !verifierSession.state().equals(state)) {
            verifierSession = verifierSessionStateStore.get(state);
            if (verifierSession != null) {
                verifierSessionService.saveSession(httpSession, verifierSession);
            }
        }
        if (state == null || state.isBlank() || verifierSession == null || !verifierSession.state().equals(state)) {
            steps.add("Verifier session and state validation failed",
                    "Verifier session not found or state mismatch.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            LOG.info("direct_post callback invalid session state={}", state);
            logCallback(state, "direct_post callback (invalid session)",
                    "POST",
                    "/verifier/callback",
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    callbackRequestBody,
                    HttpStatus.BAD_REQUEST.value(),
                    Map.of(),
                    "vp_token length=%d".formatted(vpToken != null ? vpToken.length() : 0),
                    null, vpTokenRaw, keyBindingJwt, effectiveDpop);
            storeResult(state, "Invalid verifier session", false, steps, parseVpTokens(vpTokenRaw), vpTokenRaw, idToken, Map.of());
            return callbackErrorResponse("Invalid verifier session");
        }
        // Enforce encrypted response for direct_post.jwt response_mode.
        // If the session's response_mode is direct_post.jwt, the wallet MUST send the
        // "response" parameter (JWE/JWS), not a plain "vp_token".
        String sessionResponseMode = verifierSession.responseMode();
        if (sessionResponseMode != null && sessionResponseMode.endsWith(".jwt")
                && (encryptedResponse == null || encryptedResponse.isBlank())) {
            steps.add("Encrypted response required",
                    "response_mode is " + sessionResponseMode + " but wallet sent plain vp_token instead of encrypted response parameter.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1");
            LOG.warn("direct_post.jwt callback rejected: wallet sent plain vp_token without encrypted response, state={}", state);
            storeResult(state, "response_mode is " + sessionResponseMode + " but no encrypted response was provided",
                    false, steps, parseVpTokens(vpTokenRaw), vpTokenRaw, idToken, Map.of());
            return callbackErrorResponse("response_mode is " + sessionResponseMode + " but no encrypted response was provided");
        }

        // Build redirect_uri for the result page
        URI resultUri = baseUri(request).path("/verifier/result/" + state).build().toUri();
        try {
            if (error != null && !error.isBlank()) {
                String viewMessage = errorDescription != null ? errorDescription : "Presentation denied";
                if (error != null && !error.isBlank() && !viewMessage.contains(error)) {
                    viewMessage = viewMessage + " (" + error + ")";
                }
                steps.add("Wallet returned error: " + error,
                        "Wallet returned error: " + error,
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
                LOG.info("direct_post callback error state={} error={} desc={}", state, error, errorDescription);
                logCallback(state, "direct_post callback (error)",
                        "POST",
                        "/verifier/callback",
                        Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        callbackRequestBody,
                        HttpStatus.BAD_REQUEST.value(),
                        Map.of(),
                        "error=%s\nerror_description=%s".formatted(error, errorDescription),
                        null, vpTokenRaw, keyBindingJwt, effectiveDpop);
                storeResult(state, viewMessage, false, steps, parseVpTokens(vpTokenRaw), vpTokenRaw, idToken, Map.of());
                return callbackJsonResponse(resultUri.toString());
            }
            List<VpTokenEntry> vpTokens = extractVpTokens(vpTokenRaw);
            if (vpTokens.isEmpty()) {
                steps.add("vp_token missing or empty",
                        "Wallet response did not include a vp_token.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
                LOG.info("direct_post callback missing vp_token state={}", state);
                logCallback(state, "direct_post callback (missing vp_token)",
                        "POST",
                        "/verifier/callback",
                        Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        callbackRequestBody,
                        HttpStatus.BAD_REQUEST.value(),
                        Map.of(),
                        "vp_token length=0",
                        null, vpTokenRaw, keyBindingJwt, effectiveDpop);
                storeResult(state, "Missing vp_token", false, steps, List.of(), vpTokenRaw, idToken, Map.of());
                return callbackJsonResponse(resultUri.toString());
            }
            if (verifierSession.authType() != null && !verifierSession.authType().isBlank()) {
                steps.add("Wallet client authentication",
                        "Wallet authenticated using " + verifierSession.authType(),
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3");
            }
            // Use stored responseUri from session for mDoc SessionTranscript verification
            // This ensures consistency with the response_uri sent in the authorization request
            String expectedResponseUri = verifierSession.responseUri() != null
                    ? verifierSession.responseUri()
                    : currentRequestExternalUrl(request);
            if (mdocGeneratedNonce != null) {
                LOG.info("[OID4VP] mdoc_generated_nonce='{}' extracted from JWE apu header", mdocGeneratedNonce);
            }
            List<Map<String, Object>> payloads = verificationService.verifyPresentations(
                    vpTokens.stream().map(VpTokenEntry::token).toList(),
                    new PresentationVerificationService.VerificationContext(
                            verifierSession.nonce(),
                            responseNonce,
                            verifierSession.trustListId(),
                            verifierSession.clientId(),
                            expectedResponseUri,
                            verifierSession.responseMode(),
                            steps,
                            verifierSession.trustedIssuerJwks(),
                            mdocGeneratedNonce));
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
            debugLogService.addVerification(
                    verifierSession.state(),
                    "Verification",
                    "Verifier verification steps",
                    "VERIFY",
                    "verifier.verifyPresentations",
                    Map.of(),
                    formatVerificationSteps(steps),
                    HttpStatus.OK.value(),
                    Map.of(),
                    "",
                    "",
                    ""
            );
            LOG.info("direct_post callback verified state={} tokens={} key_binding_present={} encrypted_vp={}", state, vpTokens.size(), keyBindingJwt != null && !keyBindingJwt.isBlank(),
                    tokenViewService.hasEncryptedToken(vpTokens.stream().map(VpTokenEntry::token).toList()));
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
            storeResult(state, "Verified credential(s)", true, steps,
                    vpTokens.stream().map(VpTokenEntry::token).toList(), vpTokenRaw, idToken, combined);
            return callbackJsonResponse(resultUri.toString());
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
            if (verifierSession != null) {
                debugLogService.addVerification(
                        verifierSession.state(),
                        "Verification",
                        "Verifier verification steps (failed)",
                        "VERIFY",
                        "verifier.verifyPresentations",
                        Map.of(),
                        formatVerificationSteps(steps),
                        HttpStatus.BAD_REQUEST.value(),
                        Map.of(),
                        e.getMessage(),
                        "",
                        ""
                );
            }
            LOG.info("direct_post callback verification failed state={} message={}", state, e.getMessage(), e);
            storeResult(state, "Unable to verify credential: " + e.getMessage(), false, steps,
                    parseVpTokens(vpTokenRaw), vpTokenRaw, idToken, Map.of());
            return callbackJsonResponse(resultUri.toString());
        } finally {
            verifierSessionStateStore.remove(state);
        }
    }

    private ResponseEntity<Map<String, String>> callbackJsonResponse(String redirectUri) {
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("redirect_uri", redirectUri));
    }

    /**
     * OID4VP 1.0 Section 8.2: The response_uri MUST respond with HTTP 200
     * even when the authorization response could not be processed.
     * When no redirect_uri is available, return an empty JSON object.
     */
    private ResponseEntity<Map<String, String>> callbackErrorResponse(String errorMessage) {
        LOG.info("direct_post callback processing error: {}", errorMessage);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of());
    }

    private void storeResult(String state, String message, boolean success, VerificationSteps steps,
                              List<String> vpTokens, String vpTokenRaw, String idToken, Map<String, Object> payload) {
        if (state == null || state.isBlank()) {
            return;
        }
        verificationResultStore.put(state, new VerificationResultStore.VerificationResult(
                state, message, success, steps.titles(), steps.details(),
                vpTokens, vpTokenRaw, idToken, payload));
    }

    @GetMapping("/result/{state}")
    public Object showResult(@PathVariable("state") String state) {
        VerificationResultStore.VerificationResult result = verificationResultStore.get(state);
        if (result == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Result not found or expired");
        }
        return resultView(result.state(), result.message(), result.success(), result.stepTitles(),
                result.vpTokens(), result.vpTokenRaw(), result.idToken(), result.payload(), result.stepDetails());
    }

    private String formatVerificationSteps(VerificationSteps steps) {
        if (steps == null || steps.details() == null || steps.details().isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int index = 0;
        for (VerificationSteps.StepDetail detail : steps.details()) {
            if (detail == null) {
                continue;
            }
            index++;
            if (sb.length() > 0) {
                sb.append("\n\n");
            }
            sb.append(index).append(". ").append(detail.title() != null ? detail.title() : "");
            if (detail.detail() != null && !detail.detail().isBlank()) {
                sb.append("\n").append(detail.detail());
            }
            if (detail.specLink() != null && !detail.specLink().isBlank()) {
                sb.append("\n").append(detail.specLink());
            }
        }
        return sb.toString();
    }


    private String currentRequestExternalUrl(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        UriComponentsBuilder builder = baseUri(request);
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String pathWithinContext = requestUri;
        if (contextPath != null && !contextPath.isBlank() && requestUri != null && requestUri.startsWith(contextPath)) {
            pathWithinContext = requestUri.substring(contextPath.length());
        }
        if (pathWithinContext != null && !pathWithinContext.isBlank()) {
            builder.path(pathWithinContext);
        }
        // Note: Query string is intentionally NOT included here.
        // For mDoc deviceAuth verification, the response_uri sent in the authorization request
        // does not include query parameters - those are added by the wallet when posting back.
        // The wallet signs the SessionTranscript using the original response_uri without query params.
        return builder.build().toUriString();
    }

    private ModelAndView resultView(String state, String message, boolean success, List<String> steps, List<String> vpTokens, String vpTokenRaw,
                                    String idToken, Map<String, Object> payload, List<VerificationSteps.StepDetail> stepDetails) {
        ModelAndView mv = new ModelAndView("verifier-result");
        mv.addObject("title", success ? "Presentation Verified" : "Verification Error");
        mv.addObject("message", message);
        mv.addObject("verificationState", state == null ? "" : state);
        mv.addObject("steps", steps);
        mv.addObject("stepDetails", stepDetails);
        List<String> tokens = vpTokens == null ? List.of() : vpTokens;
        mv.addObject("vpTokens", tokenViewService.presentableTokens(tokens));
        mv.addObject("vpTokensRawList", tokens);
        mv.addObject("hasEncryptedVpToken", tokenViewService.hasEncryptedToken(tokens));
        mv.addObject("hasSdJwtToken", tokenViewService.hasSdJwtToken(tokens));
        mv.addObject("hasMdocToken", tokenViewService.hasMdocToken(tokens));
        mv.addObject("mdocViews", tokenViewService.mdocViews(tokens));
        mv.addObject("vpTokenRaw", vpTokenRaw);
        mv.addObject("vpTokenRawDisplay", tokenViewService.presentableToken(vpTokenRaw));
        mv.addObject("idToken", idToken);
        Map<String, Object> claimsOnly = payload == null ? Map.of() : new LinkedHashMap<>(payload);
        claimsOnly.remove("key_binding_jwt");
        claimsOnly.remove("dpop_token");
        mv.addObject("claims", claimsOnly);
        mv.addObject("keyBindingJwt", payload.getOrDefault("key_binding_jwt", null));
        mv.addObject("dpopToken", payload.getOrDefault("dpop_token", null));
        mv.addObject("verificationDebug", debugLogService.verification());
        try {
            mv.addObject("claimsJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(claimsOnly));
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
            // OID4VP 1.0: encrypted_response_enc_values_supported declares supported content encryption methods
            // HAIP Section 5-2.5: MUST support A128GCM and A256GCM
            // The key agreement algorithm (ECDH-ES) is conveyed via the JWK's "alg" field
            meta.putArray("encrypted_response_enc_values_supported").add("A128GCM").add("A256GCM");
            // VP formats per OID4VP 1.0 Section 11.1
            ObjectNode formats = meta.putObject("vp_formats_supported");
            ObjectNode sdJwt = objectMapper.createObjectNode();
            sdJwt.putArray("sd-jwt_alg_values").add("ES256");
            sdJwt.putArray("kb-jwt_alg_values").add("ES256");
            formats.set("dc+sd-jwt", sdJwt);
            ObjectNode mdoc = objectMapper.createObjectNode();
            mdoc.putArray("issuerauth_alg_values").add(-7);
            mdoc.putArray("deviceauth_alg_values").add(-7);
            formats.set("mso_mdoc", mdoc);
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

    private List<VpTokenEntry> extractVpTokens(String vpTokenRaw) {
        if (vpTokenRaw == null || vpTokenRaw.isBlank()) {
            return List.of();
        }
        List<VpTokenEntry> entries = new ArrayList<>();
        try {
            JsonParser parser = objectMapper.createParser(vpTokenRaw);
            JsonNode node = objectMapper.readTree(parser);
            if (parser.nextToken() != null) {
                throw new IllegalArgumentException("Trailing content in vp_token");
            }
            if (node.isObject()) {
                ObjectNode objectNode = (ObjectNode) node;
                objectNode.properties().forEach(field -> {
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

    private JsonNode parseWalletMetadata(String walletMetadata) {
        if (walletMetadata == null || walletMetadata.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(walletMetadata);
        } catch (Exception e) {
            return null;
        }
    }

    private JWK selectEncryptionKey(JsonNode walletMeta) {
        if (walletMeta == null || walletMeta.isMissingNode()) {
            return null;
        }
        JsonNode jwksNode = walletMeta.get("jwks");
        if (jwksNode == null || jwksNode.isMissingNode()) {
            return null;
        }
        try {
            JWKSet set = JWKSet.parse(jwksNode.toString());
            return set.getKeys().stream()
                    .filter(jwk -> jwk instanceof RSAKey || jwk instanceof ECKey)
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private EncryptionPreferences extractEncryptionPreferences(JsonNode walletMeta) {
        if (walletMeta == null || walletMeta.isMissingNode()) {
            return new EncryptionPreferences(null, null);
        }
        return new EncryptionPreferences(
                firstSupported(walletMeta.get("request_object_encryption_alg_values_supported")),
                firstSupported(walletMeta.get("request_object_encryption_enc_values_supported"))
        );
    }

    private String firstSupported(JsonNode node) {
        if (node != null && node.isArray() && node.size() > 0 && node.get(0).isTextual()) {
            return node.get(0).asText();
        }
        return null;
    }

    private EncryptionResult encryptRequestObject(String payload, JWK key, String algOverride, String encOverride) {
        if (key == null || payload == null || payload.isBlank()) {
            return new EncryptionResult(payload, false, null, null);
        }
        try {
            JWEAlgorithm alg = algOverride != null && !algOverride.isBlank()
                    ? JWEAlgorithm.parse(algOverride)
                    : (key instanceof RSAKey ? JWEAlgorithm.RSA_OAEP_256 : JWEAlgorithm.ECDH_ES_A256KW);
            EncryptionMethod enc = encOverride != null && !encOverride.isBlank()
                    ? EncryptionMethod.parse(encOverride)
                    : EncryptionMethod.A256GCM;
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(alg, enc).keyID(key.getKeyID()).build(),
                    new Payload(payload)
            );
            if (key instanceof RSAKey rsaKey) {
                jwe.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));
            } else if (key instanceof ECKey ecKey) {
                jwe.encrypt(new ECDHEncrypter(ecKey.toECPublicKey()));
            } else {
                return new EncryptionResult(payload, false, null, null);
            }
            return new EncryptionResult(jwe.serialize(), true, alg.getName(), enc.getName());
        } catch (Exception e) {
            return new EncryptionResult(payload, false, null, null);
        }
    }

    private String buildDecodedForLog(String signedPayload, EncryptionResult encryption) {
        if (signedPayload == null || signedPayload.isBlank()) {
            return "";
        }
        if (encryption != null && encryption.encrypted()) {
            String decodedSigned = tokenViewService.decodeJwtLike(signedPayload);
            StringBuilder sb = new StringBuilder("Encrypted request object");
            if (encryption.alg() != null || encryption.enc() != null) {
                sb.append(" (");
                if (encryption.alg() != null && !encryption.alg().isBlank()) {
                    sb.append(encryption.alg());
                }
                if (encryption.enc() != null && !encryption.enc().isBlank()) {
                    if (encryption.alg() != null && !encryption.alg().isBlank()) {
                        sb.append("/");
                    }
                    sb.append(encryption.enc());
                }
                sb.append(")");
            }
            if (decodedSigned != null && !decodedSigned.isBlank()) {
                sb.append("\n\n").append(decodedSigned);
            }
            return sb.toString();
        }
        return tokenViewService.decodeJwtLike(signedPayload);
    }

    private String walletRequestLog(String walletMetadata, String walletNonce) {
        StringBuilder sb = new StringBuilder();
        if (walletMetadata != null && !walletMetadata.isBlank()) {
            sb.append("wallet_metadata=").append(walletMetadata);
        }
        if (walletNonce != null && !walletNonce.isBlank()) {
            if (sb.length() > 0) {
                sb.append("\n");
            }
            sb.append("wallet_nonce=").append(walletNonce);
        }
        return sb.toString();
    }

    private String extractState(JWTClaimsSet claims) {
        if (claims == null) {
            return "unknown";
        }
        try {
            String state = claims.getStringClaim("state");
            return state != null && !state.isBlank() ? state : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Determines the signing algorithm from the wallet's metadata.
     * The actual signing key is resolved later in {@link RequestObjectService#resolve}
     * which prefers the stored key (matching the original x5c/JWK headers) and adapts the
     * algorithm to the key type if needed.
     */
    private RequestObjectService.SigningRequest determineSigningRequest(JsonNode walletMeta) {
        if (walletMeta == null || walletMeta.isMissingNode()) {
            return null;
        }
        String alg = firstSupported(walletMeta.get("request_object_signing_alg_values_supported"));
        if (alg == null || alg.isBlank()) {
            return null;
        }
        try {
            JWSAlgorithm jwsAlg = JWSAlgorithm.parse(alg);
            // Pass only the wallet's preferred algorithm — the stored key (from x509 material
            // or verifier_attestation cnf) will be used for signing. If no stored key exists,
            // resolve() will fall back to the verifier's default signing key.
            return new RequestObjectService.SigningRequest(jwsAlg, null);
        } catch (Exception e) {
            return null;
        }
    }

    private record EncryptionPreferences(String alg, String enc) {
    }

    private record EncryptionResult(String payload, boolean encrypted, String alg, String enc) {
    }

    private record ParsedResponseFields(String state, String vpToken, String idToken, String nonce,
                                         String error, String errorDescription, String keyBindingJwt,
                                         String mdocGeneratedNonce) {
    }

    private ParsedResponseFields decodeEncryptedResponse(String encryptedResponse, VerificationSteps steps) {
        // Try JWE decryption first
        try {
            com.nimbusds.jose.JWEObject jweObject = com.nimbusds.jose.JWEObject.parse(encryptedResponse);
            String mdocGeneratedNonce = extractApuNonce(jweObject);
            String decrypted = verifierKeyService.decrypt(encryptedResponse);
            JsonNode node = objectMapper.readTree(decrypted);
            steps.add("Decrypted encrypted response (JWE)",
                    "Decrypted response payload with verifier encryption key.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1");
            return extractResponseFields(node, mdocGeneratedNonce);
        } catch (Exception e) {
            // Fall back to JWS parsing
            try {
                SignedJWT signed = SignedJWT.parse(encryptedResponse);
                JsonNode node = objectMapper.readTree(signed.getPayload().toString());
                steps.add("Parsed signed response (JWS)",
                        "Decoded signed response JWT payload (signature not validated).",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1");
                return extractResponseFields(node, null);
            } catch (Exception parseException) {
                steps.add("Unable to decode response", e.getMessage(),
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1");
                return null;
            }
        }
    }

    private String extractApuNonce(com.nimbusds.jose.JWEObject jweObject) {
        try {
            com.nimbusds.jose.util.Base64URL apu = jweObject.getHeader().getAgreementPartyUInfo();
            if (apu != null) {
                String nonce = new String(apu.decode(), java.nio.charset.StandardCharsets.UTF_8);
                LOG.info("[OID4VP] Extracted mdoc_generated_nonce from JWE apu: '{}'", nonce);
                return nonce;
            }
        } catch (Exception e) {
            LOG.info("[OID4VP] Could not extract apu from JWE header: {}", e.getMessage());
        }
        return null;
    }

    private ParsedResponseFields extractResponseFields(JsonNode node, String mdocGeneratedNonce) {
        String vpToken = null;
        JsonNode vpNode = node.get("vp_token");
        if (vpNode != null && !vpNode.isNull()) {
            try {
                vpToken = vpNode.isTextual() ? vpNode.asText() : objectMapper.writeValueAsString(vpNode);
            } catch (Exception e) {
                vpToken = vpNode.toString();
            }
        }
        return new ParsedResponseFields(
                node.path("state").asText(null),
                vpToken,
                node.path("id_token").asText(null),
                node.path("nonce").asText(null),
                node.path("error").asText(null),
                node.path("error_description").asText(null),
                node.path("key_binding_jwt").asText(null),
                mdocGeneratedNonce
        );
    }

    private URI parsePublicBase(String publicBaseUrl) {
        if (publicBaseUrl == null || publicBaseUrl.isBlank()) {
            return null;
        }
        String normalized = publicBaseUrl.trim();
        if (!normalized.endsWith("/")) {
            normalized = normalized + "/";
        }
        return URI.create(normalized);
    }

    private UriComponentsBuilder baseUri(HttpServletRequest request) {
        if (publicBaseUri != null) {
            UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                    .scheme(publicBaseUri.getScheme())
                    .host(publicBaseUri.getHost());
            if (publicBaseUri.getPort() != -1) {
                builder.port(publicBaseUri.getPort());
            }
            if (publicBaseUri.getPath() != null && !publicBaseUri.getPath().isBlank()) {
                builder.path(publicBaseUri.getPath());
            }
            return builder;
        }
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
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isBlank()) {
            builder.path(contextPath);
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
