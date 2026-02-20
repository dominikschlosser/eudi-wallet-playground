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
package de.arbeitsagentur.keycloak.wallet.demo.oid4vp;

import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.demo.oid4vp.PresentationService;
import de.arbeitsagentur.keycloak.wallet.demo.oid4vp.PresentationService.DescriptorMatch;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.SessionService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.WalletSession;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocDeviceResponseBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;

@Controller
public class Oid4vpController {
    private static final Logger LOG = LoggerFactory.getLogger(Oid4vpController.class);
    private final PresentationService presentationService;
    private final WalletKeyService walletKeyService;
    private final WalletProperties walletProperties;
    private final ObjectMapper objectMapper;
    private final DebugLogService debugLogService;
    private final SessionService sessionService;
    private final RestTemplate restTemplate;
    private final SdJwtParser sdJwtParser;
    private final MdocParser mdocParser;
    private final MdocDeviceResponseBuilder mdocDeviceResponseBuilder;
    private volatile Set<TrustAnchor> cachedX509TrustAnchors;
    private static final String SESSION_REQUEST = "oid4vp_request";
    private static final String POST_LOGIN_REDIRECT = "postLoginRedirect";

    public Oid4vpController(PresentationService presentationService,
                            WalletKeyService walletKeyService,
                            WalletProperties walletProperties,
                            ObjectMapper objectMapper,
                            DebugLogService debugLogService,
                            SessionService sessionService,
                            RestTemplate restTemplate) {
        this.presentationService = presentationService;
        this.walletKeyService = walletKeyService;
        this.walletProperties = walletProperties;
        this.objectMapper = objectMapper;
        this.debugLogService = debugLogService;
        this.sessionService = sessionService;
        this.restTemplate = restTemplate;
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.mdocParser = new MdocParser();
        this.mdocDeviceResponseBuilder = new MdocDeviceResponseBuilder();
    }

    @GetMapping("/oid4vp/auth")
    public ModelAndView handleAuth(@RequestParam(name = "response_uri", required = false) String responseUri,
                                   @RequestParam(name = "redirect_uri", required = false) String redirectUri,
                                   @RequestParam(name = "state", required = false) String state,
                                   @RequestParam(name = "dcql_query", required = false) String dcqlQuery,
                                   @RequestParam(name = "nonce", required = false) String nonce,
                                   @RequestParam(name = "response_mode", required = false) String responseMode,
                                   @RequestParam(name = "client_id", required = false) String clientId,
                                   @RequestParam(name = "client_metadata", required = false) String clientMetadata,
                                   @RequestParam(name = "request", required = false) String requestObject,
                                   @RequestParam(name = "request_uri", required = false) String requestUri,
                                   @RequestParam(name = "client_cert", required = false) String clientCert,
                                   HttpSession httpSession,
                                   HttpServletRequest httpRequest) {
        WalletSession walletSession = sessionService.getSession(httpSession);
        String rawRequestDebug = formatRawRequest(httpRequest);
        String targetResponseUri = responseUri != null && !responseUri.isBlank() ? responseUri : redirectUri;
        PendingRequest pending;
        String resolvedRequestObject = requestObject;
        RequestObjectResolution requestResolution = null;
        if ((resolvedRequestObject == null || resolvedRequestObject.isBlank()) && requestUri != null && !requestUri.isBlank()) {
            try {
                requestResolution = resolveRequestUri(requestUri);
                resolvedRequestObject = requestResolution.requestObject();
            } catch (IllegalStateException e) {
                return errorView(e.getMessage());
            }
        }
        if (resolvedRequestObject != null && !resolvedRequestObject.isBlank()) {
            try {
                pending = parseRequestObject(resolvedRequestObject, state, targetResponseUri,
                        requestResolution != null ? requestResolution.walletNonce() : null, rawRequestDebug);
            } catch (Exception e) {
                return requestObjectErrorView(resolvedRequestObject, e);
            }
	        } else {
	            String effectiveState = state;
	            if (effectiveState == null || effectiveState.isBlank()) {
	                return errorView("Missing state parameter");
	            }
	            if (clientId != null
	                    && (clientId.startsWith("x509_hash:")
	                    || clientId.startsWith("x509_san_dns:")
                    || clientId.startsWith("verifier_attestation:"))) {
                String scheme = clientId.contains(":") ? clientId.substring(0, clientId.indexOf(':')) : clientId;
                return errorView("Request object required for " + scheme + " client_id");
            }
            try {
                validateClientBinding(clientId, clientMetadata, clientCert);
            } catch (IllegalStateException e) {
                return errorView(e.getMessage());
            }
            // Per OID4VP DC API spec: derive client_id from response_uri origin if not provided
            String effectiveClientId = clientId;
            if ((effectiveClientId == null || effectiveClientId.isBlank()) && targetResponseUri != null) {
                effectiveClientId = deriveClientIdFromUri(targetResponseUri);
            }
	            pending = new PendingRequest(
	                    effectiveState,
	                    nonce,
	                    targetResponseUri,
	                    effectiveClientId,
	                    dcqlQuery,
	                    clientMetadata,
	                    responseMode,
	                    rawRequestDebug,
	                    null,
	                    null,
	                    null,
	                    List.of()
	            );
	        }
        if (requestResolution != null) {
            debugLogService.addVerification(
                    pending.state(),
                    "Wallet",
                    "request_uri retrieval",
                    requestResolution.usedPost() ? "POST" : "GET",
                    requestUri,
                    Map.of(),
                    requestResolution.requestLog(),
                    200,
                    Map.of(),
                    "signed=%s encrypted=%s".formatted(requestResolution.signed(), requestResolution.encrypted()),
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-parameter",
                    decodeJwtLike(resolvedRequestObject)
            );
        }
        httpSession.setAttribute(SESSION_REQUEST, pending);
        httpSession.setAttribute(POST_LOGIN_REDIRECT, "/oid4vp/continue");
        // Continue directly to consent page - don't require login
        // If not authenticated, only mock-issuer credentials will be shown
        return continuePending(httpSession);
    }

    @PostMapping("/oid4vp/consent")
    public ModelAndView handleConsent(@RequestParam("decision") String decision, HttpSession httpSession, HttpServletRequest request) {
        PendingRequest pending = (PendingRequest) httpSession.getAttribute(SESSION_REQUEST);
        if (pending == null) {
            return errorView("Presentation request not found or expired");
        }
        if (!"accept".equalsIgnoreCase(decision)) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return submitResponse(pending, Map.of(
                    "state", pending.state(),
                    "error", "access_denied",
                    "error_description", "User denied presentation"
            ));
        }
        WalletSession walletSession = sessionService.getSession(httpSession);
        boolean authenticated = walletSession != null && walletSession.isAuthenticated();
        // Determine which credentials to use:
        // - If authenticated: show user's credentials + mock-issuer credentials
        // - If not authenticated: only show mock-issuer credentials
        List<String> ownerIds = authenticated
                ? walletSession.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER)
                : List.of(CredentialStore.MOCK_ISSUER_OWNER);
        if (pending.responseUri() == null || pending.responseUri().isBlank()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return errorView("Missing response_uri for direct_post");
        }
        var options = pending.options() != null
                ? Optional.of(pending.options())
                : presentationService.preparePresentationOptions(ownerIds, pending.dcqlQuery());
        if (options.isEmpty()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return noMatchErrorView(pending, "Your wallet does not contain a credential that matches what the verifier requested.");
        }
        // Extract which descriptors are included (checkbox checked)
        Set<String> includedDescriptors = extractIncludedDescriptors(request.getParameterMap());
        // Filter options to only include checked descriptors
        var filteredOptions = filterOptionsByInclusion(options.get(), includedDescriptors);
        if (filteredOptions.options().isEmpty()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return submitResponse(pending, Map.of(
                    "state", pending.state(),
                    "error", "access_denied",
                    "error_description", "No credentials selected for presentation"
            ));
        }
        Map<String, String> selections = extractSelections(httpSession, pending, request.getParameterMap());
        Optional<List<DescriptorMatch>> chosen = presentationService.selectDistinctMatches(filteredOptions, selections);
        if (chosen.isEmpty() || chosen.get().size() != filteredOptions.options().size()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return noMatchErrorView(pending, "Could not select matching credentials for all requested credential types.");
        }
        Map<String, List<String>> vpTokens = new LinkedHashMap<>();
        try {
            String audience = pending.clientId();
            for (DescriptorMatch match : chosen.get()) {
                String token = buildVpToken(match.vpToken(),
                        pending.nonce(),
                        audience,
                        pending.responseUri(),
                        pending.clientMetadata(),
                        pending.responseMode());
                vpTokens.computeIfAbsent(match.descriptorId(), k -> new ArrayList<>()).add(token);
            }
        } catch (Exception e) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return errorView("Failed to build presentation: " + e.getMessage());
        }
        String vpTokenParam;
        try {
            vpTokenParam = objectMapper.writeValueAsString(vpTokens);
        } catch (Exception e) {
            vpTokenParam = vpTokens.toString();
        }

        httpSession.removeAttribute(SESSION_REQUEST);

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("state", pending.state());
        fields.put("vp_token", vpTokenParam);

        debugLogService.addVerification(
                pending.state(),
                "Wallet",
                "User approved presentation",
                "POST",
                "/oid4vp/consent",
                Map.of(),
                "response_uri=%s\nvp_token entries=%d".formatted(pending.responseUri(),
                        vpTokens.values().stream().mapToInt(List::size).sum()),
                302,
                Map.of("Location", pending.responseUri()),
                "vp_token entries=%d".formatted(vpTokens.values().stream().mapToInt(List::size).sum()),
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html",
                decodeJwtLike(vpTokenParam)
        );
        return submitResponse(pending, fields);
    }

    @GetMapping("/oid4vp/continue")
    public ModelAndView continuePending(HttpSession httpSession) {
        PendingRequest pending = (PendingRequest) httpSession.getAttribute(SESSION_REQUEST);
        if (pending == null) {
            return errorView("Presentation request not found or expired");
        }
        WalletSession walletSession = sessionService.getSession(httpSession);
        boolean authenticated = walletSession != null && walletSession.isAuthenticated();
        // Determine which credentials to show:
        // - If authenticated: show user's credentials + mock-issuer credentials
        // - If not authenticated: only show mock-issuer credentials
        List<String> ownerIds = authenticated
                ? walletSession.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER)
                : List.of(CredentialStore.MOCK_ISSUER_OWNER);
        var options = pending.options();
        if (options == null) {
            Optional<PresentationService.PresentationOptions> prepared = presentationService.preparePresentationOptions(ownerIds,
                    pending.dcqlQuery());
            if (prepared.isEmpty()) {
                httpSession.removeAttribute(SESSION_REQUEST);
                return noMatchErrorView(pending, "Your wallet does not contain a credential that matches what the verifier requested.");
            }
            options = prepared.get();
            pending = pending.withOptions(options);
            httpSession.setAttribute(SESSION_REQUEST, pending);
        }
        ModelAndView mv = new ModelAndView("oid4vp-consent");
        mv.addObject("descriptorOptions", options.options());
        mv.addObject("state", pending.state());
        mv.addObject("rawRequestDebug", pending.rawRequestDebug());
        mv.addObject("requestObjectDebug", decodeJwtFull(pending.requestObjectRaw()));
        mv.addObject("authenticated", authenticated);
        Map<String, String> descriptorVcts = new LinkedHashMap<>();
        for (var opt : options.options()) {
            Map<String, Object> first = opt.candidates().isEmpty() ? null : opt.candidates().get(0).credential();
            descriptorVcts.put(opt.request().id(), deriveVct(first));
        }
        mv.addObject("descriptorVcts", descriptorVcts);
        Map<String, String> candidateVcts = new LinkedHashMap<>();
        for (var opt : options.options()) {
            String descriptorVct = descriptorVcts.getOrDefault(opt.request().id(), "");
            for (var cand : opt.candidates()) {
                String vct = deriveVct(cand.credential());
                if ((vct == null || vct.isBlank()) && descriptorVct != null && !descriptorVct.isBlank()) {
                    vct = descriptorVct;
                }
                candidateVcts.put(cand.credentialFileName(), vct == null ? "" : vct);
            }
        }
        mv.addObject("candidateVcts", candidateVcts);
        if (pending.warnings() != null && !pending.warnings().isEmpty()) {
            mv.addObject("warnings", pending.warnings());
        }
        if (walletSession != null && walletSession.getUserProfile() != null) {
            mv.addObject("userName", walletSession.getUserProfile().displayName());
            mv.addObject("userEmail", walletSession.getUserProfile().email());
        }
        return mv;
    }

    private ModelAndView errorView(String message) {
        ModelAndView mv = new ModelAndView("verifier-result");
        mv.addObject("title", "OID4VP Error");
        mv.addObject("message", message);
        return mv;
    }

    private ModelAndView requestObjectErrorView(String requestObject, Exception error) {
        ModelAndView mv = new ModelAndView("oid4vp-request-error");
        mv.addObject("error", error.getMessage());
        mv.addObject("requestObjectRaw", requestObject);
        try {
            mv.addObject("requestObjectDecoded", decodeJwtLike(requestObject));
        } catch (Exception e) {
            mv.addObject("requestObjectDecoded", "(failed to decode)");
        }
        return mv;
    }

    private ModelAndView submitView(String responseUri, Map<String, String> fields) {
        ModelAndView mv = new ModelAndView("oid4vp-submit");
        mv.addObject("redirectUri", responseUri);
        mv.addObject("fields", fields);
        return mv;
    }

    private ModelAndView submitErrorResponse(PendingRequest pending, String error, String errorDescription) {
        if (pending == null) {
            return errorView("Presentation request not found or expired");
        }
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("state", pending.state());
        if (error != null && !error.isBlank()) {
            fields.put("error", error);
        }
        if (errorDescription != null && !errorDescription.isBlank()) {
            fields.put("error_description", errorDescription);
        }
        return submitResponse(pending, fields);
    }

    private ModelAndView noMatchErrorView(PendingRequest pending, String errorDescription) {
        if (pending == null) {
            return errorView("Presentation request not found or expired");
        }
        ModelAndView mv = new ModelAndView("oid4vp-no-match");
        mv.addObject("state", pending.state());
        mv.addObject("error", "access_denied");
        mv.addObject("errorDescription", errorDescription);
        mv.addObject("redirectUri", pending.responseUri());
        mv.addObject("dcqlQuery", pretty(pending.dcqlQuery()));
        return mv;
    }

    private ModelAndView submitResponse(PendingRequest pending, Map<String, String> fields) {
        if (pending == null) {
            return errorView("Presentation request not found or expired");
        }
        // OID4VP 1.0 Section 5.6: response_mode defaults based on context
        // - If response_uri is present: default is direct_post
        // - If client_metadata requests encrypted responses: prefer direct_post.jwt
        // - DC API uses dc_api.jwt for encrypted responses
        String responseMode = resolveResponseMode(pending);
        boolean encryptedResponse = responseMode != null && responseMode.toLowerCase().endsWith(".jwt");
        if (encryptedResponse) {
            try {
                ObjectNode payload = objectMapper.createObjectNode();
                for (Map.Entry<String, String> entry : fields.entrySet()) {
                    if (entry.getKey() == null || entry.getValue() == null) {
                        continue;
                    }
                    if ("vp_token".equals(entry.getKey())) {
                        payload.set("vp_token", objectMapper.readTree(entry.getValue()));
                    } else {
                        payload.put(entry.getKey(), entry.getValue());
                    }
                }
                String encrypted = encryptResponse(payload.toString(), pending.clientMetadata());
                return submitView(pending.responseUri(), Map.of("response", encrypted));
            } catch (Exception e) {
                return errorView("Failed to encrypt response: " + e.getMessage());
            }
        }
        return submitView(pending.responseUri(), fields);
    }

    private String buildVpToken(String innerVpToken,
                                String nonce,
                                String audience,
                                String responseUri,
                                String clientMetadata,
                                String responseMode) throws Exception {
        if (sdJwtParser.isSdJwt(innerVpToken)) {
            return buildSdJwtPresentation(innerVpToken, nonce, audience);
        }
        if (mdocParser.isIssuerSigned(innerVpToken)) {
            // Per OID4VP spec, encrypted responses use .jwt suffix (direct_post.jwt or dc_api.jwt)
            boolean encryptedResponse = responseMode != null && responseMode.toLowerCase().endsWith(".jwt");
            boolean isDcApiMode = responseMode != null && responseMode.toLowerCase().startsWith("dc_api");
            LOG.debug("buildVpToken mDoc: responseMode='{}', isDcApiMode={}, responseUri='{}'", responseMode, isDcApiMode, responseUri);
            JWK handoverJwk = encryptedResponse ? selectResponseEncryptionJwk(clientMetadata) : null;
            if (encryptedResponse && handoverJwk == null) {
                throw new IllegalStateException("Missing client_metadata.jwks for encrypted response SessionTranscript");
            }
            // For DC API mode (Appendix B.2.5), use the origin of response_uri for SessionTranscript.
            // For regular OID4VP mode, use the full response_uri as provided.
            String sessionTranscriptResponseUri = isDcApiMode ? deriveOriginWithTrailingSlash(responseUri) : responseUri;
            LOG.debug("buildVpToken mDoc: sessionTranscriptResponseUri='{}'", sessionTranscriptResponseUri);
            return mdocDeviceResponseBuilder.buildDeviceResponse(
                    innerVpToken,
                    walletKeyService.loadOrCreateKey(),
                    audience,
                    nonce,
                    sessionTranscriptResponseUri,
                    handoverJwk
            );
        }
        return innerVpToken;
    }

    /**
     * Derives the origin from a URI with a trailing slash (e.g., "http://example.com/").
     * Per OID4VP spec Appendix B.2.5, mDoc SessionTranscript uses the origin for response_uri.
     */
    private String deriveOriginWithTrailingSlash(String uri) {
        if (uri == null || uri.isBlank()) {
            return uri;
        }
        try {
            URI parsed = URI.create(uri);
            String scheme = parsed.getScheme();
            String host = parsed.getHost();
            int port = parsed.getPort();
            if (scheme == null || host == null) {
                return uri;
            }
            boolean includePort = port != -1
                    && !((port == 80 && "http".equalsIgnoreCase(scheme))
                    || (port == 443 && "https".equalsIgnoreCase(scheme)));
            if (includePort) {
                return "%s://%s:%d/".formatted(scheme.toLowerCase(), host, port);
            }
            return "%s://%s/".formatted(scheme.toLowerCase(), host);
        } catch (Exception e) {
            return uri;
        }
    }

    private JWK selectResponseEncryptionJwk(String clientMetadataJson) throws Exception {
        if (clientMetadataJson == null || clientMetadataJson.isBlank()) {
            return null;
        }
        JsonNode meta = objectMapper.readTree(clientMetadataJson);
        JsonNode jwksNode = meta.get("jwks");
        if (jwksNode == null || jwksNode.isMissingNode()) {
            return null;
        }
        JWKSet set = JWKSet.parse(jwksNode.toString());
        return set.getKeys().stream()
                .filter(k -> k.getAlgorithm() != null)
                .findFirst()
                .orElse(null);
    }

    private String buildSdJwtPresentation(String sdJwt, String nonce, String audience) {
        if (nonce == null || nonce.isBlank()) {
            return sdJwt;
        }
        if (audience == null || audience.isBlank()) {
            return sdJwt;
        }
        try {
            ECKey holderKey = walletKeyService.loadOrCreateKey();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("kb+jwt"))
                    .keyID(holderKey.getKeyID())
                    .build();
            SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwt);
            String sdHash = SdJwtUtils.computeSdHash(parts, objectMapper);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .claim("nonce", nonce)
                    .claim("sd_hash", sdHash)
                    .build();
            SignedJWT kbJwt = new SignedJWT(header, claims);
            kbJwt.sign(new ECDSASigner(holderKey));
            String withoutKb = sdJwtParser.signedJwt(sdJwt);
            if (parts.disclosures() != null) {
                for (String disclosure : parts.disclosures()) {
                    if (disclosure != null && !disclosure.isBlank()) {
                        withoutKb = withoutKb + "~" + disclosure;
                    }
                }
            }
            return withoutKb + "~" + kbJwt.serialize();
        } catch (Exception e) {
            return sdJwt;
        }
    }

    private RequestObjectResolution resolveRequestUri(String requestUri) {
        try {
            URI uri = URI.create(requestUri);
            String scheme = uri.getScheme();
            if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                throw new IllegalStateException("Unsupported request_uri scheme");
            }
            if (!walletProperties.requestUriWalletMetadataEnabledOrDefault()) {
                ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
                if (!response.getStatusCode().is2xxSuccessful()) {
                    throw new IllegalStateException("Failed to resolve request_uri (HTTP " + response.getStatusCode() + ")");
                }
                String body = response.getBody();
                if (body == null || body.isBlank()) {
                    throw new IllegalStateException("request_uri did not return a request object");
                }
                String trimmed = body.trim();
                return new RequestObjectResolution(trimmed, null, false, looksLikeSignedJwt(trimmed), null, false);
            }
            String walletNonce = generateWalletNonce();
            String walletMetadata = buildWalletMetadata();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            if (walletMetadata != null && !walletMetadata.isBlank()) {
                form.add("wallet_metadata", walletMetadata);
            }
            form.add("wallet_nonce", walletNonce);
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(uri, entity, String.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new IllegalStateException("Failed to resolve request_uri (HTTP " + response.getStatusCode() + ")");
            }
            String body = response.getBody();
            if (body == null || body.isBlank()) {
                throw new IllegalStateException("request_uri did not return a request object");
            }
            String trimmed = body.trim();
            boolean encrypted = isEncryptedJwe(trimmed);
            String requestObject = encrypted ? decryptRequestObject(trimmed) : trimmed;
            return new RequestObjectResolution(requestObject, walletNonce, encrypted, looksLikeSignedJwt(requestObject), walletMetadata, true);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to resolve request_uri", e);
        }
    }

    private String buildWalletMetadata() {
        try {
            ECKey key = walletKeyService.loadOrCreateKey();
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("jwks", new JWKSet(key.toPublicJWK()).toJSONObject(false));
            meta.put("request_object_signing_alg_values_supported", List.of("ES256", "RS256"));
            meta.put("request_object_encryption_alg_values_supported", List.of("ECDH-ES+A256KW"));
            meta.put("request_object_encryption_enc_values_supported", List.of("A256GCM"));
            Map<String, Object> formats = new LinkedHashMap<>();
            Map<String, Object> sdJwt = new LinkedHashMap<>();
            sdJwt.put("sd-jwt_alg_values", List.of("ES256"));
            sdJwt.put("kb-jwt_alg_values", List.of("ES256"));
            formats.put("dc+sd-jwt", sdJwt);
            meta.put("vp_formats_supported", formats);
            return objectMapper.writeValueAsString(meta);
        } catch (Exception e) {
            return null;
        }
    }

    private String generateWalletNonce() {
        byte[] random = new byte[24];
        new SecureRandom().nextBytes(random);
        return base64UrlEncodeNoPad(random);
    }

    private boolean isEncryptedJwe(String token) {
        if (token == null) {
            return false;
        }
        if (token.chars().filter(c -> c == '.').count() == 4) {
            return true;
        }
        try {
            JWEObject.parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String decryptRequestObject(String token) {
        try {
            JWEObject jwe = JWEObject.parse(token);
            jwe.decrypt(new ECDHDecrypter(walletKeyService.loadOrCreateKey()));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt request object", e);
        }
    }

    private boolean looksLikeSignedJwt(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        if (token.chars().filter(c -> c == '.').count() == 2) {
            return true;
        }
        try {
            SignedJWT.parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

		    private PendingRequest parseRequestObject(String requestObject,
		                                              String expectedState,
		                                              String incomingRedirectUri,
		                                              String expectedWalletNonce,
		                                              String rawRequestDebug) throws Exception {
		        JWT parsed = JWTParser.parse(requestObject);
		        SignedJWT requestJwt = parsed instanceof SignedJWT sj ? sj : null;
		        JWTClaimsSet claims = parsed.getJWTClaimsSet();
		        String clientId = claims.getStringClaim("client_id");
	        String responseUri = claims.getStringClaim("response_uri");
	        String responseMode = claims.getStringClaim("response_mode");
        if (responseUri == null || responseUri.isBlank()) {
            responseUri = incomingRedirectUri;
        }
        String dcqlQuery = extractJsonClaim(claims.getClaim("dcql_query"));
        String nonce = claims.getStringClaim("nonce");
        String state = claims.getStringClaim("state");
        if (state == null || state.isBlank()) {
            throw new IllegalStateException("Missing state in request object");
        }
        if (expectedState != null && !expectedState.isBlank() && !state.equals(expectedState)) {
            throw new IllegalStateException("State mismatch in request object");
        }
        if (expectedWalletNonce != null && !expectedWalletNonce.isBlank()) {
            String walletNonce = claims.getStringClaim("wallet_nonce");
            if (walletNonce == null || walletNonce.isBlank()) {
                throw new IllegalStateException("Missing wallet_nonce in request object");
            }
            if (!expectedWalletNonce.equals(walletNonce)) {
                throw new IllegalStateException("wallet_nonce mismatch in request object");
            }
        }
	        String clientMetadata = extractClientMetadata(claims.getClaim("client_metadata"));
	        String authType = clientId != null && clientId.startsWith("verifier_attestation:") ? "verifier_attestation" : "plain";
	        if ("verifier_attestation".equals(authType)) {
            if (requestJwt == null) {
                throw new IllegalStateException("Request object must be signed for verifier_attestation");
            }
            String attestationJwt = (String) requestJwt.getHeader().getCustomParam("jwt");
            if (attestationJwt == null || attestationJwt.isBlank()) {
                throw new IllegalStateException("Missing verifier_attestation JWT header");
            }
            verifyAttestationRequest(clientId, attestationJwt, requestJwt, responseUri);
        }
        List<String> warnings = new ArrayList<>();
        if (clientId != null && clientId.startsWith("x509_hash:")) {
            if (requestJwt == null) {
                throw new IllegalStateException("Request object must be signed for x509_hash client_id");
            }
            warnings.addAll(verifyX509HashRequest(clientId, requestJwt));
        }
	        if (clientId != null && clientId.startsWith("x509_san_dns:")) {
	            if (requestJwt == null) {
	                throw new IllegalStateException("Request object must be signed for x509_san_dns client_id");
	            }
	            warnings.addAll(verifyX509SanDnsRequest(clientId, requestJwt, responseUri));
	        }
		        return new PendingRequest(
		                state,
		                nonce,
		                responseUri,
		                clientId,
		                dcqlQuery,
		                clientMetadata,
		                responseMode,
		                rawRequestDebug,
		                requestObject,
		                null,
		                null,
		                warnings
	        );
	    }

    private void verifyAttestationRequest(String clientId, String attestationJwt, SignedJWT requestJwt, String responseUri) throws Exception {
        SignedJWT att = SignedJWT.parse(attestationJwt);
        JWK attJwk = att.getHeader().getJWK();
        if (attJwk == null) {
            throw new IllegalStateException("Attestation missing embedded JWK");
        }
        boolean attValid = switch (attJwk.getKeyType().getValue()) {
            case "RSA" -> attJwk instanceof RSAKey rsa && att.verify(new RSASSAVerifier(rsa));
            case "EC" -> attJwk instanceof ECKey ec && att.verify(new ECDSAVerifier(ec));
            default -> false;
        };
        if (!attValid) {
            throw new IllegalStateException("Invalid verifier attestation signature");
        }
        JWTClaimsSet attClaims = att.getJWTClaimsSet();
        if (attClaims.getExpirationTime() == null || attClaims.getExpirationTime().before(new Date())) {
            throw new IllegalStateException("Verifier attestation expired");
        }
        if (attClaims.getNotBeforeTime() != null && attClaims.getNotBeforeTime().after(new Date())) {
            throw new IllegalStateException("Verifier attestation not yet valid");
        }
        String iss = attClaims.getIssuer();
        List<String> trusted = walletProperties.trustedAttestationIssuers();
        if (trusted == null || trusted.isEmpty()) {
            throw new IllegalStateException("No trusted verifier attestation issuers configured");
        }
        if (iss == null || iss.isBlank() || !trusted.contains(iss)) {
            throw new IllegalStateException("Untrusted verifier attestation issuer");
        }
        String baseClientId = clientId != null && clientId.startsWith("verifier_attestation:")
                ? clientId.substring("verifier_attestation:".length())
                : clientId;
        if (!attClaims.getSubject().equals(baseClientId)) {
            throw new IllegalStateException("Attestation sub mismatch");
        }
        var redirectUris = attClaims.getStringListClaim("redirect_uris");
        if (redirectUris != null && !redirectUris.isEmpty() && (responseUri == null || !redirectUris.contains(responseUri))) {
            throw new IllegalStateException("redirect_uri not allowed by attestation");
        }
        JWK cnf = null;
        Object cnfClaim = attClaims.getClaim("cnf");
        if (cnfClaim instanceof Map<?, ?> map && map.containsKey("jwk")) {
            cnf = JWK.parse((Map<String, Object>) map.get("jwk"));
        }
        if (cnf == null) {
            throw new IllegalStateException("Attestation missing cnf.jwk");
        }
        boolean reqValid = switch (cnf.getKeyType().getValue()) {
            case "RSA" -> cnf instanceof RSAKey rsa && requestJwt.verify(new RSASSAVerifier(rsa));
            case "EC" -> cnf instanceof ECKey ec && requestJwt.verify(new ECDSAVerifier(ec));
            default -> false;
        };
        if (!reqValid) {
            throw new IllegalStateException("Request object signature invalid (cnf key)");
        }
    }

    private List<String> verifyX509HashRequest(String clientId, SignedJWT requestJwt) throws Exception {
        List<String> warnings = new ArrayList<>();
        List<Base64> chain = requestJwt.getHeader().getX509CertChain();
        CertChainResult chainResult = validateCertificateChainResult(chain);
        X509Certificate leaf = chainResult.leaf();
        if (!chainResult.trusted() && chainResult.warning() != null) {
            warnings.add(chainResult.warning());
        }
        String expected = clientId.substring("x509_hash:".length());
        String actual = hashCertificate(leaf);
        if (!expected.equals(actual)) {
            throw new IllegalStateException("client_id hash does not match x5c certificate");
        }
        if (!verifySignatureWithCertificate(requestJwt, leaf)) {
            throw new IllegalStateException("Request object signature invalid (x509_hash)");
        }
        return warnings;
    }

    private List<String> verifyX509SanDnsRequest(String clientId, SignedJWT requestJwt, String responseUri) throws Exception {
        List<String> warnings = new ArrayList<>();
        List<Base64> chain = requestJwt.getHeader().getX509CertChain();
        CertChainResult chainResult = validateCertificateChainResult(chain);
        X509Certificate leaf = chainResult.leaf();
        if (!chainResult.trusted() && chainResult.warning() != null) {
            warnings.add(chainResult.warning());
        }
        String expectedDns = clientId.substring("x509_san_dns:".length());
        if (expectedDns.isBlank()) {
            throw new IllegalStateException("x509_san_dns client_id is missing DNS value");
        }
        String actualDns = firstDnsSan(leaf);
        if (actualDns == null || actualDns.isBlank()) {
            throw new IllegalStateException("x509_san_dns request certificate missing dNSName SAN");
        }
        if (!expectedDns.equals(actualDns)) {
            throw new IllegalStateException("client_id does not match certificate dNSName SAN");
        }
        if (responseUri != null && !responseUri.isBlank()) {
            URI parsed = URI.create(responseUri);
            String host = parsed.getHost();
            if (host == null || host.isBlank() || !expectedDns.equalsIgnoreCase(host)) {
                warnings.add("response_uri host (%s) does not match x509_san_dns client_id (%s) - relaxed for mock wallet debugging."
                        .formatted(host, expectedDns));
            }
        }
        if (!verifySignatureWithCertificate(requestJwt, leaf)) {
            throw new IllegalStateException("Request object signature invalid (x509_san_dns)");
        }
        return warnings;
    }

    private boolean verifySignatureWithCertificate(SignedJWT jwt, X509Certificate certificate) throws Exception {
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            return jwt.verify(new RSASSAVerifier(rsaPublicKey));
        }
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            return jwt.verify(new ECDSAVerifier(ecPublicKey));
        }
        throw new IllegalStateException("Unsupported certificate public key type: " + publicKey.getAlgorithm());
    }

    private String firstDnsSan(X509Certificate cert) throws Exception {
        if (cert.getSubjectAlternativeNames() == null) {
            return null;
        }
        for (List<?> entry : cert.getSubjectAlternativeNames()) {
            if (entry != null && entry.size() >= 2 && entry.get(0) instanceof Integer type && type == 2) {
                Object value = entry.get(1);
                if (value != null) {
                    return String.valueOf(value);
                }
            }
        }
        return null;
    }

    private String decodeJwtFull(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        try {
            if (sdJwtParser.isSdJwt(token)) {
                token = sdJwtParser.signedJwt(token);
            }
            if (!token.contains(".")) {
                return null;
            }
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            var sb = new StringBuilder();
            sb.append("--- JOSE Header ---\n");
            byte[] header = base64UrlDecode(parts[0]);
            sb.append(objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(header)));
            sb.append("\n\n--- Payload ---\n");
            byte[] payload = base64UrlDecode(parts[1]);
            sb.append(objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(payload)));
            return sb.toString();
        } catch (Exception e) {
            return token;
        }
    }

    private String decodeJwtLike(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        try {
            if (sdJwtParser.isSdJwt(token)) {
                token = sdJwtParser.signedJwt(token);
            }
            if (!token.contains(".")) {
                return "";
            }
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return "";
            }
            byte[] payload = base64UrlDecode(parts[1]);
            return objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(payload));
        } catch (Exception e) {
            return "";
        }
    }

    private String toJsonArray(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values);
        } catch (Exception e) {
            return String.join(",", values);
        }
    }

    private String encryptResponse(String jsonPayload, String clientMetadataJson) throws Exception {
        if (clientMetadataJson == null || clientMetadataJson.isBlank()) {
            throw new IllegalStateException("Missing client_metadata for encrypted response");
        }
        JsonNode meta = objectMapper.readTree(clientMetadataJson);
        JsonNode jwksNode = meta.get("jwks");
        if (jwksNode == null || jwksNode.isMissingNode()) {
            throw new IllegalStateException("client_metadata.jwks missing for encrypted response");
        }
        JWKSet set = JWKSet.parse(jwksNode.toString());
        JWK jwk = set.getKeys().stream()
                .filter(k -> k.getAlgorithm() != null)
                .findFirst()
                .orElse(null);
        if (jwk == null) {
            throw new IllegalStateException("No suitable encryption key found in client_metadata.jwks");
        }
        JWEAlgorithm jweAlg = JWEAlgorithm.parse(jwk.getAlgorithm().getName());
        EncryptionMethod jweEnc = EncryptionMethod.A128GCM;
        // Prefer new OID4VP parameter, fall back to legacy parameter
        JsonNode encValue = meta.get("authorization_encrypted_response_enc");
        if (encValue != null && encValue.isTextual()) {
            String enc = encValue.asText(null);
            if (enc != null && !enc.isBlank()) {
                jweEnc = EncryptionMethod.parse(enc);
            }
        } else {
            JsonNode encValues = meta.get("encrypted_response_enc_values_supported");
            if (encValues != null && encValues.isArray() && !encValues.isEmpty()) {
                String enc = encValues.get(0).asText(null);
                if (enc != null && !enc.isBlank()) {
                    jweEnc = EncryptionMethod.parse(enc);
                }
            }
        }
        JWEHeader.Builder header = new JWEHeader.Builder(jweAlg, jweEnc);
        if (jwk.getKeyID() != null && !jwk.getKeyID().isBlank()) {
            header.keyID(jwk.getKeyID());
        }
        JWEObject jwe = new JWEObject(header.build(), new Payload(jsonPayload));
        if (jwk instanceof RSAKey rsaKey) {
            jwe.encrypt(new RSAEncrypter(rsaKey));
        } else if (jwk instanceof ECKey ecKey) {
            jwe.encrypt(new ECDHEncrypter(ecKey));
        } else {
            throw new IllegalStateException("Unsupported encryption key type: " + jwk.getKeyType());
        }
        return jwe.serialize();
    }

    private Map<String, String> extractSelections(HttpSession session, PendingRequest pending, Map<String, String[]> params) {
        Map<String, String> selections = pending.selections() != null ? new LinkedHashMap<>(pending.selections()) : new LinkedHashMap<>();
        if (params != null) {
            params.forEach((key, values) -> {
                if (key != null && key.startsWith("selection-") && values != null && values.length > 0) {
                    String descriptorId = key.substring("selection-".length());
                    if (!descriptorId.isBlank() && values[0] != null && !values[0].isBlank()) {
                        selections.put(descriptorId, values[0]);
                    }
                }
            });
        }
        session.setAttribute(SESSION_REQUEST, pending.withSelections(selections));
        return selections;
    }

    /**
     * Extract which descriptors are included based on checkbox values.
     * Checkboxes use the format "include-{descriptorId}" with value "true".
     */
    private Set<String> extractIncludedDescriptors(Map<String, String[]> params) {
        Set<String> included = new HashSet<>();
        if (params != null) {
            params.forEach((key, values) -> {
                if (key != null && key.startsWith("include-") && values != null && values.length > 0) {
                    String descriptorId = key.substring("include-".length());
                    if (!descriptorId.isBlank() && "true".equals(values[0])) {
                        included.add(descriptorId);
                    }
                }
            });
        }
        return included;
    }

    /**
     * Filter presentation options to only include descriptors that were checked.
     */
    private PresentationService.PresentationOptions filterOptionsByInclusion(
            PresentationService.PresentationOptions options,
            Set<String> includedDescriptors) {
        List<PresentationService.DescriptorOptions> filtered = options.options().stream()
                .filter(opt -> includedDescriptors.contains(opt.request().id()))
                .toList();
        return new PresentationService.PresentationOptions(filtered);
    }

    private String deriveVct(Map<String, Object> credential) {
        if (credential == null || credential.isEmpty()) {
            return "";
        }
        Object vct = credential.get("vct");
        if (vct instanceof String s && !s.isBlank()) {
            return s;
        }
        if (vct != null) {
            String text = vct.toString();
            if (text != null && !text.isBlank()) {
                return text;
            }
        }
        Object type = credential.get("type");
        if (type instanceof String s && !s.isBlank()) {
            return s;
        }
        if (type instanceof List<?> list && !list.isEmpty()) {
            Object first = list.get(0);
            if (first != null) {
                String text = first.toString();
                if (text != null && !text.isBlank()) {
                    return text;
                }
            }
        }
        return "";
    }

    private String formatRawRequest(HttpServletRequest request) {
        var sb = new StringBuilder();
        sb.append(request.getMethod()).append(" ").append(request.getRequestURI());
        if (request.getQueryString() != null) {
            sb.append("?").append(request.getQueryString());
        }
        sb.append("\n");
        var headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            var values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                sb.append(name).append(": ").append(values.nextElement()).append("\n");
            }
        }
        // For GET requests, show decoded query parameters as the body section
        if ("GET".equalsIgnoreCase(request.getMethod()) && request.getQueryString() != null) {
            sb.append("\n--- Query Parameters ---\n");
            request.getParameterMap().forEach((key, vals) -> {
                for (String val : vals) {
                    String display = val;
                    // Try to pretty-print JSON values
                    if (display.trim().startsWith("{") || display.trim().startsWith("[")) {
                        display = pretty(display);
                    }
                    sb.append(key).append("=").append(display).append("\n");
                }
            });
        }
        return sb.toString();
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

    /**
     * Resolves the response_mode per OID4VP 1.0 Section 5.6.
     * - If explicitly provided, use that value
     * - If response_uri is present and client_metadata indicates encrypted response support, use direct_post.jwt
     * - If response_uri is present, default to direct_post
     * - Otherwise fall back to direct_post (this wallet only supports direct_post variants)
     */
    private String resolveResponseMode(PendingRequest pending) {
        if (pending.responseMode() != null && !pending.responseMode().isBlank()) {
            return pending.responseMode();
        }
        // Check if client metadata indicates encrypted responses are required/supported
        if (pending.clientMetadata() != null && !pending.clientMetadata().isBlank()) {
            try {
                JsonNode meta = objectMapper.readTree(pending.clientMetadata());
                // If client provides encryption keys via jwks and specifies encryption alg values,
                // prefer encrypted response mode
                JsonNode jwks = meta.get("jwks");
                JsonNode encAlgValues = meta.get("authorization_encrypted_response_alg");
                if (encAlgValues == null) {
                    encAlgValues = meta.get("encrypted_response_alg_values_supported");
                }
                if (jwks != null && !jwks.isMissingNode() && encAlgValues != null && !encAlgValues.isMissingNode()) {
                    return "direct_post.jwt";
                }
            } catch (Exception ignored) {
                // Fall through to default
            }
        }
        // Default to direct_post when response_uri is present (OID4VP Section 5.6)
        return "direct_post";
    }

    private void validateClientBinding(String clientId, String clientMetadata, String clientCert) {
        if (clientId == null || !clientId.startsWith("x509_hash:")) {
            return;
        }
        String expectedHash = clientId.substring("x509_hash:".length());
        if (expectedHash.isBlank()) {
            throw new IllegalStateException("x509_hash client_id is missing hash value");
        }
        if (clientCert == null || clientCert.isBlank()) {
            throw new IllegalStateException("client_cert must be supplied for x509_hash client_id");
        }
        String calculated = computeCertificateHash(clientCert);
        if (!expectedHash.equals(calculated)) {
            throw new IllegalStateException("client_id hash does not match client_cert");
        }
    }

    private String computeCertificateHash(String clientCertPem) {
        try {
            String sanitized = extractFirstPemBlock(clientCertPem);
            if (sanitized != null) {
                sanitized = sanitized.replace(' ', '+');
            }
            byte[] der = base64Decode(sanitized);
            return hashCertificate(der);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid client_cert for x509_hash client_id", e);
        }
    }

    private String hashCertificate(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            return hashCertificate(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash certificate", e);
        }
    }

    private String hashCertificate(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            return base64UrlEncodeNoPad(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash certificate", e);
        }
    }

    private static String base64UrlEncodeNoPad(byte[] value) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] base64UrlDecode(String value) {
        return java.util.Base64.getUrlDecoder().decode(value);
    }

    private static byte[] base64Decode(String value) {
        return java.util.Base64.getDecoder().decode(value);
    }

    private String extractFirstPemBlock(String pem) {
        String[] parts = pem.split("-----BEGIN CERTIFICATE-----");
        for (String part : parts) {
            if (part.contains("-----END CERTIFICATE-----")) {
                String body = part.substring(0, part.indexOf("-----END CERTIFICATE-----"));
                String cleaned = body.replaceAll("\\s+", "");
                if (!cleaned.isBlank()) {
                    return cleaned;
                }
            }
        }
        throw new IllegalStateException("No certificate found in client_cert");
    }

    private record CertChainResult(X509Certificate leaf, boolean trusted, String warning) {}

    private CertChainResult validateCertificateChainResult(List<Base64> chain) throws Exception {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalStateException("Signed request object missing x5c header");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        for (Base64 entry : chain) {
            byte[] der = entry.decode();
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            cert.checkValidity();
            certs.add(cert);
        }
        try {
            validateX509TrustChain(cf, certs);
            return new CertChainResult(certs.get(0), true, null);
        } catch (IllegalStateException e) {
            LOG.warn("X.509 trust chain validation failed (mock wallet will proceed with signature-only validation): {}", e.getMessage());
            return new CertChainResult(certs.get(0), false,
                    "Certificate chain is NOT trusted (issuer not in trust store). Signature was verified using the embedded public key only.");
        }
    }

    private X509Certificate validateCertificateChain(List<Base64> chain) throws Exception {
        CertChainResult result = validateCertificateChainResult(chain);
        if (!result.trusted()) {
            throw new IllegalStateException("Untrusted X.509 certificate chain in x5c header");
        }
        return result.leaf();
    }

    private void validateX509TrustChain(CertificateFactory cf, List<X509Certificate> chain) throws Exception {
        Set<TrustAnchor> trustAnchors = x509TrustAnchors();
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new IllegalStateException("No trust anchors available for X.509 trust chain validation");
        }

        List<List<X509Certificate>> candidates = new ArrayList<>();
        candidates.add(chain);
        if (chain.size() > 1 && isSelfSigned(chain.get(chain.size() - 1))) {
            candidates.add(chain.subList(0, chain.size() - 1));
        }

        Exception last = null;
        for (List<X509Certificate> candidate : candidates) {
            try {
                PKIXParameters params = new PKIXParameters(trustAnchors);
                params.setRevocationEnabled(false);
                CertPath certPath = cf.generateCertPath(candidate);
                CertPathValidator.getInstance("PKIX").validate(certPath, params);
                return;
            } catch (Exception e) {
                last = e;
            }
        }

        if (chain.size() == 1 && isExplicitTrustAnchor(chain.get(0), trustAnchors)) {
            return;
        }

        throw new IllegalStateException("Untrusted X.509 certificate chain in x5c header", last);
    }

    private boolean isSelfSigned(X509Certificate certificate) {
        try {
            if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return false;
            }
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExplicitTrustAnchor(X509Certificate certificate, Set<TrustAnchor> trustAnchors) {
        try {
            byte[] encoded = certificate.getEncoded();
            for (TrustAnchor anchor : trustAnchors) {
                X509Certificate trusted = anchor.getTrustedCert();
                if (trusted != null && Arrays.equals(encoded, trusted.getEncoded())) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private Set<TrustAnchor> x509TrustAnchors() throws Exception {
        Set<TrustAnchor> cached = cachedX509TrustAnchors;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (cachedX509TrustAnchors != null) {
                return cachedX509TrustAnchors;
            }
            Set<TrustAnchor> anchors = new HashSet<>();
            anchors.addAll(systemTrustAnchors());
            if (walletProperties.x509TrustAnchorsPem() != null) {
                anchors.addAll(pemTrustAnchors(walletProperties.x509TrustAnchorsPem()));
            }
            cachedX509TrustAnchors = anchors;
            return anchors;
        }
    }

    private Set<TrustAnchor> systemTrustAnchors() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        for (TrustManager manager : tmf.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                Set<TrustAnchor> anchors = new HashSet<>();
                for (X509Certificate cert : x509.getAcceptedIssuers()) {
                    anchors.add(new TrustAnchor(cert, null));
                }
                return anchors;
            }
        }
        return Set.of();
    }

    private Set<TrustAnchor> pemTrustAnchors(Path pemFile) throws Exception {
        if (!Files.exists(pemFile)) {
            throw new IllegalStateException("X.509 trust anchor file not found: " + pemFile.toAbsolutePath());
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = Files.newInputStream(pemFile)) {
            Set<TrustAnchor> anchors = new HashSet<>();
            for (Certificate cert : cf.generateCertificates(is)) {
                if (cert instanceof X509Certificate x509) {
                    anchors.add(new TrustAnchor(x509, null));
                }
            }
            return anchors;
        }
    }

    private String extractClientMetadata(Object claim) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof String str) {
            return str;
        }
        try {
            return objectMapper.writeValueAsString(claim);
        } catch (Exception e) {
            return claim.toString();
        }
    }

    private String extractJsonClaim(Object claim) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof String str) {
            return str;
        }
        try {
            return objectMapper.writeValueAsString(claim);
        } catch (Exception e) {
            return claim.toString();
        }
    }

    private record RequestObjectResolution(String requestObject,
                                           String walletNonce,
                                           boolean encrypted,
                                           boolean signed,
                                           String walletMetadata,
                                           boolean usedPost) {
        String requestLog() {
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
    }

    /**
     * Derives a client_id from a URI by extracting its origin.
     * Per OID4VP DC API spec, for web verifiers the client_id is the origin.
     */
    private String deriveClientIdFromUri(String uri) {
        if (uri == null || uri.isBlank()) {
            return null;
        }
        try {
            URI parsed = URI.create(uri);
            String scheme = parsed.getScheme();
            String host = parsed.getHost();
            int port = parsed.getPort();
            if (scheme == null || host == null) {
                return null;
            }
            boolean includePort = port != -1
                    && !((port == 80 && "http".equalsIgnoreCase(scheme))
                    || (port == 443 && "https".equalsIgnoreCase(scheme)));
            if (includePort) {
                return "%s://%s:%d".formatted(scheme.toLowerCase(), host, port);
            }
            return "%s://%s".formatted(scheme.toLowerCase(), host);
        } catch (Exception e) {
            return null;
        }
    }

    private record PendingRequest(String state,
                                  String nonce,
                                  String responseUri,
                                  String clientId,
                                  String dcqlQuery,
                                  String clientMetadata,
                                  String responseMode,
                                  String rawRequestDebug,
                                  String requestObjectRaw,
                                  PresentationService.PresentationOptions options,
                                  Map<String, String> selections,
                                  List<String> warnings) {
        PendingRequest withOptions(PresentationService.PresentationOptions o) {
            return new PendingRequest(state, nonce, responseUri, clientId, dcqlQuery, clientMetadata, responseMode,
                    rawRequestDebug, requestObjectRaw, o, selections, warnings);
        }

        PendingRequest withSelections(Map<String, String> newSelections) {
            return new PendingRequest(state, nonce, responseUri, clientId, dcqlQuery, clientMetadata, responseMode,
                    rawRequestDebug, requestObjectRaw, options, newSelections, warnings);
        }
    }
}
