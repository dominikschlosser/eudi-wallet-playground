package de.arbeitsagentur.keycloak.wallet.demo.oid4vp;

import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import de.arbeitsagentur.keycloak.wallet.demo.oid4vp.PresentationService;
import de.arbeitsagentur.keycloak.wallet.demo.oid4vp.PresentationService.DescriptorMatch;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.SessionService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.WalletSession;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Controller
public class Oid4vpController {
    private final PresentationService presentationService;
    private final WalletKeyService walletKeyService;
    private final WalletProperties walletProperties;
    private final ObjectMapper objectMapper;
    private final DebugLogService debugLogService;
    private final SessionService sessionService;
    private final RestTemplate restTemplate;
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
    }

    @GetMapping("/oid4vp/auth")
    public ModelAndView handleAuth(@RequestParam(name = "response_uri", required = false) String responseUri,
                                   @RequestParam(name = "redirect_uri", required = false) String redirectUri,
                                   @RequestParam(name = "state", required = false) String state,
                                   @RequestParam(name = "dcql_query", required = false) String dcqlQuery,
                                   @RequestParam(name = "nonce", required = false) String nonce,
                                   @RequestParam(name = "client_id", required = false) String clientId,
                                   @RequestParam(name = "client_metadata", required = false) String clientMetadata,
                                   @RequestParam(name = "request", required = false) String requestObject,
                                   @RequestParam(name = "request_uri", required = false) String requestUri,
                                   @RequestParam(name = "client_cert", required = false) String clientCert,
                                   HttpSession httpSession) {
        WalletSession walletSession = sessionService.getSession(httpSession);
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
                        requestResolution != null ? requestResolution.walletNonce() : null);
            } catch (Exception e) {
                return errorView("Invalid request object: " + e.getMessage());
            }
        } else {
            if (state == null || state.isBlank()) {
                return errorView("Missing state parameter");
            }
            try {
                validateClientBinding(clientId, clientMetadata, clientCert);
            } catch (IllegalStateException e) {
                return errorView(e.getMessage());
            }
            pending = new PendingRequest(
                    state,
                    nonce,
                    targetResponseUri,
                    clientId,
                    dcqlQuery,
                    clientMetadata,
                    null,
                    null
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
        if (walletSession == null || !walletSession.isAuthenticated()) {
            return new ModelAndView("redirect:/auth/login");
        }
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
            return submitView(pending.responseUri(), Map.of(
                    "state", pending.state(),
                    "error", "access_denied",
                    "error_description", "User denied presentation"
            ));
        }
        WalletSession walletSession = sessionService.getSession(httpSession);
        if (walletSession == null || !walletSession.isAuthenticated()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return errorView("Please sign in to your wallet before sharing credentials.");
        }
        if (pending.responseUri() == null || pending.responseUri().isBlank()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return errorView("Missing response_uri for direct_post");
        }
        var options = pending.options() != null
                ? Optional.of(pending.options())
                : presentationService.preparePresentationOptions(walletSession.getUserProfile().sub(),
                pending.dcqlQuery());
        if (options.isEmpty()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return errorView("No matching credential found");
        }
        Map<String, String> selections = extractSelections(httpSession, pending, request.getParameterMap());
        Optional<List<DescriptorMatch>> chosen = presentationService.selectDistinctMatches(options.get(), selections);
        if (chosen.isEmpty() || chosen.get().size() != options.get().options().size()) {
            httpSession.removeAttribute(SESSION_REQUEST);
            return errorView("No matching credential found");
        }
        Map<String, List<String>> vpTokens = new LinkedHashMap<>();
        for (DescriptorMatch match : chosen.get()) {
            String token = buildEnvelopeVpToken(match.vpToken(), pending.nonce(), pending.clientId());
            token = encryptIfRequested(token, pending.clientMetadata());
            vpTokens.computeIfAbsent(match.descriptorId(), k -> new ArrayList<>()).add(token);
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
        if (pending.nonce() != null && !pending.nonce().isBlank()) {
            fields.put("nonce", pending.nonce());
        }

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
        return submitView(pending.responseUri(), fields);
    }

    @GetMapping("/oid4vp/continue")
    public ModelAndView continuePending(HttpSession httpSession) {
        PendingRequest pending = (PendingRequest) httpSession.getAttribute(SESSION_REQUEST);
        if (pending == null) {
            return errorView("Presentation request not found or expired");
        }
        WalletSession walletSession = sessionService.getSession(httpSession);
        if (walletSession == null || !walletSession.isAuthenticated()) {
            httpSession.setAttribute(POST_LOGIN_REDIRECT, "/oid4vp/continue");
            return new ModelAndView("redirect:/auth/login");
        }
        var options = pending.options();
        if (options == null) {
            Optional<PresentationService.PresentationOptions> prepared = presentationService.preparePresentationOptions(walletSession.getUserProfile().sub(),
                    pending.dcqlQuery());
            if (prepared.isEmpty()) {
                return errorView("No credential matching the dcql_query");
            }
            options = prepared.get();
            pending = pending.withOptions(options);
            httpSession.setAttribute(SESSION_REQUEST, pending);
        }
        ModelAndView mv = new ModelAndView("oid4vp-consent");
        mv.addObject("descriptorOptions", options.options());
        mv.addObject("dcqlQuery", pretty(pending.dcqlQuery()));
        mv.addObject("state", pending.state());
        mv.addObject("responseUri", pending.responseUri());
        mv.addObject("nonce", pending.nonce());
        mv.addObject("clientId", pending.clientId());
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
        if (walletSession.getUserProfile() != null) {
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

    private ModelAndView submitView(String responseUri, Map<String, String> fields) {
        ModelAndView mv = new ModelAndView("oid4vp-submit");
        mv.addObject("redirectUri", responseUri);
        mv.addObject("fields", fields);
        return mv;
    }

    private String buildEnvelopeVpToken(String innerVpToken, String nonce, String audience) {
        try {
            ECKey holderKey = walletKeyService.loadOrCreateKey();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("kb+jwt"))
                    .keyID(holderKey.getKeyID())
                    .build();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(walletProperties.walletDid())
                    .claim("vp_token", innerVpToken)
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .claim("nonce", nonce)
                    .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
            if (audience != null && !audience.isBlank()) {
                claims.audience(audience);
            }
            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new ECDSASigner(holderKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            return innerVpToken;
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
            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);
            org.springframework.util.MultiValueMap<String, String> form = new org.springframework.util.LinkedMultiValueMap<>();
            if (walletMetadata != null && !walletMetadata.isBlank()) {
                form.add("wallet_metadata", walletMetadata);
            }
            form.add("wallet_nonce", walletNonce);
            org.springframework.http.HttpEntity<org.springframework.util.MultiValueMap<String, String>> entity = new org.springframework.http.HttpEntity<>(form, headers);
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
            meta.put("request_object_signing_alg_values_supported", List.of("RS256"));
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
        new java.security.SecureRandom().nextBytes(random);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    private boolean isEncryptedJwe(String token) {
        if (token == null) {
            return false;
        }
        if (token.chars().filter(c -> c == '.').count() == 4) {
            return true;
        }
        try {
            com.nimbusds.jose.JWEObject.parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String decryptRequestObject(String token) {
        try {
            com.nimbusds.jose.JWEObject jwe = com.nimbusds.jose.JWEObject.parse(token);
            jwe.decrypt(new com.nimbusds.jose.crypto.ECDHDecrypter(walletKeyService.loadOrCreateKey()));
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

    private PendingRequest parseRequestObject(String requestObject, String expectedState, String incomingRedirectUri, String expectedWalletNonce) throws Exception {
        com.nimbusds.jwt.JWT parsed = com.nimbusds.jwt.JWTParser.parse(requestObject);
        SignedJWT requestJwt = parsed instanceof SignedJWT sj ? sj : null;
        JWTClaimsSet claims = parsed.getJWTClaimsSet();
        String clientId = claims.getStringClaim("client_id");
        String responseUri = claims.getStringClaim("response_uri");
        if (responseUri == null || responseUri.isBlank()) {
            responseUri = incomingRedirectUri;
        }
        String dcqlQuery = claims.getStringClaim("dcql_query");
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
        if (clientId != null && clientId.startsWith("x509_hash:")) {
            if (requestJwt == null) {
                throw new IllegalStateException("Request object must be signed for x509_hash client_id");
            }
            verifyX509HashRequest(clientId, requestJwt);
        }
        return new PendingRequest(
                state,
                nonce,
                responseUri,
                clientId,
                dcqlQuery,
                clientMetadata,
                null,
                null
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
        if (trusted != null && !trusted.isEmpty() && (iss == null || !trusted.contains(iss))) {
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

    private void verifyX509HashRequest(String clientId, SignedJWT requestJwt) throws Exception {
        List<com.nimbusds.jose.util.Base64> chain = requestJwt.getHeader().getX509CertChain();
        X509Certificate leaf = validateCertificateChain(chain);
        String expected = clientId.substring("x509_hash:".length());
        String actual = hashCertificate(leaf);
        if (!expected.equals(actual)) {
            throw new IllegalStateException("client_id hash does not match x5c certificate");
        }
        RSAKey rsaKey = RSAKey.parse(leaf);
        boolean verified = requestJwt.verify(new RSASSAVerifier(rsaKey));
        if (!verified) {
            throw new IllegalStateException("Request object signature invalid (x509_hash)");
        }
    }

    private String decodeJwtLike(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        try {
            if (token.contains("~")) {
                token = token.split("~")[0];
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

    private String toJsonArray(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values);
        } catch (Exception e) {
            return String.join(",", values);
        }
    }

    private String encryptIfRequested(String token, String clientMetadataJson) {
        if (clientMetadataJson == null || clientMetadataJson.isBlank()) {
            return token;
        }
        try {
            JsonNode meta = objectMapper.readTree(clientMetadataJson);
            JsonNode jwksNode = meta.get("jwks");
            if (jwksNode == null || jwksNode.isMissingNode()) {
                return token;
            }
            JWKSet set = JWKSet.parse(jwksNode.toString());
            JWK jwk = set.getKeys().stream()
                    .filter(k -> k instanceof RSAKey)
                    .findFirst()
                    .orElse(null);
            if (!(jwk instanceof RSAKey rsaKey)) {
                return token;
            }
            String alg = meta.path("response_encryption_alg").asText("RSA-OAEP-256");
            String enc = meta.path("response_encryption_enc").asText("A256GCM");
            JWEAlgorithm jweAlg = JWEAlgorithm.parse(alg);
            EncryptionMethod jweEnc = EncryptionMethod.parse(enc);
            com.nimbusds.jose.JWEObject jwe = new com.nimbusds.jose.JWEObject(
                    new JWEHeader.Builder(jweAlg, jweEnc).keyID(rsaKey.getKeyID()).build(),
                    new com.nimbusds.jose.Payload(token)
            );
            jwe.encrypt(new RSAEncrypter(rsaKey));
            return jwe.serialize();
        } catch (Exception e) {
            return token;
        }
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
            byte[] der = java.util.Base64.getDecoder().decode(sanitized);
            return hashCertificate(der);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid client_cert for x509_hash client_id", e);
        }
    }

    private String hashCertificate(byte[] der) {
        try {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
            return hashCertificate(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash certificate", e);
        }
    }

    private String hashCertificate(java.security.cert.X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash certificate", e);
        }
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

    private X509Certificate validateCertificateChain(List<com.nimbusds.jose.util.Base64> chain) throws Exception {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalStateException("x509_hash request missing x5c header");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        for (com.nimbusds.jose.util.Base64 entry : chain) {
            byte[] der = entry.decode();
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
            cert.checkValidity();
            certs.add(cert);
        }
        for (int i = 0; i < certs.size(); i++) {
            X509Certificate cert = certs.get(i);
            X509Certificate issuer = i + 1 < certs.size() ? certs.get(i + 1) : certs.get(certs.size() - 1);
            cert.verify(issuer.getPublicKey());
        }
        return certs.get(0);
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

    private record PendingRequest(String state,
                                  String nonce,
                                  String responseUri,
                                  String clientId,
                                  String dcqlQuery,
                                  String clientMetadata,
                                  PresentationService.PresentationOptions options,
                                  Map<String, String> selections) {
        PendingRequest withOptions(PresentationService.PresentationOptions o) {
            return new PendingRequest(state, nonce, responseUri, clientId, dcqlQuery, clientMetadata, o, selections);
        }

        PendingRequest withSelections(Map<String, String> newSelections) {
            return new PendingRequest(state, nonce, responseUri, clientId, dcqlQuery, clientMetadata, options, newSelections);
        }
    }
}
