package de.arbeitsagentur.keycloak.wallet.mockissuer;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerConfigurationStore;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
public class MockIssuerService {
    private final MockIssuerProperties properties;
    private final ObjectMapper objectMapper;
    private final MockIssuerKeyService keyService;
    private final MockIssuerConfigurationStore configurationStore;
    private final Map<String, OfferState> offers = new ConcurrentHashMap<>();
    private final Map<String, AccessTokenState> accessTokens = new ConcurrentHashMap<>();

    public MockIssuerService(MockIssuerProperties properties,
                             ObjectMapper objectMapper,
                             MockIssuerKeyService keyService,
                             MockIssuerConfigurationStore configurationStore) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.keyService = keyService;
        this.configurationStore = configurationStore;
    }

    public OfferResult createOffer(BuilderRequest request, String issuer) {
        ensureEnabled();
        OfferState state = createOfferState(request, issuer);
        offers.put(state.preAuthorizedCode(), state);
        return new OfferResult(state.offerId(),
                state.preAuthorizedCode(),
                buildCredentialOffer(state),
                credentialOfferUri(state),
                preview(state));
    }

    public PreviewResult preview(BuilderRequest request, String issuer) {
        ensureEnabled();
        OfferState state = createOfferState(request, issuer);
        return preview(state);
    }

    public Map<String, Object> metadata(String issuer) {
        ensureEnabled();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("credential_issuer", issuer);
        meta.put("credential_endpoint", issuer + "/credential");
        meta.put("token_endpoint", issuer + "/token");
        meta.put("nonce_endpoint", issuer + "/nonce");
        meta.put("grants", Map.of(
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                Map.of("tx_code_required", false)
        ));
        Map<String, Object> configs = new LinkedHashMap<>();
        for (MockIssuerProperties.CredentialConfiguration cfg : configurationStore.configurations()) {
            if (!supportsFormat(cfg.format())) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("format", cfg.format());
            entry.put("scope", cfg.scope());
            entry.put("vct", cfg.vct());
            entry.put("cryptographic_binding_methods_supported", List.of("jwk"));
            entry.put("credential_signing_alg_values_supported", List.of("ES256"));
            entry.put("display", List.of(Map.of("name", cfg.name(), "locale", "en")));
            entry.put("proof_types_supported", Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))));
            configs.put(cfg.id(), entry);
        }
        if (configs.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No supported credential configurations");
        }
        meta.put("credential_configurations_supported", configs);
        return meta;
    }

    public OfferState findOfferById(String offerId) {
        if (offerId == null) {
            return null;
        }
        return offers.values().stream()
                .filter(o -> offerId.equals(o.offerId()))
                .findFirst()
                .orElse(null);
    }

    public Optional<OfferSummary> findOfferSummary(String offerId) {
        OfferState state = findOfferById(offerId);
        if (state == null) {
            return Optional.empty();
        }
        return Optional.of(new OfferSummary(state.preAuthorizedCode(), state.configurationId(), state.issuer()));
    }

    public TokenResult exchangePreAuthorizedCode(String preAuthCode) {
        ensureEnabled();
        OfferState offer = offers.get(preAuthCode);
        if (offer == null || offer.expiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(BAD_REQUEST, "Unknown or expired pre-authorized_code");
        }
        String accessToken = "mock-at-" + UUID.randomUUID();
        String cNonce = newNonceValue();
        AccessTokenState state = new AccessTokenState(accessToken, offer, cNonce,
                Instant.now().plus(properties.credentialTtl()));
        accessTokens.put(accessToken, state);
        return new TokenResult(accessToken, "Bearer", (int) properties.credentialTtl().toSeconds(), cNonce,
                (int) properties.credentialTtl().toSeconds());
    }

    public NonceResult issueNonce(String accessToken) {
        ensureEnabled();
        AccessTokenState state = accessTokens.get(stripBearer(accessToken));
        if (state == null || state.expiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(UNAUTHORIZED, "Invalid or expired access token");
        }
        String cNonce = newNonceValue();
        state = state.withNewNonce(cNonce, Instant.now().plus(properties.credentialTtl()));
        accessTokens.put(accessToken, state);
        return new NonceResult(cNonce, (int) properties.credentialTtl().toSeconds());
    }

    public CredentialResult issueCredential(String bearerToken, Map<String, Object> request, String issuer) {
        String token = stripBearer(bearerToken);
        AccessTokenState state = accessTokens.get(token);
        if (state == null || state.expiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(UNAUTHORIZED, "Invalid or expired access token");
        }
        String format = Optional.ofNullable(request.get("format"))
                .map(Object::toString)
                .filter(StringUtils::hasText)
                .orElse(state.offer().format());
        if (!"dc+sd-jwt".equalsIgnoreCase(format)) {
            throw new ResponseStatusException(BAD_REQUEST, "Only dc+sd-jwt is supported right now");
        }
        String credentialConfigurationId = Optional.ofNullable(request.get("credential_configuration_id"))
                .map(Object::toString)
                .filter(StringUtils::hasText)
                .orElse(state.offer().configurationId());
        if (!credentialConfigurationId.equals(state.offer().configurationId())) {
            throw new ResponseStatusException(BAD_REQUEST, "credential_configuration_id mismatch");
        }
        ProofValidation validation = validateProof(request, state, issuer);
        BuildResult built = buildSdJwt(state.offer(), issuer, validation.cnf());
        String nextNonce = newNonceValue();
        accessTokens.put(token, state.withNewNonce(nextNonce, Instant.now().plus(properties.credentialTtl())));

        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("format", "dc+sd-jwt");
        credential.put("credential", built.sdJwt());
        credential.put("credential_configuration_id", credentialConfigurationId);
        credential.put("vct", built.vct());
        if (!built.disclosures().isEmpty()) {
            credential.put("disclosures", built.disclosures());
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("credentials", List.of(credential));
        body.put("c_nonce", nextNonce);
        body.put("c_nonce_expires_in", (int) properties.credentialTtl().toSeconds());
        return new CredentialResult(body, built.decoded(), built.sdJwt());
    }

    public Map<String, Object> credentialOfferPayload(OfferState state) {
        ensureEnabled();
        return buildCredentialOffer(state);
    }

    private void ensureEnabled() {
        if (!Boolean.TRUE.equals(properties.enabled())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Mock issuer disabled");
        }
    }

    private OfferState createOfferState(BuilderRequest request, String issuer) {
        MockIssuerProperties.CredentialConfiguration cfg = resolveConfiguration(request.configurationId());
        String format = cfg.format();
        if (request.format() != null && !request.format().isBlank() && !request.format().equalsIgnoreCase(cfg.format())) {
            throw new ResponseStatusException(BAD_REQUEST, "Format not supported for this configuration");
        }
        if (!supportsFormat(format)) {
            throw new ResponseStatusException(BAD_REQUEST, "Format not supported yet");
        }
        String vct = cfg.vct();
        if (request.vct() != null && !request.vct().isBlank() && !request.vct().equals(cfg.vct())) {
            throw new ResponseStatusException(BAD_REQUEST, "vct must match configured credential type");
        }
        Map<String, Object> claims = resolveClaims(cfg, request.claims());
        return new OfferState(
                UUID.randomUUID().toString(),
                "mock-pre-" + UUID.randomUUID(),
                cfg.id(),
                cfg.name(),
                format,
                vct,
                issuer,
                claims,
                Instant.now().plus(Duration.ofHours(1))
        );
    }

    private MockIssuerProperties.CredentialConfiguration resolveConfiguration(String configurationId) {
        return configurationStore.findById(configurationId)
                .orElseGet(() -> configurationStore.defaultConfiguration()
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No credential configurations available")));
    }

    private Map<String, Object> resolveClaims(MockIssuerProperties.CredentialConfiguration cfg, List<ClaimInput> claims) {
        Map<String, Object> provided = normalizeClaims(claims);
        Map<String, MockIssuerProperties.ClaimTemplate> templates = cfg.claims().stream()
                .collect(Collectors.toMap(MockIssuerProperties.ClaimTemplate::name, Function.identity(), (a, b) -> a, LinkedHashMap::new));
        Set<String> allowed = templates.keySet();
        if (!provided.isEmpty()) {
            Set<String> unknown = new LinkedHashSet<>(provided.keySet());
            unknown.removeAll(allowed);
            if (!unknown.isEmpty()) {
                throw new ResponseStatusException(BAD_REQUEST, "Unsupported claims: " + String.join(", ", unknown));
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, MockIssuerProperties.ClaimTemplate> entry : templates.entrySet()) {
            String name = entry.getKey();
            MockIssuerProperties.ClaimTemplate template = entry.getValue();
            Object value = provided.containsKey(name) ? provided.get(name) : parseValue(template.defaultValue());
            if (value != null) {
                result.put(name, value);
            } else if (Boolean.TRUE.equals(template.required())) {
                throw new ResponseStatusException(BAD_REQUEST, "Missing claim: " + name);
            }
        }
        return result;
    }

    private Map<String, Object> normalizeClaims(List<ClaimInput> claims) {
        if (claims == null || claims.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (ClaimInput claim : claims) {
            if (claim == null || claim.name() == null || claim.name().isBlank()) {
                continue;
            }
            Object value = parseValue(claim.value());
            if (value != null) {
                result.put(claim.name().trim(), value);
            }
        }
        return result;
    }

    private Object parseValue(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (node.isTextual()) {
                return node.asText();
            }
            if (node.isNumber()) {
                return node.numberValue();
            }
            if (node.isBoolean()) {
                return node.booleanValue();
            }
            if (node.isArray() || node.isObject()) {
                return objectMapper.convertValue(node, Object.class);
            }
        } catch (Exception ignored) {
        }
        return trimmed;
    }

    private PreviewResult preview(OfferState state) {
        BuildResult built = buildSdJwt(state, state.issuer(), null);
        return new PreviewResult(state.configurationId(), state.format(), state.vct(), built.sdJwt(), built.decoded());
    }

    private BuildResult buildSdJwt(OfferState offer, String issuer, JsonNode cnf) {
        try {
            SDObjectBuilder builder = new SDObjectBuilder();
            List<Disclosure> disclosures = new ArrayList<>();
            for (Map.Entry<String, Object> entry : offer.claims().entrySet()) {
                Disclosure disclosure = builder.putSDClaim(entry.getKey(), entry.getValue());
                if (disclosure != null) {
                    disclosures.add(disclosure);
                }
            }
            Map<String, Object> payload = builder.build();
            payload.put("vct", offer.vct());
            payload.put("iss", issuer);
            payload.put("iat", Instant.now().getEpochSecond());
            payload.put("exp", Instant.now().plus(properties.credentialTtl()).getEpochSecond());
            if (cnf != null) {
                payload.put("cnf", objectMapper.convertValue(cnf, Map.class));
            }
            SignedJWT jwt = sign(payload);
            String sdJwt = new com.authlete.sd.SDJWT(jwt.serialize(), disclosures, null).toString();
            Map<String, Object> disclosed = SdJwtUtils.extractDisclosedClaims(SdJwtUtils.split(sdJwt), objectMapper);
            Map<String, Object> decoded = new LinkedHashMap<>();
            decoded.put("iss", issuer);
            decoded.put("credential_configuration_id", offer.configurationId());
            decoded.put("vct", offer.vct());
            decoded.put("iat", payload.get("iat"));
            decoded.put("exp", payload.get("exp"));
            if (cnf != null) {
                decoded.put("cnf", objectMapper.convertValue(cnf, Map.class));
            }
            decoded.put("claims", disclosed);
            return new BuildResult(sdJwt, disclosures.stream().map(Disclosure::getDisclosure).toList(), decoded, offer.vct());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SD-JWT", e);
        }
    }

    private SignedJWT sign(Map<String, Object> claims) throws JOSEException {
        ECKey key = keyService.signingKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(Optional.ofNullable(key.getKeyID()).orElse("mock-issuer-es256"))
                .type(JOSEObjectType.JWT)
                .build();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getValue() != null) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }
        }
        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(key));
        return jwt;
    }

    private ProofValidation validateProof(Map<String, Object> request, AccessTokenState state, String issuer) {
        String proofJwt = extractProofJwt(request);
        if (!StringUtils.hasText(proofJwt)) {
            throw new ResponseStatusException(BAD_REQUEST, "Missing proof.jwt");
        }
        try {
            SignedJWT jwt = SignedJWT.parse(proofJwt);
            if (jwt.getJWTClaimsSet().getExpirationTime() != null
                    && jwt.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
                throw new ResponseStatusException(BAD_REQUEST, "Proof expired");
            }
            String nonce = jwt.getJWTClaimsSet().getStringClaim("nonce");
            if (!Objects.equals(nonce, state.cNonce())) {
                throw new ResponseStatusException(BAD_REQUEST, "c_nonce mismatch");
            }
            List<String> audience = jwt.getJWTClaimsSet().getAudience();
            if (issuer != null && !audience.isEmpty() && !issuer.equals(audience.get(0))) {
                throw new ResponseStatusException(BAD_REQUEST, "audience mismatch");
            }
            JWK jwk = jwt.getHeader().getJWK();
            return new ProofValidation(jwk != null ? objectMapper.readTree(jwk.toJSONString()) : null);
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(BAD_REQUEST, "Invalid proof", e);
        }
    }

    private String extractProofJwt(Map<String, Object> request) {
        if (request == null) {
            return null;
        }
        Object proof = request.get("proof");
        if (proof instanceof Map<?, ?> proofMap) {
            Object jwt = proofMap.get("jwt");
            if (jwt != null) {
                return jwt.toString();
            }
        }
        Object proofs = request.get("proofs");
        if (proofs instanceof Map<?, ?> proofsMap) {
            Object jwt = proofsMap.get("jwt");
            if (jwt instanceof String str) {
                return str;
            }
            if (jwt instanceof List<?> list && !list.isEmpty()) {
                Object first = list.get(0);
                if (first != null) {
                    return first.toString();
                }
            }
        }
        return null;
    }

    private String stripBearer(String bearerToken) {
        if (!StringUtils.hasText(bearerToken)) {
            return bearerToken;
        }
        if (bearerToken.toLowerCase().startsWith("bearer ")) {
            return bearerToken.substring(7).trim();
        }
        return bearerToken.trim();
    }

    private Map<String, Object> buildCredentialOffer(OfferState state) {
        Map<String, Object> grants = Map.of(
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                Map.of("pre-authorized_code", state.preAuthorizedCode(), "tx_code_required", false)
        );
        Map<String, Object> offer = new LinkedHashMap<>();
        offer.put("credential_issuer", state.issuer());
        offer.put("credential_configuration_ids", List.of(state.configurationId()));
        offer.put("grants", grants);
        offer.put("display", List.of(Map.of("name", state.displayName(), "locale", "en")));
        return offer;
    }

    private String credentialOfferUri(OfferState state) {
        return state.issuer() + "/credential-offer/" + state.offerId();
    }

    private String newNonceValue() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes());
    }

    private boolean supportsFormat(String format) {
        return "dc+sd-jwt".equalsIgnoreCase(format);
    }

    public record BuilderRequest(String configurationId, String format, String vct, List<ClaimInput> claims) {
    }

    public record ClaimInput(String name, String value) {
    }

    public record OfferResult(String offerId, String preAuthorizedCode, Map<String, Object> credentialOffer,
                              String credentialOfferUri, PreviewResult preview) {
    }

    public record PreviewResult(String configurationId, String format, String vct,
                                String encoded, Map<String, Object> decoded) {
    }

    public record TokenResult(String accessToken, String tokenType, int expiresIn,
                              String cNonce, int cNonceExpiresIn) {
    }

    public record NonceResult(String cNonce, int cNonceExpiresIn) {
    }

    public record CredentialResult(Map<String, Object> body, Map<String, Object> decoded, String encoded) {
    }

    public record OfferSummary(String preAuthorizedCode, String configurationId, String issuer) {
    }

    record OfferState(String offerId,
                      String preAuthorizedCode,
                      String configurationId,
                      String displayName,
                      String format,
                      String vct,
                      String issuer,
                      Map<String, Object> claims,
                      Instant expiresAt) {
    }

    private record AccessTokenState(String accessToken,
                                    OfferState offer,
                                    String cNonce,
                                    Instant expiresAt) {
        AccessTokenState withNewNonce(String newNonce, Instant newExpiry) {
            return new AccessTokenState(accessToken, offer, newNonce, newExpiry);
        }
    }

    private record BuildResult(String sdJwt, List<String> disclosures, Map<String, Object> decoded, String vct) {
    }

    private record ProofValidation(JsonNode cnf) {
    }
}
