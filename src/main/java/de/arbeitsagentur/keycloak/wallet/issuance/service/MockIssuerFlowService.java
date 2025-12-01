package de.arbeitsagentur.keycloak.wallet.issuance.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.BuilderRequest;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.CredentialResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.OfferResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.TokenResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerConfigurationStore;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class MockIssuerFlowService {
    private final MockIssuerService mockIssuerService;
    private final WalletKeyService walletKeyService;
    private final CredentialStore credentialStore;
    private final MockIssuerConfigurationStore configurationStore;
    private final MockIssuerProperties properties;
    private final ObjectMapper objectMapper;

    public MockIssuerFlowService(MockIssuerService mockIssuerService,
                                 WalletKeyService walletKeyService,
                                 CredentialStore credentialStore,
                                 MockIssuerConfigurationStore configurationStore,
                                 MockIssuerProperties properties,
                                 ObjectMapper objectMapper) {
        this.mockIssuerService = mockIssuerService;
        this.walletKeyService = walletKeyService;
        this.credentialStore = credentialStore;
        this.configurationStore = configurationStore;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public Map<String, Object> issueWithMockIssuer(String userId,
                                                   HttpServletRequest request,
                                                   List<MockIssuerService.ClaimInput> claims,
                                                   String configurationId,
                                                   String vct) {
        String issuer = issuerBase(request);
        BuilderRequest builder = new BuilderRequest(
                resolveConfigurationId(configurationId),
                "dc+sd-jwt",
                resolveVct(configurationId, vct),
                claims != null && !claims.isEmpty() ? claims : defaultClaims(configurationId)
        );
        OfferResult offer = mockIssuerService.createOffer(builder, issuer);
        TokenResult token = mockIssuerService.exchangePreAuthorizedCode(offer.preAuthorizedCode());
        String proofJwt = buildProofJwt(issuer, token.cNonce());
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("credential_configuration_id", builder.configurationId());
        requestBody.put("proof", Map.of("proof_type", "jwt", "jwt", proofJwt));
        CredentialResult credential = mockIssuerService.issueCredential(
                "Bearer " + token.accessToken(),
                requestBody,
                issuer
        );
        Map<String, Object> stored = toStoredCredential(credential);
        stored.put("storedAt", Instant.now().toString());
        credentialStore.saveCredential(CredentialStore.MOCK_ISSUER_OWNER, stored);
        return stored;
    }

    private Map<String, Object> toStoredCredential(CredentialResult credential) {
        Map<String, Object> stored = new LinkedHashMap<>();
        Map<String, Object> body = credential.body();
        stored.putAll(body);
        stored.put("vct", credential.decoded().get("vct"));
        stored.put("credentialSubject", credential.decoded().get("claims"));
        Object credentials = body.get("credentials");
        if (credentials instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof Map<?, ?> first) {
            Object raw = ((Map<?, ?>) first).get("credential");
            if (raw != null) {
                stored.put("rawCredential", raw);
            }
            Object format = ((Map<?, ?>) first).get("format");
            if (format != null) {
                stored.put("format", format);
            }
            Object disclosures = ((Map<?, ?>) first).get("disclosures");
            if (disclosures != null) {
                stored.put("disclosures", disclosures);
            }
        }
        return stored;
    }

    private MockIssuerProperties.CredentialConfiguration resolveConfiguration(String configurationId) {
        return configurationStore.findById(configurationId)
                .orElseGet(() -> configurationStore.defaultConfiguration()
                        .orElseThrow(() -> new IllegalStateException("No mock issuer configurations available")));
    }

    private String resolveConfigurationId(String configurationId) {
        return resolveConfiguration(configurationId).id();
    }

    private String resolveVct(String configurationId, String requestedVct) {
        MockIssuerProperties.CredentialConfiguration cfg = resolveConfiguration(configurationId);
        if (StringUtils.hasText(requestedVct) && !requestedVct.equals(cfg.vct())) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST, "Requested vct does not match configuration");
        }
        return cfg.vct();
    }

    private String issuerBase(HttpServletRequest request) {
        if (StringUtils.hasText(properties.issuerId())) {
            return properties.issuerId();
        }
        return ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(request.getContextPath())
                .path("/mock-issuer")
                .build()
                .toUriString();
    }

    private String buildProofJwt(String audience, String nonce) {
        try {
            ECKey key = walletKeyService.loadOrCreateKey();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .jwk(key.toPublicJWK())
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    header,
                    new com.nimbusds.jwt.JWTClaimsSet.Builder()
                            .issuer("did:example:wallet")
                            .audience(audience)
                            .issueTime(new java.util.Date())
                            .expirationTime(java.util.Date.from(Instant.now().plusSeconds(300)))
                            .claim("nonce", nonce)
                            .build()
            );
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign proof JWT", e);
        }
    }

    private List<MockIssuerService.ClaimInput> defaultClaims(String configurationId) {
        MockIssuerProperties.CredentialConfiguration cfg = resolveConfiguration(configurationId);
        List<MockIssuerService.ClaimInput> defaults = new ArrayList<>();
        for (MockIssuerProperties.ClaimTemplate template : cfg.claims()) {
            if (template.defaultValue() != null && !template.defaultValue().isBlank()) {
                defaults.add(new MockIssuerService.ClaimInput(template.name(), template.defaultValue()));
            }
        }
        return defaults;
    }
}
