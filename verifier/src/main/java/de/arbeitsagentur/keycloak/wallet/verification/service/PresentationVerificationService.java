package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocVerifier;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtVerifier;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.text.ParseException;

@Service
public class PresentationVerificationService {
    private final TrustListService trustListService;
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;
    private final VerifierKeyService verifierKeyService;
    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;

    public PresentationVerificationService(TrustListService trustListService,
                                           VerifierProperties properties,
                                           ObjectMapper objectMapper,
                                           VerifierKeyService verifierKeyService) {
        this.trustListService = trustListService;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.verifierKeyService = verifierKeyService;
        this.sdJwtVerifier = new SdJwtVerifier(objectMapper, trustListService);
        this.mdocVerifier = new MdocVerifier(trustListService);
    }

    public List<Map<String, Object>> verifyPresentations(List<String> vpTokens,
                                                         String expectedNonce,
                                                         String responseNonce,
                                                         String trustListId,
                                                         String expectedAudience,
                                                         VerificationSteps steps) throws Exception {
        List<Map<String, Object>> payloads = new ArrayList<>();
        int index = 0;
        for (String token : vpTokens) {
            steps.add("Validating vp_token " + (++index),
                    "Start processing the vp_token and verify trust, audience, nonce, and timing.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            payloads.add(verifySinglePresentation(token, expectedNonce, responseNonce, trustListId, expectedAudience, steps));
        }
        return payloads;
    }

    public Map<String, Object> verifySinglePresentation(String vpToken,
                                                        String expectedNonce,
                                                        String responseNonce,
                                                        String trustListId,
                                                        String expectedAudience,
                                                        VerificationSteps steps) throws Exception {
        String audience = expectedAudience != null && !expectedAudience.isBlank()
                ? expectedAudience
                : properties.clientId();
        String decryptedToken = decryptIfEncrypted(vpToken, steps);
        Envelope envelope = unwrapEnvelope(decryptedToken);
        String keyBindingJwt = envelope != null ? envelope.kbJwt() : null;
        if (envelope != null) {
            decryptedToken = envelope.innerToken();
        } else if (expectedNonce != null && responseNonce != null && !expectedNonce.equals(responseNonce)) {
            throw new IllegalStateException("Nonce mismatch in presentation");
        }

        if (sdJwtVerifier.isSdJwt(decryptedToken)) {
            return sdJwtVerifier.verify(decryptedToken, trustListId, audience, expectedNonce, keyBindingJwt, steps);
        }
        if (mdocVerifier.isMdoc(decryptedToken)) {
            return mdocVerifier.verify(decryptedToken, trustListId, keyBindingJwt, audience, expectedNonce, steps);
        }

        SignedJWT jwt = SignedJWT.parse(decryptedToken);
        steps.add("Parsed JWT presentation",
                "Parsed JWT based presentation and prepared for trust and claim validation.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
        if (!trustListService.verify(jwt, trustListId)) {
            throw new IllegalStateException("Credential signature not trusted");
        }
        steps.add("Signature verified against trust-list.json",
                "Checked JWT/SD-JWT signature against trusted issuers in the trust list.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
        if (jwt.getJWTClaimsSet().getExpirationTime() != null
                && jwt.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
            throw new IllegalStateException("Credential presentation expired");
        }
        if (jwt.getJWTClaimsSet().getNotBeforeTime() != null
                && jwt.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            throw new IllegalStateException("Credential presentation not yet valid");
        }
        if (jwt.getJWTClaimsSet().getAudience() != null && !jwt.getJWTClaimsSet().getAudience().isEmpty()) {
            String aud = jwt.getJWTClaimsSet().getAudience().get(0);
            if (!audience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = jwt.getJWTClaimsSet().getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
        steps.add("Nonce and audience matched verifier session",
                "Validated presentation audience and nonce against verifier session.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1.2");
        steps.add("Credential timing rules validated",
                "Checked exp/nbf timestamps to ensure presentation is currently valid.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1.2");
        Map<String, Object> claims = new LinkedHashMap<>(jwt.getJWTClaimsSet().getClaims());
        if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
            sdJwtVerifier.verifyHolderBinding(keyBindingJwt, decryptedToken, audience, expectedNonce);
            steps.add("Validated holder binding",
                    "Validated KB-JWT holder binding: cnf key matches credential and signature verified.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.4");
            claims.put("key_binding_jwt", keyBindingJwt);
        }
        return claims;
    }

    private String decryptIfEncrypted(String vpToken, VerificationSteps steps) {
        if (vpToken == null) {
            return null;
        }
        if (vpToken.chars().filter(c -> c == '.').count() == 4) {
            steps.add("Decrypting encrypted vp_token",
                    "vp_token was JWE-encrypted; decrypted with verifier private key.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3");
            return verifierKeyService.decrypt(vpToken);
        }
        return vpToken;
    }

    Envelope unwrapEnvelope(String token) {
        try {
            SignedJWT outer = SignedJWT.parse(token);
            JsonNode claims = objectMapper.readTree(outer.getPayload().toString());
            JsonNode inner = claims.get("vp_token");
            if (inner == null || inner.asText().isBlank()) {
                return null;
            }
            return new Envelope(inner.asText(), claims.path("nonce").asText(null), firstAudience(outer), token);
        } catch (ParseException e) {
            return null;
        } catch (Exception e) {
            throw new IllegalStateException("Credential signature not trusted", e);
        }
    }

    private String firstAudience(SignedJWT outer) throws ParseException {
        if (outer.getJWTClaimsSet().getAudience() != null && !outer.getJWTClaimsSet().getAudience().isEmpty()) {
            return outer.getJWTClaimsSet().getAudience().get(0);
        }
        return null;
    }

    public record Envelope(String innerToken, String nonce, String audience, String kbJwt) {
    }
}
