package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps.StepDetail;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class PresentationVerificationService {
    private final TrustListService trustListService;
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;
    private final VerifierKeyService verifierKeyService;

    public PresentationVerificationService(TrustListService trustListService,
                                           VerifierProperties properties,
                                           ObjectMapper objectMapper,
                                           VerifierKeyService verifierKeyService) {
        this.trustListService = trustListService;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.verifierKeyService = verifierKeyService;
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
            if (expectedNonce != null && !expectedNonce.equals(envelope.nonce())) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
            if (envelope.audience() != null && !audience.equals(envelope.audience())) {
                throw new IllegalStateException("Audience mismatch in presentation");
            }
            decryptedToken = envelope.innerToken();
            steps.add("Validated holder binding envelope (audience/nonce)",
                    "Validated KB-JWT holder binding: cnf key matches credential and signature verified.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.4");
        } else if (expectedNonce != null && responseNonce != null && !expectedNonce.equals(responseNonce)) {
            throw new IllegalStateException("Nonce mismatch in presentation");
        }

        if (decryptedToken.contains("~")) {
            SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(decryptedToken);
            SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
            steps.add("Parsed SD-JWT presentation",
                    "Parsed SD-JWT based presentation and prepared for signature/disclosure checks.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            if (!trustListService.verify(jwt, trustListId)) {
                throw new IllegalStateException("Credential signature not trusted");
            }
            steps.add("Signature verified against trust-list.json",
                    "Checked JWT/SD-JWT signature against trusted issuers in the trust list.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
            boolean disclosuresValid;
            try {
                disclosuresValid = SdJwtUtils.verifyDisclosures(jwt, parts, objectMapper);
            } catch (Exception e) {
                throw new IllegalStateException("Credential signature not trusted", e);
            }
            if (!disclosuresValid) {
                throw new IllegalStateException("Credential signature not trusted");
            }
            steps.add("Disclosures validated",
                    "Validated selective disclosure digests against presented disclosures.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
            Map<String, Object> claims = new java.util.LinkedHashMap<>(SdJwtUtils.extractDisclosedClaims(parts, objectMapper));
            if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
                claims.put("key_binding_jwt", keyBindingJwt);
            }
            return claims;
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
        Map<String, Object> claims = new java.util.LinkedHashMap<>(jwt.getJWTClaimsSet().getClaims());
        if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
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
            String innerToken = inner.asText();
            PublicKey credentialKey = extractHolderKey(innerToken);
            if (credentialKey == null) {
                return null;
            }
            PublicKey kbKey = parsePublicJwk(claims.path("cnf").path("jwk"));
            if (kbKey == null) {
                throw new IllegalStateException("Holder binding KB-JWT missing cnf.jwk");
            }
            if (!keysMatch(credentialKey, kbKey)) {
                throw new IllegalStateException("Holder binding key does not match credential cnf");
            }
            if (!TrustListService.verifyWithKey(outer, kbKey)) {
                throw new IllegalStateException("Holder binding signature invalid");
            }
            if (outer.getJWTClaimsSet().getExpirationTime() != null
                    && outer.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
                throw new IllegalStateException("Presentation has expired");
            }
            if (outer.getJWTClaimsSet().getNotBeforeTime() != null
                    && outer.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
                throw new IllegalStateException("Presentation not yet valid");
            }
            String nonce = claims.path("nonce").asText(null);
            String aud = null;
            if (outer.getJWTClaimsSet().getAudience() != null && !outer.getJWTClaimsSet().getAudience().isEmpty()) {
                aud = outer.getJWTClaimsSet().getAudience().get(0);
            }
            return new Envelope(innerToken, nonce, aud, token);
        } catch (java.text.ParseException e) {
            return null;
        } catch (Exception e) {
            throw new IllegalStateException("Credential signature not trusted", e);
        }
    }

    private java.security.PublicKey extractHolderKey(String sdJwt) {
        try {
            String candidate = sdJwt;
            if (candidate.contains("~")) {
                candidate = candidate.split("~")[0];
            }
            if (!candidate.contains(".")) {
                return null;
            }
            String[] parts = candidate.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            JsonNode jwk = node.path("cnf").path("jwk");
            if (jwk.isMissingNode()) {
                return null;
            }
            com.nimbusds.jose.jwk.JWK parsed = com.nimbusds.jose.jwk.JWK.parse(jwk.toString());
            if (parsed instanceof com.nimbusds.jose.jwk.ECKey ecKey) {
                return ecKey.toECPublicKey();
            }
            if (parsed instanceof com.nimbusds.jose.jwk.RSAKey rsaKey) {
                return rsaKey.toRSAPublicKey();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private PublicKey parsePublicJwk(JsonNode jwkNode) {
        if (jwkNode == null || jwkNode.isMissingNode() || jwkNode.isNull()) {
            return null;
        }
        try {
            com.nimbusds.jose.jwk.JWK parsed = com.nimbusds.jose.jwk.JWK.parse(jwkNode.toString());
            if (parsed instanceof com.nimbusds.jose.jwk.ECKey ecKey) {
                return ecKey.toECPublicKey();
            }
            if (parsed instanceof com.nimbusds.jose.jwk.RSAKey rsaKey) {
                return rsaKey.toRSAPublicKey();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean keysMatch(PublicKey left, PublicKey right) {
        if (left == null || right == null) {
            return false;
        }
        return Arrays.equals(left.getEncoded(), right.getEncoded());
    }

    public record Envelope(String innerToken, String nonce, String audience, String kbJwt) {
    }
}
