package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.TrustedIssuerResolver;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.VerificationStepSink;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Verifies SD-JWT credentials including issuer signature, disclosures and optional holder binding.
 */
public class SdJwtVerifier {
    private final SdJwtParser sdJwtParser;
    private final ObjectMapper objectMapper;
    private final TrustedIssuerResolver trustResolver;

    public SdJwtVerifier(ObjectMapper objectMapper, TrustedIssuerResolver trustResolver) {
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.objectMapper = objectMapper;
        this.trustResolver = trustResolver;
    }

    public boolean isSdJwt(String token) {
        return sdJwtParser.isSdJwt(token);
    }

    public Map<String, Object> verify(String sdJwt,
                                      String trustListId,
                                      String expectedAudience,
                                      String expectedNonce,
                                      String keyBindingJwt,
                                      VerificationStepSink steps) throws Exception {
        SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwt);
        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        if (steps != null) {
            steps.add("Parsed SD-JWT presentation",
                    "Parsed SD-JWT based presentation and prepared for signature/disclosure checks.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
        }
        if (!trustResolver.verify(jwt, trustListId)) {
            throw new IllegalStateException("Credential signature not trusted");
        }
        if (steps != null) {
            steps.add("Signature verified against trust-list.json",
                    "Checked JWT/SD-JWT signature against trusted issuers in the trust list.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
        }
        validateTimestamps(jwt);
        validateAudienceAndNonce(jwt, expectedAudience, expectedNonce);
        boolean disclosuresValid = SdJwtUtils.verifyDisclosures(jwt, parts, objectMapper);
        if (!disclosuresValid) {
            throw new IllegalStateException("Credential signature not trusted");
        }
        if (steps != null) {
            steps.add("Disclosures validated",
                    "Validated selective disclosure digests against presented disclosures.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
        }
        Map<String, Object> claims = new LinkedHashMap<>(SdJwtUtils.extractDisclosedClaims(parts, objectMapper));
        if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
            verifyHolderBinding(keyBindingJwt, sdJwt, expectedAudience, expectedNonce);
            if (steps != null) {
                steps.add("Validated holder binding",
                        "Validated KB-JWT holder binding: cnf key matches credential and signature verified.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.4");
            }
            claims.put("key_binding_jwt", keyBindingJwt);
        }
        return claims;
    }

    public void verifyHolderBinding(String keyBindingJwt,
                                    String credentialToken,
                                    String expectedAudience,
                                    String expectedNonce) throws Exception {
        if (keyBindingJwt == null || keyBindingJwt.isBlank()) {
            return;
        }
        SignedJWT holderBinding = SignedJWT.parse(keyBindingJwt);
        PublicKey credentialKey = extractHolderKey(credentialToken);
        PublicKey kbKey = parsePublicJwk(holderBinding.getJWTClaimsSet().getJSONObjectClaim("cnf"));
        if (credentialKey != null && kbKey != null && !keysMatch(credentialKey, kbKey)) {
            throw new IllegalStateException("Holder binding key does not match credential cnf");
        }
        PublicKey keyToUse = credentialKey != null ? credentialKey : kbKey;
        if (keyToUse == null || !TrustedIssuerResolver.verifyWithKey(holderBinding, keyToUse)) {
            throw new IllegalStateException("Holder binding signature invalid");
        }
        if (holderBinding.getJWTClaimsSet().getExpirationTime() != null
                && holderBinding.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
            throw new IllegalStateException("Presentation has expired");
        }
        if (holderBinding.getJWTClaimsSet().getNotBeforeTime() != null
                && holderBinding.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            throw new IllegalStateException("Presentation not yet valid");
        }
        if (expectedAudience != null && holderBinding.getJWTClaimsSet().getAudience() != null
                && !holderBinding.getJWTClaimsSet().getAudience().isEmpty()) {
            String aud = holderBinding.getJWTClaimsSet().getAudience().get(0);
            if (!expectedAudience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = holderBinding.getJWTClaimsSet().getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
    }

    private void validateTimestamps(SignedJWT jwt) throws Exception {
        if (jwt.getJWTClaimsSet().getExpirationTime() != null
                && jwt.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
            throw new IllegalStateException("Credential presentation expired");
        }
        if (jwt.getJWTClaimsSet().getNotBeforeTime() != null
                && jwt.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            throw new IllegalStateException("Credential presentation not yet valid");
        }
    }

    private void validateAudienceAndNonce(SignedJWT jwt, String expectedAudience, String expectedNonce) throws Exception {
        if (expectedAudience != null && jwt.getJWTClaimsSet().getAudience() != null
                && !jwt.getJWTClaimsSet().getAudience().isEmpty()) {
            String aud = jwt.getJWTClaimsSet().getAudience().get(0);
            if (!expectedAudience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = jwt.getJWTClaimsSet().getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
    }

    private PublicKey extractHolderKey(String token) {
        try {
            String candidate = isSdJwt(token) ? sdJwtParser.signedJwt(token) : token;
            if (candidate == null || !candidate.contains(".")) {
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
            JWK parsed = JWK.parse(jwk.toString());
            if (parsed instanceof ECKey ecKey) {
                return ecKey.toECPublicKey();
            }
            if (parsed instanceof RSAKey rsaKey) {
                return rsaKey.toRSAPublicKey();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private PublicKey parsePublicJwk(Map<String, Object> jwkObj) {
        if (jwkObj == null || jwkObj.isEmpty()) {
            return null;
        }
        try {
            Object candidate = jwkObj.containsKey("jwk") ? jwkObj.get("jwk") : jwkObj;
            if (!(candidate instanceof Map<?, ?> map)) {
                return null;
            }
            Map<String, Object> normalized = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    normalized.put(entry.getKey().toString(), entry.getValue());
                }
            }
            JWK parsed = JWK.parse(normalized);
            if (parsed instanceof ECKey ecKey) {
                return ecKey.toECPublicKey();
            }
            if (parsed instanceof RSAKey rsaKey) {
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
        byte[] leftBytes = left.getEncoded();
        byte[] rightBytes = right.getEncoded();
        return Arrays.equals(leftBytes, rightBytes);
    }
}
