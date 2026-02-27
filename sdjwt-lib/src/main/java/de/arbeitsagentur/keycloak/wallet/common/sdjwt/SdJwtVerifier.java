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
package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.StatusListVerifier;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import de.arbeitsagentur.keycloak.wallet.common.credential.VerificationStepSink;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies SD-JWT credentials including issuer signature, disclosures and optional holder binding.
 */
public class SdJwtVerifier {
    private static final Logger LOG = LoggerFactory.getLogger(SdJwtVerifier.class);
    /** Default maximum age for KB-JWT iat claim to prevent replay attacks (5 minutes) */
    public static final Duration DEFAULT_KB_JWT_MAX_AGE = Duration.ofMinutes(5);
    /** Clock skew tolerance in seconds for timestamp validation */
    private static final long CLOCK_SKEW_SECONDS = 60;

    private final SdJwtParser sdJwtParser;
    private final ObjectMapper objectMapper;
    private final TrustedIssuerResolver trustResolver;
    private final Duration kbJwtMaxAge;
    private final StatusListVerifier statusListVerifier;

    public SdJwtVerifier(ObjectMapper objectMapper, TrustedIssuerResolver trustResolver) {
        this(objectMapper, trustResolver, DEFAULT_KB_JWT_MAX_AGE);
    }

    public SdJwtVerifier(ObjectMapper objectMapper, TrustedIssuerResolver trustResolver, Duration kbJwtMaxAge) {
        this(objectMapper, trustResolver, kbJwtMaxAge, new StatusListVerifier());
    }

    public SdJwtVerifier(ObjectMapper objectMapper, TrustedIssuerResolver trustResolver, Duration kbJwtMaxAge,
                          StatusListVerifier statusListVerifier) {
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.objectMapper = objectMapper;
        this.trustResolver = trustResolver;
        this.kbJwtMaxAge = kbJwtMaxAge != null ? kbJwtMaxAge : DEFAULT_KB_JWT_MAX_AGE;
        this.statusListVerifier = statusListVerifier;
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
        LOG.debug("verify() called with: trustListId={}, expectedAudience={}, expectedNonce={}",
                trustListId, expectedAudience, expectedNonce);
        SdJwtUtils.SdJwtParts parts = sdJwtParser.split(sdJwt);
        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        validateSdJwtType(jwt);
        if (steps != null) {
            steps.add("Parsed SD-JWT presentation",
                    "Parsed SD-JWT based presentation and prepared for signature/disclosure checks.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
        }
        if (!trustResolver.verify(jwt, trustListId)) {
            LOG.debug("Signature verification failed against trust list");
            throw new IllegalStateException("Credential signature not trusted");
        }
        LOG.debug("Signature verified successfully");
        if (steps != null) {
            steps.add("Signature verified against trust list",
                    "Checked JWT/SD-JWT signature against trusted issuers in the trust list.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
        }
        // Check revocation status via Token Status List
        checkRevocationStatus(jwt, steps);
        validateTimestamps(jwt);
        validateAudienceAndNonceLenient(jwt, expectedAudience, expectedNonce);
        boolean disclosuresValid = SdJwtUtils.verifyDisclosures(jwt, parts, objectMapper);
        if (!disclosuresValid) {
            throw new IllegalStateException("Credential signature not trusted");
        }
        if (steps != null) {
            steps.add("Disclosures validated",
                    "Validated selective disclosure digests against presented disclosures.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
        }
        Map<String, Object> claims = new LinkedHashMap<>(SdJwtUtils.extractDisclosedClaims(parts, objectMapper));
        String embeddedKeyBinding = parts.keyBindingJwt();
        String effectiveKeyBinding = embeddedKeyBinding != null && !embeddedKeyBinding.isBlank()
                ? embeddedKeyBinding
                : keyBindingJwt;
        if (embeddedKeyBinding != null && keyBindingJwt != null
                && !embeddedKeyBinding.isBlank()
                && !keyBindingJwt.isBlank()
                && !Objects.equals(embeddedKeyBinding, keyBindingJwt)) {
            throw new IllegalStateException("Key binding JWT mismatch");
        }
        if (effectiveKeyBinding != null && !effectiveKeyBinding.isBlank()) {
            verifyHolderBinding(effectiveKeyBinding, parts, expectedAudience, expectedNonce);
            if (steps != null) {
                steps.add("Validated holder binding",
                        "Validated KB-JWT holder binding: cnf key matches credential and signature verified.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            }
            claims.put("key_binding_jwt", effectiveKeyBinding);
        }
        return claims;
    }

    public void verifyHolderBinding(String keyBindingJwt,
                                    SdJwtUtils.SdJwtParts presentationParts,
                                    String expectedAudience,
                                    String expectedNonce) throws Exception {
        validateHolderBindingInputs(keyBindingJwt, presentationParts);

        SignedJWT holderBinding = SignedJWT.parse(keyBindingJwt);
        validateKeyBindingType(holderBinding);

        verifyHolderBindingSignature(holderBinding, presentationParts.signedJwt());
        validateKeyBindingTimestamps(holderBinding);
        validateKeyBindingAudienceAndNonce(holderBinding, expectedAudience, expectedNonce);
        validateSdHash(holderBinding, presentationParts);
    }

    private void validateHolderBindingInputs(String keyBindingJwt, SdJwtUtils.SdJwtParts parts) {
        if (keyBindingJwt == null || keyBindingJwt.isBlank()) {
            throw new IllegalStateException("Missing key binding JWT");
        }
        if (parts == null || parts.signedJwt() == null || parts.signedJwt().isBlank()) {
            throw new IllegalStateException("Missing SD-JWT");
        }
    }

    private void verifyHolderBindingSignature(SignedJWT holderBinding, String credentialJwt) throws Exception {
        PublicKey credentialKey = extractHolderKey(credentialJwt);
        if (credentialKey == null) {
            throw new IllegalStateException("SD-JWT does not contain a holder binding key (cnf)");
        }
        if (!TrustedIssuerResolver.verifyWithKey(holderBinding, credentialKey)) {
            throw new IllegalStateException("Holder binding signature invalid");
        }
    }

    private void validateKeyBindingTimestamps(SignedJWT holderBinding) throws Exception {
        var claims = holderBinding.getJWTClaimsSet();
        if (claims.getIssueTime() == null) {
            throw new IllegalStateException("Presentation missing iat");
        }
        Instant issuedAt = claims.getIssueTime().toInstant();
        Instant now = Instant.now();
        // Allow small clock skew (60 seconds) for iat in the future
        if (issuedAt.isAfter(now.plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new IllegalStateException("Presentation iat is in the future");
        }
        if (issuedAt.plus(kbJwtMaxAge).isBefore(now)) {
            throw new IllegalStateException("Presentation too old (iat exceeds max age of " + kbJwtMaxAge.toSeconds() + "s)");
        }
        if (claims.getExpirationTime() != null && claims.getExpirationTime().toInstant().isBefore(now)) {
            throw new IllegalStateException("Presentation has expired");
        }
        if (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().toInstant().isAfter(now)) {
            throw new IllegalStateException("Presentation not yet valid");
        }
    }

    private void validateKeyBindingAudienceAndNonce(SignedJWT holderBinding,
                                                    String expectedAudience,
                                                    String expectedNonce) throws Exception {
        var claims = holderBinding.getJWTClaimsSet();

        if (expectedAudience == null || expectedAudience.isBlank()) {
            throw new IllegalStateException("Expected audience missing");
        }
        if (claims.getAudience() == null || claims.getAudience().isEmpty()) {
            throw new IllegalStateException("Presentation missing aud");
        }
        String aud = claims.getAudience().get(0);
        if (!expectedAudience.equals(aud)) {
            LOG.error("Audience mismatch: expected='{}', actual='{}'", expectedAudience, aud);
            throw new IllegalStateException("Audience mismatch in presentation: expected='" + expectedAudience + "', actual='" + aud + "'");
        }

        if (expectedNonce == null || expectedNonce.isBlank()) {
            throw new IllegalStateException("Expected nonce missing");
        }
        String nonce = claims.getStringClaim("nonce");
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalStateException("Presentation missing nonce");
        }
        if (!expectedNonce.equals(nonce)) {
            throw new IllegalStateException("Nonce mismatch in presentation");
        }
    }

    private void validateSdHash(SignedJWT holderBinding, SdJwtUtils.SdJwtParts parts) throws Exception {
        String sdHash = holderBinding.getJWTClaimsSet().getStringClaim("sd_hash");
        if (sdHash == null || sdHash.isBlank()) {
            throw new IllegalStateException("Presentation missing sd_hash");
        }
        String expectedSdHash = SdJwtUtils.computeSdHash(parts, objectMapper);
        if (expectedSdHash == null || !expectedSdHash.equals(sdHash)) {
            throw new IllegalStateException("sd_hash mismatch in presentation");
        }
    }

    public void verifyHolderBinding(String keyBindingJwt,
                                    String credentialToken,
                                    String expectedAudience,
                                    String expectedNonce) throws Exception {
        if (isSdJwt(credentialToken)) {
            verifyHolderBinding(keyBindingJwt, sdJwtParser.split(credentialToken), expectedAudience, expectedNonce);
            return;
        }
        if (keyBindingJwt == null || keyBindingJwt.isBlank()) {
            return;
        }
        SignedJWT holderBinding = SignedJWT.parse(keyBindingJwt);
        verifyHolderBindingSignatureForPlainJwt(holderBinding, credentialToken);
        validateTimestamps(holderBinding);
        validateAudienceAndNonceLenient(holderBinding, expectedAudience, expectedNonce);
    }

    private void verifyHolderBindingSignatureForPlainJwt(SignedJWT holderBinding, String credentialToken) throws Exception {
        PublicKey credentialKey = extractHolderKey(credentialToken);
        PublicKey kbKey = parsePublicJwk(holderBinding.getJWTClaimsSet().getJSONObjectClaim("cnf"));

        if (credentialKey != null && kbKey != null && !keysMatch(credentialKey, kbKey)) {
            throw new IllegalStateException("Holder binding key does not match credential cnf");
        }

        PublicKey keyToUse = credentialKey != null ? credentialKey : kbKey;
        if (keyToUse == null || !TrustedIssuerResolver.verifyWithKey(holderBinding, keyToUse)) {
            throw new IllegalStateException("Holder binding signature invalid");
        }
    }

    private void checkRevocationStatus(SignedJWT jwt, VerificationStepSink steps) {
        try {
            byte[] payload = Base64.getUrlDecoder().decode(jwt.getParsedString().split("\\.")[1]);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) objectMapper.readValue(payload, Map.class);
            statusListVerifier.checkRevocationStatus(claims);
            if (steps != null) {
                steps.add("Revocation status checked",
                        "Verified credential has not been revoked via Token Status List.",
                        "https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/");
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            LOG.info("[SD-JWT] Could not check revocation status (non-fatal): {}", e.getMessage());
            LOG.debug("[SD-JWT] Revocation check error details:", e);
        }
    }

    private void validateTimestamps(SignedJWT jwt) throws Exception {
        var claims = jwt.getJWTClaimsSet();
        Instant now = Instant.now();
        if (claims.getExpirationTime() != null && claims.getExpirationTime().toInstant().isBefore(now)) {
            throw new IllegalStateException("Presentation has expired");
        }
        if (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().toInstant().isAfter(now)) {
            throw new IllegalStateException("Presentation not yet valid");
        }
    }

    private void validateAudienceAndNonceLenient(SignedJWT jwt, String expectedAudience, String expectedNonce) throws Exception {
        var claims = jwt.getJWTClaimsSet();
        // Lenient: only check if both expected and actual values are present
        if (expectedAudience != null && claims.getAudience() != null && !claims.getAudience().isEmpty()) {
            String aud = claims.getAudience().get(0);
            if (!expectedAudience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = claims.getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
    }

    private void validateSdJwtType(SignedJWT jwt) {
        if (jwt == null || jwt.getHeader() == null) {
            throw new IllegalStateException("Invalid SD-JWT header");
        }
        JOSEObjectType type = jwt.getHeader().getType();
        if (type == null || type.toString().isBlank()) {
            throw new IllegalStateException("SD-JWT missing typ header");
        }
        String value = type.toString();
        if (!"dc+sd-jwt".equals(value) && !"vc+sd-jwt".equals(value) && !"JWT".equals(value) && !"JWS".equals(value)) {
            throw new IllegalStateException("Invalid SD-JWT typ: " + value);
        }
    }

    private void validateKeyBindingType(SignedJWT jwt) {
        if (jwt == null || jwt.getHeader() == null) {
            throw new IllegalStateException("Invalid key binding header");
        }
        JOSEObjectType type = jwt.getHeader().getType();
        if (type == null || type.toString().isBlank()) {
            throw new IllegalStateException("Key binding JWT missing typ header");
        }
        String value = type.toString();
        if (!"kb+jwt".equals(value)) {
            throw new IllegalStateException("Invalid key binding JWT typ: " + value);
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
