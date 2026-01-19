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
package de.arbeitsagentur.keycloak.oid4vp;

import org.jboss.logging.Logger;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocVerifier;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtVerifier;

import java.net.URI;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Oid4vpVerifierService {
    private static final Logger LOG = Logger.getLogger(Oid4vpVerifierService.class);
    private final ObjectMapper objectMapper;
    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;
    private final Oid4vpTrustListService trustListService;

    public Oid4vpVerifierService(ObjectMapper objectMapper, Oid4vpTrustListService trustListService) {
        this.objectMapper = objectMapper;
        this.trustListService = trustListService;
        this.sdJwtVerifier = new SdJwtVerifier(objectMapper, trustListService);
        this.mdocVerifier = new MdocVerifier(trustListService);
    }

    public VerifiedPresentation verify(String vpToken,
                                String trustListId,
                                String expectedClientId,
                                String expectedNonce,
                                String expectedResponseUri,
                                byte[] expectedJwkThumbprint) throws Exception {
        return verify(vpToken, trustListId, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, false);
    }

    /**
     * Verify a VP token, optionally trusting x5c certificates from the credential.
     *
     * @param trustX5cFromCredential If true, trust x5c certificates embedded in the credential
     *                                rather than requiring them to be in the trust list.
     *                                This is useful for testing but should be used with caution.
     */
    public VerifiedPresentation verify(String vpToken,
                                String trustListId,
                                String expectedClientId,
                                String expectedNonce,
                                String expectedResponseUri,
                                byte[] expectedJwkThumbprint,
                                boolean trustX5cFromCredential) throws Exception {
        String extracted = extractFirstVpToken(vpToken);
        if (extracted == null || extracted.isBlank()) {
            throw new IllegalArgumentException("Missing vp_token");
        }
        String normalized = extracted.trim();
        String expectedDcApiAudience = dcApiAudienceFromResponseUri(expectedResponseUri);

        return verifyCredentialWithAudienceFallback(
                normalized, trustListId, expectedClientId, expectedDcApiAudience,
                expectedNonce, expectedResponseUri, expectedJwkThumbprint);
    }

    /**
     * Core verification logic with audience fallback.
     * Tries expectedClientId first, then falls back to DC API audience if different.
     */
    private VerifiedPresentation verifyCredentialWithAudienceFallback(
            String credential,
            String trustListId,
            String expectedClientId,
            String expectedDcApiAudience,
            String expectedNonce,
            String expectedResponseUri,
            byte[] expectedJwkThumbprint) throws Exception {

        if (sdJwtVerifier.isSdJwt(credential)) {
            return verifySdJwtWithFallback(credential, trustListId, expectedClientId, expectedDcApiAudience, expectedNonce);
        }
        if (mdocVerifier.isMdoc(credential)) {
            return verifyMdocWithFallback(credential, trustListId, expectedClientId, expectedDcApiAudience,
                    expectedNonce, expectedResponseUri, expectedJwkThumbprint);
        }
        throw new IllegalArgumentException("Unsupported credential format");
    }

    private VerifiedPresentation verifySdJwtWithFallback(String credential, String trustListId,
                                                          String primaryAudience, String fallbackAudience,
                                                          String expectedNonce) throws Exception {
        Exception firstError = null;
        try {
            Map<String, Object> claims = sdJwtVerifier.verify(credential, trustListId, primaryAudience, expectedNonce, null, null);
            return new VerifiedPresentation(PresentationType.SD_JWT, claims);
        } catch (Exception e) {
            firstError = e;
        }

        if (shouldTryFallbackAudience(primaryAudience, fallbackAudience)) {
            try {
                Map<String, Object> claims = sdJwtVerifier.verify(credential, trustListId, fallbackAudience, expectedNonce, null, null);
                return new VerifiedPresentation(PresentationType.SD_JWT, claims);
            } catch (Exception e) {
                e.addSuppressed(firstError);
                throw e;
            }
        }
        throw firstError;
    }

    private VerifiedPresentation verifyMdocWithFallback(String credential, String trustListId,
                                                         String primaryAudience, String fallbackAudience,
                                                         String expectedNonce, String expectedResponseUri,
                                                         byte[] expectedJwkThumbprint) {
        LOG.debugf("Detected mDoc format: primaryAudience=%s, expectedNonce=%s, expectedResponseUri=%s, fallbackAudience=%s",
                primaryAudience, expectedNonce, expectedResponseUri, fallbackAudience);

        RuntimeException firstError = null;
        try {
            Map<String, Object> claims = mdocVerifier.verify(credential, trustListId, primaryAudience,
                    expectedNonce, expectedResponseUri, expectedJwkThumbprint, null);
            return new VerifiedPresentation(PresentationType.MDOC, claims);
        } catch (RuntimeException e) {
            LOG.debugf("First mDoc verification attempt failed: %s", e.getMessage());
            firstError = e;
        }

        if (shouldTryFallbackAudience(primaryAudience, fallbackAudience)) {
            LOG.debugf("Retrying mDoc verification with fallback audience: %s", fallbackAudience);
            try {
                Map<String, Object> claims = mdocVerifier.verify(credential, trustListId, fallbackAudience,
                        expectedNonce, expectedResponseUri, expectedJwkThumbprint, null);
                return new VerifiedPresentation(PresentationType.MDOC, claims);
            } catch (RuntimeException e) {
                LOG.debugf("Second mDoc verification attempt also failed: %s", e.getMessage());
                e.addSuppressed(firstError);
                throw e;
            }
        }
        throw firstError;
    }

    private boolean shouldTryFallbackAudience(String primaryAudience, String fallbackAudience) {
        return fallbackAudience != null
                && !fallbackAudience.isBlank()
                && !fallbackAudience.equals(primaryAudience);
    }

    /**
     * Verify a multi-credential VP token containing multiple credentials keyed by credential ID.
     * The vp_token format is: {"credential_id_1": ["credential1"], "credential_id_2": ["credential2"]}
     *
     * @return A map of credential ID to VerifiedPresentation
     */
    public Map<String, VerifiedPresentation> verifyMultiCredential(String vpToken,
                                                                     String trustListId,
                                                                     String expectedClientId,
                                                                     String expectedNonce,
                                                                     String expectedResponseUri,
                                                                     byte[] expectedJwkThumbprint,
                                                                     boolean trustX5cFromCredential) throws Exception {
        LOG.debugf("verifyMultiCredential called: trustX5cFromCredential=%b, trustListId=%s",
                trustX5cFromCredential, trustListId);
        Map<String, VerifiedPresentation> results = new LinkedHashMap<>();

        if (vpToken == null || vpToken.isBlank()) {
            throw new IllegalArgumentException("Missing vp_token");
        }

        String trimmed = vpToken.trim();
        if (!trimmed.startsWith("{")) {
            // Not a JSON object, treat as single credential
            VerifiedPresentation single = verify(vpToken, trustListId, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, trustX5cFromCredential);
            results.put("single", single);
            return results;
        }

        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (!node.isObject()) {
                throw new IllegalArgumentException("vp_token must be a JSON object for multi-credential mode");
            }

            String expectedDcApiAudience = dcApiAudienceFromResponseUri(expectedResponseUri);
            LOG.infof("Verifying multi-credential VP token with %d credentials", node.size());

            for (var entry : node.properties()) {
                VerifiedPresentation verified = verifyCredentialEntry(entry, trustListId, expectedClientId,
                        expectedDcApiAudience, expectedNonce, expectedResponseUri, expectedJwkThumbprint, trustX5cFromCredential);
                if (verified != null) {
                    results.put(entry.getKey(), verified);
                }
            }

            if (results.isEmpty()) {
                throw new IllegalArgumentException("No valid credentials found in vp_token");
            }

            return results;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse multi-credential vp_token: " + e.getMessage(), e);
        }
    }

    private VerifiedPresentation verifyCredentialEntry(Map.Entry<String, JsonNode> entry,
                                                        String trustListId,
                                                        String expectedClientId,
                                                        String expectedDcApiAudience,
                                                        String expectedNonce,
                                                        String expectedResponseUri,
                                                        byte[] expectedJwkThumbprint,
                                                        boolean trustX5cFromCredential) throws Exception {
        String credentialId = entry.getKey();
        JsonNode credentialArray = entry.getValue();

        if (!credentialArray.isArray() || credentialArray.isEmpty()) {
            LOG.warnf("Credential '%s' has invalid format (expected array), skipping", credentialId);
            return null;
        }

        String credential = credentialArray.get(0).asText();
        if (credential == null || credential.isBlank()) {
            LOG.warnf("Credential '%s' is empty, skipping", credentialId);
            return null;
        }

        LOG.infof("Verifying credential '%s' (length: %d)", credentialId, credential.length());

        try {
            VerifiedPresentation verified = verifySingleCredential(credential, trustListId, expectedClientId,
                    expectedDcApiAudience, expectedNonce, expectedResponseUri, expectedJwkThumbprint, trustX5cFromCredential);
            LOG.infof("Credential '%s' verified successfully, type: %s", credentialId, verified.type());
            return verified;
        } catch (Exception e) {
            LOG.errorf("Failed to verify credential '%s': %s", credentialId, e.getMessage());
            throw new IllegalArgumentException("Failed to verify credential '" + credentialId + "': " + e.getMessage(), e);
        }
    }

    /**
     * Verify a single credential string (SD-JWT or mDoc).
     */
    private VerifiedPresentation verifySingleCredential(String credential,
                                                         String trustListId,
                                                         String expectedClientId,
                                                         String expectedDcApiAudience,
                                                         String expectedNonce,
                                                         String expectedResponseUri,
                                                         byte[] expectedJwkThumbprint,
                                                         boolean trustX5cFromCredential) throws Exception {
        String normalized = credential.trim();

        if (trustX5cFromCredential) {
            LOG.debugf("Attempting to register x5c from credential to trust list '%s'", trustListId);
            registerX5cFromCredential(normalized, trustListId);
        }

        return verifyCredentialWithAudienceFallback(
                normalized, trustListId, expectedClientId, expectedDcApiAudience,
                expectedNonce, expectedResponseUri, expectedJwkThumbprint);
    }

    /**
     * Extract x5c certificate from credential and register it to the trust list.
     * This enables trusting self-signed or dynamically issued credentials.
     */
    private void registerX5cFromCredential(String credential, String trustListId) {
        try {
            // Extract the JWT part (before any ~ disclosure separator)
            String jwtPart = credential.contains("~") ? credential.split("~")[0] : credential;

            // Extract the header (first part before the period)
            String[] jwtParts = jwtPart.split("\\.");
            if (jwtParts.length < 2) {
                LOG.debug("Cannot extract x5c: invalid JWT structure");
                return;
            }

            String headerBase64 = jwtParts[0];
            String headerJson = new String(Base64.getUrlDecoder().decode(headerBase64));
            JsonNode header = objectMapper.readTree(headerJson);

            // Check for x5c array in header
            JsonNode x5cNode = header.get("x5c");
            if (x5cNode == null || !x5cNode.isArray() || x5cNode.isEmpty()) {
                LOG.debug("No x5c certificate found in credential header");
                return;
            }

            // Get the first certificate (leaf certificate)
            String certBase64 = x5cNode.get(0).asText();
            if (certBase64 == null || certBase64.isBlank()) {
                LOG.debug("Empty x5c certificate in credential header");
                return;
            }

            // Convert to PEM format and register
            String certPem = "-----BEGIN CERTIFICATE-----\n" + certBase64 + "\n-----END CERTIFICATE-----";
            trustListService.registerCertificate(trustListId, certPem);
            LOG.infof("Registered x5c certificate from credential to trust list '%s'", trustListId);
        } catch (Exception e) {
            LOG.warnf("Failed to extract/register x5c certificate from credential: %s", e.getMessage());
        }
    }

    private String dcApiAudienceFromResponseUri(String responseUri) {
        if (responseUri == null || responseUri.isBlank()) {
            return null;
        }
        URI uri;
        try {
            uri = URI.create(responseUri);
        } catch (Exception e) {
            return null;
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            return null;
        }
        String scheme = uri.getScheme().toLowerCase();
        int port = uri.getPort();
        String host = uri.getHost();
        boolean includePort = port != -1 && !((port == 80 && "http".equals(scheme)) || (port == 443 && "https".equals(scheme)));
        try {
            URI origin = new URI(scheme, null, host, includePort ? port : -1, "/", null, null);
            return "origin:" + origin.toString();
        } catch (Exception e) {
            String origin = includePort ? "%s://%s:%d".formatted(scheme, host, port) : "%s://%s".formatted(scheme, host);
            return "origin:" + origin + "/";
        }
    }

    private String extractFirstVpToken(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                JsonNode node = objectMapper.readTree(trimmed);
                String extracted = extractFirstStringValue(node);
                if (extracted != null) {
                    return extracted;
                }
            } catch (Exception ignored) {
            }
        }
        return trimmed;
    }

    private String extractFirstStringValue(JsonNode node) {
        if (node == null) {
            return null;
        }
        if (node.isTextual()) {
            return node.asText();
        }
        if (node.isArray()) {
            for (JsonNode entry : node) {
                String extracted = extractFirstStringValue(entry);
                if (extracted != null) {
                    return extracted;
                }
            }
            return null;
        }
        if (node.isObject()) {
            for (JsonNode value : node) {
                String extracted = extractFirstStringValue(value);
                if (extracted != null) {
                    return extracted;
                }
            }
        }
        return null;
    }

    public enum PresentationType {
        SD_JWT,
        MDOC
    }

    public record VerifiedPresentation(PresentationType type, Map<String, Object> claims) {
    }
}
