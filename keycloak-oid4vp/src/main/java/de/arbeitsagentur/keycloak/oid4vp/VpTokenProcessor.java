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
import org.keycloak.broker.provider.IdentityBrokerException;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Processes VP tokens by detecting format, verifying credentials, and extracting claims.
 * Handles both single and multi-credential formats with automatic retry for redirect flows.
 */
public class VpTokenProcessor {

    private static final Logger LOG = Logger.getLogger(VpTokenProcessor.class);

    private final Oid4vpVerifierService verifierService;
    private final ObjectMapper objectMapper;

    public VpTokenProcessor(Oid4vpVerifierService verifierService, ObjectMapper objectMapper) {
        this.verifierService = verifierService;
        this.objectMapper = objectMapper;
    }

    /**
     * Verifies a VP token and extracts all credentials and claims.
     *
     * @param vpToken The VP token to verify
     * @param trustListId Trust list ID for issuer verification
     * @param clientId Client ID for audience verification
     * @param expectedNonce Expected nonce value
     * @param responseUri Response URI for audience verification
     * @param jwkThumbprint JWK thumbprint for key binding (optional)
     * @param trustX5c Whether to trust X.509 certificate chains
     * @param alternateResponseUri Alternative response URI for redirect flow retry (optional)
     * @return Verification result containing all credentials and merged claims
     * @throws IdentityBrokerException if verification fails
     */
    public VpTokenVerificationResult process(
            String vpToken,
            String trustListId,
            String clientId,
            String expectedNonce,
            String responseUri,
            byte[] jwkThumbprint,
            boolean trustX5c,
            String alternateResponseUri) throws IdentityBrokerException {

        VpTokenFormat.Type format = VpTokenFormat.detect(vpToken, objectMapper);
        LOG.debugf("VP token format: %s", format);

        if (format == VpTokenFormat.Type.MULTI_CREDENTIAL) {
            return processMultiCredential(vpToken, trustListId, clientId, expectedNonce,
                    responseUri, jwkThumbprint, trustX5c, alternateResponseUri);
        } else {
            return processSingleCredential(vpToken, trustListId, clientId, expectedNonce,
                    responseUri, jwkThumbprint, trustX5c, alternateResponseUri);
        }
    }

    private VpTokenVerificationResult processMultiCredential(
            String vpToken, String trustListId, String clientId, String expectedNonce,
            String responseUri, byte[] jwkThumbprint, boolean trustX5c, String alternateResponseUri) {

        Map<String, Oid4vpVerifierService.VerifiedPresentation> verified = verifyMultiCredentialWithRetry(
                vpToken, trustListId, clientId, expectedNonce, responseUri, jwkThumbprint, trustX5c, alternateResponseUri);

        Map<String, VpTokenVerificationResult.VerifiedCredential> credentials = new LinkedHashMap<>();
        Map<String, Object> mergedClaims = new LinkedHashMap<>();

        for (var entry : verified.entrySet()) {
            String credentialId = entry.getKey();
            Oid4vpVerifierService.VerifiedPresentation presentation = entry.getValue();

            String issuer = CredentialClaimsExtractor.extractClaim(presentation.claims(), "iss");
            String credentialType = CredentialClaimsExtractor.extractCredentialType(
                    presentation.claims(), presentation.type());

            credentials.put(credentialId, new VpTokenVerificationResult.VerifiedCredential(
                    credentialId,
                    issuer,
                    credentialType,
                    presentation.claims(),
                    presentation.type()
            ));

            mergedClaims.putAll(presentation.claims());
        }

        return new VpTokenVerificationResult(VpTokenFormat.Type.MULTI_CREDENTIAL, credentials, mergedClaims);
    }

    private VpTokenVerificationResult processSingleCredential(
            String vpToken, String trustListId, String clientId, String expectedNonce,
            String responseUri, byte[] jwkThumbprint, boolean trustX5c, String alternateResponseUri) {

        Oid4vpVerifierService.VerifiedPresentation verified = verifySingleCredentialWithRetry(
                vpToken, trustListId, clientId, expectedNonce, responseUri, jwkThumbprint, trustX5c, alternateResponseUri);

        String issuer = CredentialClaimsExtractor.extractClaim(verified.claims(), "iss");
        String credentialType = CredentialClaimsExtractor.extractCredentialType(verified.claims(), verified.type());

        // For mDoc credentials, issuer may not be in claims
        if ((issuer == null || issuer.isBlank()) &&
                verified.type() == Oid4vpVerifierService.PresentationType.MDOC) {
            issuer = "mdoc-trusted-issuer";
        }

        Map<String, VpTokenVerificationResult.VerifiedCredential> credentials = new LinkedHashMap<>();
        credentials.put("primary", new VpTokenVerificationResult.VerifiedCredential(
                "primary",
                issuer,
                credentialType,
                verified.claims(),
                verified.type()
        ));

        return new VpTokenVerificationResult(VpTokenFormat.Type.SINGLE_CREDENTIAL, credentials, verified.claims());
    }

    private Map<String, Oid4vpVerifierService.VerifiedPresentation> verifyMultiCredentialWithRetry(
            String vpToken, String trustListId, String clientId, String expectedNonce,
            String responseUri, byte[] jwkThumbprint, boolean trustX5c, String alternateResponseUri) {

        try {
            return verifierService.verifyMultiCredential(
                    vpToken, trustListId, clientId, expectedNonce, responseUri, jwkThumbprint, trustX5c);
        } catch (Exception e) {
            if (alternateResponseUri != null && !alternateResponseUri.equals(responseUri)) {
                LOG.debugf("Retrying multi-credential verification with alternate response URI");
                try {
                    return verifierService.verifyMultiCredential(
                            vpToken, trustListId, clientId, expectedNonce, alternateResponseUri, jwkThumbprint, trustX5c);
                } catch (Exception e2) {
                    throw new IdentityBrokerException("VP verification failed: " + e2.getMessage(), e2);
                }
            }
            throw new IdentityBrokerException("VP verification failed: " + e.getMessage(), e);
        }
    }

    private Oid4vpVerifierService.VerifiedPresentation verifySingleCredentialWithRetry(
            String vpToken, String trustListId, String clientId, String expectedNonce,
            String responseUri, byte[] jwkThumbprint, boolean trustX5c, String alternateResponseUri) {

        // Extract credential from JSON wrapper if present (e.g., {"pid": ["eyJ..."]})
        String credential = VpTokenFormat.extractSingleCredential(vpToken, objectMapper);

        try {
            return verifierService.verify(
                    credential, trustListId, clientId, expectedNonce, responseUri, jwkThumbprint, trustX5c);
        } catch (Exception e) {
            boolean isSessionTranscriptMismatch = e.getMessage() != null &&
                    (e.getMessage().contains("SessionTranscript mismatch") ||
                            (e.getCause() != null && e.getCause().getMessage() != null &&
                                    e.getCause().getMessage().contains("SessionTranscript mismatch")));

            if (isSessionTranscriptMismatch && alternateResponseUri != null && !alternateResponseUri.equals(responseUri)) {
                LOG.debugf("Retrying single-credential verification with alternate response URI");
                try {
                    return verifierService.verify(
                            credential, trustListId, clientId, expectedNonce, alternateResponseUri, jwkThumbprint, trustX5c);
                } catch (Exception e2) {
                    throw new IdentityBrokerException("VP verification failed: " + e2.getMessage(), e2);
                }
            }
            throw new IdentityBrokerException("VP verification failed: " + e.getMessage(), e);
        }
    }
}
