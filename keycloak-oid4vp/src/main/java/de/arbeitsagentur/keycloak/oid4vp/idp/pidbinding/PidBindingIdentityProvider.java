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
package de.arbeitsagentur.keycloak.oid4vp.idp.pidbinding;

import de.arbeitsagentur.keycloak.oid4vp.CredentialClaimsExtractor;
import de.arbeitsagentur.keycloak.oid4vp.FederatedIdentityKeyGenerator;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpDcApiRequestObjectService;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpTrustListService;
import de.arbeitsagentur.keycloak.oid4vp.VpTokenVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProvider;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderConfig;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * German PID Binding Identity Provider.
 * <p>
 * Implements a two-phase authentication flow for German PID credentials:
 * <ol>
 *   <li><b>First login</b>: User presents PID only → authenticate with username/password → issue ba-login-credential</li>
 *   <li><b>Subsequent logins</b>: User presents PID + ba-login-credential → direct login using ba-login-credential's user_id</li>
 * </ol>
 * <p>
 * The key insight is that German PID has no claim suitable as a persistent unique subject identifier.
 * Instead, we issue a "ba-login-credential" containing the Keycloak user ID, which becomes the
 * federated identity anchor for subsequent logins.
 * <p>
 * <b>Re-binding flow</b>: If a returning user presents only PID (lost their ba-login-credential),
 * they go through the first-login flow again: verify identity with username/password, then issue a new credential.
 */
public class PidBindingIdentityProvider extends Oid4vpIdentityProvider {

    private static final Logger LOG = Logger.getLogger(PidBindingIdentityProvider.class);

    // Session notes for PID binding flow
    public static final String SESSION_NEEDS_CREDENTIAL_ISSUANCE = "pid_binding_needs_credential_issuance";
    public static final String SESSION_CREDENTIAL_OFFER_URI = "pid_binding_credential_offer_uri";
    public static final String SESSION_PID_CLAIMS = "pid_binding_pid_claims";
    public static final String SESSION_CREDENTIAL_USER_ID = "pid_binding_credential_user_id";
    public static final String SESSION_IDP_ALIAS = "pid_binding_idp_alias";

    // Session notes from parent class (package-private access)
    private static final String SESSION_STATE = "oid4vp_state";
    private static final String SESSION_NONCE = "oid4vp_nonce";
    private static final String SESSION_RESPONSE_URI = "oid4vp_response_uri";
    private static final String SESSION_REDIRECT_FLOW_RESPONSE_URI = "oid4vp_redirect_flow_response_uri";
    private static final String SESSION_ENCRYPTION_KEY = "oid4vp_encryption_key";
    private static final String SESSION_EFFECTIVE_CLIENT_ID = "oid4vp_effective_client_id";

    private final PidBindingIdentityProviderConfig pidBindingConfig;
    private final Oid4vpDcApiRequestObjectService dcApiRequestObjectService;

    public PidBindingIdentityProvider(KeycloakSession session,
                                       PidBindingIdentityProviderConfig config,
                                       ObjectMapper objectMapper,
                                       Oid4vpTrustListService trustListService) {
        super(session, config, objectMapper, trustListService);
        this.pidBindingConfig = config;
        this.dcApiRequestObjectService = new Oid4vpDcApiRequestObjectService(session, objectMapper);
    }

    /**
     * Get the PID binding specific config.
     */
    @Override
    public PidBindingIdentityProviderConfig getConfig() {
        return pidBindingConfig;
    }

    /**
     * Build the DCQL query for this authentication request.
     * <p>
     * The DCQL requests both PID and ba-login-credential, with the following credential_sets:
     * <ul>
     *   <li>Option 1: Both PID and ba-login-credential (preferred for returning users)</li>
     *   <li>Option 2: PID only (fallback for first-time users)</li>
     * </ul>
     * <p>
     * This allows wallets to present whatever they have while we detect the flow type.
     */
    private static final String CRED_ID_PID = "german_pid";
    private static final String CRED_ID_LOGIN = "ba_login_credential";

    @Override
    protected String buildDcqlQueryFromConfig() {
        String manualDcql = pidBindingConfig.getDcqlQuery();
        if (manualDcql != null && !manualDcql.isBlank()) {
            LOG.infof("[PID-BINDING] Using explicit DCQL query from config");
            return manualDcql;
        }

        try {
            Map<String, Object> dcqlQuery = new LinkedHashMap<>();
            dcqlQuery.put("credentials", List.of(
                    buildPidCredentialEntry(),
                    buildLoginCredentialEntry()
            ));
            dcqlQuery.put("credential_sets", List.of(Map.of(
                    "purpose", "Login with German eID",
                    "options", List.of(
                            List.of(CRED_ID_PID, CRED_ID_LOGIN),  // Preferred: both
                            List.of(CRED_ID_PID)                   // Fallback: PID only
                    )
            )));

            String dcql = objectMapper.writeValueAsString(dcqlQuery);
            LOG.infof("[PID-BINDING] Built DCQL query: %s", dcql);
            return dcql;
        } catch (Exception e) {
            LOG.errorf(e, "[PID-BINDING] Failed to build DCQL query, using fallback");
            return buildFallbackDcql();
        }
    }

    private Map<String, Object> buildPidCredentialEntry() {
        List<Map<String, Object>> claims = pidBindingConfig.getPidRequestedClaimsList().stream()
                .map(claim -> Map.<String, Object>of("path", List.of(claim)))
                .toList();
        return Map.of(
                "id", CRED_ID_PID,
                "format", Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                "meta", Map.of("vct_values", List.of(pidBindingConfig.getPidCredentialType())),
                "claims", claims
        );
    }

    private Map<String, Object> buildLoginCredentialEntry() {
        return Map.of(
                "id", CRED_ID_LOGIN,
                "format", Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                "meta", Map.of("vct_values", List.of(pidBindingConfig.getLoginCredentialType())),
                "claims", List.of(
                        Map.of("path", List.of("user_id")),
                        Map.of("path", List.of("linked_at"))
                )
        );
    }

    private String buildFallbackDcql() {
        return "{\"credentials\":[{\"id\":\"german_pid\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"" +
                pidBindingConfig.getPidCredentialType() + "\"]},\"claims\":[{\"path\":[\"given_name\"]},{\"path\":[\"family_name\"]},{\"path\":[\"birthdate\"]}]}]}";
    }

    /**
     * Process the callback from the wallet.
     * <p>
     * This method handles VP token verification and determines the flow type:
     * <ul>
     *   <li>PID + ba-login-credential with user_id → Returning user flow (direct login)</li>
     *   <li>PID only → First login flow (requires username/password authentication)</li>
     * </ul>
     * <p>
     * Unlike the parent class, this method does NOT require a subject claim for first-time users.
     */
    @Override
    public BrokeredIdentityContext processCallback(AuthenticationSessionModel authSession,
                                                    String state,
                                                    String vpToken,
                                                    String encryptedResponse,
                                                    String error,
                                                    String errorDescription) {
        LOG.infof("[PID-BINDING] ========== processCallback called ==========");

        validateStateAndErrors(authSession, state, error, errorDescription);
        String resolvedVpToken = resolveVpToken(vpToken, encryptedResponse, authSession);
        VpTokenVerificationResult result = verifyVpToken(authSession, resolvedVpToken);

        ExtractedCredentials extracted = extractCredentials(result);
        clearSessionNotes(authSession);

        if (extracted.hasLoginCredential()) {
            return processReturningUser(authSession, extracted.allClaims(), extracted.userId(), extracted.pidClaims());
        } else {
            return processFirstLogin(authSession, extracted.allClaims(), extracted.pidClaims(),
                    extracted.pidIssuer(), extracted.pidType());
        }
    }

    private void validateStateAndErrors(AuthenticationSessionModel authSession, String state,
                                         String error, String errorDescription) {
        String expectedState = authSession.getAuthNote(SESSION_STATE);
        LOG.infof("[PID-BINDING] Expected state: %s, Got: %s", expectedState, state);
        if (expectedState == null || !expectedState.equals(state)) {
            LOG.warnf("[PID-BINDING] State mismatch! Expected: %s, Got: %s", expectedState, state);
            throw new IdentityBrokerException("Invalid state parameter");
        }

        if (error != null && !error.isBlank()) {
            String message = errorDescription != null && !errorDescription.isBlank()
                    ? error + ": " + errorDescription : error;
            LOG.warnf("[PID-BINDING] Wallet returned error: %s", message);
            throw new IdentityBrokerException("Wallet returned error: " + message);
        }
    }

    private String resolveVpToken(String vpToken, String encryptedResponse, AuthenticationSessionModel authSession) {
        if (vpToken != null && !vpToken.isBlank()) {
            return vpToken;
        }
        if (encryptedResponse == null || encryptedResponse.isBlank()) {
            throw new IdentityBrokerException("Missing vp_token");
        }

        LOG.infof("[PID-BINDING] Decrypting encrypted response...");
        String encryptionKey = authSession.getAuthNote(SESSION_ENCRYPTION_KEY);
        try {
            var decrypted = dcApiRequestObjectService.decryptEncryptedResponse(encryptedResponse, encryptionKey);
            JsonNode node = decrypted.payload();
            if (node.hasNonNull("error")) {
                String err = node.get("error").asText("");
                String desc = node.hasNonNull("error_description") ? node.get("error_description").asText("") : "";
                throw new IdentityBrokerException("Wallet error: " + err + (desc.isEmpty() ? "" : " - " + desc));
            }
            if (!node.hasNonNull("vp_token")) {
                throw new IdentityBrokerException("Missing vp_token in encrypted response");
            }
            String resolved = node.get("vp_token").isTextual()
                    ? node.get("vp_token").asText()
                    : node.get("vp_token").toString();
            LOG.infof("[PID-BINDING] Extracted vp_token from encrypted response");
            return resolved;
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            LOG.errorf(e, "[PID-BINDING] Failed to decrypt response: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to decrypt response: " + e.getMessage(), e);
        }
    }

    private VpTokenVerificationResult verifyVpToken(AuthenticationSessionModel authSession, String vpToken) {
        String expectedNonce = authSession.getAuthNote(SESSION_NONCE);
        String responseUri = authSession.getAuthNote(SESSION_RESPONSE_URI);
        String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        String clientId = effectiveClientId != null ? effectiveClientId : computeClientId(authSession);
        byte[] jwkThumbprint = computeJwkThumbprint(authSession.getAuthNote(SESSION_ENCRYPTION_KEY));

        LOG.infof("[PID-BINDING] Verification params - nonce: %s, responseUri: %s, clientId: %s",
                expectedNonce, responseUri, clientId);

        VpTokenVerificationResult result = vpTokenProcessor.process(
                vpToken,
                getConfig().getTrustListId(),
                clientId,
                expectedNonce,
                responseUri,
                jwkThumbprint,
                getConfig().getEffectiveTrustX5cFromCredential(),
                authSession.getAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI)
        );
        LOG.infof("[PID-BINDING] VP verified, format: %s, credentials: %d",
                result.format(), result.credentials().size());
        return result;
    }

    private record ExtractedCredentials(
            Map<String, Object> allClaims,
            String userId,
            Map<String, Object> pidClaims,
            String pidIssuer,
            String pidType
    ) {
        boolean hasLoginCredential() {
            return userId != null && !userId.isBlank();
        }
    }

    private ExtractedCredentials extractCredentials(VpTokenVerificationResult result) {
        Map<String, Object> allClaims = new LinkedHashMap<>(result.mergedClaims());
        String userId = null;
        Map<String, Object> pidClaims = null;
        String pidIssuer = null;
        String pidType = null;

        VpTokenVerificationResult.VerifiedCredential loginCred =
                result.findCredentialByVct(pidBindingConfig.getLoginCredentialType());
        if (loginCred != null) {
            userId = CredentialClaimsExtractor.extractClaim(loginCred.claims(), "user_id");
            LOG.infof("[PID-BINDING] Found ba-login-credential with user_id: %s", userId);
        }

        for (var cred : result.credentials().values()) {
            String vct = CredentialClaimsExtractor.extractClaim(cred.claims(), "vct");
            if (!pidBindingConfig.getLoginCredentialType().equals(vct)) {
                pidClaims = cred.claims();
                pidIssuer = cred.issuer();
                pidType = cred.credentialType();
                LOG.infof("[PID-BINDING] Found PID credential, issuer: %s, type: %s", pidIssuer, pidType);
                break;
            }
        }

        if (pidClaims == null) {
            VpTokenVerificationResult.VerifiedCredential primary = result.getPrimaryCredential();
            if (primary != null) {
                pidClaims = primary.claims();
                pidIssuer = primary.issuer();
                pidType = primary.credentialType();
            }
        }

        LOG.infof("[PID-BINDING] Has ba-login-credential: %b, user_id: %s", userId != null && !userId.isBlank(), userId);
        return new ExtractedCredentials(allClaims, userId, pidClaims, pidIssuer, pidType);
    }

    /**
     * Process returning user flow.
     * The ba-login-credential's user_id is used as the federated identity subject.
     */
    private BrokeredIdentityContext processReturningUser(AuthenticationSessionModel authSession,
                                                          Map<String, Object> allClaims,
                                                          String userId,
                                                          Map<String, Object> pidClaims) {
        LOG.infof("[PID-BINDING] Processing returning user flow with user_id: %s", userId);

        authSession.setAuthNote(SESSION_CREDENTIAL_USER_ID, userId);

        // Get the issuer from the realm URL
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri = baseUri + "/";
        }
        String issuer = baseUri + "realms/" + session.getContext().getRealm().getName();
        String loginCredentialType = pidBindingConfig.getLoginCredentialType();

        // Compute lookup key based on ba-login-credential
        String lookupKey = FederatedIdentityKeyGenerator.computeLookupKey(issuer, loginCredentialType, userId);
        LOG.debugf("[PID-BINDING] Lookup key: issuer=%s, type=%s, userId=%s", issuer, loginCredentialType, userId);

        BrokeredIdentityContext context = new BrokeredIdentityContext(lookupKey, getConfig());
        context.setIdp(this);
        context.setUsername(userId);
        context.setAuthenticationSession(authSession);

        // Store credential metadata
        String credentialMetadata = CredentialClaimsExtractor.buildCredentialMetadataJson(
                issuer, loginCredentialType, userId, "user_id", allClaims, objectMapper);
        context.setToken(credentialMetadata);

        // Map PID claims to user attributes
        mapClaimsToContext(pidClaims != null ? pidClaims : allClaims, context);

        // Store claims for mappers
        context.getContextData().put("oid4vp_claims", allClaims);
        context.getContextData().put("oid4vp_credential_type", loginCredentialType);
        context.getContextData().put("oid4vp_subject", userId);

        LOG.infof("[PID-BINDING] Returning user flow completed: user_id=%s", userId);
        return context;
    }

    /**
     * Process first login flow.
     * <p>
     * For first-time users who only have a PID:
     * <ol>
     *   <li>Create a temporary identity based on PID claims</li>
     *   <li>Mark the session for first-broker-login (username/password authentication)</li>
     *   <li>After authentication, issue a ba-login-credential with the user's ID</li>
     * </ol>
     */
    private BrokeredIdentityContext processFirstLogin(AuthenticationSessionModel authSession,
                                                       Map<String, Object> allClaims,
                                                       Map<String, Object> pidClaims,
                                                       String pidIssuer,
                                                       String pidType) {
        LOG.infof("[PID-BINDING] Processing first login flow (PID only)");

        // Mark the session for first-broker-login flow
        authSession.setAuthNote(SESSION_NEEDS_CREDENTIAL_ISSUANCE, "true");
        // Store IDP alias for use in credential issuance authenticator
        authSession.setAuthNote(SESSION_IDP_ALIAS, getConfig().getAlias());

        // Store PID claims for later use in credential issuance
        try {
            String pidClaimsJson = objectMapper.writeValueAsString(pidClaims != null ? pidClaims : allClaims);
            authSession.setAuthNote(SESSION_PID_CLAIMS, pidClaimsJson);
        } catch (Exception e) {
            LOG.warnf(e, "[PID-BINDING] Failed to serialize PID claims");
        }

        // Generate a temporary subject for the first-broker-login flow
        String tempSubject = generateTemporarySubject(pidClaims != null ? pidClaims : allClaims);
        LOG.infof("[PID-BINDING] Generated temporary subject: %s", tempSubject);

        // Use PID issuer and type for the temporary lookup key
        if (pidIssuer == null || pidIssuer.isBlank()) {
            pidIssuer = "pid-issuer";
        }
        if (pidType == null || pidType.isBlank()) {
            pidType = pidBindingConfig.getPidCredentialType();
        }
        String lookupKey = FederatedIdentityKeyGenerator.computeLookupKey(pidIssuer, pidType, tempSubject);

        // Create context for first-broker-login
        BrokeredIdentityContext context = new BrokeredIdentityContext(lookupKey, getConfig());
        context.setIdp(this);
        context.setUsername(tempSubject);
        context.setAuthenticationSession(authSession);

        // Store context data for first-broker-login flow
        context.getContextData().put("oid4vp_claims", allClaims);
        context.getContextData().put("pid_binding_temp_subject", tempSubject);
        context.getContextData().put("pid_binding_flow", "first_login");
        context.getContextData().put("pid_binding_needs_auth", "true");

        // Map PID claims to user attributes
        mapClaimsToContext(pidClaims != null ? pidClaims : allClaims, context);

        // Build credential offer URI for use after user linking
        String credentialOfferUri = buildCredentialOfferUri();
        if (credentialOfferUri != null) {
            authSession.setAuthNote(SESSION_CREDENTIAL_OFFER_URI, credentialOfferUri);
            LOG.infof("[PID-BINDING] Credential offer URI stored: %s", credentialOfferUri);
        }

        LOG.infof("[PID-BINDING] First login flow initialized - user will be directed to first-broker-login");
        return context;
    }

    /**
     * Generate a temporary subject for first-time users.
     * Combines PID claims with random data for uniqueness.
     */
    private String generateTemporarySubject(Map<String, Object> claims) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(CredentialClaimsExtractor.extractClaim(claims, "given_name"));
            sb.append("|");
            sb.append(CredentialClaimsExtractor.extractClaim(claims, "family_name"));
            sb.append("|");
            sb.append(CredentialClaimsExtractor.extractClaim(claims, "birthdate"));
            sb.append("|");
            sb.append(System.currentTimeMillis());
            sb.append("|");
            sb.append(UUID.randomUUID());

            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "pid-" + Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
        } catch (Exception e) {
            LOG.warnf(e, "[PID-BINDING] Failed to generate temporary subject, using UUID");
            return "pid-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        }
    }

    /**
     * Build the credential offer URI for OID4VCI.
     */
    private String buildCredentialOfferUri() {
        String issuerUrl = pidBindingConfig.getCredentialIssuerUrl();
        if (issuerUrl == null || issuerUrl.isBlank()) {
            issuerUrl = session.getContext().getUri().getBaseUri().toString() +
                    "realms/" + session.getContext().getRealm().getName();
        }

        String configId = pidBindingConfig.getCredentialConfigurationId();
        return issuerUrl + "/protocol/oid4vc/credential-offer?credential_configuration_id=" + configId;
    }

    /**
     * Map claims from the credential to the BrokeredIdentityContext.
     */
    private void mapClaimsToContext(Map<String, Object> claims, BrokeredIdentityContext context) {
        if (claims == null) {
            return;
        }

        String givenName = CredentialClaimsExtractor.extractClaim(claims, "given_name");
        if (givenName != null && !givenName.isBlank()) {
            context.setFirstName(givenName);
        }

        String familyName = CredentialClaimsExtractor.extractClaim(claims, "family_name");
        if (familyName != null && !familyName.isBlank()) {
            context.setLastName(familyName);
        }

        String email = CredentialClaimsExtractor.extractClaim(claims, "email");
        if (email != null && !email.isBlank()) {
            context.setEmail(email);
        }
    }

    /**
     * Compute the client_id for OID4VP verification.
     */
    private String computeClientId(AuthenticationSessionModel authSession) {
        String realmUrl = session.getContext().getUri().getBaseUri().toString() +
                "realms/" + session.getContext().getRealm().getName();
        return realmUrl;
    }

    /**
     * Compute JWK thumbprint for verification.
     */
    private byte[] computeJwkThumbprint(String encryptionKeyJson) {
        if (encryptionKeyJson == null || encryptionKeyJson.isBlank()) {
            return null;
        }
        try {
            com.nimbusds.jose.jwk.JWK jwk = com.nimbusds.jose.jwk.JWK.parse(encryptionKeyJson);
            return jwk.computeThumbprint().decode();
        } catch (Exception e) {
            LOG.warnf(e, "[PID-BINDING] Failed to compute JWK thumbprint");
            return null;
        }
    }

    /**
     * Clear session notes after processing.
     */
    private void clearSessionNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(SESSION_STATE);
        authSession.removeAuthNote(SESSION_NONCE);
        authSession.removeAuthNote(SESSION_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_ENCRYPTION_KEY);
        authSession.removeAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
    }
}
