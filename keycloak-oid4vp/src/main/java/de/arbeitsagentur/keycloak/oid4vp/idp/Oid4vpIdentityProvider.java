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
package de.arbeitsagentur.keycloak.oid4vp.idp;

import com.nimbusds.jose.jwk.JWK;
import de.arbeitsagentur.keycloak.oid4vp.CredentialClaimsExtractor;
import de.arbeitsagentur.keycloak.oid4vp.FederatedIdentityKeyGenerator;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpConfig;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpDcApiRequestObjectService;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpQrCodeService;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpTrustListService;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpVerifierService;
import de.arbeitsagentur.keycloak.oid4vp.VpTokenProcessor;
import de.arbeitsagentur.keycloak.oid4vp.VpTokenVerificationResult;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OID4VP Identity Provider for Keycloak.
 * <p>
 * Enables "Sign in with Wallet" functionality using verifiable credentials.
 * Supports both SD-JWT and mDoc credential formats.
 */
public class Oid4vpIdentityProvider extends AbstractIdentityProvider<Oid4vpIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProvider.class);
    static final String SESSION_STATE = "oid4vp_state";
    static final String SESSION_NONCE = "oid4vp_nonce";
    static final String SESSION_RESPONSE_URI = "oid4vp_response_uri";
    static final String SESSION_REDIRECT_FLOW_RESPONSE_URI = "oid4vp_redirect_flow_response_uri";
    static final String SESSION_ENCRYPTION_KEY = "oid4vp_encryption_key";
    static final String SESSION_CLIENT_ID = "oid4vp_client_id";
    static final String SESSION_REQUEST_OBJECT = "oid4vp_request_object";
    static final String SESSION_EFFECTIVE_CLIENT_ID = "oid4vp_effective_client_id";
    static final String SESSION_MDOC_GENERATED_NONCE = "oid4vp_mdoc_generated_nonce";

    protected final ObjectMapper objectMapper;
    protected final Oid4vpVerifierService verifierService;
    protected final VpTokenProcessor vpTokenProcessor;
    private final Oid4vpDcApiRequestObjectService dcApiRequestObjectService;
    private final Oid4vpRedirectFlowService redirectFlowService;
    private final Oid4vpQrCodeService qrCodeService;
    private final Oid4vpTrustListService trustListService;

    // Shared request object store for redirect flows (same-device and cross-device)
    // Uses Keycloak's SingleUseObjectProvider for cluster-aware storage
    private static final Oid4vpRequestObjectStore REQUEST_OBJECT_STORE = new Oid4vpRequestObjectStore();

    public Oid4vpIdentityProvider(KeycloakSession session,
                                   Oid4vpIdentityProviderConfig config,
                                   ObjectMapper objectMapper,
                                   Oid4vpTrustListService trustListService) {
        super(session, config);
        this.objectMapper = objectMapper;
        this.trustListService = trustListService;
        this.verifierService = new Oid4vpVerifierService(objectMapper, trustListService);
        this.vpTokenProcessor = new VpTokenProcessor(verifierService, objectMapper);
        this.dcApiRequestObjectService = new Oid4vpDcApiRequestObjectService(session, objectMapper);
        this.redirectFlowService = new Oid4vpRedirectFlowService(session, objectMapper);
        this.qrCodeService = new Oid4vpQrCodeService();
    }

    Oid4vpDcApiRequestObjectService getDcApiRequestObjectService() {
        return dcApiRequestObjectService;
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        LOG.infof("[OID4VP-IDP] ========== performLogin called ==========");
        try {
            AuthenticationSessionModel authSession = request.getAuthenticationSession();
            LOG.infof("[OID4VP-IDP] AuthSession: tabId=%s, client=%s, realm=%s",
                    authSession != null ? authSession.getTabId() : "null",
                    authSession != null && authSession.getClient() != null ? authSession.getClient().getClientId() : "null",
                    authSession != null && authSession.getRealm() != null ? authSession.getRealm().getName() : "null");

            // Initialize session state (state, nonce, clientId)
            Oid4vpSessionState sessionState = initializeSessionState(request, authSession);

            // Build DC API request object
            Oid4vpConfig legacyConfig = toLegacyConfig(getConfig());
            String origin = originFromUri(request.getUriInfo().getBaseUri());
            Oid4vpDcApiRequestObjectService.DcApiRequestObject requestObject =
                    buildDcApiRequestObject(authSession, legacyConfig, origin, sessionState);

            // Build redirect flow data (same-device/cross-device URLs)
            boolean dcApiEnabled = getConfig().isDcApiEnabled();
            boolean sameDeviceEnabled = getConfig().isSameDeviceEnabled();
            boolean crossDeviceEnabled = getConfig().isCrossDeviceEnabled();
            LOG.infof("[OID4VP-IDP] Enabled flows - DC API: %b, Same-device: %b, Cross-device: %b",
                    dcApiEnabled, sameDeviceEnabled, crossDeviceEnabled);

            RedirectFlowData redirectFlowData = buildRedirectFlowData(
                    request, authSession, legacyConfig, sessionState, requestObject,
                    dcApiEnabled, sameDeviceEnabled, crossDeviceEnabled);

            // Return the login form
            return buildLoginFormResponse(authSession, sessionState, requestObject, redirectFlowData,
                    dcApiEnabled, sameDeviceEnabled, crossDeviceEnabled);

        } catch (Exception e) {
            LOG.errorf(e, "[OID4VP-IDP] Failed to initiate OID4VP login: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to initiate wallet login", e);
        }
    }

    private Oid4vpSessionState initializeSessionState(AuthenticationRequest request, AuthenticationSessionModel authSession) {
        // Generate state for session lookup in callback (format: {tabId}.{randomData})
        String tabId = authSession.getTabId();
        String state = tabId + "." + randomState();
        String nonce = randomState();
        String clientId = computeClientId(request);

        LOG.infof("[OID4VP-IDP] Generated state: %s, nonce: %s, clientId: %s", state, nonce, clientId);

        // Store OID4VP state in auth notes only — do NOT overwrite clientNote("state")
        // which holds the OIDC state from the client app (needed for redirect verification)
        authSession.setAuthNote(SESSION_STATE, state);
        authSession.setAuthNote(SESSION_NONCE, nonce);
        authSession.setAuthNote(SESSION_CLIENT_ID, clientId);

        // Build response URI with state
        String redirectUri = request.getRedirectUri();
        String responseUri = redirectUri.contains("state=") ? redirectUri
                : redirectUri + (redirectUri.contains("?") ? "&" : "?") + "state=" + state;
        authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);

        // Store session identifiers for callback
        var uriInfo = request.getUriInfo();
        String sessionTabId = uriInfo.getQueryParameters().getFirst("tab_id");
        String clientData = uriInfo.getQueryParameters().getFirst("client_data");
        String sessionCode = uriInfo.getQueryParameters().getFirst("session_code");
        authSession.setAuthNote("oid4vp_tab_id", sessionTabId != null ? sessionTabId : "");
        authSession.setAuthNote("oid4vp_client_data", clientData != null ? clientData : "");
        authSession.setAuthNote("oid4vp_session_code", sessionCode != null ? sessionCode : "");

        // Build form action URL
        String formActionUrl = buildFormActionUrl(redirectUri, state, sessionTabId, sessionCode, clientData);
        LOG.infof("[OID4VP-IDP] Form action URL: %s", formActionUrl);

        return new Oid4vpSessionState(state, nonce, clientId, formActionUrl, redirectUri);
    }

    private String buildFormActionUrl(String redirectUri, String state, String tabId, String sessionCode,
                                      String clientData) {
        UriBuilder builder = UriBuilder.fromUri(stripQueryParams(redirectUri));
        builder.queryParam("state", state);
        if (tabId != null && !tabId.isEmpty()) {
            builder.queryParam("tab_id", tabId);
        }
        if (sessionCode != null && !sessionCode.isEmpty()) {
            builder.queryParam("session_code", sessionCode);
        }
        if (clientData != null && !clientData.isEmpty()) {
            builder.queryParam("client_data", clientData);
        }
        return builder.build().toString();
    }

    private Oid4vpDcApiRequestObjectService.DcApiRequestObject buildDcApiRequestObject(
            AuthenticationSessionModel authSession, Oid4vpConfig legacyConfig,
            String origin, Oid4vpSessionState sessionState) {

        Oid4vpDcApiRequestObjectService.DcApiRequestObject requestObject =
                dcApiRequestObjectService.buildRequestObject(legacyConfig, origin,
                        sessionState.clientId(), sessionState.state(), sessionState.nonce());

        if (requestObject == null) {
            return null;
        }

        if (requestObject.responseEncryptionPrivateJwk() != null) {
            authSession.setAuthNote(SESSION_ENCRYPTION_KEY, requestObject.responseEncryptionPrivateJwk());
        }
        if (requestObject.responseUri() != null) {
            authSession.setAuthNote(SESSION_RESPONSE_URI, requestObject.responseUri());
        }
        if (requestObject.requestObjectJwt() != null) {
            authSession.setAuthNote(SESSION_REQUEST_OBJECT, requestObject.requestObjectJwt());
        }
        return requestObject;
    }

    private RedirectFlowData buildRedirectFlowData(
            AuthenticationRequest request,
            AuthenticationSessionModel authSession,
            Oid4vpConfig legacyConfig,
            Oid4vpSessionState sessionState,
            Oid4vpDcApiRequestObjectService.DcApiRequestObject requestObject,
            boolean dcApiEnabled,
            boolean sameDeviceEnabled,
            boolean crossDeviceEnabled) {

        if (!sameDeviceEnabled && !crossDeviceEnabled) {
            return RedirectFlowData.EMPTY;
        }

        String effectiveClientId = computeEffectiveClientId(sessionState.clientId());
        authSession.setAuthNote(SESSION_EFFECTIVE_CLIENT_ID, effectiveClientId);

        String dcApiEncryptionKey = (dcApiEnabled && requestObject != null)
                ? requestObject.responseEncryptionPrivateJwk() : null;

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId() : null;
        String clientIdForSession = authSession.getClient() != null
                ? authSession.getClient().getClientId() : null;

        String sameDeviceWalletUrl = null;
        String crossDeviceWalletUrl = null;
        String qrCodeBase64 = null;

        // Track whether indexes have been stored in this transaction.
        // Infinispan transactions don't allow two put() calls for the same key,
        // so only the first store() call creates state and kid indexes.
        boolean indexesStored = false;

        if (sameDeviceEnabled) {
            try {
                // Same-device: response_uri = clean base endpoint URL (no session params).
                // The wallet uses this exact value for the mDoc SessionTranscript, so it must
                // NOT include session-specific query params (state, tab_id, session_code, client_data)
                // that the verifier would strip. State is sent as a form param instead.
                String sameDeviceResponseUri = stripQueryParams(sessionState.redirectUri());
                URI sameDeviceRequestUri = buildSignStoreRequestObject(request, authSession, legacyConfig,
                        sessionState, effectiveClientId, sameDeviceResponseUri, dcApiEncryptionKey,
                        dcApiEnabled, rootSessionId, clientIdForSession, indexesStored);
                indexesStored = true;

                sameDeviceWalletUrl = redirectFlowService.buildWalletAuthorizationUrl(
                        getConfig().getSameDeviceWalletUrl(), getConfig().getSameDeviceWalletScheme(),
                        effectiveClientId, "plain", sameDeviceRequestUri).toString();
                LOG.infof("[OID4VP-IDP] Same-device wallet URL: %s", sameDeviceWalletUrl);
            } catch (Exception e) {
                LOG.errorf(e, "[OID4VP-IDP] Failed to build same-device request object: %s", e.getMessage());
            }
        }

        if (crossDeviceEnabled) {
            try {
                // Cross-device: response_uri = clean base endpoint URL + ?flow=cross_device.
                // Same rationale as same-device: no session params to avoid SessionTranscript mismatch.
                String crossDeviceResponseUri = stripQueryParams(sessionState.redirectUri())
                        + "?flow=cross_device";
                URI crossDeviceRequestUri = buildSignStoreRequestObject(request, authSession, legacyConfig,
                        sessionState, effectiveClientId, crossDeviceResponseUri, dcApiEncryptionKey,
                        dcApiEnabled, rootSessionId, clientIdForSession, indexesStored);

                crossDeviceWalletUrl = redirectFlowService.buildWalletAuthorizationUrl(
                        null, "openid4vp://", effectiveClientId, "plain", crossDeviceRequestUri).toString();
                qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceWalletUrl, 250, 250);
                LOG.infof("[OID4VP-IDP] Cross-device wallet URL: %s", crossDeviceWalletUrl);
            } catch (Exception e) {
                LOG.errorf(e, "[OID4VP-IDP] Failed to build cross-device request object: %s", e.getMessage());
            }
        }

        return new RedirectFlowData(sameDeviceWalletUrl, crossDeviceWalletUrl, qrCodeBase64);
    }

    /**
     * Builds a signed request object, stores it, and returns the request-object URI.
     * When multiple request objects share the same state/kid (same-device + cross-device),
     * only the first call should create indexes (skipIndexes=false).
     * Subsequent calls must use skipIndexes=true because Infinispan transactions
     * don't allow two put() calls for the same key.
     */
    private URI buildSignStoreRequestObject(AuthenticationRequest request,
                                             AuthenticationSessionModel authSession,
                                             Oid4vpConfig legacyConfig,
                                             Oid4vpSessionState sessionState,
                                             String effectiveClientId,
                                             String responseUri,
                                             String dcApiEncryptionKey,
                                             boolean dcApiEnabled,
                                             String rootSessionId,
                                             String clientIdForSession,
                                             boolean skipIndexes) {
        Oid4vpRedirectFlowService.SignedRequestObject signedRequest = redirectFlowService.buildSignedRequestObject(
                legacyConfig, effectiveClientId, getConfig().getClientIdScheme(),
                responseUri, sessionState.state(), sessionState.nonce(),
                getConfig().getX509CertificatePem(), getConfig().getX509SigningKeyJwk(), dcApiEncryptionKey);

        // Store response_uri and encryption key in auth session for VP token verification.
        // Note: if both same-device and cross-device are enabled, the second call overwrites
        // these notes. This is OK because SESSION_RESPONSE_URI is corrected at POST time
        // from the actual request URL.
        authSession.setAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI, responseUri);
        if (!dcApiEnabled) {
            authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);
            if (signedRequest.encryptionKeyJson() != null) {
                authSession.setAuthNote(SESSION_ENCRYPTION_KEY, signedRequest.encryptionKeyJson());
            }
        }

        String encryptionPublicKeyJson = extractEncryptionPublicKey(signedRequest.encryptionKeyJson());

        Oid4vpRequestObjectStore.RebuildParams rebuildParams = new Oid4vpRequestObjectStore.RebuildParams(
                effectiveClientId, getConfig().getClientIdScheme(), responseUri,
                legacyConfig != null ? legacyConfig.dcqlQuery() : null,
                getConfig().getX509CertificatePem(), getConfig().getX509SigningKeyJwk(), encryptionPublicKeyJson,
                legacyConfig != null ? legacyConfig.verifierInfo() : null);

        String requestObjectId = REQUEST_OBJECT_STORE.store(session, signedRequest.jwt(), signedRequest.encryptionKeyJson(),
                sessionState.state(), sessionState.nonce(), rootSessionId, clientIdForSession, rebuildParams, skipIndexes);

        return request.getUriInfo().getBaseUriBuilder()
                .path("realms").path(request.getRealm().getName())
                .path("broker").path(getConfig().getAlias())
                .path("endpoint").path("request-object").path(requestObjectId)
                .build();
    }

    private String computeEffectiveClientId(String clientId) {
        String clientIdScheme = getConfig().getClientIdScheme();
        String x509Pem = getConfig().getX509CertificatePem();
        if ("x509_san_dns".equalsIgnoreCase(clientIdScheme) && x509Pem != null && !x509Pem.isBlank()) {
            return redirectFlowService.computeX509SanDnsClientId(x509Pem);
        } else if ("x509_hash".equalsIgnoreCase(clientIdScheme) && x509Pem != null && !x509Pem.isBlank()) {
            return redirectFlowService.computeX509HashClientId(x509Pem);
        }
        return clientId;
    }

    private String extractEncryptionPublicKey(String encryptionKeyJson) {
        if (encryptionKeyJson == null) {
            return null;
        }
        try {
            var encKey = com.nimbusds.jose.jwk.ECKey.parse(encryptionKeyJson);
            return encKey.toPublicJWK().toJSONString();
        } catch (Exception e) {
            LOG.warnf("[OID4VP-IDP] Failed to extract public key: %s", e.getMessage());
            return null;
        }
    }

    private String buildCrossDeviceStatusUrl() {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + session.getContext().getRealm().getName()
                + "/broker/" + getConfig().getAlias() + "/endpoint/cross-device/status";
    }

    private Response buildLoginFormResponse(AuthenticationSessionModel authSession,
                                             Oid4vpSessionState sessionState,
                                             Oid4vpDcApiRequestObjectService.DcApiRequestObject requestObject,
                                             RedirectFlowData redirectFlowData,
                                             boolean dcApiEnabled,
                                             boolean sameDeviceEnabled,
                                             boolean crossDeviceEnabled) {
        return session.getProvider(org.keycloak.forms.login.LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setAttribute("state", sessionState.state())
                .setAttribute("nonce", sessionState.nonce())
                .setAttribute("clientId", sessionState.clientId())
                .setAttribute("responseUri", sessionState.redirectUri())
                .setAttribute("dcqlQuery", buildDcqlQueryFromConfig())
                .setAttribute("dcApiRequestObject", requestObject != null ? requestObject.requestObjectJwt() : null)
                .setAttribute("idpAlias", getConfig().getAlias())
                .setAttribute("formActionUrl", sessionState.formActionUrl())
                .setAttribute("dcApiEnabled", dcApiEnabled)
                .setAttribute("sameDeviceEnabled", sameDeviceEnabled)
                .setAttribute("crossDeviceEnabled", crossDeviceEnabled)
                .setAttribute("sameDeviceWalletUrl", redirectFlowData.sameDeviceWalletUrl())
                .setAttribute("crossDeviceWalletUrl", redirectFlowData.crossDeviceWalletUrl())
                .setAttribute("qrCodeBase64", redirectFlowData.qrCodeBase64())
                .setAttribute("crossDeviceStatusUrl", (crossDeviceEnabled || sameDeviceEnabled) ? buildCrossDeviceStatusUrl() : null)
                .createForm("login-oid4vp-idp.ftl");
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        // OID4VP doesn't have persistent tokens like OAuth
        return null;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Oid4vpIdentityProviderEndpoint(session, realm, this, callback, event, REQUEST_OBJECT_STORE);
    }

    /** Provides access to redirect flow service for endpoint. */
    Oid4vpRedirectFlowService getRedirectFlowService() {
        return redirectFlowService;
    }

    /**
     * Process the callback from the wallet.
     * This is called by the endpoint when the wallet submits the VP token.
     */
    public BrokeredIdentityContext processCallback(AuthenticationSessionModel authSession,
                                                    String state,
                                                    String vpToken,
                                                    String encryptedResponse,
                                                    String error,
                                                    String errorDescription) {

        LOG.infof("[OID4VP-IDP] ========== processCallback called ==========");
        LOG.infof("[OID4VP-IDP] state: %s", state);
        LOG.infof("[OID4VP-IDP] vpToken present: %b, length: %d",
                vpToken != null && !vpToken.isBlank(),
                vpToken != null ? vpToken.length() : 0);
        LOG.infof("[OID4VP-IDP] encryptedResponse present: %b", encryptedResponse != null && !encryptedResponse.isBlank());
        LOG.infof("[OID4VP-IDP] error: %s, errorDescription: %s", error, errorDescription);

        // Validate state
        String expectedState = authSession.getAuthNote(SESSION_STATE);
        LOG.infof("[OID4VP-IDP] Expected state from session: %s", expectedState);
        if (expectedState == null || !expectedState.equals(state)) {
            LOG.warnf("[OID4VP-IDP] State mismatch! Expected: %s, Got: %s", expectedState, state);
            throw new IdentityBrokerException("Invalid state parameter");
        }
        LOG.infof("[OID4VP-IDP] State validated successfully");

        // Check for errors from wallet
        if (error != null && !error.isBlank()) {
            String message = errorDescription != null && !errorDescription.isBlank()
                    ? error + ": " + errorDescription
                    : error;
            LOG.warnf("[OID4VP-IDP] Wallet returned error: %s", message);
            throw new IdentityBrokerException("Wallet returned error: " + message);
        }

        // Decrypt response if encrypted
        String mdocGeneratedNonce = null;
        if ((vpToken == null || vpToken.isBlank()) && encryptedResponse != null && !encryptedResponse.isBlank()) {
            LOG.infof("[OID4VP-IDP] Decrypting encrypted response...");
            String encryptionKey = authSession.getAuthNote(SESSION_ENCRYPTION_KEY);
            LOG.infof("[OID4VP-IDP] Encryption key present: %b", encryptionKey != null && !encryptionKey.isBlank());
            try {
                var decrypted = dcApiRequestObjectService.decryptEncryptedResponse(encryptedResponse, encryptionKey);
                var node = decrypted.payload();
                mdocGeneratedNonce = decrypted.mdocGeneratedNonce();
                LOG.infof("[OID4VP-IDP] Decrypted response: %s", node != null ? node.toString().substring(0, Math.min(200, node.toString().length())) : "null");
                if (mdocGeneratedNonce != null) {
                    LOG.infof("[OID4VP-IDP] Extracted mdoc_generated_nonce from JWE apu: '%s'", mdocGeneratedNonce);
                }
                if (node.hasNonNull("error")) {
                    String err = node.get("error").asText("");
                    String desc = node.hasNonNull("error_description") ? node.get("error_description").asText("") : "";
                    LOG.warnf("[OID4VP-IDP] Decrypted response contains error: %s - %s", err, desc);
                    throw new IdentityBrokerException("Wallet error: " + err + (desc.isEmpty() ? "" : " - " + desc));
                }
                if (!node.hasNonNull("vp_token")) {
                    LOG.warnf("[OID4VP-IDP] Decrypted response missing vp_token");
                    throw new IdentityBrokerException("Missing vp_token in encrypted response");
                }
                vpToken = node.get("vp_token").isTextual()
                        ? node.get("vp_token").asText()
                        : node.get("vp_token").toString();
                LOG.infof("[OID4VP-IDP] Extracted vp_token from encrypted response, length: %d", vpToken.length());
            } catch (IdentityBrokerException e) {
                throw e;
            } catch (Exception e) {
                LOG.errorf(e, "[OID4VP-IDP] Failed to decrypt response: %s", e.getMessage());
                throw new IdentityBrokerException("Failed to decrypt response: " + e.getMessage(), e);
            }
        }

        // If mdocGeneratedNonce was pre-extracted (JWE decrypted in endpoint), pick it up from auth note
        if (mdocGeneratedNonce == null) {
            mdocGeneratedNonce = authSession.getAuthNote(SESSION_MDOC_GENERATED_NONCE);
            if (mdocGeneratedNonce != null) {
                LOG.infof("[OID4VP-IDP] Using pre-extracted mdoc_generated_nonce from auth session: '%s'", mdocGeneratedNonce);
                authSession.removeAuthNote(SESSION_MDOC_GENERATED_NONCE);
            }
        }

        if (vpToken == null || vpToken.isBlank()) {
            LOG.warnf("[OID4VP-IDP] Missing vp_token after all processing");
            throw new IdentityBrokerException("Missing vp_token");
        }
        LOG.infof("[OID4VP-IDP] vp_token ready for verification, length: %d", vpToken.length());
        LOG.infof("[OID4VP-IDP] vp_token preview: %s...", vpToken.substring(0, Math.min(100, vpToken.length())));

        // Get verification parameters from session
        String expectedNonce = authSession.getAuthNote(SESSION_NONCE);
        String responseUri = authSession.getAuthNote(SESSION_RESPONSE_URI);

        // For redirect flows (same-device), use the effective client_id which matches the credential's audience
        // For DC API flows, use the URL-style client_id
        String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        String clientId = effectiveClientId != null ? effectiveClientId : computeClientId(authSession);

        byte[] jwkThumbprint = computeJwkThumbprint(authSession.getAuthNote(SESSION_ENCRYPTION_KEY));
        LOG.infof("[OID4VP-IDP] Verification params - nonce: %s, responseUri: %s, clientId: %s, effectiveClientId: %s, hasJwkThumbprint: %b",
                expectedNonce, responseUri, clientId, effectiveClientId, jwkThumbprint != null);

        // Register additional trusted certificates if configured
        String additionalCerts = getConfig().getAdditionalTrustedCertificates();
        if (additionalCerts != null && !additionalCerts.isBlank()) {
            String trustListId = getConfig().getTrustListId();
            LOG.infof("[OID4VP-IDP] Registering additional trusted certificates to trust list: %s", trustListId);
            for (String certPem : splitPemCertificates(additionalCerts)) {
                if (!certPem.isBlank()) {
                    try {
                        trustListService.registerCertificate(trustListId, certPem);
                        LOG.infof("[OID4VP-IDP] Registered additional certificate to trust list");
                    } catch (Exception e) {
                        LOG.warnf("[OID4VP-IDP] Failed to register additional certificate: %s", e.getMessage());
                    }
                }
            }
        }

        // Verify the VP token using VpTokenProcessor (handles format detection and retry)
        boolean trustX5c = getConfig().getEffectiveTrustX5cFromCredential();
        String redirectFlowResponseUri = authSession.getAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        if (getConfig().isSkipTrustListVerification()) {
            LOG.warnf("[OID4VP-IDP] Trust list verification SKIPPED (skipTrustListVerification=true), auto-trusting x5c");
        }
        LOG.infof("[OID4VP-IDP] Verifying VP token with trustListId: %s, trustX5c: %b",
                getConfig().getTrustListId(), trustX5c);

        VpTokenVerificationResult result = vpTokenProcessor.process(
                vpToken,
                getConfig().getTrustListId(),
                clientId,
                expectedNonce,
                responseUri,
                jwkThumbprint,
                trustX5c,
                redirectFlowResponseUri,
                mdocGeneratedNonce
        );
        LOG.infof("[OID4VP-IDP] VP token verified, format: %s, credentials: %d",
                result.format(), result.credentials().size());

        // Log received credentials for debugging
        for (var entry : result.credentials().entrySet()) {
            var cred = entry.getValue();
            LOG.infof("[OID4VP-IDP] Credential [%s]: type=%s, issuer=%s, format=%s, claims=%s",
                    entry.getKey(), cred.credentialType(), cred.issuer(), cred.presentationType(),
                    cred.claims());
        }

        // Extract identity info from verified credentials
        Map<String, Object> claims;
        String subject;
        String issuer;
        String credentialType;
        Oid4vpVerifierService.PresentationType presentationType;
        String userMappingClaimName;

        if (result.isMultiCredential()) {
            // For multi-credential, search all credentials for the user mapping claim
            VpTokenVerificationResult.VerifiedCredential primary = result.getPrimaryCredential();
            if (primary == null) {
                throw new IdentityBrokerException("No valid credential found in multi-credential response");
            }
            presentationType = primary.presentationType();
            String credentialFormat = presentationType == Oid4vpVerifierService.PresentationType.MDOC
                    ? Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC
                    : Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC;
            userMappingClaimName = getConfig().getUserMappingClaimForFormat(credentialFormat);
            claims = result.mergedClaims();

            // Find the credential that contains the mapping claim
            VpTokenVerificationResult.VerifiedCredential matchingCred = null;
            for (VpTokenVerificationResult.VerifiedCredential cred : result.credentials().values()) {
                if (CredentialClaimsExtractor.extractClaim(cred.claims(), userMappingClaimName) != null) {
                    matchingCred = cred;
                    break;
                }
            }
            if (matchingCred != null) {
                subject = CredentialClaimsExtractor.extractClaim(matchingCred.claims(), userMappingClaimName);
                issuer = matchingCred.issuer();
                credentialType = matchingCred.credentialType();
            } else {
                subject = CredentialClaimsExtractor.extractClaim(claims, userMappingClaimName);
                issuer = primary.issuer();
                credentialType = primary.credentialType();
            }
            LOG.infof("[OID4VP-IDP] Multi-credential: using merged claims for identity");
        } else {
            // Single credential
            VpTokenVerificationResult.VerifiedCredential primary = result.getPrimaryCredential();
            claims = primary.claims();
            presentationType = primary.presentationType();
            String credentialFormat = presentationType == Oid4vpVerifierService.PresentationType.MDOC
                    ? Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC
                    : Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC;
            userMappingClaimName = getConfig().getUserMappingClaimForFormat(credentialFormat);
            subject = CredentialClaimsExtractor.extractClaim(claims, userMappingClaimName);
            issuer = primary.issuer();
            credentialType = primary.credentialType();
        }

        LOG.infof("[OID4VP-IDP] Extracted - subject: %s, issuer: %s, credentialType: %s",
                subject, issuer, credentialType);

        if (subject == null || subject.isBlank()) {
            LOG.warnf("[OID4VP-IDP] Missing subject claim '%s' in credential", userMappingClaimName);
            throw new IdentityBrokerException("Missing subject claim in credential");
        }

        // Validate issuer and credential type against config
        if (!getConfig().isIssuerAllowed(issuer)) {
            LOG.warnf("[OID4VP-IDP] Issuer not allowed: %s", issuer);
            throw new IdentityBrokerException("Issuer not allowed: " + issuer);
        }
        if (!getConfig().isCredentialTypeAllowed(credentialType)) {
            LOG.warnf("[OID4VP-IDP] Credential type not allowed: %s", credentialType);
            throw new IdentityBrokerException("Credential type not allowed: " + credentialType);
        }

        // Compute the composite lookup key (used as federated user ID)
        String lookupKey = FederatedIdentityKeyGenerator.computeLookupKey(issuer, credentialType, subject);
        LOG.debugf("[OID4VP-IDP] Computed lookup key: %s", lookupKey);

        // Build credential metadata JSON (stored in FederatedIdentity.token for bi-directional matching)
        String credentialMetadata = CredentialClaimsExtractor.buildCredentialMetadataJson(
                issuer, credentialType, subject, userMappingClaimName, claims, objectMapper);

        // Create brokered identity context
        BrokeredIdentityContext context = new BrokeredIdentityContext(lookupKey, getConfig());
        context.setIdp(this);
        context.setUsername(subject);
        context.setToken(credentialMetadata);

        // Store claims for IdP mappers
        context.getContextData().put("oid4vp_claims", claims);
        context.getContextData().put("oid4vp_issuer", issuer);
        context.getContextData().put("oid4vp_credential_type", credentialType);
        context.getContextData().put("oid4vp_subject", subject);
        context.getContextData().put("oid4vp_presentation_type", presentationType.name());

        clearSessionNotes(authSession);
        LOG.infof("[OID4VP-IDP] processCallback completed: user=%s, lookupKey=%s", subject, lookupKey);
        return context;
    }

    private String computeClientId(AuthenticationRequest request) {
        String configuredClientId = getConfig().getDcApiClientId();
        if (configuredClientId != null && !configuredClientId.isBlank()) {
            return configuredClientId;
        }
        URI realmBase = request.getUriInfo().getBaseUriBuilder()
                .path("realms")
                .path(request.getRealm().getName())
                .build();
        String value = realmBase.toString();
        return value.endsWith("/") ? value : value + "/";
    }

    private String computeClientId(AuthenticationSessionModel authSession) {
        String configuredClientId = getConfig().getDcApiClientId();
        if (configuredClientId != null && !configuredClientId.isBlank()) {
            return configuredClientId;
        }
        RealmModel realm = authSession.getRealm();
        URI baseUri = session.getContext().getUri().getBaseUri();
        String baseUriStr = baseUri.toString();
        if (!baseUriStr.endsWith("/")) {
            baseUriStr += "/";
        }
        String value = baseUriStr + "realms/" + realm.getName();
        return value.endsWith("/") ? value : value + "/";
    }

    private String stripQueryParams(String uri) {
        if (uri == null) {
            return null;
        }
        int queryIndex = uri.indexOf('?');
        return queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;
    }

    private String originFromUri(URI uri) {
        if (uri == null || uri.getScheme() == null || uri.getHost() == null) {
            return null;
        }
        String scheme = uri.getScheme().toLowerCase();
        int port = uri.getPort();
        boolean includePort = port != -1 && !((port == 80 && "http".equals(scheme)) || (port == 443 && "https".equals(scheme)));
        if (includePort) {
            return "%s://%s:%d".formatted(scheme, uri.getHost(), port);
        }
        return "%s://%s".formatted(scheme, uri.getHost());
    }

    private byte[] computeJwkThumbprint(String jwkJson) {
        if (jwkJson == null || jwkJson.isBlank()) {
            return null;
        }
        try {
            JWK jwk = JWK.parse(jwkJson);
            return jwk.toPublicJWK().computeThumbprint().decode();
        } catch (Exception e) {
            LOG.warnf("Failed to compute JWK thumbprint: %s", e.getMessage());
            return null;
        }
    }

    private void clearSessionNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(SESSION_STATE);
        authSession.removeAuthNote(SESSION_NONCE);
        authSession.removeAuthNote(SESSION_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_ENCRYPTION_KEY);
        authSession.removeAuthNote(SESSION_CLIENT_ID);
        authSession.removeAuthNote(SESSION_REQUEST_OBJECT);
        authSession.removeAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        // Clear session identifiers stored for form
        authSession.removeAuthNote("oid4vp_tab_id");
        authSession.removeAuthNote("oid4vp_client_data");
        authSession.removeAuthNote("oid4vp_session_code");
    }

    /**
     * Split a string containing multiple PEM certificates into individual certificates.
     * Certificates are delimited by BEGIN/END CERTIFICATE markers.
     */
    private List<String> splitPemCertificates(String pemCertificates) {
        if (pemCertificates == null || pemCertificates.isBlank()) {
            return List.of();
        }
        List<String> certs = new ArrayList<>();
        String remaining = pemCertificates;
        while (true) {
            int beginIndex = remaining.indexOf("-----BEGIN CERTIFICATE-----");
            if (beginIndex < 0) {
                break;
            }
            int endIndex = remaining.indexOf("-----END CERTIFICATE-----", beginIndex);
            if (endIndex < 0) {
                break;
            }
            endIndex += "-----END CERTIFICATE-----".length();
            certs.add(remaining.substring(beginIndex, endIndex));
            remaining = remaining.substring(endIndex);
        }
        return certs;
    }

    /**
     * Build DCQL query from IdP configuration.
     * <p>
     * Priority:
     * <ol>
     *   <li>Explicit dcqlQuery config (if set) - allows full control over the DCQL query</li>
     *   <li>Auto-generated from IdP mappers - each mapper specifies credential type and claims</li>
     *   <li>Default empty DCQL query</li>
     * </ol>
     * <p>
     * When using mappers and multiple credential types are configured, a credential_sets
     * section is added based on the credentialSetMode config (optional = any one, all = all required).
     */
    protected String buildDcqlQueryFromConfig() {
        // First priority: explicit manual DCQL query setting
        // This allows tests and advanced configurations to override mapper-based generation
        String manual = getConfig().getDcqlQuery();
        if (manual != null && !manual.isBlank()) {
            return manual;
        }

        // Second priority: aggregate mappers by credential type
        Map<String, DcqlQueryBuilder.CredentialTypeSpec> credentialTypes = aggregateMappersByCredentialType();

        // If mappers configured, build DCQL from them
        if (!credentialTypes.isEmpty()) {
            try {
                return DcqlQueryBuilder.fromMapperSpecs(
                        objectMapper,
                        credentialTypes,
                        getConfig().isAllCredentialsRequired(),
                        getConfig().getCredentialSetPurpose()
                ).build();
            } catch (Exception e) {
                LOG.warnf("[OID4VP-IDP] Failed to build DCQL from mappers: %s", e.getMessage());
            }
        }

        // Fallback: default empty DCQL query
        return new DcqlQueryBuilder(objectMapper).build();
    }

    /**
     * Aggregate IdP mappers by credential type (format + type).
     * Returns a map from type key to credential spec with collected claim specs (including optional flag).
     * <p>
     * Automatically includes user mapping claims (userMappingClaim for SD-JWT,
     * userMappingClaimMdoc for mDoc) to ensure they are requested in the DCQL query.
     * <p>
     * When mappers have optional=true, the resulting DCQL will include claim_sets
     * allowing wallets to present either all claims or just the required ones.
     */
    private Map<String, DcqlQueryBuilder.CredentialTypeSpec> aggregateMappersByCredentialType() {
        Map<String, DcqlQueryBuilder.CredentialTypeSpec> result = new LinkedHashMap<>();

        try {
            RealmModel realm = session.getContext().getRealm();
            if (realm == null) {
                LOG.debugf("[OID4VP-IDP] No realm in context, cannot get mappers");
                return result;
            }

            String idpAlias = getConfig().getAlias();
            // Temporary map to collect claims by type (with optional flag)
            Map<String, List<DcqlQueryBuilder.ClaimSpec>> claimsByType = new LinkedHashMap<>();
            Map<String, String> formatByType = new LinkedHashMap<>();

            realm.getIdentityProviderMappersByAliasStream(idpAlias)
                    .forEach(mapper -> {
                        String format = mapper.getConfig().get("credential.format");
                        String type = mapper.getConfig().get("credential.type");
                        String claimPath = mapper.getConfig().get("claim");
                        boolean isOptional = "true".equalsIgnoreCase(mapper.getConfig().get("optional"));

                        if (format == null || format.isBlank()) {
                            format = Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC; // default
                        }
                        if (type == null || type.isBlank()) {
                            LOG.debugf("[OID4VP-IDP] Mapper missing credential.type, skipping");
                            return;
                        }

                        // Use format+type as key for aggregation
                        String typeKey = format + "|" + type;
                        formatByType.put(typeKey, format);

                        if (claimPath != null && !claimPath.isBlank()) {
                            DcqlQueryBuilder.ClaimSpec claimSpec = new DcqlQueryBuilder.ClaimSpec(claimPath, isOptional);
                            claimsByType.computeIfAbsent(typeKey, k -> new ArrayList<>()).add(claimSpec);
                            LOG.debugf("[OID4VP-IDP] Found mapper: format=%s, type=%s, claim=%s, optional=%s",
                                    format, type, claimPath, isOptional);
                        }
                    });

            // Automatically add user mapping claims for each credential type
            // These claims are used to identify the user and must be included in the DCQL (always required)
            String sdJwtUserMappingClaim = getConfig().getUserMappingClaim();
            String mdocUserMappingClaim = getConfig().getUserMappingClaimMdoc();

            for (String typeKey : formatByType.keySet()) {
                String format = formatByType.get(typeKey);
                List<DcqlQueryBuilder.ClaimSpec> claims = claimsByType.computeIfAbsent(typeKey, k -> new ArrayList<>());

                // Add the appropriate user mapping claim if not already present
                String userMappingClaim = Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(format)
                        ? mdocUserMappingClaim
                        : sdJwtUserMappingClaim;

                if (userMappingClaim != null && !userMappingClaim.isBlank()) {
                    // Check if already present
                    boolean alreadyPresent = claims.stream()
                            .anyMatch(spec -> spec.path().equals(userMappingClaim));
                    if (!alreadyPresent) {
                        // User mapping claim is always required (not optional)
                        claims.add(new DcqlQueryBuilder.ClaimSpec(userMappingClaim, false));
                        LOG.debugf("[OID4VP-IDP] Auto-added user mapping claim: format=%s, claim=%s", format, userMappingClaim);
                    }
                }
            }

            // Build CredentialTypeSpec for each type
            for (Map.Entry<String, List<DcqlQueryBuilder.ClaimSpec>> entry : claimsByType.entrySet()) {
                String typeKey = entry.getKey();
                String[] parts = typeKey.split("\\|", 2);
                String format = formatByType.get(typeKey);
                String type = parts.length > 1 ? parts[1] : parts[0];
                result.put(typeKey, new DcqlQueryBuilder.CredentialTypeSpec(format, type, entry.getValue()));
            }

            LOG.debugf("[OID4VP-IDP] Aggregated %d credential types from mappers", result.size());
        } catch (Exception e) {
            LOG.warnf("[OID4VP-IDP] Failed to aggregate mappers: %s", e.getMessage());
        }

        return result;
    }

    private Oid4vpConfig toLegacyConfig(Oid4vpIdentityProviderConfig config) {
        // Log HAIP enforcement status
        if (config.isEnforceHaip()) {
            LOG.infof("[OID4VP-IDP] HAIP enforcement enabled: %s", config.getHaipEnforcementSummary());
        }
        return new Oid4vpConfig(
                buildDcqlQueryFromConfig(),
                config.getTrustListId(),
                config.getUserMappingClaim(),
                false,
                null,
                config.getEffectiveDcApiRequestMode(), // Use HAIP-enforced value
                config.getDcApiClientId(),
                config.getDcApiSigningKeyId(),
                config.getVerifierInfo(),
                config.getX509SigningKeyJwk(),
                config.getX509CertificatePem()
        );
    }

    private static String randomState() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
