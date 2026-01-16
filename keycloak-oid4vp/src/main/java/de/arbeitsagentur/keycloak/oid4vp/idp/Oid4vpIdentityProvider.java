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
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import jakarta.enterprise.inject.Vetoed;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
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

    @Override
    public Response performLogin(AuthenticationRequest request) {
        LOG.infof("[OID4VP-IDP] ========== performLogin called ==========");
        try {
            AuthenticationSessionModel authSession = request.getAuthenticationSession();
            LOG.infof("[OID4VP-IDP] AuthSession: tabId=%s, client=%s, realm=%s",
                    authSession != null ? authSession.getTabId() : "null",
                    authSession != null && authSession.getClient() != null ? authSession.getClient().getClientId() : "null",
                    authSession != null && authSession.getRealm() != null ? authSession.getRealm().getName() : "null");

            // Generate state for session lookup in callback
            // For IdP broker flow, state must be in format: {tabId}.{randomData}
            // Keycloak's getAndVerifyAuthenticationSession(state) parses this to find the session
            String tabId = authSession.getTabId();
            String randomPart = randomState();
            String state = tabId + "." + randomPart;
            LOG.infof("[OID4VP-IDP] Generated state: %s (tabId=%s)", state, tabId);

            // Generate nonce for OID4VP (separate from state)
            String nonce = randomState();
            LOG.infof("[OID4VP-IDP] Generated nonce: %s", nonce);

            // Compute client_id (default to realm URL)
            String clientId = computeClientId(request);
            LOG.infof("[OID4VP-IDP] Computed clientId: %s", clientId);

            // Store state as client note for getAndVerifyAuthenticationSession(state) lookup
            // This is required for Keycloak's IdP callback mechanism
            authSession.setClientNote("state", state);
            LOG.infof("[OID4VP-IDP] Stored state as client note");

            // Store additional notes for verification
            authSession.setAuthNote(SESSION_STATE, state);
            authSession.setAuthNote(SESSION_NONCE, nonce);
            authSession.setAuthNote(SESSION_CLIENT_ID, clientId);
            LOG.infof("[OID4VP-IDP] Stored auth notes - state: %s, nonce: %s, clientId: %s", state, nonce, clientId);

            // Build redirect URI with state parameter for callback lookup
            String redirectUri = request.getRedirectUri();
            LOG.infof("[OID4VP-IDP] Redirect URI from request: %s", redirectUri);
            String responseUri = redirectUri;
            if (!redirectUri.contains("state=")) {
                responseUri = redirectUri + (redirectUri.contains("?") ? "&" : "?") + "state=" + state;
            }
            authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);
            LOG.infof("[OID4VP-IDP] Response URI (with state): %s", responseUri);

            // Get session identifiers from the current request URI - these are needed for callback lookup
            // The current URL has: tab_id, client_data, session_code which Keycloak uses for session lookup
            var uriInfo = request.getUriInfo();
            String sessionTabId = uriInfo.getQueryParameters().getFirst("tab_id");
            String clientData = uriInfo.getQueryParameters().getFirst("client_data");
            String sessionCode = uriInfo.getQueryParameters().getFirst("session_code");
            LOG.infof("[OID4VP-IDP] Session identifiers - tab_id: %s, client_data length: %d, session_code: %s",
                    sessionTabId,
                    clientData != null ? clientData.length() : 0,
                    sessionCode);

            // Store session identifiers for the form
            authSession.setAuthNote("oid4vp_tab_id", sessionTabId != null ? sessionTabId : "");
            authSession.setAuthNote("oid4vp_client_data", clientData != null ? clientData : "");
            authSession.setAuthNote("oid4vp_session_code", sessionCode != null ? sessionCode : "");

            // Build DC API request object if configured
            Oid4vpConfig legacyConfig = toLegacyConfig(getConfig());
            String origin = originFromUri(request.getUriInfo().getBaseUri());
            LOG.infof("[OID4VP-IDP] Origin: %s", origin);

            Oid4vpDcApiRequestObjectService.DcApiRequestObject requestObject =
                    dcApiRequestObjectService.buildRequestObject(legacyConfig, origin, clientId, state, nonce);
            LOG.infof("[OID4VP-IDP] Request object built: hasJwt=%b, hasEncryptionKey=%b, hasResponseUri=%b",
                    requestObject != null && requestObject.requestObjectJwt() != null,
                    requestObject != null && requestObject.responseEncryptionPrivateJwk() != null,
                    requestObject != null && requestObject.responseUri() != null);

            if (requestObject != null && requestObject.responseEncryptionPrivateJwk() != null) {
                authSession.setAuthNote(SESSION_ENCRYPTION_KEY, requestObject.responseEncryptionPrivateJwk());
                LOG.infof("[OID4VP-IDP] Stored encryption key in session");
            }

            // Update response_uri if request object provides one (for mDoc SessionTranscript)
            if (requestObject != null && requestObject.responseUri() != null) {
                authSession.setAuthNote(SESSION_RESPONSE_URI, requestObject.responseUri());
                LOG.infof("[OID4VP-IDP] Updated response URI from request object: %s", requestObject.responseUri());
            }

            // Store request object JWT if available
            if (requestObject != null && requestObject.requestObjectJwt() != null) {
                authSession.setAuthNote(SESSION_REQUEST_OBJECT, requestObject.requestObjectJwt());
                LOG.infof("[OID4VP-IDP] Stored request object JWT (length: %d)", requestObject.requestObjectJwt().length());
            }

            // The form should post back to the redirect URI (which includes the broker endpoint)
            // Include state (required!), tab_id, session_code, and client_data in the form action URL
            // These are ALL needed for Keycloak to reconstruct the authentication session on callback
            String baseUrl = stripQueryParams(redirectUri);
            UriBuilder formActionBuilder = UriBuilder.fromUri(baseUrl);
            // State is CRITICAL - it must be in query params for IdentityBrokerService.callback()
            formActionBuilder.queryParam("state", state);
            if (sessionTabId != null && !sessionTabId.isEmpty()) {
                formActionBuilder.queryParam("tab_id", sessionTabId);
            }
            // session_code is CRITICAL for Keycloak to look up the auth session
            if (sessionCode != null && !sessionCode.isEmpty()) {
                formActionBuilder.queryParam("session_code", sessionCode);
            }
            if (clientData != null && !clientData.isEmpty()) {
                formActionBuilder.queryParam("client_data", clientData);
            }
            String formActionUrl = formActionBuilder.build().toString();
            LOG.infof("[OID4VP-IDP] Form action URL: %s", formActionUrl);

            LOG.infof("[OID4VP-IDP] Creating login form with attributes - state: %s, nonce: %s, clientId: %s, idpAlias: %s",
                    state, nonce, clientId, getConfig().getAlias());

            // Check which flows are enabled
            boolean dcApiEnabled = getConfig().isDcApiEnabled();
            boolean sameDeviceEnabled = getConfig().isSameDeviceEnabled();
            boolean crossDeviceEnabled = getConfig().isCrossDeviceEnabled();
            LOG.infof("[OID4VP-IDP] Enabled flows - DC API: %b, Same-device: %b, Cross-device: %b",
                    dcApiEnabled, sameDeviceEnabled, crossDeviceEnabled);

            // Variables for redirect flows (same-device and cross-device)
            String sameDeviceWalletUrl = null;
            String crossDeviceWalletUrl = null;
            String qrCodeBase64 = null;

            // Build redirect flow request object if same-device or cross-device is enabled
            if (sameDeviceEnabled || crossDeviceEnabled) {
                try {
                    // Build the response_uri for redirect flows (where wallet posts the response)
                    // Use the same formActionUrl but ensure it can handle direct_post
                    String redirectResponseUri = formActionUrl;
                    LOG.infof("[OID4VP-IDP] Building redirect flow request object with responseUri: %s", redirectResponseUri);

                    // Compute effective client_id based on scheme BEFORE building request object
                    // This ensures the client_id in the request object matches the URL query parameter
                    String effectiveClientId = clientId;
                    String clientIdScheme = getConfig().getClientIdScheme();
                    String x509Pem = getConfig().getX509CertificatePem();
                    if ("x509_san_dns".equalsIgnoreCase(clientIdScheme) && x509Pem != null && !x509Pem.isBlank()) {
                        effectiveClientId = redirectFlowService.computeX509SanDnsClientId(x509Pem);
                        LOG.infof("[OID4VP-IDP] Using x509_san_dns client_id: %s", effectiveClientId);
                    } else if ("x509_hash".equalsIgnoreCase(clientIdScheme) && x509Pem != null && !x509Pem.isBlank()) {
                        effectiveClientId = redirectFlowService.computeX509HashClientId(x509Pem);
                        LOG.infof("[OID4VP-IDP] Using x509_hash client_id: %s", effectiveClientId);
                    }

                    // Store effective client_id in session for use during verification
                    // This is needed because the credential's audience matches the effective client_id, not the URL-style client_id
                    authSession.setAuthNote(SESSION_EFFECTIVE_CLIENT_ID, effectiveClientId);
                    LOG.infof("[OID4VP-IDP] Stored effective client_id for verification: %s", effectiveClientId);

                    // Build signed request object for redirect flows using the effective client_id
                    // Pass the actual clientIdScheme so the JWT claims are correct (client_id_scheme, x5c header)
                    // When DC API is enabled, share the same encryption key to avoid decryption mismatches
                    // when user switches from DC API to same-device flow
                    String x509SigningKeyJwk = getConfig().getX509SigningKeyJwk();
                    String dcApiEncryptionKey = (dcApiEnabled && requestObject != null)
                            ? requestObject.responseEncryptionPrivateJwk()
                            : null;
                    Oid4vpRedirectFlowService.SignedRequestObject signedRequest = redirectFlowService.buildSignedRequestObject(
                            legacyConfig,
                            effectiveClientId,
                            clientIdScheme,
                            redirectResponseUri,
                            state,
                            nonce,
                            x509Pem,
                            x509SigningKeyJwk,
                            dcApiEncryptionKey
                    );
                    LOG.infof("[OID4VP-IDP] Created signed request object, JWT length: %d", signedRequest.jwt().length());

                    // Store the redirect flow response_uri for same-device/cross-device flow verification
                    // This is stored separately from SESSION_RESPONSE_URI because:
                    // - DC API uses origin-only response_uri for SessionTranscript
                    // - Redirect flow uses full URL for SessionTranscript
                    // During verification, we try both if verification fails with SessionTranscript mismatch
                    authSession.setAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI, redirectResponseUri);
                    LOG.infof("[OID4VP-IDP] Stored redirect flow response_uri: %s", redirectResponseUri);

                    // Also update SESSION_RESPONSE_URI if DC API is not enabled (backward compatibility)
                    if (!dcApiEnabled) {
                        authSession.setAuthNote(SESSION_RESPONSE_URI, redirectResponseUri);
                        LOG.infof("[OID4VP-IDP] Updated main response_uri for redirect flow verification: %s", redirectResponseUri);
                    } else {
                        LOG.infof("[OID4VP-IDP] Keeping DC API response_uri (origin-only) as main, redirect flow URI stored separately");
                    }

                    // Store the request object for later retrieval by wallet
                    // Include root session ID and client ID for direct_post callback session lookup
                    String rootSessionId = authSession.getParentSession() != null
                            ? authSession.getParentSession().getId() : null;
                    String clientIdForSession = authSession.getClient() != null
                            ? authSession.getClient().getClientId() : null;

                    // Build rebuild params for wallet_nonce support
                    // Extract public key from encryption key for client_metadata reconstruction
                    String encryptionPublicKeyJson = null;
                    if (signedRequest.encryptionKeyJson() != null) {
                        try {
                            var encKey = com.nimbusds.jose.jwk.ECKey.parse(signedRequest.encryptionKeyJson());
                            encryptionPublicKeyJson = encKey.toPublicJWK().toJSONString();
                        } catch (Exception e) {
                            LOG.warnf("[OID4VP-IDP] Failed to extract public key from encryption key: %s", e.getMessage());
                        }
                    }
                    Oid4vpRequestObjectStore.RebuildParams rebuildParams = new Oid4vpRequestObjectStore.RebuildParams(
                            effectiveClientId,
                            clientIdScheme,
                            redirectResponseUri,
                            legacyConfig != null ? legacyConfig.dcqlQuery() : null,
                            x509Pem,
                            x509SigningKeyJwk,
                            encryptionPublicKeyJson
                    );

                    String requestObjectId = REQUEST_OBJECT_STORE.store(
                            session,
                            signedRequest.jwt(),
                            signedRequest.encryptionKeyJson(),
                            state,
                            nonce,
                            rootSessionId,
                            clientIdForSession,
                            rebuildParams
                    );
                    LOG.infof("[OID4VP-IDP] Stored request object with id: %s, rootSessionId: %s, clientId: %s",
                            requestObjectId, rootSessionId, clientIdForSession);

                    // Store encryption key in session for response decryption
                    // ONLY if DC API is not enabled (to avoid overwriting DC API's encryption key)
                    // When both flows are enabled, DC API's key takes precedence since it was set first
                    if (signedRequest.encryptionKeyJson() != null && !dcApiEnabled) {
                        authSession.setAuthNote(SESSION_ENCRYPTION_KEY, signedRequest.encryptionKeyJson());
                        LOG.infof("[OID4VP-IDP] Stored redirect flow encryption key (DC API disabled)");
                    } else if (signedRequest.encryptionKeyJson() != null) {
                        LOG.infof("[OID4VP-IDP] Skipping redirect flow encryption key storage (DC API is enabled, using DC API key)");
                    }

                    // Build request_uri - endpoint where wallet can GET the request object
                    URI requestUri = request.getUriInfo().getBaseUriBuilder()
                            .path("realms")
                            .path(request.getRealm().getName())
                            .path("broker")
                            .path(getConfig().getAlias())
                            .path("endpoint")
                            .path("request-object")
                            .path(requestObjectId)
                            .build();
                    LOG.infof("[OID4VP-IDP] Request URI for wallet: %s", requestUri);

                    // Build wallet URLs
                    // Note: effectiveClientId already has the scheme prefix from computeX509SanDnsClientId/computeX509HashClientId
                    // so we pass "plain" to avoid double-prefixing
                    if (sameDeviceEnabled) {
                        URI sameDeviceUri = redirectFlowService.buildWalletAuthorizationUrl(
                                getConfig().getSameDeviceWalletUrl(),
                                getConfig().getSameDeviceWalletScheme(),
                                effectiveClientId,
                                "plain", // effectiveClientId already includes scheme prefix
                                requestUri
                        );
                        sameDeviceWalletUrl = sameDeviceUri.toString();
                        LOG.infof("[OID4VP-IDP] Same-device wallet URL: %s", sameDeviceWalletUrl);
                    }

                    if (crossDeviceEnabled) {
                        // For cross-device, always use openid4vp:// scheme for QR code
                        URI crossDeviceUri = redirectFlowService.buildWalletAuthorizationUrl(
                                null, // no HTTPS URL for QR code
                                "openid4vp://",
                                effectiveClientId,
                                "plain", // effectiveClientId already includes scheme prefix
                                requestUri
                        );
                        crossDeviceWalletUrl = crossDeviceUri.toString();
                        LOG.infof("[OID4VP-IDP] Cross-device wallet URL: %s", crossDeviceWalletUrl);

                        // Generate QR code
                        qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceWalletUrl, 250, 250);
                        LOG.infof("[OID4VP-IDP] Generated QR code, base64 length: %d", qrCodeBase64.length());
                    }
                } catch (Exception e) {
                    LOG.warnf(e, "[OID4VP-IDP] Failed to build redirect flow request object: %s", e.getMessage());
                    // Continue without redirect flows - DC API might still work
                }
            }

            // Return the login form directly
            return session.getProvider(org.keycloak.forms.login.LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setAttribute("state", state)
                    .setAttribute("nonce", nonce)
                    .setAttribute("clientId", clientId)
                    .setAttribute("responseUri", redirectUri)
                    .setAttribute("dcqlQuery", buildDcqlQueryFromConfig())
                    .setAttribute("dcApiRequestObject", requestObject != null ? requestObject.requestObjectJwt() : null)
                    .setAttribute("idpAlias", getConfig().getAlias())
                    .setAttribute("formActionUrl", formActionUrl)
                    // Flow enable flags
                    .setAttribute("dcApiEnabled", dcApiEnabled)
                    .setAttribute("sameDeviceEnabled", sameDeviceEnabled)
                    .setAttribute("crossDeviceEnabled", crossDeviceEnabled)
                    // Redirect flow URLs
                    .setAttribute("sameDeviceWalletUrl", sameDeviceWalletUrl)
                    .setAttribute("crossDeviceWalletUrl", crossDeviceWalletUrl)
                    .setAttribute("qrCodeBase64", qrCodeBase64)
                    .createForm("login-oid4vp-idp.ftl");

        } catch (Exception e) {
            LOG.errorf(e, "[OID4VP-IDP] Failed to initiate OID4VP login: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to initiate wallet login", e);
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        // OID4VP doesn't have persistent tokens like OAuth
        return null;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(session, realm, this, callback, event);
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
        if ((vpToken == null || vpToken.isBlank()) && encryptedResponse != null && !encryptedResponse.isBlank()) {
            LOG.infof("[OID4VP-IDP] Decrypting encrypted response...");
            String encryptionKey = authSession.getAuthNote(SESSION_ENCRYPTION_KEY);
            LOG.infof("[OID4VP-IDP] Encryption key present: %b", encryptionKey != null && !encryptionKey.isBlank());
            try {
                var node = dcApiRequestObjectService.decryptEncryptedResponse(encryptedResponse, encryptionKey);
                LOG.infof("[OID4VP-IDP] Decrypted response: %s", node != null ? node.toString().substring(0, Math.min(200, node.toString().length())) : "null");
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
                redirectFlowResponseUri
        );
        LOG.infof("[OID4VP-IDP] VP token verified, format: %s, credentials: %d",
                result.format(), result.credentials().size());

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
        String value = baseUri.toString() + "realms/" + realm.getName();
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
                config.getVerifierInfo()
        );
    }

    private static String randomState() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Callback endpoint for OID4VP Identity Provider.
     * Receives the VP token from the wallet and processes authentication.
     * <p>
     * This is a static inner class (standard Keycloak pattern) to avoid CDI bean discovery.
     * The @Vetoed annotation explicitly excludes this from CDI bean discovery.
     */
    @Vetoed
    @Path("")
    public static class Endpoint {

        private static final Logger LOG = Logger.getLogger(Endpoint.class);

        private final KeycloakSession session;
        private final RealmModel realm;
        private final Oid4vpIdentityProvider provider;
        private final AuthenticationCallback callback;
        private final EventBuilder event;

        public Endpoint(
                KeycloakSession session,
                RealmModel realm,
                Oid4vpIdentityProvider provider,
                AuthenticationCallback callback,
                EventBuilder event) {
            LOG.infof("[OID4VP-ENDPOINT] Constructor called - realm=%s, provider=%s",
                    realm != null ? realm.getName() : "null",
                    provider != null ? provider.getConfig().getAlias() : "null");
            this.session = session;
            this.realm = realm;
            this.provider = provider;
            this.callback = callback;
            this.event = event;
        }

        private IdentityProviderModel getIdpModel() {
            return provider.getConfig();
        }

        /**
         * Handle GET callback (used for errors).
         */
        @GET
        public Response handleGet(
                @QueryParam("state") String state,
                @QueryParam("error") String error,
                @QueryParam("error_description") String errorDescription) {

            LOG.infof("[OID4VP-ENDPOINT] ========== GET callback received ==========");
            LOG.infof("[OID4VP-ENDPOINT] state: %s, error: %s, error_description: %s", state, error, errorDescription);

            // Try to resolve auth session for proper error handling
            AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
            if (authSession == null && state != null) {
                try {
                    authSession = callback.getAndVerifyAuthenticationSession(state);
                } catch (Exception e) {
                    LOG.warnf("[OID4VP-ENDPOINT] GET: getAndVerifyAuthenticationSession failed: %s", e.getMessage());
                }
            }

            if (error != null && !error.isBlank()) {
                if (authSession != null) {
                    return handleError(state, error, errorDescription, authSession, false);
                } else {
                    // Fallback: return simple error page if no session
                    LOG.warnf("[OID4VP-ENDPOINT] GET: No auth session for error handling, returning simple error");
                    event.event(EventType.LOGIN_ERROR)
                            .detail("error", error)
                            .detail("error_description", errorDescription)
                            .error(Errors.IDENTITY_PROVIDER_ERROR);
                    return callback.error(getIdpModel(), error + (errorDescription != null ? ": " + errorDescription : ""));
                }
            }

            // GET without error is unexpected - redirect to login
            LOG.warnf("[OID4VP-ENDPOINT] Unexpected GET callback without error. State: %s", state);
            return callback.error(getIdpModel(), "No credential response received");
        }

        /**
         * Handle POST callback with VP token from wallet.
         */
        @POST
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        public Response handlePost(
                @QueryParam("state") String queryState,
                @QueryParam("tab_id") String tabId,
                @QueryParam("session_code") String sessionCode,
                @QueryParam("client_data") String clientData,
                @FormParam("state") String formState,
                @FormParam("vp_token") String vpToken,
                @FormParam("response") String encryptedResponse,
                @FormParam("error") String error,
                @FormParam("error_description") String errorDescription) {

            LOG.infof("[OID4VP-ENDPOINT] ========== POST callback received ==========");
            LOG.infof("[OID4VP-ENDPOINT] Query params - queryState: %s, tab_id: %s, session_code: %s, client_data length: %d",
                    queryState, tabId, sessionCode, clientData != null ? clientData.length() : 0);
            LOG.infof("[OID4VP-ENDPOINT] Form params - formState: %s, vpToken length: %d, encryptedResponse length: %d, error: %s",
                    formState,
                    vpToken != null ? vpToken.length() : 0,
                    encryptedResponse != null ? encryptedResponse.length() : 0,
                    error);
            // Prefer query state (OAuth2 style) over form state
            String state = queryState != null && !queryState.isBlank() ? queryState : formState;
            LOG.infof("[OID4VP-ENDPOINT] Resolved state: %s (query=%s, form=%s)", state, queryState, formState);
            LOG.infof("[OID4VP-ENDPOINT] vp_token present: %b, length: %d",
                    vpToken != null && !vpToken.isBlank(),
                    vpToken != null ? vpToken.length() : 0);
            LOG.infof("[OID4VP-ENDPOINT] encryptedResponse present: %b, length: %d",
                    encryptedResponse != null && !encryptedResponse.isBlank(),
                    encryptedResponse != null ? encryptedResponse.length() : 0);
            LOG.infof("[OID4VP-ENDPOINT] error: %s, error_description: %s", error, errorDescription);
            LOG.infof("[OID4VP-ENDPOINT] realm: %s", realm != null ? realm.getName() : "null");
            LOG.infof("[OID4VP-ENDPOINT] provider config alias: %s", provider.getConfig() != null ? provider.getConfig().getAlias() : "null");

            // Note: Error handling is deferred until after auth session resolution
            // This is needed for direct_post flow where auth session is resolved via REQUEST_OBJECT_STORE
            boolean hasError = error != null && !error.isBlank();

            // Declare authSession outside try block so it's accessible in catch blocks
            AuthenticationSessionModel authSession = null;

            // Track whether this is a direct_post flow (from external wallet without cookies)
            // This determines if we need to return a redirect_uri in JSON body instead of HTTP 302
            boolean isDirectPostFlow = false;

            // Track whether we found a valid root session from cookies (indicating browser request)
            // This is used to prevent incorrectly treating DC API browser requests as direct_post
            boolean foundRootSessionFromCookie = false;

            try {
                // Try to get the auth session from the Keycloak context
                // The IdentityBrokerService should have already parsed the session before calling our callback
                LOG.infof("[OID4VP-ENDPOINT] Attempting session lookup via context");
                authSession = session.getContext().getAuthenticationSession();
                LOG.infof("[OID4VP-ENDPOINT] Context auth session: %s",
                        authSession != null ? "found (tabId=" + authSession.getTabId() + ")" : "null");

                // If context doesn't have it, try getAndVerifyAuthenticationSession with the state
                if (authSession == null && state != null) {
                    LOG.infof("[OID4VP-ENDPOINT] Trying getAndVerifyAuthenticationSession with state: %s", state);
                    try {
                        authSession = callback.getAndVerifyAuthenticationSession(state);
                        LOG.infof("[OID4VP-ENDPOINT] getAndVerifyAuthenticationSession returned: %s",
                                authSession != null ? "found" : "null");
                    } catch (Exception e) {
                        LOG.warnf("[OID4VP-ENDPOINT] getAndVerifyAuthenticationSession failed: %s", e.getMessage());
                    }
                }

                // If still null, try using AuthenticationSessionManager directly with the tabId
                if (authSession == null && tabId != null && !tabId.isBlank()) {
                    LOG.infof("[OID4VP-ENDPOINT] Trying AuthenticationSessionManager with tabId: %s", tabId);
                    try {
                        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
                        // Try to get root session from cookie
                        RootAuthenticationSessionModel rootSession = authSessionManager.getCurrentRootAuthenticationSession(realm);
                        LOG.infof("[OID4VP-ENDPOINT] Root session from cookie: %s",
                                rootSession != null ? "found (id=" + rootSession.getId() + ")" : "null");

                        // Track if we found a root session from cookie - this indicates a browser request
                        if (rootSession != null) {
                            foundRootSessionFromCookie = true;
                        }
                        if (rootSession != null) {
                            // Log all available auth sessions in root session
                            LOG.infof("[OID4VP-ENDPOINT] Root session has %d auth sessions", rootSession.getAuthenticationSessions().size());
                            for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
                                LOG.infof("[OID4VP-ENDPOINT]   - Auth session: tabId=%s, client=%s",
                                        entry.getKey(), entry.getValue().getClient() != null ? entry.getValue().getClient().getClientId() : "null");
                            }

                            // Try with context client
                            var contextClient = session.getContext().getClient();
                            LOG.infof("[OID4VP-ENDPOINT] Context client: %s", contextClient != null ? contextClient.getClientId() : "null");
                            if (contextClient != null) {
                                authSession = rootSession.getAuthenticationSession(contextClient, tabId);
                                LOG.infof("[OID4VP-ENDPOINT] Auth session for context client + tabId: %s",
                                        authSession != null ? "found" : "null");
                            }

                            // If not found, try to find auth session by tabId alone (iterate through all)
                            if (authSession == null) {
                                for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
                                    if (entry.getKey().equals(tabId)) {
                                        authSession = entry.getValue();
                                        LOG.infof("[OID4VP-ENDPOINT] Found auth session by tabId iteration: client=%s",
                                                authSession.getClient() != null ? authSession.getClient().getClientId() : "null");
                                        break;
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        LOG.warnf("[OID4VP-ENDPOINT] AuthenticationSessionManager lookup failed: %s", e.getMessage());
                    }
                }

                // If still null, try looking up via REQUEST_OBJECT_STORE using state
                // This is needed for direct_post from external wallets which don't have cookies
                if (authSession == null && state != null) {
                    LOG.infof("[OID4VP-ENDPOINT] Trying REQUEST_OBJECT_STORE lookup by state: %s", state);
                    try {
                        Oid4vpRequestObjectStore.StoredRequestObject storedRequest = REQUEST_OBJECT_STORE.resolveByState(session, state);
                        if (storedRequest != null && storedRequest.rootSessionId() != null) {
                            LOG.infof("[OID4VP-ENDPOINT] Found stored request with rootSessionId: %s, clientId: %s",
                                    storedRequest.rootSessionId(), storedRequest.clientId());

                            // Only treat as direct_post flow if we didn't find a root session from cookies
                            // If foundRootSessionFromCookie is true, this is likely a DC API browser request
                            // where the auth session lookup by tabId failed, but the browser still has cookies
                            if (!foundRootSessionFromCookie) {
                                isDirectPostFlow = true;
                                LOG.infof("[OID4VP-ENDPOINT] Setting isDirectPostFlow = true (session found via REQUEST_OBJECT_STORE, no cookie-based root session)");
                            } else {
                                LOG.infof("[OID4VP-ENDPOINT] Keeping isDirectPostFlow = false (found root session from cookie, treating as browser request)");
                            }

                            // Look up the root session by ID
                            RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                                    .getRootAuthenticationSession(realm, storedRequest.rootSessionId());
                            if (rootSession != null) {
                                LOG.infof("[OID4VP-ENDPOINT] Found root session by ID, has %d auth sessions",
                                        rootSession.getAuthenticationSessions().size());

                                // Find auth session by tabId (extracted from state)
                                if (tabId != null) {
                                    for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
                                        if (entry.getKey().equals(tabId)) {
                                            authSession = entry.getValue();
                                            LOG.infof("[OID4VP-ENDPOINT] Found auth session via stored rootSessionId + tabId: client=%s",
                                                    authSession.getClient() != null ? authSession.getClient().getClientId() : "null");
                                            break;
                                        }
                                    }
                                }

                                // If still not found, try with stored clientId
                                if (authSession == null && storedRequest.clientId() != null) {
                                    var client = realm.getClientByClientId(storedRequest.clientId());
                                    if (client != null && tabId != null) {
                                        authSession = rootSession.getAuthenticationSession(client, tabId);
                                        LOG.infof("[OID4VP-ENDPOINT] Found auth session via stored clientId + tabId: %s",
                                                authSession != null ? "found" : "null");
                                    }
                                }
                            } else {
                                LOG.warnf("[OID4VP-ENDPOINT] Root session not found for stored rootSessionId: %s",
                                        storedRequest.rootSessionId());
                            }
                        } else {
                            LOG.infof("[OID4VP-ENDPOINT] No stored request found for state: %s", state);
                        }
                    } catch (Exception e) {
                        LOG.warnf("[OID4VP-ENDPOINT] REQUEST_OBJECT_STORE lookup failed: %s", e.getMessage());
                    }
                }

                if (authSession == null) {
                    LOG.warnf("[OID4VP-ENDPOINT] Authentication session NOT FOUND for state: %s", state);
                    event.event(EventType.LOGIN_ERROR)
                            .error(Errors.SESSION_EXPIRED);
                    return callback.error(getIdpModel(), "Session expired or invalid");
                }
                LOG.infof("[OID4VP-ENDPOINT] Auth session found: tabId=%s, client=%s",
                        authSession.getTabId(),
                        authSession.getClient() != null ? authSession.getClient().getClientId() : "null");
                LOG.infof("[OID4VP-ENDPOINT] Auth session notes - state: %s, nonce: %s",
                        authSession.getAuthNote(SESSION_STATE),
                        authSession.getAuthNote(SESSION_NONCE));

                // Handle wallet errors now that we have the auth session
                if (hasError) {
                    LOG.infof("[OID4VP-ENDPOINT] Handling error response after session resolution, isDirectPostFlow: %b", isDirectPostFlow);
                    return handleError(state, error, errorDescription, authSession, isDirectPostFlow);
                }

                // Process the callback through the identity provider
                LOG.infof("[OID4VP-ENDPOINT] Calling provider.processCallback()");
                BrokeredIdentityContext context = provider.processCallback(
                        authSession, state, vpToken, encryptedResponse, error, errorDescription);
                LOG.infof("[OID4VP-ENDPOINT] processCallback returned context: id=%s, username=%s",
                        context != null ? context.getId() : "null",
                        context != null ? context.getUsername() : "null");

                // Set the auth session
                context.setAuthenticationSession(authSession);
                LOG.infof("[OID4VP-ENDPOINT] Set auth session on context");

                // Let Keycloak handle the rest (user lookup/creation, first broker login flow, etc.)
                LOG.infof("[OID4VP-ENDPOINT] Calling callback.authenticated()");
                Response response = callback.authenticated(context);
                LOG.infof("[OID4VP-ENDPOINT] callback.authenticated() returned status: %d, isDirectPostFlow: %b",
                        response != null ? response.getStatus() : -1, isDirectPostFlow);

                // For direct_post flow, return redirect_uri in JSON body instead of HTTP 302
                // This is required by OID4VP spec for wallets that POST directly without browser context
                if (isDirectPostFlow && response != null) {
                    int status = response.getStatus();
                    URI location = response.getLocation();
                    LOG.infof("[OID4VP-ENDPOINT] Direct post flow - status: %d, location: %s, headers: %s",
                            status, location, response.getHeaders());

                    // Handle 302/303 redirects
                    if ((status == 302 || status == 303) && location != null) {
                        LOG.infof("[OID4VP-ENDPOINT] Converting redirect to JSON response for direct_post flow");
                        LOG.infof("[OID4VP-ENDPOINT] redirect_uri: %s", location);
                        String jsonResponse = "{\"redirect_uri\":\"" + location.toString() + "\"}";
                        return Response.ok(jsonResponse)
                                .type(MediaType.APPLICATION_JSON)
                                .build();
                    }

                    // Also check Location header manually (some Keycloak responses use different methods)
                    if ((status == 302 || status == 303) && location == null) {
                        Object locationHeader = response.getHeaders().getFirst("Location");
                        if (locationHeader != null) {
                            LOG.infof("[OID4VP-ENDPOINT] Found Location in headers: %s", locationHeader);
                            String jsonResponse = "{\"redirect_uri\":\"" + locationHeader.toString() + "\"}";
                            return Response.ok(jsonResponse)
                                    .type(MediaType.APPLICATION_JSON)
                                    .build();
                        }
                    }

                    // If status is 200, it might be a HTML page (first login flow, etc.)
                    // We need to return something to the wallet in this case too
                    if (status == 200 && location == null) {
                        LOG.warnf("[OID4VP-ENDPOINT] Direct post flow got 200 without redirect - returning success without redirect_uri");
                        // Return empty JSON response - the wallet interaction is complete but user needs to continue in browser
                        return Response.ok("{}")
                                .type(MediaType.APPLICATION_JSON)
                                .build();
                    }
                }

                return response;

            } catch (IdentityBrokerException e) {
                LOG.warnf("[OID4VP-ENDPOINT] Identity broker error: %s", e.getMessage());
                event.event(EventType.LOGIN_ERROR)
                        .detail("reason", e.getMessage())
                        .error(Errors.IDENTITY_PROVIDER_ERROR);

                // Clean up stored request objects for this state to allow clean retry
                if (state != null) {
                    REQUEST_OBJECT_STORE.removeByState(session, state);
                    LOG.infof("[OID4VP-ENDPOINT] Removed request objects for state after IdentityBrokerException: %s", state);
                }

                // Note: Don't clear session notes - Keycloak manages auth session state

                // Set auth session in context if available (needed for callback.error/cancelled to work)
                if (authSession != null) {
                    session.getContext().setAuthenticationSession(authSession);
                }

                // Check if this is a user cancellation error (access_denied from encrypted response)
                String errorMessage = e.getMessage();
                boolean isUserCancellation = errorMessage != null &&
                        (errorMessage.contains("access_denied") || errorMessage.contains("user_cancelled"));

                Response errorResponse;
                if (isUserCancellation) {
                    LOG.infof("[OID4VP-ENDPOINT] User cancellation detected, calling callback.cancelled()");
                    errorResponse = callback.cancelled(getIdpModel());
                } else {
                    errorResponse = callback.error(getIdpModel(), e.getMessage());
                }

                // For direct_post flow, convert redirect to JSON response
                if (isDirectPostFlow && errorResponse != null) {
                    return convertErrorResponseForDirectPost(errorResponse);
                }

                return errorResponse;

            } catch (Exception e) {
                LOG.errorf("[OID4VP-ENDPOINT] Unexpected error processing OID4VP callback: %s", e.getMessage());
                LOG.errorf(e, "[OID4VP-ENDPOINT] Full exception stack trace");
                event.event(EventType.LOGIN_ERROR)
                        .detail("reason", e.getMessage())
                        .error(Errors.IDENTITY_PROVIDER_ERROR);

                // Clean up stored request objects for this state to allow clean retry
                if (state != null) {
                    REQUEST_OBJECT_STORE.removeByState(session, state);
                    LOG.infof("[OID4VP-ENDPOINT] Removed request objects for state after unexpected error: %s", state);
                }

                // Note: Don't clear session notes - Keycloak manages auth session state

                // Set auth session in context if available (needed for callback.error to work)
                if (authSession != null) {
                    session.getContext().setAuthenticationSession(authSession);
                }

                Response errorResponse = callback.error(getIdpModel(), "Authentication failed: " + e.getMessage());

                // For direct_post flow, convert redirect to JSON response
                if (isDirectPostFlow && errorResponse != null) {
                    return convertErrorResponseForDirectPost(errorResponse);
                }

                return errorResponse;
            }
        }

        /**
         * Convert an error response to JSON format for direct_post flow.
         */
        private Response convertErrorResponseForDirectPost(Response response) {
            int status = response.getStatus();
            URI location = response.getLocation();
            LOG.infof("[OID4VP-ENDPOINT] Converting error response for direct_post - status: %d, location: %s", status, location);

            if ((status == 302 || status == 303) && location != null) {
                LOG.infof("[OID4VP-ENDPOINT] Converting error redirect to JSON for direct_post flow");
                String jsonResponse = "{\"redirect_uri\":\"" + location.toString() + "\"}";
                return Response.ok(jsonResponse)
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Also check Location header manually
            if ((status == 302 || status == 303)) {
                Object locationHeader = response.getHeaders().getFirst("Location");
                if (locationHeader != null) {
                    LOG.infof("[OID4VP-ENDPOINT] Found Location in error response headers: %s", locationHeader);
                    String jsonResponse = "{\"redirect_uri\":\"" + locationHeader.toString() + "\"}";
                    return Response.ok(jsonResponse)
                            .type(MediaType.APPLICATION_JSON)
                            .build();
                }
            }

            return response;
        }

        /**
         * GET request-object endpoint for redirect flows.
         * Wallet fetches the signed request object using request_uri.
         */
        @GET
        @Path("/request-object/{id}")
        @Produces("application/oauth-authz-req+jwt")
        public Response getRequestObject(@PathParam("id") String id) {
            LOG.infof("[OID4VP-ENDPOINT] ========== GET request-object called ==========");
            LOG.infof("[OID4VP-ENDPOINT] Request object id: %s", id);

            if (id == null || id.isBlank()) {
                LOG.warnf("[OID4VP-ENDPOINT] Missing request object id");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing request object id\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            Oid4vpRequestObjectStore.StoredRequestObject stored = REQUEST_OBJECT_STORE.resolve(session, id);
            if (stored == null) {
                LOG.warnf("[OID4VP-ENDPOINT] Request object not found or expired: %s", id);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("{\"error\":\"not_found\",\"error_description\":\"Request object not found or expired\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            LOG.infof("[OID4VP-ENDPOINT] Returning request object JWT, length: %d", stored.requestObjectJwt().length());
            return Response.ok(stored.requestObjectJwt())
                    .type("application/oauth-authz-req+jwt")
                    .build();
        }

        /**
         * POST request-object endpoint for advanced wallet flows.
         * Per OID4VP spec, when wallet POSTs with wallet_nonce, the verifier MUST
         * return a new request object that includes the wallet_nonce claim.
         */
        @POST
        @Path("/request-object/{id}")
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces("application/oauth-authz-req+jwt")
        public Response postRequestObject(
                @PathParam("id") String id,
                @FormParam("wallet_metadata") String walletMetadata,
                @FormParam("wallet_nonce") String walletNonce) {

            LOG.infof("[OID4VP-ENDPOINT] ========== POST request-object called ==========");
            LOG.infof("[OID4VP-ENDPOINT] Request object id: %s", id);
            LOG.infof("[OID4VP-ENDPOINT] wallet_metadata present: %b, wallet_nonce: %s",
                    walletMetadata != null && !walletMetadata.isBlank(), walletNonce);

            if (id == null || id.isBlank()) {
                LOG.warnf("[OID4VP-ENDPOINT] Missing request object id");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing request object id\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            Oid4vpRequestObjectStore.StoredRequestObject stored = REQUEST_OBJECT_STORE.resolve(session, id);
            if (stored == null) {
                LOG.warnf("[OID4VP-ENDPOINT] Request object not found or expired: %s", id);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("{\"error\":\"not_found\",\"error_description\":\"Request object not found or expired\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // If wallet_nonce is provided, rebuild the request object with it
            if (walletNonce != null && !walletNonce.isBlank() && stored.rebuildParams() != null) {
                LOG.infof("[OID4VP-ENDPOINT] Rebuilding request object with wallet_nonce");
                try {
                    Oid4vpRedirectFlowService.SignedRequestObject rebuilt = provider.redirectFlowService.rebuildWithWalletNonce(
                            stored.rebuildParams(),
                            stored.state(),
                            stored.nonce(),
                            walletNonce
                    );
                    LOG.infof("[OID4VP-ENDPOINT] Returning rebuilt request object with wallet_nonce, JWT length: %d",
                            rebuilt.jwt().length());
                    return Response.ok(rebuilt.jwt())
                            .type("application/oauth-authz-req+jwt")
                            .build();
                } catch (Exception e) {
                    LOG.errorf(e, "[OID4VP-ENDPOINT] Failed to rebuild request object with wallet_nonce");
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity("{\"error\":\"server_error\",\"error_description\":\"Failed to rebuild request object\"}")
                            .type(MediaType.APPLICATION_JSON)
                            .build();
                }
            }

            // No wallet_nonce or no rebuild params - return original request object
            LOG.infof("[OID4VP-ENDPOINT] Returning original request object JWT, length: %d", stored.requestObjectJwt().length());
            return Response.ok(stored.requestObjectJwt())
                    .type("application/oauth-authz-req+jwt")
                    .build();
        }

        private Response handleError(String state, String error, String errorDescription,
                                      AuthenticationSessionModel authSession, boolean isDirectPostFlow) {
            String message = errorDescription != null && !errorDescription.isBlank()
                    ? error + ": " + errorDescription
                    : error;

            LOG.warnf("Wallet returned error. State: %s, Error: %s, isDirectPostFlow: %b", state, message, isDirectPostFlow);

            event.event(EventType.LOGIN_ERROR)
                    .detail("error", error)
                    .detail("error_description", errorDescription)
                    .error(Errors.IDENTITY_PROVIDER_ERROR);

            // Clean up stored request objects for this state to allow clean retry
            if (state != null) {
                REQUEST_OBJECT_STORE.removeByState(session, state);
                LOG.infof("[OID4VP-ENDPOINT] Removed request objects for state: %s", state);
            }

            // For browser-based flows, redirect back to the IdP login page (with the "Sign in with Wallet" button)
            // This preserves the authentication session and allows the user to retry without losing PKCE state
            if (!isDirectPostFlow) {
                String idpLoginUrl = buildIdpLoginPageUrl(authSession);
                if (idpLoginUrl != null) {
                    LOG.infof("[OID4VP-ENDPOINT] Redirecting to IdP login page for retry: %s", idpLoginUrl);
                    return Response.status(Response.Status.FOUND)
                            .location(URI.create(idpLoginUrl))
                            .build();
                }
            }

            // For direct_post flow, redirect to fresh auth URL (JSON response)
            if (isDirectPostFlow) {
                String freshAuthUrl = buildFreshAuthenticationUrl(authSession);
                if (freshAuthUrl != null) {
                    LOG.infof("[OID4VP-ENDPOINT] Returning JSON redirect for direct_post flow: %s", freshAuthUrl);
                    String jsonResponse = "{\"redirect_uri\":\"" + freshAuthUrl + "\"}";
                    return Response.ok(jsonResponse)
                            .type(MediaType.APPLICATION_JSON)
                            .build();
                }
            }

            // Fallback to standard callback handling if we can't build a redirect URL
            LOG.warnf("[OID4VP-ENDPOINT] Could not build fresh auth URL, falling back to callback handling");
            session.getContext().setAuthenticationSession(authSession);

            Response response;
            // Check for user cancellation
            if ("access_denied".equals(error) || "user_cancelled".equals(error)) {
                response = callback.cancelled(getIdpModel());
            } else {
                response = callback.error(getIdpModel(), message);
            }

            // For direct_post flow, convert redirect to JSON response
            if (response != null) {
                int status = response.getStatus();
                URI location = response.getLocation();
                LOG.infof("[OID4VP-ENDPOINT] Error response for direct_post - status: %d, location: %s", status, location);

                if ((status == 302 || status == 303) && location != null) {
                    LOG.infof("[OID4VP-ENDPOINT] Converting error redirect to JSON for direct_post flow");
                    String jsonResponse = "{\"redirect_uri\":\"" + location.toString() + "\"}";
                    return Response.ok(jsonResponse)
                            .type(MediaType.APPLICATION_JSON)
                            .build();
                }

                // Also check Location header manually
                if ((status == 302 || status == 303)) {
                    Object locationHeader = response.getHeaders().getFirst("Location");
                    if (locationHeader != null) {
                        LOG.infof("[OID4VP-ENDPOINT] Found Location in error response headers: %s", locationHeader);
                        String jsonResponse = "{\"redirect_uri\":\"" + locationHeader.toString() + "\"}";
                        return Response.ok(jsonResponse)
                                .type(MediaType.APPLICATION_JSON)
                                .build();
                    }
                }
            }

            return response;
        }

        /**
         * Build the IdP login page URL (where the "Sign in with Wallet" button is).
         * This preserves the authentication session and allows retry without losing PKCE state.
         */
        private String buildIdpLoginPageUrl(AuthenticationSessionModel authSession) {
            try {
                if (authSession == null) {
                    return null;
                }

                // Get the stored session identifiers from performLogin
                String tabId = authSession.getAuthNote("oid4vp_tab_id");
                String clientData = authSession.getAuthNote("oid4vp_client_data");
                String sessionCode = authSession.getAuthNote("oid4vp_session_code");

                LOG.infof("[OID4VP-ENDPOINT] Building IdP login URL - tabId: %s, clientData length: %d, sessionCode: %s",
                        tabId, clientData != null ? clientData.length() : 0, sessionCode);

                // Build the IdP login page URL
                // Format: /realms/{realm}/broker/{idp}/login?tab_id=...&client_data=...&session_code=...
                StringBuilder url = new StringBuilder();
                url.append(session.getContext().getUri().getBaseUri().toString());
                url.append("realms/").append(realm.getName());
                url.append("/broker/").append(getIdpModel().getAlias()).append("/login");

                boolean hasParam = false;
                if (tabId != null && !tabId.isEmpty()) {
                    url.append("?tab_id=").append(urlEncode(tabId));
                    hasParam = true;
                }
                if (clientData != null && !clientData.isEmpty()) {
                    url.append(hasParam ? "&" : "?").append("client_data=").append(urlEncode(clientData));
                    hasParam = true;
                }
                if (sessionCode != null && !sessionCode.isEmpty()) {
                    url.append(hasParam ? "&" : "?").append("session_code=").append(urlEncode(sessionCode));
                }

                return url.toString();
            } catch (Exception e) {
                LOG.warnf(e, "[OID4VP-ENDPOINT] Failed to build IdP login page URL");
                return null;
            }
        }

        /**
         * Build a fresh OIDC authorization URL using the original request parameters.
         * This allows clean retry after wallet errors without "Invalid Request" errors.
         */
        private String buildFreshAuthenticationUrl(AuthenticationSessionModel authSession) {
            try {
                if (authSession == null || authSession.getClient() == null) {
                    return null;
                }

                String clientId = authSession.getClient().getClientId();
                String redirectUri = authSession.getRedirectUri();

                if (clientId == null || redirectUri == null) {
                    LOG.warnf("[OID4VP-ENDPOINT] Missing client_id or redirect_uri for fresh auth URL");
                    return null;
                }

                // Get original request parameters from client notes
                String responseType = authSession.getClientNote("response_type");
                if (responseType == null || responseType.isBlank()) {
                    responseType = "code";
                }

                String scope = authSession.getClientNote("scope");
                if (scope == null || scope.isBlank()) {
                    scope = "openid";
                }

                String originalState = authSession.getClientNote("state");
                String nonce = authSession.getClientNote("nonce");

                // Build the authorization URL
                StringBuilder url = new StringBuilder();
                url.append(session.getContext().getUri().getBaseUri().toString());
                url.append("realms/").append(realm.getName());
                url.append("/protocol/openid-connect/auth");
                url.append("?client_id=").append(urlEncode(clientId));
                url.append("&redirect_uri=").append(urlEncode(redirectUri));
                url.append("&response_type=").append(urlEncode(responseType));
                url.append("&scope=").append(urlEncode(scope));

                if (originalState != null && !originalState.isBlank()) {
                    url.append("&state=").append(urlEncode(originalState));
                }
                if (nonce != null && !nonce.isBlank()) {
                    url.append("&nonce=").append(urlEncode(nonce));
                }

                return url.toString();
            } catch (Exception e) {
                LOG.warnf(e, "[OID4VP-ENDPOINT] Failed to build fresh authentication URL");
                return null;
            }
        }

        private String urlEncode(String value) {
            try {
                return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                return value;
            }
        }
    }
}
