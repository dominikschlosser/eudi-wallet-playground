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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpRequestObjectStore;
import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import com.nimbusds.jose.JWEObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProvider.*;

/**
 * JAX-RS Callback endpoint for OID4VP Identity Provider.
 * Receives the VP token from the wallet and processes authentication.
 * <p>
 * This is a separate class (standard Keycloak pattern) to avoid CDI bean discovery.
 * The @Vetoed annotation explicitly excludes this from CDI bean discovery.
 */
@Vetoed
@Path("")
public class Oid4vpIdentityProviderEndpoint {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderEndpoint.class);
    static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    private static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    private static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    private static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";
    private static final long CROSS_DEVICE_COMPLETE_TTL_SECONDS = 300; // 5 minutes

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpIdentityProvider provider;
    private final AbstractIdentityProvider.AuthenticationCallback callback;
    private final EventBuilder event;
    private final Oid4vpRequestObjectStore requestObjectStore;

    public Oid4vpIdentityProviderEndpoint(
            KeycloakSession session,
            RealmModel realm,
            Oid4vpIdentityProvider provider,
            AbstractIdentityProvider.AuthenticationCallback callback,
            EventBuilder event,
            Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.provider = provider;
        this.callback = callback;
        this.event = event;
        this.requestObjectStore = requestObjectStore;
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

        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession == null && state != null) {
            // Try request-object-store lookup instead of callback.getAndVerifyAuthenticationSession(),
            // which fires error events for OID4VP state format (UUID vs Keycloak encoded format).
            Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolveByState(session, state);
            if (stored != null && stored.rootSessionId() != null) {
                RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                        .getRootAuthenticationSession(realm, stored.rootSessionId());
                if (rootSession != null) {
                    authSession = findAuthSessionFromStoredRequest(rootSession, stored, null);
                }
            }
        }

        if (error != null && !error.isBlank()) {
            if (authSession != null) {
                return handleError(state, error, errorDescription, authSession, false, false);
            } else {
                LOG.warnf("[OID4VP-ENDPOINT] GET: No auth session for error handling, returning simple error");
                event.event(EventType.LOGIN_ERROR)
                        .detail("error", error)
                        .detail("error_description", errorDescription)
                        .error(Errors.IDENTITY_PROVIDER_ERROR);
                return callback.error(getIdpModel(), error + (errorDescription != null ? ": " + errorDescription : ""));
            }
        }

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
            @QueryParam("flow") String flow,
            @FormParam("state") String formState,
            @FormParam("vp_token") String vpToken,
            @FormParam("response") String encryptedResponse,
            @FormParam("error") String error,
            @FormParam("error_description") String errorDescription) {

        // Global safety net: ALL responses to wallets MUST be JSON, never HTML.
        // Any uncaught exception from Keycloak internals would otherwise produce HTML error pages.
        try {
            return handlePostInternal(queryState, tabId, sessionCode, clientData, flow,
                    formState, vpToken, encryptedResponse, error, errorDescription);
        } catch (Exception e) {
            LOG.errorf(e, "[OID4VP-ENDPOINT] Uncaught exception in handlePost: %s", e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"" + jsonEscape(e.getMessage()) + "\"}")
                    .type(MediaType.APPLICATION_JSON).build();
        }
    }

    private Response handlePostInternal(String queryState, String tabId, String sessionCode,
                                         String clientData, String flow, String formState,
                                         String vpToken, String encryptedResponse,
                                         String error, String errorDescription) {
        LOG.infof("[OID4VP-ENDPOINT] ========== POST callback received ==========");
        LOG.infof("[OID4VP-ENDPOINT] Request URI: %s", session.getContext().getUri().getRequestUri());
        logPostParams(queryState, tabId, sessionCode, clientData, formState, vpToken, encryptedResponse, error);

        boolean isCrossDeviceFlow = "cross_device".equals(flow);
        LOG.infof("[OID4VP-ENDPOINT] flow param: '%s', isCrossDeviceFlow: %b", flow, isCrossDeviceFlow);

        String state = queryState != null && !queryState.isBlank() ? queryState : formState;
        boolean hasError = error != null && !error.isBlank();

        // When state is null but we have an encrypted response, the state is inside the JWE.
        // Real wallets using direct_post.jwt send response=<JWE> with no external state.
        // Parse the JWE header kid to find the encryption key, decrypt, and extract state.
        String preDecryptedMdocGeneratedNonce = null;
        if ((state == null || state.isBlank()) && encryptedResponse != null && !encryptedResponse.isBlank()) {
            LOG.infof("[OID4VP-ENDPOINT] State is null with encrypted response - attempting JWE kid lookup");
            try {
                JWEObject jwe = JWEObject.parse(encryptedResponse);
                String kid = jwe.getHeader().getKeyID();
                LOG.infof("[OID4VP-ENDPOINT] JWE kid: %s", kid);
                if (kid != null) {
                    Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolveByKid(session, kid);
                    if (stored != null && stored.encryptionKeyJson() != null) {
                        state = stored.state();
                        LOG.infof("[OID4VP-ENDPOINT] Resolved state from kid lookup: %s", state);
                        // Pre-decrypt to avoid double-decryption in processCallback
                        var decrypted = provider.getDcApiRequestObjectService()
                                .decryptEncryptedResponse(encryptedResponse, stored.encryptionKeyJson());
                        var payload = decrypted.payload();
                        preDecryptedMdocGeneratedNonce = decrypted.mdocGeneratedNonce();
                        if (payload.hasNonNull("vp_token")) {
                            // Set vpToken and clear encryptedResponse so processCallback uses the pre-decrypted value
                            vpToken = payload.get("vp_token").isTextual()
                                    ? payload.get("vp_token").asText()
                                    : payload.get("vp_token").toString();
                            encryptedResponse = null;
                            LOG.infof("[OID4VP-ENDPOINT] Pre-decrypted vp_token from JWE, length: %d", vpToken.length());
                        }
                        if (payload.hasNonNull("error")) {
                            error = payload.get("error").asText("");
                            errorDescription = payload.hasNonNull("error_description")
                                    ? payload.get("error_description").asText("") : null;
                            hasError = true;
                        }
                    }
                }
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] JWE kid lookup/decrypt failed: %s", e.getMessage());
            }
        }

        AuthSessionResolutionResult resolution = resolveAuthSession(state, tabId, sessionCode, clientData,
                isCrossDeviceFlow);
        AuthenticationSessionModel authSession = resolution.authSession();
        // Native wallet detection: if auth session was resolved via request-object-store
        // (not via browser cookies), this POST came from a native wallet app.
        boolean isDirectPostFlow = isCrossDeviceFlow || resolution.isDirectPostFlow();

        if (authSession == null) {
            LOG.warnf("[OID4VP-ENDPOINT] Authentication session NOT FOUND for state: %s", state);
            // The wallet may be re-sending a VP token for an already-completed login
            // (e.g., wallet caches first login's request and retries on second login).
            // If a completed auth result exists, return the redirect_uri so the wallet
            // can "complete" its stale flow and clear its pending state.
            if (state != null) {
                Map<String, String> completedResult = session.singleUseObjects().get(
                        DEFERRED_AUTH_PREFIX + state + ":completed");
                if (completedResult != null) {
                    String completeAuthUrl = buildCompleteAuthUrl(state);
                    LOG.infof("[OID4VP-ENDPOINT] Returning completed auth redirect for stale VP token, state: %s", state);
                    return jsonRedirectResponse(completeAuthUrl);
                }
            }
            event.event(EventType.LOGIN_ERROR).error(Errors.SESSION_EXPIRED);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"session_expired\"}")
                    .type(MediaType.APPLICATION_JSON).build();
        }

        // Store pre-decrypted mdoc_generated_nonce so processCallback can use it
        if (preDecryptedMdocGeneratedNonce != null) {
            authSession.setAuthNote(SESSION_MDOC_GENERATED_NONCE, preDecryptedMdocGeneratedNonce);
            LOG.infof("[OID4VP-ENDPOINT] Stored pre-decrypted mdoc_generated_nonce in auth session");
        }

        // Fix SESSION_RESPONSE_URI from the actual POST URL. When both same-device and
        // cross-device are enabled, each has a different response_uri baked into its JWT.
        // The auth session note may have been overwritten by the second build. The actual
        // POST URL is the definitive response_uri for mDoc SessionTranscript verification.
        // NOTE: Strip wallet-added query params (state) since the mDoc SessionTranscript
        // uses the response_uri from the request object JWT which doesn't include state.
        if (isDirectPostFlow) {
            String actualResponseUri = stripWalletQueryParams(
                    session.getContext().getUri().getRequestUri().toString());
            authSession.setAuthNote(SESSION_RESPONSE_URI, actualResponseUri);
            LOG.infof("[OID4VP-ENDPOINT] Fixed SESSION_RESPONSE_URI from POST URL: %s", actualResponseUri);
        }

        LOG.infof("[OID4VP-ENDPOINT] Auth session found: tabId=%s, client=%s",
                authSession.getTabId(),
                authSession.getClient() != null ? authSession.getClient().getClientId() : "null");

        if (hasError) {
            return handleError(state, error, errorDescription, authSession, isDirectPostFlow, isCrossDeviceFlow);
        }

        return processVpToken(authSession, state, vpToken, encryptedResponse, error, errorDescription,
                isDirectPostFlow, isCrossDeviceFlow);
    }

    /**
     * GET request-object endpoint for redirect flows.
     */
    @GET
    @Path("/request-object/{id}")
    @Produces("application/oauth-authz-req+jwt")
    public Response getRequestObject(@PathParam("id") String id) {
        LOG.infof("[OID4VP-ENDPOINT] ========== GET request-object called, id: %s ==========", id);

        if (id == null || id.isBlank()) {
            return badRequest("Missing request object id");
        }

        Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolve(session, id);
        if (stored == null) {
            LOG.warnf("[OID4VP-ENDPOINT] Request object not found or expired: %s", id);
            return notFound("Request object not found or expired");
        }

        // Update SESSION_RESPONSE_URI to match this request object's response_uri.
        // When DC API + same-device + cross-device are all enabled, each builds a separate
        // request object with a different response_uri. The wallet fetching THIS request object
        // will use its response_uri for the mDoc SessionTranscript. We must set it now so
        // the verifier uses the same response_uri when the VP token POST arrives later.
        updateSessionResponseUri(stored);

        LOG.infof("[OID4VP-ENDPOINT] Returning request object JWT, length: %d", stored.requestObjectJwt().length());
        logRequestObjectClaims(stored.requestObjectJwt());
        return Response.ok(stored.requestObjectJwt())
                .type("application/oauth-authz-req+jwt")
                .build();
    }

    /**
     * POST request-object endpoint for advanced wallet flows with wallet_nonce.
     */
    @POST
    @Path("/request-object/{id}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/oauth-authz-req+jwt")
    public Response postRequestObject(
            @PathParam("id") String id,
            @FormParam("wallet_metadata") String walletMetadata,
            @FormParam("wallet_nonce") String walletNonce) {

        LOG.infof("[OID4VP-ENDPOINT] ========== POST request-object called, id: %s, wallet_nonce: %s ==========",
                id, walletNonce);

        if (id == null || id.isBlank()) {
            return badRequest("Missing request object id");
        }

        Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolve(session, id);
        if (stored == null) {
            LOG.warnf("[OID4VP-ENDPOINT] Request object not found or expired: %s", id);
            return notFound("Request object not found or expired");
        }

        if (walletNonce != null && !walletNonce.isBlank() && stored.rebuildParams() != null) {
            return rebuildRequestObjectWithWalletNonce(stored, walletNonce);
        }

        updateSessionResponseUri(stored);

        LOG.infof("[OID4VP-ENDPOINT] Returning original request object JWT, length: %d", stored.requestObjectJwt().length());
        return Response.ok(stored.requestObjectJwt())
                .type("application/oauth-authz-req+jwt")
                .build();
    }

    /**
     * SSE endpoint for cross-device QR code flow.
     * The desktop browser connects here to wait for the wallet (on a different device)
     * to complete authentication. Sends SSE events when auth completes.
     */
    @GET
    @Path("/cross-device/status")
    @Produces("text/event-stream")
    public Response crossDeviceStatus(@QueryParam("state") String state) {
        LOG.infof("[OID4VP-ENDPOINT] ========== SSE cross-device status requested, state: %s ==========", state);

        if (state == null || state.isBlank()) {
            return badRequest("Missing state parameter");
        }

        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        String realmName = realm.getName();

        StreamingOutput stream = output -> {
            try {
                for (int i = 0; i < 300; i++) { // 5 minutes max (300 * 1s)
                    try (KeycloakSession pollingSession = sessionFactory.create()) {
                        pollingSession.getTransactionManager().begin();
                        try {
                            RealmModel pollingRealm = pollingSession.realms().getRealmByName(realmName);
                            if (pollingRealm == null) {
                                writeSseEvent(output, "error", "{\"error\":\"realm_not_found\"}");
                                return;
                            }
                            SingleUseObjectProvider store = pollingSession.singleUseObjects();
                            Map<String, String> entry = store.get(CROSS_DEVICE_COMPLETE_PREFIX + state);
                            if (entry != null) {
                                String completeAuthUrl = entry.get("complete_auth_url");
                                if (completeAuthUrl != null) {
                                    LOG.infof("[OID4VP-ENDPOINT] SSE: Found deferred auth for state %s", state);
                                    writeSseEvent(output, "complete", "{\"redirect_uri\":\"" + completeAuthUrl + "\"}");
                                } else {
                                    // Legacy: bridge token flow
                                    String bridgeToken = entry.get("bridge_token");
                                    if (bridgeToken != null) {
                                        String bridgeUrl = buildBridgeUrl(bridgeToken);
                                        LOG.infof("[OID4VP-ENDPOINT] SSE: Found bridge completion for state %s", state);
                                        writeSseEvent(output, "complete", "{\"redirect_uri\":\"" + bridgeUrl + "\"}");
                                    }
                                }
                                pollingSession.getTransactionManager().commit();
                                return;
                            }
                            pollingSession.getTransactionManager().commit();
                        } catch (Exception e) {
                            pollingSession.getTransactionManager().rollback();
                            LOG.warnf("[OID4VP-ENDPOINT] SSE: Error checking status: %s", e.getMessage());
                        }
                    }

                    // Send keepalive ping every 5 seconds
                    if (i % 5 == 0) {
                        writeSseEvent(output, "ping", "{}");
                    }

                    Thread.sleep(1000);
                }

                // Timeout
                LOG.infof("[OID4VP-ENDPOINT] SSE: Timeout for state %s", state);
                writeSseEvent(output, "timeout", "{\"error\":\"timeout\"}");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOG.infof("[OID4VP-ENDPOINT] SSE: Interrupted for state %s", state);
            } catch (IOException e) {
                // Client disconnected
                LOG.infof("[OID4VP-ENDPOINT] SSE: Client disconnected for state %s", state);
            }
        };

        return Response.ok(stream)
                .type("text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("Connection", "keep-alive")
                .header("X-Accel-Buffering", "no")
                .build();
    }

    /**
     * Session bridge endpoint for cross-device flow.
     * When authentication completes on the phone, the desktop browser is redirected here
     * to set the Keycloak SSO cookies before navigating to the final redirect URL.
     * Without this, the desktop browser would have no SSO session cookie.
     */
    @GET
    @Path("/cross-device/complete")
    public Response crossDeviceComplete(@QueryParam("token") String token,
                                        @QueryParam("source") String source) {
        LOG.infof("[OID4VP-ENDPOINT] ========== Bridge requested, token: %s, source: %s ==========", token, source);

        if (token == null || token.isBlank()) {
            return badRequest("Missing token parameter");
        }

        // Use non-destructive get() so the bridge URL can be used by BOTH the wallet redirect
        // (which opens a new browser tab) AND the SSE listener (in the original tab that has
        // the SPA's PKCE sessionStorage). Token expires by TTL (5 min).
        Map<String, String> entry = session.singleUseObjects().get(CROSS_DEVICE_COMPLETE_PREFIX + token);
        if (entry == null) {
            LOG.warnf("[OID4VP-ENDPOINT] Bridge completion not found for token: %s", token);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Session expired. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        String redirectUri = entry.get("redirect_uri");
        String userSessionId = entry.get("user_session_id");
        String rootSessionId = entry.get("root_session_id");

        if (redirectUri == null || redirectUri.isBlank()) {
            LOG.warnf("[OID4VP-ENDPOINT] No redirect_uri in completion data for token: %s", token);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Authentication failed. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        // Set AUTH_SESSION_ID cookie so the browser can find the authentication session.
        // This is critical for first-broker-login and other login-actions redirects that
        // require the auth session from a cookie.
        if (rootSessionId != null && !rootSessionId.isBlank()) {
            try {
                LOG.infof("[OID4VP-ENDPOINT] Setting AUTH_SESSION_ID cookie for root session: %s", rootSessionId);
                new AuthenticationSessionManager(session).setAuthSessionCookie(rootSessionId);
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] Failed to set AUTH_SESSION_ID cookie: %s", e.getMessage());
            }
        }

        // Set SSO cookies if we have a user session.
        // When SSO cookies are set, redirect to the base URL (without OIDC params like code/state)
        // so the SPA detects the SSO session and auto-authenticates with a fresh auth code.
        // This avoids issues with PKCE state mismatch (new tab doesn't have sessionStorage)
        // and auth code single-use (two tabs racing to exchange the same code).
        boolean ssoCookieSet = false;
        if (userSessionId != null && !userSessionId.isBlank()) {
            try {
                UserSessionModel userSession = session.sessions().getUserSession(realm, userSessionId);
                if (userSession != null) {
                    UserModel user = userSession.getUser();
                    LOG.infof("[OID4VP-ENDPOINT] Setting SSO cookie for user: %s, session: %s",
                            user.getUsername(), userSessionId);
                    AuthenticationManager.createLoginCookie(session, realm, user, userSession,
                            session.getContext().getUri(), session.getContext().getConnection());
                    ssoCookieSet = true;
                } else {
                    LOG.warnf("[OID4VP-ENDPOINT] User session not found: %s", userSessionId);
                }
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] Failed to set SSO cookie: %s", e.getMessage());
            }
        }

        // When opened by the wallet (same-device flow), show a "login complete" page instead
        // of redirecting to the OIDC callback. The actual OIDC redirect happens in the original
        // browser tab via the SSE listener, which has the PKCE sessionStorage state.
        if ("wallet".equals(source)) {
            LOG.infof("[OID4VP-ENDPOINT] Bridge opened by wallet — showing completion page");
            String html = "<!DOCTYPE html><html><head><title>Login Complete</title>"
                    + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                    + "<style>body{font-family:sans-serif;display:flex;justify-content:center;"
                    + "align-items:center;min-height:100vh;margin:0;background:#f5f5f5;}"
                    + ".card{text-align:center;padding:40px;background:white;border-radius:8px;"
                    + "box-shadow:0 2px 8px rgba(0,0,0,0.1);}"
                    + "h1{color:#333;margin-bottom:10px;}p{color:#666;}</style></head>"
                    + "<body><div class=\"card\"><h1>Login Complete</h1>"
                    + "<p>Authentication successful. You can close this tab.</p>"
                    + "<p>Your original browser tab will complete the login automatically.</p>"
                    + "</div></body></html>";
            return Response.ok(html).type(MediaType.TEXT_HTML).build();
        }

        if (ssoCookieSet) {
            String baseRedirectUri = stripOidcQueryParams(redirectUri);
            LOG.infof("[OID4VP-ENDPOINT] Bridge redirecting to base URL (SSO): %s", baseRedirectUri);
            return Response.status(Response.Status.FOUND).location(URI.create(baseRedirectUri)).build();
        }

        LOG.infof("[OID4VP-ENDPOINT] Bridge redirecting to: %s", redirectUri);
        return Response.status(Response.Status.FOUND).location(URI.create(redirectUri)).build();
    }

    /**
     * Complete deferred authentication in the browser context.
     * Called from the browser (via same-device wallet redirect or cross-device SSE).
     * The browser has proper Keycloak cookies. This endpoint loads the stored identity,
     * calls callback.authenticated(), and returns the redirect that completes the login flow.
     *
     * Same-device: wallet opens this URL in the system browser (same browser, has cookies).
     * Cross-device: SSE in desktop browser auto-navigates here (desktop browser, has cookies).
     */
    @GET
    @Path("/complete-auth")
    public Response completeAuth(@QueryParam("state") String state) {
        LOG.infof("[OID4VP-ENDPOINT] ========== complete-auth requested, state: %s ==========", state);

        if (state == null || state.isBlank()) {
            return badRequest("Missing state parameter");
        }

        // Load deferred auth signal. Use non-destructive get() instead of remove() because
        // the signal expires by TTL (5 minutes) and may be read by diagnostics.
        Map<String, String> signal = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (signal == null) {
            LOG.infof("[OID4VP-ENDPOINT] Deferred auth signal not found for state: %s", state);
            Response ssoRedirect = redirectToAccountIfSsoSession();
            if (ssoRedirect != null) return ssoRedirect;
            // Redirect to the realm login page so the user can retry immediately.
            // This handles the case where the wallet replays a stale complete-auth URL
            // from a previous login (e.g., after Keycloak restart or session expiry).
            return redirectToRealmLoginPage();
        }

        String rootSessionId = signal.get("root_session_id");
        String tabId = signal.get("tab_id");
        LOG.infof("[OID4VP-ENDPOINT] Deferred auth: rootSessionId=%s, tabId=%s", rootSessionId, tabId);

        // Set AUTH_SESSION_ID cookie so Keycloak can find the auth session
        if (rootSessionId != null) {
            try {
                new AuthenticationSessionManager(session).setAuthSessionCookie(rootSessionId);
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] Failed to set AUTH_SESSION_ID cookie: %s", e.getMessage());
            }
        }

        // Find the auth session
        AuthenticationSessionModel authSession = null;
        if (rootSessionId != null) {
            RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                    .getRootAuthenticationSession(realm, rootSessionId);
            if (rootSession == null) {
                LOG.warnf("[OID4VP-ENDPOINT] Root session NOT FOUND: %s (was it removed by a previous callback.authenticated()?)",
                        rootSessionId);
            } else if (tabId != null) {
                LOG.infof("[OID4VP-ENDPOINT] Root session found: %s, has %d auth sessions",
                        rootSessionId, rootSession.getAuthenticationSessions().size());
                logRootSessionContents(rootSession);
                authSession = findAuthSessionInRoot(rootSession, tabId);
            }
        }
        if (authSession == null) {
            // Auth session may have been consumed by a concurrent /complete-auth request
            // (SSE + wallet redirect race). Try recovery strategies.
            LOG.infof("[OID4VP-ENDPOINT] Auth session not found — trying recovery");
            Response recovery = recoverFromConsumedAuthSession(state);
            if (recovery != null) return recovery;
            return redirectToRealmLoginPage();
        }

        // Read the serialized identity from auth session notes
        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);
        if (serializedCtx == null) {
            // Identity already consumed by a concurrent request (SSE + wallet redirect race).
            LOG.infof("[OID4VP-ENDPOINT] Deferred identity already consumed — trying recovery");
            Response recovery = recoverFromConsumedAuthSession(state);
            if (recovery != null) return recovery;
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Authentication data not found. Please try again.")
                    .type(MediaType.TEXT_PLAIN).build();
        }

        // Set the request context so IdentityBrokerService and downstream code can find
        // the auth session and client via session.getContext()
        session.getContext().setAuthenticationSession(authSession);
        session.getContext().setClient(authSession.getClient());

        // Deserialize and authenticate
        BrokeredIdentityContext context = serializedCtx.deserialize(session, authSession);
        context.setAuthenticationSession(authSession);

        // Remove stale user.attributes.* entries from the deserialized context.
        // The deferred identity was serialized BEFORE mappers ran (firstName/lastName were null),
        // so contextData has user.attributes.firstName=[null], user.attributes.lastName=[null], etc.
        // If we don't remove these, SerializedBrokeredIdentityContext.serialize() inside
        // callback.authenticated() will overwrite the mapper-set values with these stale nulls.
        context.getContextData().keySet().removeIf(key -> key.startsWith("user.attributes."));

        // Restore claims from the separate auth note (they don't survive contextData serialization)
        String claimsJson = authSession.getAuthNote(DEFERRED_CLAIMS_NOTE);
        if (claimsJson != null) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> claims = org.keycloak.util.JsonSerialization.readValue(claimsJson, Map.class);
                context.getContextData().put("oid4vp_claims", claims);
                LOG.infof("[OID4VP-ENDPOINT] Restored claims from auth note (%d chars)", claimsJson.length());
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] Failed to deserialize claims: %s", e.getMessage());
            }
            authSession.removeAuthNote(DEFERRED_CLAIMS_NOTE);
        }

        // Clear the note so it's not reused
        authSession.removeAuthNote(DEFERRED_IDENTITY_NOTE);

        event.event(EventType.LOGIN);
        LOG.infof("[OID4VP-ENDPOINT] Calling callback.authenticated() from browser context");
        try {
            Response response = callback.authenticated(context);
            LOG.infof("[OID4VP-ENDPOINT] callback.authenticated() returned status: %d",
                    response != null ? response.getStatus() : -1);

            // Store the completed auth result so a late /complete-auth caller (e.g., wallet's
            // browser tab arriving after SSE already completed auth) can set SSO cookies and redirect.
            storeCompletedAuthResult(state, response);

            // Clean up old request objects (state/kid indexes) so the wallet can't reuse
            // stale kid indexes from a previous login when the user logs in again.
            try {
                requestObjectStore.removeByState(session, state);
                LOG.infof("[OID4VP-ENDPOINT] Cleaned up request objects for state: %s", state);
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] Failed to clean up request objects: %s", e.getMessage());
            }

            return response;
        } catch (Exception e) {
            // Race condition: another request (SSE + wallet redirect) already completed auth.
            LOG.warnf("[OID4VP-ENDPOINT] callback.authenticated() failed: %s — checking SSO", e.getMessage());
            Response ssoRedirect = redirectToAccountIfSsoSession();
            if (ssoRedirect != null) return ssoRedirect;
            throw e;
        }
    }

    /**
     * Store the result of a successful callback.authenticated() so that a late /complete-auth
     * caller can recover. This handles the race where SSE and wallet redirect both hit
     * /complete-auth: the first caller succeeds and stores the result, the second caller
     * (which finds the root auth session consumed) can use this to set SSO cookies and redirect.
     */
    private void storeCompletedAuthResult(String state, Response response) {
        try {
            Map<String, String> result = new HashMap<>();
            // Extract redirect URI from the response
            URI location = response.getLocation();
            if (location == null) {
                Object locationHeader = response.getHeaders().getFirst("Location");
                if (locationHeader != null) {
                    location = URI.create(locationHeader.toString());
                }
            }
            if (location != null) {
                result.put("redirect_uri", location.toString());
            }
            // Store user session ID for SSO cookie setup
            AuthenticationManager.AuthResult authResult =
                    AuthenticationManager.authenticateIdentityCookie(session, realm, true);
            if (authResult != null && authResult.getSession() != null) {
                result.put("user_session_id", authResult.getSession().getId());
            }
            if (!result.isEmpty()) {
                session.singleUseObjects().put(
                        DEFERRED_AUTH_PREFIX + state + ":completed",
                        CROSS_DEVICE_COMPLETE_TTL_SECONDS,
                        result);
                LOG.infof("[OID4VP-ENDPOINT] Stored completed auth result for state: %s", state);
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to store completed auth result: %s", e.getMessage());
        }
    }

    /**
     * Recover when the auth session has been consumed by a previous /complete-auth call.
     * Checks for a stored completed auth result (user session ID + redirect URI) from the
     * first successful caller, sets SSO cookies, and redirects to the application.
     * Falls back to SSO cookie check if no stored result exists.
     */
    private Response recoverFromConsumedAuthSession(String state) {
        // Check for stored completed auth result from a previous successful /complete-auth
        if (state != null) {
            Map<String, String> completedResult = session.singleUseObjects().get(
                    DEFERRED_AUTH_PREFIX + state + ":completed");
            if (completedResult != null) {
                LOG.infof("[OID4VP-ENDPOINT] Found completed auth result for state: %s", state);
                String userSessionId = completedResult.get("user_session_id");
                if (userSessionId != null) {
                    try {
                        UserSessionModel userSession = session.sessions().getUserSession(realm, userSessionId);
                        if (userSession != null) {
                            UserModel user = userSession.getUser();
                            LOG.infof("[OID4VP-ENDPOINT] Setting SSO cookie from completed auth: user=%s", user.getUsername());
                            AuthenticationManager.createLoginCookie(session, realm, user, userSession,
                                    session.getContext().getUri(), session.getContext().getConnection());
                            // Redirect to the base account URL (strip OIDC params to avoid code reuse)
                            String redirectUri = completedResult.get("redirect_uri");
                            if (redirectUri != null) {
                                String baseRedirectUri = stripOidcQueryParams(redirectUri);
                                return Response.status(Response.Status.FOUND)
                                        .location(URI.create(baseRedirectUri)).build();
                            }
                        }
                    } catch (Exception e) {
                        LOG.warnf("[OID4VP-ENDPOINT] Failed to recover from completed auth result: %s", e.getMessage());
                    }
                }
            }
        }
        // Fall back to SSO cookie check
        Response ssoRedirect = redirectToAccountIfSsoSession();
        if (ssoRedirect != null) return ssoRedirect;
        return null;
    }

    private void writeSseEvent(OutputStream output, String event, String data) throws IOException {
        output.write(("event: " + event + "\n").getBytes(StandardCharsets.UTF_8));
        output.write(("data: " + data + "\n\n").getBytes(StandardCharsets.UTF_8));
        output.flush();
    }

    // ==================== Private Helper Methods ====================

    private void logPostParams(String queryState, String tabId, String sessionCode, String clientData,
                               String formState, String vpToken, String encryptedResponse, String error) {
        LOG.infof("[OID4VP-ENDPOINT] state=%s, tab_id=%s, session_code=%s, error=%s, " +
                        "vp_token=%d chars, encrypted_response=%d chars",
                queryState != null ? queryState : formState, tabId, sessionCode, error,
                vpToken != null ? vpToken.length() : 0,
                encryptedResponse != null ? encryptedResponse.length() : 0);
        LOG.debugf("[OID4VP-ENDPOINT] Raw vp_token: %s", vpToken);
    }

    private record AuthSessionResolutionResult(AuthenticationSessionModel authSession, boolean isDirectPostFlow) {}

    private AuthSessionResolutionResult resolveAuthSession(String state, String tabId, String sessionCode,
                                                            String clientData, boolean isCrossDeviceFlow) {
        AuthenticationSessionModel authSession = null;
        boolean isDirectPostFlow = false;
        boolean foundRootSessionFromCookie = false;

        // Detect wallet direct POST: cross-device is always direct post. For same-device,
        // no tabId/sessionCode/clientData means the POST came from a native wallet app.
        boolean isWalletDirectPost = isCrossDeviceFlow
                || ((tabId == null || tabId.isBlank())
                    && (sessionCode == null || sessionCode.isBlank())
                    && (clientData == null || clientData.isBlank()));

        if (isWalletDirectPost) {
            LOG.infof("[OID4VP-ENDPOINT] Wallet direct POST detected (isCrossDevice=%b), skipping cookie-based lookups",
                    isCrossDeviceFlow);
            if (state != null) {
                AuthSessionFromStoreResult storeResult = tryRequestObjectStore(state, tabId, false);
                authSession = storeResult.authSession();
                isDirectPostFlow = storeResult.isDirectPostFlow();
            }
            return new AuthSessionResolutionResult(authSession, isDirectPostFlow);
        }

        // Browser-based flow (DC API): try cookie-based lookups first
        authSession = session.getContext().getAuthenticationSession();
        LOG.infof("[OID4VP-ENDPOINT] Context auth session: %s",
                authSession != null ? "found (tabId=" + authSession.getTabId() + ")" : "null");

        // NOTE: We intentionally do NOT call callback.getAndVerifyAuthenticationSession(state) here.
        // OID4VP uses its own state format (UUID), not Keycloak's encoded state format
        // (clientId.tabId.code.clientData). Calling getAndVerifyAuthenticationSession with an OID4VP
        // state causes Keycloak to fire an IDENTITY_PROVIDER_LOGIN_ERROR event with
        // "invalidRequestMessage" as a side effect before throwing — tainting the event builder
        // and logging spurious errors. The auth session is found via context, AuthSessionManager,
        // or request-object-store instead.

        // Try AuthenticationSessionManager with tabId
        if (authSession == null && tabId != null && !tabId.isBlank()) {
            AuthSessionFromManagerResult managerResult = tryAuthSessionManager(tabId);
            authSession = managerResult.authSession();
            foundRootSessionFromCookie = managerResult.foundRootSession();
        }

        // Try REQUEST_OBJECT_STORE lookup by state
        if (authSession == null && state != null) {
            AuthSessionFromStoreResult storeResult = tryRequestObjectStore(state, tabId, foundRootSessionFromCookie);
            authSession = storeResult.authSession();
            isDirectPostFlow = storeResult.isDirectPostFlow();
        }

        return new AuthSessionResolutionResult(authSession, isDirectPostFlow);
    }

    private record AuthSessionFromManagerResult(AuthenticationSessionModel authSession, boolean foundRootSession) {}

    private AuthSessionFromManagerResult tryAuthSessionManager(String tabId) {
        LOG.infof("[OID4VP-ENDPOINT] Trying AuthenticationSessionManager with tabId: %s", tabId);
        try {
            AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
            RootAuthenticationSessionModel rootSession = authSessionManager.getCurrentRootAuthenticationSession(realm);
            LOG.infof("[OID4VP-ENDPOINT] Root session from cookie: %s",
                    rootSession != null ? "found (id=" + rootSession.getId() + ")" : "null");

            if (rootSession == null) {
                return new AuthSessionFromManagerResult(null, false);
            }

            logRootSessionContents(rootSession);
            AuthenticationSessionModel authSession = findAuthSessionInRoot(rootSession, tabId);
            return new AuthSessionFromManagerResult(authSession, true);
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] AuthenticationSessionManager lookup failed: %s", e.getMessage());
            return new AuthSessionFromManagerResult(null, false);
        }
    }

    private void logRootSessionContents(RootAuthenticationSessionModel rootSession) {
        LOG.infof("[OID4VP-ENDPOINT] Root session has %d auth sessions", rootSession.getAuthenticationSessions().size());
        for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
            LOG.infof("[OID4VP-ENDPOINT]   - Auth session: tabId=%s, client=%s",
                    entry.getKey(), entry.getValue().getClient() != null ? entry.getValue().getClient().getClientId() : "null");
        }
    }

    private AuthenticationSessionModel findAuthSessionInRoot(RootAuthenticationSessionModel rootSession, String tabId) {
        var contextClient = session.getContext().getClient();
        LOG.infof("[OID4VP-ENDPOINT] Context client: %s", contextClient != null ? contextClient.getClientId() : "null");

        if (contextClient != null) {
            AuthenticationSessionModel authSession = rootSession.getAuthenticationSession(contextClient, tabId);
            if (authSession != null) {
                LOG.infof("[OID4VP-ENDPOINT] Auth session for context client + tabId: found");
                return authSession;
            }
        }

        // Try to find by tabId alone
        for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
            if (entry.getKey().equals(tabId)) {
                LOG.infof("[OID4VP-ENDPOINT] Found auth session by tabId iteration: client=%s",
                        entry.getValue().getClient() != null ? entry.getValue().getClient().getClientId() : "null");
                return entry.getValue();
            }
        }
        return null;
    }

    private record AuthSessionFromStoreResult(AuthenticationSessionModel authSession, boolean isDirectPostFlow) {}

    private AuthSessionFromStoreResult tryRequestObjectStore(String state, String tabId, boolean foundRootSessionFromCookie) {
        LOG.infof("[OID4VP-ENDPOINT] Trying REQUEST_OBJECT_STORE lookup by state: %s", state);
        try {
            Oid4vpRequestObjectStore.StoredRequestObject storedRequest = requestObjectStore.resolveByState(session, state);
            if (storedRequest == null || storedRequest.rootSessionId() == null) {
                LOG.infof("[OID4VP-ENDPOINT] No stored request found for state: %s", state);
                return new AuthSessionFromStoreResult(null, false);
            }

            LOG.infof("[OID4VP-ENDPOINT] Found stored request with rootSessionId: %s, clientId: %s",
                    storedRequest.rootSessionId(), storedRequest.clientId());

            boolean isDirectPostFlow = !foundRootSessionFromCookie;
            LOG.infof("[OID4VP-ENDPOINT] isDirectPostFlow = %b (foundRootSessionFromCookie=%b)",
                    isDirectPostFlow, foundRootSessionFromCookie);

            RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                    .getRootAuthenticationSession(realm, storedRequest.rootSessionId());

            if (rootSession == null) {
                LOG.warnf("[OID4VP-ENDPOINT] Root session not found for stored rootSessionId: %s",
                        storedRequest.rootSessionId());
                return new AuthSessionFromStoreResult(null, isDirectPostFlow);
            }

            LOG.infof("[OID4VP-ENDPOINT] Found root session by ID, has %d auth sessions",
                    rootSession.getAuthenticationSessions().size());

            AuthenticationSessionModel authSession = findAuthSessionFromStoredRequest(rootSession, storedRequest, tabId);

            // Update SESSION_RESPONSE_URI to match this specific request object's response_uri.
            // When both same-device and cross-device are enabled, each has its own request object
            // with a different response_uri. The auth session note may have been overwritten by
            // the second request object build. We must fix it here so the mDoc SessionTranscript
            // verification uses the correct response_uri.
            if (authSession != null && storedRequest.requestObjectJwt() != null) {
                updateResponseUriFromRequestObject(authSession, storedRequest.requestObjectJwt());
            }

            return new AuthSessionFromStoreResult(authSession, isDirectPostFlow);
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] REQUEST_OBJECT_STORE lookup failed: %s", e.getMessage());
            return new AuthSessionFromStoreResult(null, false);
        }
    }

    /**
     * Update SESSION_RESPONSE_URI from a stored request object.
     * Called when the wallet fetches the request object (GET/POST /request-object/{id})
     * so the verifier uses the correct response_uri for mDoc SessionTranscript verification.
     */
    private void updateSessionResponseUri(Oid4vpRequestObjectStore.StoredRequestObject stored) {
        if (stored.requestObjectJwt() == null || stored.rootSessionId() == null) return;
        try {
            RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                    .getRootAuthenticationSession(realm, stored.rootSessionId());
            if (rootSession == null) return;
            // Find the auth session (try all tabs)
            for (Map.Entry<String, AuthenticationSessionModel> entry :
                    rootSession.getAuthenticationSessions().entrySet()) {
                AuthenticationSessionModel authSession = entry.getValue();
                String sessionState = authSession.getAuthNote(Oid4vpIdentityProvider.SESSION_STATE);
                if (sessionState != null && sessionState.equals(stored.state())) {
                    updateResponseUriFromRequestObject(authSession, stored.requestObjectJwt());
                    return;
                }
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to update session response URI from request object: %s", e.getMessage());
        }
    }

    private void updateResponseUriFromRequestObject(AuthenticationSessionModel authSession, String requestObjectJwt) {
        try {
            String[] parts = requestObjectJwt.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                // Simple JSON parsing to extract response_uri
                int idx = payload.indexOf("\"response_uri\"");
                if (idx >= 0) {
                    int valueStart = payload.indexOf("\"", idx + 14) + 1;
                    int valueEnd = payload.indexOf("\"", valueStart);
                    if (valueStart > 0 && valueEnd > valueStart) {
                        String responseUri = payload.substring(valueStart, valueEnd);
                        String current = authSession.getAuthNote(SESSION_RESPONSE_URI);
                        if (!responseUri.equals(current)) {
                            LOG.infof("[OID4VP-ENDPOINT] Updating SESSION_RESPONSE_URI from '%s' to '%s'",
                                    current, responseUri);
                            authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to extract response_uri from request object JWT: %s", e.getMessage());
        }
    }

    private AuthenticationSessionModel findAuthSessionFromStoredRequest(
            RootAuthenticationSessionModel rootSession,
            Oid4vpRequestObjectStore.StoredRequestObject storedRequest,
            String tabId) {

        if (tabId != null) {
            for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
                if (entry.getKey().equals(tabId)) {
                    LOG.infof("[OID4VP-ENDPOINT] Found auth session via stored rootSessionId + tabId: client=%s",
                            entry.getValue().getClient() != null ? entry.getValue().getClient().getClientId() : "null");
                    return entry.getValue();
                }
            }
        }

        if (storedRequest.clientId() != null && tabId != null) {
            var client = realm.getClientByClientId(storedRequest.clientId());
            if (client != null) {
                AuthenticationSessionModel authSession = rootSession.getAuthenticationSession(client, tabId);
                LOG.infof("[OID4VP-ENDPOINT] Found auth session via stored clientId + tabId: %s",
                        authSession != null ? "found" : "null");
                return authSession;
            }
        }

        // Fallback: find auth session by matching OID4VP state in session notes (no tabId available)
        if (storedRequest.state() != null) {
            for (var entry : rootSession.getAuthenticationSessions().entrySet()) {
                AuthenticationSessionModel authSession = entry.getValue();
                String sessionState = authSession.getAuthNote(Oid4vpIdentityProvider.SESSION_STATE);
                if (storedRequest.state().equals(sessionState)) {
                    LOG.infof("[OID4VP-ENDPOINT] Found auth session via state match: tabId=%s, client=%s",
                            entry.getKey(),
                            authSession.getClient() != null ? authSession.getClient().getClientId() : "null");
                    return authSession;
                }
            }
        }
        return null;
    }

    private Response processVpToken(AuthenticationSessionModel authSession, String state, String vpToken,
                                    String encryptedResponse, String error, String errorDescription,
                                    boolean isDirectPostFlow, boolean isCrossDeviceFlow) {
        try {
            LOG.infof("[OID4VP-ENDPOINT] Calling provider.processCallback()");
            BrokeredIdentityContext context = provider.processCallback(
                    authSession, state, vpToken, encryptedResponse, error, errorDescription);
            LOG.infof("[OID4VP-ENDPOINT] processCallback returned context: id=%s, username=%s",
                    context != null ? context.getId() : "null",
                    context != null ? context.getUsername() : "null");

            context.setAuthenticationSession(authSession);

            if (isDirectPostFlow) {
                // Auth session was found via stored request object (not via browser cookies).
                // This means the POST came from a native wallet app or cross-device wallet,
                // NOT from a browser form submission. We must defer authentication because
                // the browser needs to complete it via /complete-auth with its own cookies.
                LOG.infof("[OID4VP-ENDPOINT] Direct post flow detected - deferring authentication");
                return deferAuthentication(authSession, context, state, isCrossDeviceFlow);
            }

            // Normal browser flow (redirect-based): call callback.authenticated() directly
            event.event(EventType.LOGIN);
            LOG.infof("[OID4VP-ENDPOINT] Calling callback.authenticated()");
            Response response = callback.authenticated(context);
            LOG.infof("[OID4VP-ENDPOINT] callback.authenticated() returned status: %d",
                    response != null ? response.getStatus() : -1);
            return response;

        } catch (IdentityBrokerException e) {
            return handleIdentityBrokerException(e, state, authSession, isDirectPostFlow, isCrossDeviceFlow);
        } catch (Exception e) {
            return handleUnexpectedException(e, state, authSession, isDirectPostFlow, isCrossDeviceFlow);
        }
    }

    /**
     * Defer authentication to the browser context.
     * Serializes the identity into the auth session and stores a signal so the browser
     * can complete authentication via /complete-auth endpoint (which has cookies).
     *
     * Same-device: wallet opens redirect_uri in system browser → browser has cookies →
     *   /complete-auth calls callback.authenticated() → redirects to application.
     * Cross-device: returns {}. SSE in desktop browser detects signal → navigates to
     *   /complete-auth → callback.authenticated() → redirects to application.
     */
    private Response deferAuthentication(AuthenticationSessionModel authSession,
                                          BrokeredIdentityContext context, String state,
                                          boolean isCrossDeviceFlow) {
        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId() : null;
        String tabId = authSession.getTabId();

        // Store claims as JSON in a separate auth note — the contextData map contains
        // complex objects (Map<String,Object>) that don't survive Keycloak's serialization.
        // The claims are needed by IdP mappers to populate firstName, lastName, etc.
        Object claims = context.getContextData().get("oid4vp_claims");
        if (claims != null) {
            try {
                String claimsJson = org.keycloak.util.JsonSerialization.writeValueAsString(claims);
                authSession.setAuthNote(DEFERRED_CLAIMS_NOTE, claimsJson);
                LOG.infof("[OID4VP-ENDPOINT] Stored %d chars of claims JSON in auth session", claimsJson.length());
            } catch (Exception e) {
                LOG.warnf("[OID4VP-ENDPOINT] Failed to serialize claims: %s", e.getMessage());
            }
        }

        // Serialize identity into auth session so /complete-auth can pick it up
        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.serialize(context);
        serializedCtx.saveToAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);
        LOG.infof("[OID4VP-ENDPOINT] Stored deferred identity for user=%s in auth session", context.getUsername());

        // Store deferred auth signal (for SSE lookup and /complete-auth)
        storeDeferredAuthSignal(state, rootSessionId, tabId, isCrossDeviceFlow);

        if (isCrossDeviceFlow) {
            // Cross-device: return empty JSON. The SSE in the desktop browser detects the
            // completion signal and auto-navigates to /complete-auth which completes auth.
            LOG.infof("[OID4VP-ENDPOINT] Cross-device: returning empty JSON, SSE will redirect browser");
            return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
        }

        // Same-device: return the /complete-auth URL. The wallet opens this in the system
        // browser (which HAS cookies from the original login page). The /complete-auth
        // endpoint loads the deferred identity, calls callback.authenticated(), and
        // redirects directly to the application. No intermediate page needed.
        String completeAuthUrl = buildCompleteAuthUrl(state);
        LOG.infof("[OID4VP-ENDPOINT] Same-device: returning complete-auth URL %s", completeAuthUrl);
        return jsonRedirectResponse(completeAuthUrl);
    }


    /**
     * Store cross-device completion data with a one-time bridge token.
     * The bridge token is a random UUID that serves as an access key for the completion data.
     * This prevents the SSE state (visible in QR code) from being used to hijack the session.
     * Returns the bridge token, or null on failure.
     */
    private String storeCrossDeviceCompletionRedirect(String state, String redirectUri, String userSessionId,
                                                        String rootSessionId) {
        try {
            if (state != null && redirectUri != null) {
                String bridgeToken = UUID.randomUUID().toString();
                Map<String, String> data = new HashMap<>();
                data.put("redirect_uri", redirectUri);
                if (userSessionId != null) {
                    data.put("user_session_id", userSessionId);
                }
                if (rootSessionId != null) {
                    data.put("root_session_id", rootSessionId);
                }
                LOG.infof("[OID4VP-ENDPOINT] Storing cross-device completion for state: %s, bridge token: %s", state, bridgeToken);
                // Store keyed by bridge token (one-time use via get())
                session.singleUseObjects().put(
                        CROSS_DEVICE_COMPLETE_PREFIX + bridgeToken,
                        CROSS_DEVICE_COMPLETE_TTL_SECONDS,
                        data);
                // Store state→bridgeToken mapping for SSE lookup
                session.singleUseObjects().put(
                        CROSS_DEVICE_COMPLETE_PREFIX + state,
                        CROSS_DEVICE_COMPLETE_TTL_SECONDS,
                        Map.of("bridge_token", bridgeToken));
                return bridgeToken;
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to store cross-device completion: %s", e.getMessage());
        }
        return null;
    }

    private String storeCrossDeviceCompletion(String state, Response response, String userSessionId,
                                               String rootSessionId) {
        try {
            URI location = response.getLocation();
            if (location == null) {
                Object locationHeader = response.getHeaders().getFirst("Location");
                if (locationHeader != null) {
                    location = URI.create(locationHeader.toString());
                }
            }
            if (location != null && state != null) {
                String redirectUri = location.toString();
                LOG.infof("[OID4VP-ENDPOINT] Storing cross-device completion for state: %s, redirect: %s", state, redirectUri);
                return storeCrossDeviceCompletionRedirect(state, redirectUri, userSessionId, rootSessionId);
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to store cross-device completion: %s", e.getMessage());
        }
        return null;
    }

    private void storeDeferredAuthSignal(String state, String rootSessionId, String tabId,
                                          boolean isCrossDeviceFlow) {
        try {
            Map<String, String> data = new HashMap<>();
            if (rootSessionId != null) data.put("root_session_id", rootSessionId);
            if (tabId != null) data.put("tab_id", tabId);
            session.singleUseObjects().put(
                    DEFERRED_AUTH_PREFIX + state,
                    CROSS_DEVICE_COMPLETE_TTL_SECONDS,
                    data);
            // Only store SSE signal for cross-device flow.
            // For same-device, the wallet opens /complete-auth directly via redirect_uri.
            // Storing the SSE signal for same-device causes a race: SSE navigates the original
            // browser tab to /complete-auth at the same time the wallet opens it in a new tab,
            // and callback.authenticated() in the first caller consumes the root auth session,
            // leaving the second caller with "auth session not found".
            if (isCrossDeviceFlow) {
                String completeAuthUrl = buildCompleteAuthUrl(state);
                session.singleUseObjects().put(
                        CROSS_DEVICE_COMPLETE_PREFIX + state,
                        CROSS_DEVICE_COMPLETE_TTL_SECONDS,
                        Map.of("complete_auth_url", completeAuthUrl));
            }
            LOG.infof("[OID4VP-ENDPOINT] Stored deferred auth signal for state: %s (sseSignal=%b)", state, isCrossDeviceFlow);
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to store deferred auth signal: %s", e.getMessage());
        }
    }

    /**
     * Check if the current HTTP request carries any cookies.
     * This distinguishes browser-based form submissions (which send cookies)
     * from native wallet app POSTs (which don't send any cookies).
     * <p>
     * We intentionally read the raw Cookie header from the HTTP request rather than
     * using Keycloak's CookieProvider, because the CookieProvider can return cookies
     * from internal session state even when the actual HTTP request has no cookies.
     */
    private boolean hasAuthSessionCookie() {
        try {
            String cookieHeader = session.getContext().getRequestHeaders().getHeaderString("Cookie");
            LOG.debugf("[OID4VP-ENDPOINT] Raw Cookie header: %s", cookieHeader);
            return cookieHeader != null && !cookieHeader.isBlank();
        } catch (Exception e) {
            return false;
        }
    }

    private String buildCompleteAuthUrl(String state) {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + realm.getName()
                + "/broker/" + getIdpModel().getAlias()
                + "/endpoint/complete-auth?state=" + urlEncode(state);
    }

    private Response convertToDirectPostResponse(Response response) {
        int status = response.getStatus();
        URI location = response.getLocation();
        LOG.infof("[OID4VP-ENDPOINT] Direct post flow - status: %d, location: %s", status, location);

        if ((status == 302 || status == 303) && location != null) {
            LOG.infof("[OID4VP-ENDPOINT] Converting redirect to JSON response for direct_post flow");
            return jsonRedirectResponse(location.toString());
        }

        if ((status == 302 || status == 303)) {
            Object locationHeader = response.getHeaders().getFirst("Location");
            if (locationHeader != null) {
                LOG.infof("[OID4VP-ENDPOINT] Found Location in headers: %s", locationHeader);
                return jsonRedirectResponse(locationHeader.toString());
            }
        }

        // For non-redirect responses (e.g. 200 HTML error pages), return the original response
        // so the caller can try fallback strategies (buildFreshAuthenticationUrl, buildCompleteAuthUrl)
        LOG.infof("[OID4VP-ENDPOINT] Direct post flow: response is not a redirect (status=%d), returning original", status);
        return response;
    }

    private Response handleIdentityBrokerException(IdentityBrokerException e, String state,
                                                   AuthenticationSessionModel authSession,
                                                   boolean isDirectPostFlow, boolean isCrossDeviceFlow) {
        LOG.warnf("[OID4VP-ENDPOINT] Identity broker error: %s", e.getMessage());
        LOG.warnf("[OID4VP-ENDPOINT] Identity broker error cause: %s",
                e.getCause() != null ? e.getCause().getMessage() : "no cause");
        event.event(EventType.LOGIN_ERROR)
                .detail("reason", e.getMessage())
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        cleanupRequestObjects(state);

        // For direct_post flows, don't call callback.cancelled()/error() — they may invalidate
        // the auth session. Return a proper error JSON to the wallet.
        if (isDirectPostFlow) {
            String errorMessage = e.getMessage();
            boolean isUserCancellation = errorMessage != null &&
                    (errorMessage.contains("access_denied") || errorMessage.contains("user_cancelled"));
            String errorCode = isUserCancellation ? "access_denied" : "server_error";
            return buildDirectPostErrorResponse(errorCode, errorMessage, state);
        }

        if (authSession != null) {
            session.getContext().setAuthenticationSession(authSession);
        }

        String errorMessage = e.getMessage();
        boolean isUserCancellation = errorMessage != null &&
                (errorMessage.contains("access_denied") || errorMessage.contains("user_cancelled"));

        return isUserCancellation
                ? callback.cancelled(getIdpModel())
                : callback.error(getIdpModel(), e.getMessage());
    }

    private Response handleUnexpectedException(Exception e, String state,
                                               AuthenticationSessionModel authSession,
                                               boolean isDirectPostFlow, boolean isCrossDeviceFlow) {
        LOG.errorf(e, "[OID4VP-ENDPOINT] Unexpected error processing OID4VP callback: %s", e.getMessage());
        event.event(EventType.LOGIN_ERROR)
                .detail("reason", e.getMessage())
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        cleanupRequestObjects(state);

        // For direct_post flows, return proper error JSON to the wallet
        if (isDirectPostFlow) {
            return buildDirectPostErrorResponse("server_error",
                    "Authentication failed: " + e.getMessage(), state);
        }

        if (authSession != null) {
            session.getContext().setAuthenticationSession(authSession);
        }

        return callback.error(getIdpModel(), "Authentication failed: " + e.getMessage());
    }

    /**
     * Build an error response for direct_post flows.
     * Returns a proper JSON error response instead of a redirect URL,
     * because native wallets cannot meaningfully navigate to Keycloak pages (no cookies).
     */
    private Response buildDirectPostErrorResponse(String errorCode, String errorDescription,
                                                   String state) {
        LOG.warnf("[OID4VP-ENDPOINT] Direct post error: %s - %s (state=%s)",
                errorCode, errorDescription, state);

        // Always return proper JSON error to the wallet (never HTML)
        String json = "{\"error\":\"" + jsonEscape(errorCode) + "\""
                + (errorDescription != null ? ",\"error_description\":\"" + jsonEscape(errorDescription) + "\"" : "")
                + "}";
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(json)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    /**
     * Strip wallet-added query params from the POST URL.
     * Wallets append 'state' to the response_uri query string, but the mDoc SessionTranscript
     * uses the response_uri from the request object JWT which only has 'flow' (if cross-device).
     * Keep 'flow' since it's part of the baked-in response_uri, strip everything else.
     */
    private static String stripWalletQueryParams(String url) {
        if (url == null) return null;
        int qIdx = url.indexOf('?');
        if (qIdx < 0) return url;
        String base = url.substring(0, qIdx);
        String query = url.substring(qIdx + 1);
        // Keep only 'flow' parameter (baked into the request object's response_uri)
        StringBuilder kept = new StringBuilder();
        for (String param : query.split("&")) {
            if (param.startsWith("flow=")) {
                if (!kept.isEmpty()) kept.append("&");
                kept.append(param);
            }
        }
        return kept.isEmpty() ? base : base + "?" + kept;
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private String buildBridgeUrl(String bridgeToken) {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + realm.getName()
                + "/broker/" + getIdpModel().getAlias()
                + "/endpoint/cross-device/complete?token=" + urlEncode(bridgeToken);
    }

    private String stripOidcQueryParams(String url) {
        try {
            URI uri = URI.create(url);
            // Return just scheme + authority + path, dropping all query params
            String base = uri.getScheme() + "://" + uri.getAuthority() + uri.getPath();
            // Preserve trailing slash
            if (url.contains("?") && !base.endsWith("/") && uri.getPath().endsWith("/")) {
                base += "/";
            }
            return base;
        } catch (Exception e) {
            return url;
        }
    }

    private String findUserSessionId(BrokeredIdentityContext context) {
        try {
            // After callback.authenticated(), the user session is accessible via the session context
            var userSessions = session.sessions().getUserSessionsStream(realm,
                    session.users().getUserByUsername(realm, context.getUsername()))
                    .toList();
            if (!userSessions.isEmpty()) {
                // Get the most recent session
                String sessionId = userSessions.get(userSessions.size() - 1).getId();
                LOG.infof("[OID4VP-ENDPOINT] Found user session: %s for user: %s", sessionId, context.getUsername());
                return sessionId;
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Could not find user session: %s", e.getMessage());
        }
        return null;
    }

    private void cleanupRequestObjects(String state) {
        if (state != null) {
            requestObjectStore.removeByState(session, state);
            LOG.infof("[OID4VP-ENDPOINT] Removed request objects for state: %s", state);
        }
    }

    private Response rebuildRequestObjectWithWalletNonce(Oid4vpRequestObjectStore.StoredRequestObject stored, String walletNonce) {
        LOG.infof("[OID4VP-ENDPOINT] Rebuilding request object with wallet_nonce");
        // Update SESSION_RESPONSE_URI to match this request object's response_uri.
        // This is critical for mDoc SessionTranscript verification: the wallet will use
        // the response_uri from the rebuilt JWT, and the verifier must use the same value.
        updateSessionResponseUri(stored);
        try {
            Oid4vpRedirectFlowService.SignedRequestObject rebuilt = provider.getRedirectFlowService().rebuildWithWalletNonce(
                    stored.rebuildParams(),
                    stored.state(),
                    stored.nonce(),
                    walletNonce,
                    realm.getAccessCodeLifespanLogin()
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

    private Response handleError(String state, String error, String errorDescription,
                                 AuthenticationSessionModel authSession, boolean isDirectPostFlow,
                                 boolean isCrossDeviceFlow) {
        String message = errorDescription != null && !errorDescription.isBlank()
                ? error + ": " + errorDescription
                : error;

        LOG.warnf("Wallet returned error. State: %s, Error: %s, isDirectPostFlow: %b", state, message, isDirectPostFlow);

        event.event(EventType.LOGIN_ERROR)
                .detail("error", error)
                .detail("error_description", errorDescription)
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        cleanupRequestObjects(state);

        if (!isDirectPostFlow) {
            String idpLoginUrl = buildIdpLoginPageUrl(authSession);
            if (idpLoginUrl != null) {
                LOG.infof("[OID4VP-ENDPOINT] Redirecting to IdP login page for retry: %s", idpLoginUrl);
                return Response.status(Response.Status.FOUND).location(URI.create(idpLoginUrl)).build();
            }
        }

        session.getContext().setAuthenticationSession(authSession);

        if (isDirectPostFlow) {
            // For direct_post (wallet app POST without cookies), return proper error JSON.
            // Don't call callback.cancelled()/error() — they may invalidate the auth session.
            // Never include redirect_uri in error responses — the OID4VP spec only defines
            // redirect_uri for successful responses. Including it on errors could cause the
            // wallet to redirect the user to an unexpected page.
            return buildDirectPostErrorResponse(error, errorDescription, state);
        }

        Response response = ("access_denied".equals(error) || "user_cancelled".equals(error))
                ? callback.cancelled(getIdpModel())
                : callback.error(getIdpModel(), message);
        return response;
    }

    private String buildIdpLoginPageUrl(AuthenticationSessionModel authSession) {
        try {
            if (authSession == null) {
                return null;
            }

            String tabId = authSession.getAuthNote("oid4vp_tab_id");
            String clientData = authSession.getAuthNote("oid4vp_client_data");
            String sessionCode = authSession.getAuthNote("oid4vp_session_code");

            StringBuilder url = new StringBuilder();
            String baseUri = session.getContext().getUri().getBaseUri().toString();
            url.append(baseUri);
            if (!baseUri.endsWith("/")) {
                url.append("/");
            }
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
            String codeChallenge = authSession.getClientNote("code_challenge");
            String codeChallengeMethod = authSession.getClientNote("code_challenge_method");

            StringBuilder url = new StringBuilder();
            String baseUri = session.getContext().getUri().getBaseUri().toString();
            url.append(baseUri);
            if (!baseUri.endsWith("/")) {
                url.append("/");
            }
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
            if (codeChallenge != null && !codeChallenge.isBlank()) {
                url.append("&code_challenge=").append(urlEncode(codeChallenge));
            }
            if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
                url.append("&code_challenge_method=").append(urlEncode(codeChallengeMethod));
            }
            return url.toString();
        } catch (Exception e) {
            LOG.warnf(e, "[OID4VP-ENDPOINT] Failed to build fresh authentication URL");
            return null;
        }
    }

    private void logRequestObjectClaims(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                LOG.infof("[OID4VP-ENDPOINT] Request object claims: %s", payload);
            }
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] Failed to decode request object for logging: %s", e.getMessage());
        }
    }

    // ==================== Response Helpers ====================

    private Response jsonRedirectResponse(String redirectUri) {
        return Response.ok("{\"redirect_uri\":\"" + redirectUri + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    /**
     * Redirect to the realm login page. Used when a stale complete-auth URL is opened
     * (e.g., wallet replays a previous login's redirect) and there's no SSO session.
     * This gives the user a fresh login page instead of a dead-end error.
     */
    private Response redirectToRealmLoginPage() {
        String baseUrl = session.getContext().getUri().getBaseUri().toString();
        if (!baseUrl.endsWith("/")) baseUrl += "/";
        String accountUrl = baseUrl + "realms/" + realm.getName() + "/account/";
        LOG.infof("[OID4VP-ENDPOINT] Redirecting to login page: %s", accountUrl);
        return Response.status(Response.Status.FOUND).location(URI.create(accountUrl)).build();
    }

    private Response redirectToAccountIfSsoSession() {
        AuthenticationManager.AuthResult authResult =
                AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (authResult != null) {
            LOG.infof("[OID4VP-ENDPOINT] User already authenticated via SSO, redirecting to account");
            String accountUrl = session.getContext().getUri().getBaseUri().toString();
            if (!accountUrl.endsWith("/")) accountUrl += "/";
            accountUrl += "realms/" + realm.getName() + "/account/";
            return Response.status(Response.Status.FOUND).location(URI.create(accountUrl)).build();
        }
        return null;
    }

    private Response badRequest(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"invalid_request\",\"error_description\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private Response notFound(String message) {
        return Response.status(Response.Status.NOT_FOUND)
                .entity("{\"error\":\"not_found\",\"error_description\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            return value;
        }
    }
}
