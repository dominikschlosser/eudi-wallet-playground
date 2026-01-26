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
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

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
        LOG.infof("[OID4VP-ENDPOINT] Constructor called - realm=%s, provider=%s",
                realm != null ? realm.getName() : "null",
                provider != null ? provider.getConfig().getAlias() : "null");
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
            @FormParam("state") String formState,
            @FormParam("vp_token") String vpToken,
            @FormParam("response") String encryptedResponse,
            @FormParam("error") String error,
            @FormParam("error_description") String errorDescription) {

        LOG.infof("[OID4VP-ENDPOINT] ========== POST callback received ==========");
        logPostParams(queryState, tabId, sessionCode, clientData, formState, vpToken, encryptedResponse, error);

        String state = queryState != null && !queryState.isBlank() ? queryState : formState;
        boolean hasError = error != null && !error.isBlank();

        AuthSessionResolutionResult resolution = resolveAuthSession(state, tabId, sessionCode, clientData);
        AuthenticationSessionModel authSession = resolution.authSession();
        boolean isDirectPostFlow = resolution.isDirectPostFlow();

        if (authSession == null) {
            LOG.warnf("[OID4VP-ENDPOINT] Authentication session NOT FOUND for state: %s", state);
            event.event(EventType.LOGIN_ERROR).error(Errors.SESSION_EXPIRED);
            return callback.error(getIdpModel(), "Session expired or invalid");
        }

        LOG.infof("[OID4VP-ENDPOINT] Auth session found: tabId=%s, client=%s",
                authSession.getTabId(),
                authSession.getClient() != null ? authSession.getClient().getClientId() : "null");

        if (hasError) {
            return handleError(state, error, errorDescription, authSession, isDirectPostFlow);
        }

        return processVpToken(authSession, state, vpToken, encryptedResponse, error, errorDescription, isDirectPostFlow);
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

        LOG.infof("[OID4VP-ENDPOINT] Returning request object JWT, length: %d", stored.requestObjectJwt().length());
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

        LOG.infof("[OID4VP-ENDPOINT] Returning original request object JWT, length: %d", stored.requestObjectJwt().length());
        return Response.ok(stored.requestObjectJwt())
                .type("application/oauth-authz-req+jwt")
                .build();
    }

    // ==================== Private Helper Methods ====================

    private void logPostParams(String queryState, String tabId, String sessionCode, String clientData,
                               String formState, String vpToken, String encryptedResponse, String error) {
        LOG.infof("[OID4VP-ENDPOINT] Query params - queryState: %s, tab_id: %s, session_code: %s, client_data length: %d",
                queryState, tabId, sessionCode, clientData != null ? clientData.length() : 0);
        LOG.infof("[OID4VP-ENDPOINT] Form params - formState: %s, vpToken length: %d, encryptedResponse length: %d, error: %s",
                formState, vpToken != null ? vpToken.length() : 0,
                encryptedResponse != null ? encryptedResponse.length() : 0, error);
    }

    private record AuthSessionResolutionResult(AuthenticationSessionModel authSession, boolean isDirectPostFlow) {}

    private AuthSessionResolutionResult resolveAuthSession(String state, String tabId, String sessionCode, String clientData) {
        AuthenticationSessionModel authSession = null;
        boolean isDirectPostFlow = false;
        boolean foundRootSessionFromCookie = false;

        // Try context first
        authSession = session.getContext().getAuthenticationSession();
        LOG.infof("[OID4VP-ENDPOINT] Context auth session: %s",
                authSession != null ? "found (tabId=" + authSession.getTabId() + ")" : "null");

        // Try getAndVerifyAuthenticationSession with state
        if (authSession == null && state != null) {
            authSession = tryGetAndVerifyAuthSession(state);
        }

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

    private AuthenticationSessionModel tryGetAndVerifyAuthSession(String state) {
        LOG.infof("[OID4VP-ENDPOINT] Trying getAndVerifyAuthenticationSession with state: %s", state);
        try {
            AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
            LOG.infof("[OID4VP-ENDPOINT] getAndVerifyAuthenticationSession returned: %s",
                    authSession != null ? "found" : "null");
            return authSession;
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] getAndVerifyAuthenticationSession failed: %s", e.getMessage());
            return null;
        }
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
            return new AuthSessionFromStoreResult(authSession, isDirectPostFlow);
        } catch (Exception e) {
            LOG.warnf("[OID4VP-ENDPOINT] REQUEST_OBJECT_STORE lookup failed: %s", e.getMessage());
            return new AuthSessionFromStoreResult(null, false);
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
        return null;
    }

    private Response processVpToken(AuthenticationSessionModel authSession, String state, String vpToken,
                                    String encryptedResponse, String error, String errorDescription,
                                    boolean isDirectPostFlow) {
        try {
            LOG.infof("[OID4VP-ENDPOINT] Calling provider.processCallback()");
            BrokeredIdentityContext context = provider.processCallback(
                    authSession, state, vpToken, encryptedResponse, error, errorDescription);
            LOG.infof("[OID4VP-ENDPOINT] processCallback returned context: id=%s, username=%s",
                    context != null ? context.getId() : "null",
                    context != null ? context.getUsername() : "null");

            context.setAuthenticationSession(authSession);
            LOG.infof("[OID4VP-ENDPOINT] Calling callback.authenticated()");
            Response response = callback.authenticated(context);
            LOG.infof("[OID4VP-ENDPOINT] callback.authenticated() returned status: %d, isDirectPostFlow: %b",
                    response != null ? response.getStatus() : -1, isDirectPostFlow);

            if (isDirectPostFlow && response != null) {
                return convertToDirectPostResponse(response);
            }
            return response;

        } catch (IdentityBrokerException e) {
            return handleIdentityBrokerException(e, state, authSession, isDirectPostFlow);
        } catch (Exception e) {
            return handleUnexpectedException(e, state, authSession, isDirectPostFlow);
        }
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

        if (status == 200 && location == null) {
            LOG.warnf("[OID4VP-ENDPOINT] Direct post flow got 200 without redirect - returning success without redirect_uri");
            return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
        }

        return response;
    }

    private Response handleIdentityBrokerException(IdentityBrokerException e, String state,
                                                   AuthenticationSessionModel authSession, boolean isDirectPostFlow) {
        LOG.warnf("[OID4VP-ENDPOINT] Identity broker error: %s", e.getMessage());
        event.event(EventType.LOGIN_ERROR)
                .detail("reason", e.getMessage())
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        cleanupRequestObjects(state);

        if (authSession != null) {
            session.getContext().setAuthenticationSession(authSession);
        }

        String errorMessage = e.getMessage();
        boolean isUserCancellation = errorMessage != null &&
                (errorMessage.contains("access_denied") || errorMessage.contains("user_cancelled"));

        Response errorResponse = isUserCancellation
                ? callback.cancelled(getIdpModel())
                : callback.error(getIdpModel(), e.getMessage());

        if (isDirectPostFlow && errorResponse != null) {
            return convertErrorResponseForDirectPost(errorResponse);
        }
        return errorResponse;
    }

    private Response handleUnexpectedException(Exception e, String state,
                                               AuthenticationSessionModel authSession, boolean isDirectPostFlow) {
        LOG.errorf(e, "[OID4VP-ENDPOINT] Unexpected error processing OID4VP callback: %s", e.getMessage());
        event.event(EventType.LOGIN_ERROR)
                .detail("reason", e.getMessage())
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        cleanupRequestObjects(state);

        if (authSession != null) {
            session.getContext().setAuthenticationSession(authSession);
        }

        Response errorResponse = callback.error(getIdpModel(), "Authentication failed: " + e.getMessage());
        if (isDirectPostFlow && errorResponse != null) {
            return convertErrorResponseForDirectPost(errorResponse);
        }
        return errorResponse;
    }

    private void cleanupRequestObjects(String state) {
        if (state != null) {
            requestObjectStore.removeByState(session, state);
            LOG.infof("[OID4VP-ENDPOINT] Removed request objects for state: %s", state);
        }
    }

    private Response convertErrorResponseForDirectPost(Response response) {
        int status = response.getStatus();
        URI location = response.getLocation();
        LOG.infof("[OID4VP-ENDPOINT] Converting error response for direct_post - status: %d, location: %s", status, location);

        if ((status == 302 || status == 303) && location != null) {
            return jsonRedirectResponse(location.toString());
        }

        if ((status == 302 || status == 303)) {
            Object locationHeader = response.getHeaders().getFirst("Location");
            if (locationHeader != null) {
                return jsonRedirectResponse(locationHeader.toString());
            }
        }
        return response;
    }

    private Response rebuildRequestObjectWithWalletNonce(Oid4vpRequestObjectStore.StoredRequestObject stored, String walletNonce) {
        LOG.infof("[OID4VP-ENDPOINT] Rebuilding request object with wallet_nonce");
        try {
            Oid4vpRedirectFlowService.SignedRequestObject rebuilt = provider.getRedirectFlowService().rebuildWithWalletNonce(
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

        cleanupRequestObjects(state);

        if (!isDirectPostFlow) {
            String idpLoginUrl = buildIdpLoginPageUrl(authSession);
            if (idpLoginUrl != null) {
                LOG.infof("[OID4VP-ENDPOINT] Redirecting to IdP login page for retry: %s", idpLoginUrl);
                return Response.status(Response.Status.FOUND).location(URI.create(idpLoginUrl)).build();
            }
        }

        if (isDirectPostFlow) {
            String freshAuthUrl = buildFreshAuthenticationUrl(authSession);
            if (freshAuthUrl != null) {
                LOG.infof("[OID4VP-ENDPOINT] Returning JSON redirect for direct_post flow: %s", freshAuthUrl);
                return jsonRedirectResponse(freshAuthUrl);
            }
        }

        LOG.warnf("[OID4VP-ENDPOINT] Could not build fresh auth URL, falling back to callback handling");
        session.getContext().setAuthenticationSession(authSession);

        Response response = ("access_denied".equals(error) || "user_cancelled".equals(error))
                ? callback.cancelled(getIdpModel())
                : callback.error(getIdpModel(), message);

        if (isDirectPostFlow && response != null) {
            return convertErrorResponseForDirectPost(response);
        }
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
            return url.toString();
        } catch (Exception e) {
            LOG.warnf(e, "[OID4VP-ENDPOINT] Failed to build fresh authentication URL");
            return null;
        }
    }

    // ==================== Response Helpers ====================

    private Response jsonRedirectResponse(String redirectUri) {
        return Response.ok("{\"redirect_uri\":\"" + redirectUri + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
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
