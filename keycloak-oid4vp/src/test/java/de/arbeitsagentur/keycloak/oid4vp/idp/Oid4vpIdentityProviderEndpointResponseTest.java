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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests for OID4VP endpoint response format requirements:
 * - Same-device wallet POSTs MUST receive JSON with redirect_uri
 * - Cross-device wallet POSTs MUST receive empty JSON {}
 * - ALL error responses MUST be JSON (never HTML)
 * - Session expired MUST return JSON error
 */
class Oid4vpIdentityProviderEndpointResponseTest {

    @SuppressWarnings("unchecked")
    @BeforeAll
    static void setUpJaxRs() {
        // JAX-RS Response.status()/Response.ok() require a RuntimeDelegate.
        // In unit tests (no container), we provide a mock that creates real-ish ResponseBuilder instances.
        RuntimeDelegate delegate = mock(RuntimeDelegate.class);
        when(delegate.createResponseBuilder()).thenAnswer(inv -> new StubResponseBuilder());

        // MediaType.valueOf() needs a HeaderDelegate<MediaType>
        RuntimeDelegate.HeaderDelegate<MediaType> mediaTypeDelegate = mock(RuntimeDelegate.HeaderDelegate.class);
        when(mediaTypeDelegate.fromString(anyString())).thenAnswer(inv -> {
            String val = inv.getArgument(0);
            if (val.contains("json")) return MediaType.APPLICATION_JSON_TYPE;
            if (val.contains("html")) return MediaType.TEXT_HTML_TYPE;
            return MediaType.WILDCARD_TYPE;
        });
        when(delegate.createHeaderDelegate(MediaType.class)).thenReturn(mediaTypeDelegate);

        RuntimeDelegate.setInstance(delegate);
    }

    private KeycloakSession session;
    private RealmModel realm;
    private Oid4vpIdentityProvider provider;
    private AbstractIdentityProvider.AuthenticationCallback callback;
    private EventBuilder event;
    private Oid4vpRequestObjectStore requestObjectStore;

    private AuthenticationSessionModel authSession;
    private RootAuthenticationSessionModel rootSession;
    private SingleUseObjectProvider singleUseObjects;
    private KeycloakContext keycloakContext;
    private KeycloakUriInfo uriInfo;

    private Oid4vpIdentityProviderEndpoint endpoint;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        provider = mock(Oid4vpIdentityProvider.class);
        callback = mock(AbstractIdentityProvider.AuthenticationCallback.class);
        event = mock(EventBuilder.class);
        requestObjectStore = mock(Oid4vpRequestObjectStore.class);

        authSession = mock(AuthenticationSessionModel.class);
        rootSession = mock(RootAuthenticationSessionModel.class);
        singleUseObjects = mock(SingleUseObjectProvider.class);
        keycloakContext = mock(KeycloakContext.class);
        uriInfo = mock(KeycloakUriInfo.class);

        // Wire mocks
        when(session.singleUseObjects()).thenReturn(singleUseObjects);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getUri()).thenReturn(uriInfo);
        when(keycloakContext.getAuthenticationSession()).thenReturn(null);
        when(realm.getName()).thenReturn("test");
        when(event.event(any(EventType.class))).thenReturn(event);
        when(event.detail(anyString(), anyString())).thenReturn(event);
        doNothing().when(event).error(anyString());

        // Auth session mocks
        when(authSession.getTabId()).thenReturn("test-tab");
        when(authSession.getParentSession()).thenReturn(rootSession);
        when(rootSession.getId()).thenReturn("root-session-123");
        when(authSession.getClient()).thenReturn(null);

        // IdP model
        IdentityProviderModel idpModel = new IdentityProviderModel();
        idpModel.setAlias("oid4vp");
        when(provider.getConfig()).thenReturn(mock(Oid4vpIdentityProviderConfig.class));
        when(provider.getConfig().getAlias()).thenReturn("oid4vp");

        endpoint = new Oid4vpIdentityProviderEndpoint(
                session, realm, provider, callback, event, requestObjectStore);
    }

    /**
     * Configures mocks so that the request-object-store resolves the auth session
     * for a given state, simulating a wallet direct POST.
     */
    private void configureRequestObjectStoreForState(String state) {
        Oid4vpRequestObjectStore.StoredRequestObject stored = new Oid4vpRequestObjectStore.StoredRequestObject(
                "jwt", null, state, "nonce", "root-session-123", "test-client", null);
        when(requestObjectStore.resolveByState(eq(session), eq(state))).thenReturn(stored);

        when(session.authenticationSessions()).thenReturn(mock(org.keycloak.sessions.AuthenticationSessionProvider.class));
        when(session.authenticationSessions().getRootAuthenticationSession(eq(realm), eq("root-session-123")))
                .thenReturn(rootSession);

        // Make the auth session findable by state match
        when(authSession.getAuthNote("oid4vp_state")).thenReturn(state);
        Map<String, AuthenticationSessionModel> sessions = Map.of("test-tab", authSession);
        when(rootSession.getAuthenticationSessions()).thenReturn(sessions);
    }

    /**
     * Configures provider.processCallback() to return a mock identity context.
     */
    private void configureSuccessfulProcessCallback() {
        BrokeredIdentityContext identityContext = mock(BrokeredIdentityContext.class);
        when(identityContext.getId()).thenReturn("user-123");
        when(identityContext.getUsername()).thenReturn("testuser");
        when(identityContext.getContextData()).thenReturn(new HashMap<>());
        IdentityProviderModel idpModel = new IdentityProviderModel();
        idpModel.setAlias("oid4vp");
        when(identityContext.getIdpConfig()).thenReturn(idpModel);
        doReturn(provider).when(identityContext).getIdp();
        // When setAuthenticationSession is called, make getAuthenticationSession return it
        doAnswer(inv -> {
            AuthenticationSessionModel s = inv.getArgument(0);
            when(identityContext.getAuthenticationSession()).thenReturn(s);
            return null;
        }).when(identityContext).setAuthenticationSession(any());
        // Auth session needs getRealm() for SerializedBrokeredIdentityContext.serialize()
        when(authSession.getRealm()).thenReturn(realm);
        when(provider.processCallback(any(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(identityContext);
    }

    /**
     * Configures provider.processCallback() to throw an exception.
     */
    private void configureFailedProcessCallback(String errorMessage) {
        when(provider.processCallback(any(), anyString(), anyString(), any(), any(), any()))
                .thenThrow(new IdentityBrokerException(errorMessage));
    }

    @Nested
    @DisplayName("Session expired")
    class SessionExpired {

        @Test
        @DisplayName("returns JSON error when no auth session found")
        void returnsJsonErrorWhenNoAuthSession() {
            when(uriInfo.getRequestUri()).thenReturn(URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=missing"));

            Response response = endpoint.handlePost(
                    "missing", null, null, null, null,
                    null, null, null, null, null);

            assertThat(response.getStatus()).isEqualTo(400);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).contains("session_expired");
            assertThat(body).doesNotContain("<html");
        }
    }

    @Nested
    @DisplayName("Same-device flow")
    class SameDeviceFlow {

        @Test
        @DisplayName("returns JSON with redirect_uri for successful VP token")
        void returnsRedirectUri() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);
            configureSuccessfulProcessCallback();

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state));
            when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc/"));

            // Same-device: no flow param, no tab_id/session_code/client_data (wallet direct POST)
            Response response = endpoint.handlePost(
                    state, null, null, null, null,
                    null, "vp_token_value", null, null, null);

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).contains("redirect_uri");
            assertThat(body).contains("complete-auth");
            assertThat(body).doesNotContain("source=wallet");
            assertThat(body).doesNotContain("<html");
        }

        @Test
        @DisplayName("does NOT store SSE signal for same-device flow (prevents race)")
        void doesNotStoreSseSignalForSameDevice() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);
            configureSuccessfulProcessCallback();

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state));
            when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc/"));

            endpoint.handlePost(state, null, null, null, null,
                    null, "vp_token_value", null, null, null);

            // Deferred auth signal (for /complete-auth) should be stored
            verify(singleUseObjects).put(eq("oid4vp_deferred:" + state), anyLong(), any());
            // SSE signal (CROSS_DEVICE_COMPLETE_PREFIX) should NOT be stored for same-device
            verify(singleUseObjects, never()).put(eq("oid4vp_complete:" + state), anyLong(), any());
        }

        @Test
        @DisplayName("returns JSON error on verification failure")
        void returnsJsonErrorOnFailure() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);
            configureFailedProcessCallback("Credential verification failed");

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state));

            Response response = endpoint.handlePost(
                    state, null, null, null, null,
                    null, "bad_vp_token", null, null, null);

            assertThat(response.getStatus()).isEqualTo(400);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).contains("error");
            assertThat(body).doesNotContain("<html");
        }
    }

    @Nested
    @DisplayName("Cross-device flow")
    class CrossDeviceFlow {

        @Test
        @DisplayName("returns empty JSON {} for successful VP token")
        void returnsEmptyJson() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);
            configureSuccessfulProcessCallback();

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state + "&flow=cross_device"));
            when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc/"));

            // Cross-device: flow=cross_device
            Response response = endpoint.handlePost(
                    state, null, null, null, "cross_device",
                    null, "vp_token_value", null, null, null);

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).isEqualTo("{}");
        }

        @Test
        @DisplayName("stores SSE signal for cross-device flow (so SSE can notify browser)")
        void storesSseSignalForCrossDevice() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);
            configureSuccessfulProcessCallback();

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state + "&flow=cross_device"));
            when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc/"));

            endpoint.handlePost(state, null, null, null, "cross_device",
                    null, "vp_token_value", null, null, null);

            // Both deferred auth signal AND SSE signal should be stored for cross-device
            verify(singleUseObjects).put(eq("oid4vp_deferred:" + state), anyLong(), any());
            verify(singleUseObjects).put(eq("oid4vp_complete:" + state), anyLong(), any());
        }

        @Test
        @DisplayName("returns JSON error on verification failure (never HTML)")
        void returnsJsonErrorOnFailure() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);
            configureFailedProcessCallback("Invalid credential");

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state + "&flow=cross_device"));

            Response response = endpoint.handlePost(
                    state, null, null, null, "cross_device",
                    null, "bad_vp_token", null, null, null);

            assertThat(response.getStatus()).isEqualTo(400);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).contains("error");
            assertThat(body).doesNotContain("<html");
        }
    }

    @Nested
    @DisplayName("Error responses are always JSON")
    class ErrorResponsesAlwaysJson {

        @Test
        @DisplayName("wallet error param returns JSON for direct post")
        void walletErrorReturnsJson() {
            String state = "tab123.abc";
            configureRequestObjectStoreForState(state);

            when(uriInfo.getRequestUri()).thenReturn(
                    URI.create("https://kc/realms/test/broker/oid4vp/endpoint?state=" + state));

            // Wallet sends error as form param
            Response response = endpoint.handlePost(
                    state, null, null, null, null,
                    null, null, null, "access_denied", "User cancelled");

            assertThat(response.getStatus()).isEqualTo(400);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).contains("access_denied");
            assertThat(body).doesNotContain("<html");
        }

        @Test
        @DisplayName("uncaught exception returns JSON (global safety net)")
        void uncaughtExceptionReturnsJson() {
            // Make getContext().getUri() throw on first call inside handlePostInternal
            // to simulate an unexpected Keycloak internal error
            when(uriInfo.getRequestUri()).thenThrow(new RuntimeException("Unexpected internal error"));

            Response response = endpoint.handlePost(
                    "some-state", null, null, null, null,
                    null, "vp_token", null, null, null);

            assertThat(response.getStatus()).isEqualTo(500);
            assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
            String body = response.getEntity().toString();
            assertThat(body).contains("server_error");
            assertThat(body).doesNotContain("<html");
        }
    }

    @Nested
    @DisplayName("Response URI is fixed from POST URL for direct post flows")
    class ResponseUriFixedFromPostUrl {

        @Test
        @DisplayName("SESSION_RESPONSE_URI strips wallet-added query params for same-device")
        void setsResponseUriForSameDevice() {
            String state = "tab123.abc";
            String postUrl = "https://kc/realms/test/broker/oid4vp/endpoint?state=" + state + "&tab_id=t&session_code=s";
            configureRequestObjectStoreForState(state);
            configureSuccessfulProcessCallback();

            when(uriInfo.getRequestUri()).thenReturn(URI.create(postUrl));
            when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc/"));

            endpoint.handlePost(state, null, null, null, null,
                    null, "vp_token_value", null, null, null);

            // Verify SESSION_RESPONSE_URI was set to the base URL without wallet-added query params
            // (state, tab_id, session_code are wallet-added; only flow= is kept)
            verify(authSession).setAuthNote(eq("oid4vp_response_uri"),
                    eq("https://kc/realms/test/broker/oid4vp/endpoint"));
        }

        @Test
        @DisplayName("SESSION_RESPONSE_URI keeps flow param for cross-device")
        void setsResponseUriForCrossDevice() {
            String state = "tab123.abc";
            String postUrl = "https://kc/realms/test/broker/oid4vp/endpoint?state=" + state + "&flow=cross_device";
            configureRequestObjectStoreForState(state);
            configureSuccessfulProcessCallback();

            when(uriInfo.getRequestUri()).thenReturn(URI.create(postUrl));
            when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc/"));

            endpoint.handlePost(state, null, null, null, "cross_device",
                    null, "vp_token_value", null, null, null);

            // Verify SESSION_RESPONSE_URI keeps flow= param (baked into request object)
            // but strips wallet-added state= param
            verify(authSession).setAuthNote(eq("oid4vp_response_uri"),
                    eq("https://kc/realms/test/broker/oid4vp/endpoint?flow=cross_device"));
        }
    }

    /**
     * Minimal JAX-RS ResponseBuilder for unit tests (no container needed).
     */
    static class StubResponseBuilder extends Response.ResponseBuilder {
        private int status;
        private Object entity;
        private MediaType mediaType;

        @Override public Response build() {
            return new StubResponse(status, entity, mediaType);
        }
        @Override public Response.ResponseBuilder clone() { return this; }
        @Override public Response.ResponseBuilder status(int status) { this.status = status; return this; }
        @Override public Response.ResponseBuilder status(int status, String reasonPhrase) { this.status = status; return this; }
        @Override public Response.ResponseBuilder entity(Object entity) { this.entity = entity; return this; }
        @Override public Response.ResponseBuilder entity(Object entity, java.lang.annotation.Annotation[] annotations) { this.entity = entity; return this; }
        @Override public Response.ResponseBuilder allow(String... methods) { return this; }
        @Override public Response.ResponseBuilder allow(java.util.Set<String> methods) { return this; }
        @Override public Response.ResponseBuilder cacheControl(jakarta.ws.rs.core.CacheControl cacheControl) { return this; }
        @Override public Response.ResponseBuilder encoding(String encoding) { return this; }
        @Override public Response.ResponseBuilder header(String name, Object value) { return this; }
        @Override public Response.ResponseBuilder replaceAll(jakarta.ws.rs.core.MultivaluedMap<String, Object> headers) { return this; }
        @Override public Response.ResponseBuilder language(String language) { return this; }
        @Override public Response.ResponseBuilder language(java.util.Locale language) { return this; }
        @Override public Response.ResponseBuilder type(MediaType type) { this.mediaType = type; return this; }
        @Override public Response.ResponseBuilder type(String type) { this.mediaType = MediaType.valueOf(type); return this; }
        @Override public Response.ResponseBuilder variant(jakarta.ws.rs.core.Variant variant) { return this; }
        @Override public Response.ResponseBuilder contentLocation(URI uri) { return this; }
        @Override public Response.ResponseBuilder cookie(jakarta.ws.rs.core.NewCookie... cookies) { return this; }
        @Override public Response.ResponseBuilder expires(java.util.Date expires) { return this; }
        @Override public Response.ResponseBuilder lastModified(java.util.Date lastModified) { return this; }
        @Override public Response.ResponseBuilder location(URI location) { return this; }
        @Override public Response.ResponseBuilder tag(jakarta.ws.rs.core.EntityTag tag) { return this; }
        @Override public Response.ResponseBuilder tag(String tag) { return this; }
        @Override public Response.ResponseBuilder variants(jakarta.ws.rs.core.Variant... variants) { return this; }
        @Override public Response.ResponseBuilder variants(java.util.List<jakarta.ws.rs.core.Variant> variants) { return this; }
        @Override public Response.ResponseBuilder links(jakarta.ws.rs.core.Link... links) { return this; }
        @Override public Response.ResponseBuilder link(URI uri, String rel) { return this; }
        @Override public Response.ResponseBuilder link(String uri, String rel) { return this; }
    }

    static class StubResponse extends Response {
        private final int status;
        private final Object entity;
        private final MediaType mediaType;

        StubResponse(int status, Object entity, MediaType mediaType) {
            this.status = status;
            this.entity = entity;
            this.mediaType = mediaType;
        }

        @Override public int getStatus() { return status; }
        @Override public StatusType getStatusInfo() { return Status.fromStatusCode(status); }
        @Override public Object getEntity() { return entity; }
        @Override public MediaType getMediaType() { return mediaType; }
        @Override public <T> T readEntity(Class<T> entityType) { return null; }
        @Override public <T> T readEntity(jakarta.ws.rs.core.GenericType<T> entityType) { return null; }
        @Override public <T> T readEntity(Class<T> entityType, java.lang.annotation.Annotation[] annotations) { return null; }
        @Override public <T> T readEntity(jakarta.ws.rs.core.GenericType<T> entityType, java.lang.annotation.Annotation[] annotations) { return null; }
        @Override public boolean hasEntity() { return entity != null; }
        @Override public boolean bufferEntity() { return false; }
        @Override public void close() {}
        @Override public java.util.Locale getLanguage() { return null; }
        @Override public int getLength() { return -1; }
        @Override public java.util.Set<String> getAllowedMethods() { return java.util.Set.of(); }
        @Override public java.util.Map<String, jakarta.ws.rs.core.NewCookie> getCookies() { return java.util.Map.of(); }
        @Override public jakarta.ws.rs.core.EntityTag getEntityTag() { return null; }
        @Override public java.util.Date getDate() { return null; }
        @Override public java.util.Date getLastModified() { return null; }
        @Override public URI getLocation() { return null; }
        @Override public java.util.Set<jakarta.ws.rs.core.Link> getLinks() { return java.util.Set.of(); }
        @Override public boolean hasLink(String relation) { return false; }
        @Override public jakarta.ws.rs.core.Link getLink(String relation) { return null; }
        @Override public jakarta.ws.rs.core.Link.Builder getLinkBuilder(String relation) { return null; }
        @Override public jakarta.ws.rs.core.MultivaluedMap<String, Object> getMetadata() { return new jakarta.ws.rs.core.MultivaluedHashMap<>(); }
        @Override public jakarta.ws.rs.core.MultivaluedMap<String, Object> getHeaders() { return new jakarta.ws.rs.core.MultivaluedHashMap<>(); }
        @Override public jakarta.ws.rs.core.MultivaluedMap<String, String> getStringHeaders() { return new jakarta.ws.rs.core.MultivaluedHashMap<>(); }
        @Override public String getHeaderString(String name) { return null; }
    }
}
