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

import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Encapsulates OID4VP session state management for Keycloak authentication sessions.
 * <p>
 * Provides type-safe access to OID4VP-specific session attributes, avoiding
 * scattered magic strings and ensuring consistent key usage across the codebase.
 */
public final class Oid4vpSessionState {
    // Session key constants
    private static final String KEY_STATE = "oid4vp_state";
    private static final String KEY_NONCE = "oid4vp_nonce";
    private static final String KEY_RESPONSE_URI = "oid4vp_response_uri";
    private static final String KEY_REDIRECT_FLOW_RESPONSE_URI = "oid4vp_redirect_flow_response_uri";
    private static final String KEY_ENCRYPTION_KEY = "oid4vp_encryption_key";
    private static final String KEY_CLIENT_ID = "oid4vp_client_id";
    private static final String KEY_REQUEST_OBJECT = "oid4vp_request_object";
    private static final String KEY_EFFECTIVE_CLIENT_ID = "oid4vp_effective_client_id";
    private static final String KEY_TAB_ID = "oid4vp_tab_id";
    private static final String KEY_CLIENT_DATA = "oid4vp_client_data";
    private static final String KEY_SESSION_CODE = "oid4vp_session_code";

    private final AuthenticationSessionModel session;

    public Oid4vpSessionState(AuthenticationSessionModel session) {
        this.session = session;
    }

    /**
     * Creates a session state wrapper for the given authentication session.
     */
    public static Oid4vpSessionState of(AuthenticationSessionModel session) {
        return new Oid4vpSessionState(session);
    }

    // State management

    public String getState() {
        return session.getAuthNote(KEY_STATE);
    }

    public void setState(String state) {
        session.setAuthNote(KEY_STATE, state);
        // Also store as client note for Keycloak IdP callback mechanism
        session.setClientNote("state", state);
    }

    // Nonce management

    public String getNonce() {
        return session.getAuthNote(KEY_NONCE);
    }

    public void setNonce(String nonce) {
        session.setAuthNote(KEY_NONCE, nonce);
    }

    // Response URI management

    public String getResponseUri() {
        return session.getAuthNote(KEY_RESPONSE_URI);
    }

    public void setResponseUri(String responseUri) {
        session.setAuthNote(KEY_RESPONSE_URI, responseUri);
    }

    public String getRedirectFlowResponseUri() {
        return session.getAuthNote(KEY_REDIRECT_FLOW_RESPONSE_URI);
    }

    public void setRedirectFlowResponseUri(String responseUri) {
        session.setAuthNote(KEY_REDIRECT_FLOW_RESPONSE_URI, responseUri);
    }

    // Client ID management

    public String getClientId() {
        return session.getAuthNote(KEY_CLIENT_ID);
    }

    public void setClientId(String clientId) {
        session.setAuthNote(KEY_CLIENT_ID, clientId);
    }

    public String getEffectiveClientId() {
        return session.getAuthNote(KEY_EFFECTIVE_CLIENT_ID);
    }

    public void setEffectiveClientId(String effectiveClientId) {
        session.setAuthNote(KEY_EFFECTIVE_CLIENT_ID, effectiveClientId);
    }

    // Encryption key management

    public String getEncryptionKey() {
        return session.getAuthNote(KEY_ENCRYPTION_KEY);
    }

    public void setEncryptionKey(String encryptionKey) {
        session.setAuthNote(KEY_ENCRYPTION_KEY, encryptionKey);
    }

    // Request object management

    public String getRequestObject() {
        return session.getAuthNote(KEY_REQUEST_OBJECT);
    }

    public void setRequestObject(String requestObject) {
        session.setAuthNote(KEY_REQUEST_OBJECT, requestObject);
    }

    // Session identifiers for callback lookup

    public String getTabId() {
        return session.getAuthNote(KEY_TAB_ID);
    }

    public void setTabId(String tabId) {
        session.setAuthNote(KEY_TAB_ID, tabId != null ? tabId : "");
    }

    public String getClientData() {
        return session.getAuthNote(KEY_CLIENT_DATA);
    }

    public void setClientData(String clientData) {
        session.setAuthNote(KEY_CLIENT_DATA, clientData != null ? clientData : "");
    }

    public String getSessionCode() {
        return session.getAuthNote(KEY_SESSION_CODE);
    }

    public void setSessionCode(String sessionCode) {
        session.setAuthNote(KEY_SESSION_CODE, sessionCode != null ? sessionCode : "");
    }

    /**
     * Stores all session identifiers from the request URI for callback reconstruction.
     */
    public void storeSessionIdentifiers(String tabId, String clientData, String sessionCode) {
        setTabId(tabId);
        setClientData(clientData);
        setSessionCode(sessionCode);
    }

    /**
     * Returns the underlying authentication session.
     */
    public AuthenticationSessionModel getSession() {
        return session;
    }
}
