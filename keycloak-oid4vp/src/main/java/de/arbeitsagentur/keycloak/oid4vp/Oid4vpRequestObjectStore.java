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

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * Store for OID4VP request objects using Keycloak's SingleUseObjectProvider.
 * This provides cluster-aware storage that works across multiple Keycloak nodes.
 * Request objects are stored with a TTL and can be retrieved via their unique ID.
 * Supports wallet_nonce for spec-compliant request object regeneration.
 */
public class Oid4vpRequestObjectStore {

    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);
    private static final String KEY_PREFIX = "oid4vp_request:";
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";

    // Map keys for serialization
    private static final String KEY_REQUEST_OBJECT_JWT = "requestObjectJwt";
    private static final String KEY_ENCRYPTION_KEY_JSON = "encryptionKeyJson";
    private static final String KEY_STATE = "state";
    private static final String KEY_NONCE = "nonce";
    private static final String KEY_ROOT_SESSION_ID = "rootSessionId";
    private static final String KEY_CLIENT_ID = "clientId";
    private static final String KEY_REBUILD_EFFECTIVE_CLIENT_ID = "rebuild.effectiveClientId";
    private static final String KEY_REBUILD_CLIENT_ID_SCHEME = "rebuild.clientIdScheme";
    private static final String KEY_REBUILD_RESPONSE_URI = "rebuild.responseUri";
    private static final String KEY_REBUILD_DCQL_QUERY = "rebuild.dcqlQuery";
    private static final String KEY_REBUILD_X509_CERT_PEM = "rebuild.x509CertPem";
    private static final String KEY_REBUILD_X509_SIGNING_KEY_JWK = "rebuild.x509SigningKeyJwk";
    private static final String KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON = "rebuild.encryptionPublicKeyJson";

    private final Duration ttl;

    public Oid4vpRequestObjectStore() {
        this(DEFAULT_TTL);
    }

    public Oid4vpRequestObjectStore(Duration ttl) {
        this.ttl = ttl;
    }

    /**
     * Store a request object and return its unique ID.
     *
     * @param session The Keycloak session
     * @param requestObjectJwt The signed JWT request object
     * @param encryptionKeyJson The private JWK for response decryption (JSON string), may be null
     * @param state The OAuth state parameter for correlation
     * @param nonce The nonce for verification
     * @return Unique ID for retrieving the request object
     */
    public String store(KeycloakSession session, String requestObjectJwt, String encryptionKeyJson, String state, String nonce) {
        return store(session, requestObjectJwt, encryptionKeyJson, state, nonce, null, null);
    }

    /**
     * Store a request object with session information and return its unique ID.
     *
     * @param session The Keycloak session
     * @param requestObjectJwt The signed JWT request object
     * @param encryptionKeyJson The private JWK for response decryption (JSON string), may be null
     * @param state The OAuth state parameter for correlation
     * @param nonce The nonce for verification
     * @param rootSessionId The root authentication session ID for direct_post callback lookup
     * @param clientId The client ID for the auth session
     * @return Unique ID for retrieving the request object
     */
    public String store(KeycloakSession session, String requestObjectJwt, String encryptionKeyJson, String state, String nonce,
                        String rootSessionId, String clientId) {
        return store(session, requestObjectJwt, encryptionKeyJson, state, nonce, rootSessionId, clientId, null);
    }

    /**
     * Store a request object with rebuild parameters for wallet_nonce support.
     *
     * @param session The Keycloak session
     * @param requestObjectJwt The signed JWT request object
     * @param encryptionKeyJson The private JWK for response decryption (JSON string), may be null
     * @param state The OAuth state parameter for correlation
     * @param nonce The nonce for verification
     * @param rootSessionId The root authentication session ID for direct_post callback lookup
     * @param clientId The client ID for the auth session
     * @param rebuildParams Parameters needed to rebuild the request object with wallet_nonce
     * @return Unique ID for retrieving the request object
     */
    public String store(KeycloakSession session, String requestObjectJwt, String encryptionKeyJson, String state, String nonce,
                        String rootSessionId, String clientId, RebuildParams rebuildParams) {
        SingleUseObjectProvider singleUseStore = session.singleUseObjects();
        String id = UUID.randomUUID().toString();
        long lifespanSeconds = ttl.toSeconds();

        // Serialize to map
        Map<String, String> notes = new java.util.HashMap<>();
        putIfNotNull(notes, KEY_REQUEST_OBJECT_JWT, requestObjectJwt);
        putIfNotNull(notes, KEY_ENCRYPTION_KEY_JSON, encryptionKeyJson);
        putIfNotNull(notes, KEY_STATE, state);
        putIfNotNull(notes, KEY_NONCE, nonce);
        putIfNotNull(notes, KEY_ROOT_SESSION_ID, rootSessionId);
        putIfNotNull(notes, KEY_CLIENT_ID, clientId);

        if (rebuildParams != null) {
            putIfNotNull(notes, KEY_REBUILD_EFFECTIVE_CLIENT_ID, rebuildParams.effectiveClientId());
            putIfNotNull(notes, KEY_REBUILD_CLIENT_ID_SCHEME, rebuildParams.clientIdScheme());
            putIfNotNull(notes, KEY_REBUILD_RESPONSE_URI, rebuildParams.responseUri());
            putIfNotNull(notes, KEY_REBUILD_DCQL_QUERY, rebuildParams.dcqlQuery());
            putIfNotNull(notes, KEY_REBUILD_X509_CERT_PEM, rebuildParams.x509CertPem());
            putIfNotNull(notes, KEY_REBUILD_X509_SIGNING_KEY_JWK, rebuildParams.x509SigningKeyJwk());
            putIfNotNull(notes, KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON, rebuildParams.encryptionPublicKeyJson());
        }

        // Store main entry
        singleUseStore.put(KEY_PREFIX + id, lifespanSeconds, notes);

        // Store state index for resolveByState lookup
        if (state != null && !state.isBlank()) {
            singleUseStore.put(STATE_INDEX_PREFIX + state, lifespanSeconds, Map.of("id", id));
        }

        return id;
    }

    /**
     * Look up a stored request object by its state parameter.
     *
     * @param session The Keycloak session
     * @param state The OAuth state parameter
     * @return The stored request object, or null if not found or expired
     */
    public StoredRequestObject resolveByState(KeycloakSession session, String state) {
        if (state == null || state.isBlank()) {
            return null;
        }
        SingleUseObjectProvider singleUseStore = session.singleUseObjects();

        // Look up ID from state index (non-destructive using replace)
        Map<String, String> indexEntry = singleUseStore.get(STATE_INDEX_PREFIX + state);
        if (indexEntry == null) {
            return null;
        }

        String id = indexEntry.get("id");
        if (id == null || id.isBlank()) {
            return null;
        }

        // Resolve by ID
        return resolve(session, id);
    }

    /**
     * Retrieve a stored request object by its ID.
     * Note: This is a non-destructive read - the object remains in the store.
     *
     * @param session The Keycloak session
     * @param id The unique ID returned by store()
     * @return The stored request object, or null if not found or expired
     */
    public StoredRequestObject resolve(KeycloakSession session, String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        SingleUseObjectProvider singleUseStore = session.singleUseObjects();

        // Get the entry (this removes it from store)
        Map<String, String> notes = singleUseStore.get(KEY_PREFIX + id);
        if (notes == null) {
            return null;
        }

        // Re-store immediately for subsequent reads (request objects may be retrieved multiple times)
        singleUseStore.put(KEY_PREFIX + id, ttl.toSeconds(), notes);

        // Also re-store the state index if present
        String state = notes.get(KEY_STATE);
        if (state != null && !state.isBlank()) {
            singleUseStore.put(STATE_INDEX_PREFIX + state, ttl.toSeconds(), Map.of("id", id));
        }

        return deserialize(notes);
    }

    /**
     * Remove a request object from the store.
     *
     * @param session The Keycloak session
     * @param id The unique ID to remove
     */
    public void remove(KeycloakSession session, String id) {
        if (id == null || id.isBlank()) {
            return;
        }
        SingleUseObjectProvider singleUseStore = session.singleUseObjects();

        // Get the entry to find the state for index cleanup
        Map<String, String> notes = singleUseStore.get(KEY_PREFIX + id);
        if (notes != null) {
            String state = notes.get(KEY_STATE);
            if (state != null && !state.isBlank()) {
                singleUseStore.remove(STATE_INDEX_PREFIX + state);
            }
        }
        // Note: get() already removed the main entry
    }

    /**
     * Remove all request objects with the given state from the store.
     * Used for cleanup after errors to allow clean retries.
     *
     * @param session The Keycloak session
     * @param state The OAuth state parameter
     */
    public void removeByState(KeycloakSession session, String state) {
        if (state == null || state.isBlank()) {
            return;
        }
        SingleUseObjectProvider singleUseStore = session.singleUseObjects();

        // Get and remove the state index entry
        Map<String, String> indexEntry = singleUseStore.get(STATE_INDEX_PREFIX + state);
        if (indexEntry != null) {
            String id = indexEntry.get("id");
            if (id != null && !id.isBlank()) {
                // Remove main entry
                singleUseStore.remove(KEY_PREFIX + id);
            }
        }
        // Note: get() already removed the state index entry
    }

    private void putIfNotNull(Map<String, String> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    private StoredRequestObject deserialize(Map<String, String> notes) {
        RebuildParams rebuildParams = null;
        String effectiveClientId = notes.get(KEY_REBUILD_EFFECTIVE_CLIENT_ID);
        if (effectiveClientId != null) {
            rebuildParams = new RebuildParams(
                    effectiveClientId,
                    notes.get(KEY_REBUILD_CLIENT_ID_SCHEME),
                    notes.get(KEY_REBUILD_RESPONSE_URI),
                    notes.get(KEY_REBUILD_DCQL_QUERY),
                    notes.get(KEY_REBUILD_X509_CERT_PEM),
                    notes.get(KEY_REBUILD_X509_SIGNING_KEY_JWK),
                    notes.get(KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON)
            );
        }

        return new StoredRequestObject(
                notes.get(KEY_REQUEST_OBJECT_JWT),
                notes.get(KEY_ENCRYPTION_KEY_JSON),
                notes.get(KEY_STATE),
                notes.get(KEY_NONCE),
                notes.get(KEY_ROOT_SESSION_ID),
                notes.get(KEY_CLIENT_ID),
                rebuildParams
        );
    }

    /**
     * Parameters needed to rebuild a request object with wallet_nonce.
     */
    public record RebuildParams(
            String effectiveClientId,
            String clientIdScheme,
            String responseUri,
            String dcqlQuery,
            String x509CertPem,
            String x509SigningKeyJwk,
            String encryptionPublicKeyJson
    ) {}

    /**
     * Record representing a stored request object with its associated data.
     */
    public record StoredRequestObject(
            String requestObjectJwt,
            String encryptionKeyJson,
            String state,
            String nonce,
            String rootSessionId,
            String clientId,
            RebuildParams rebuildParams
    ) {}
}
