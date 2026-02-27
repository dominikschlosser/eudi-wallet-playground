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

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectStore.class);
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);
    private static final String KEY_PREFIX = "oid4vp_request:";
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";
    private static final String KID_INDEX_PREFIX = "oid4vp_kid:";

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
    private static final String KEY_REBUILD_VERIFIER_INFO = "rebuild.verifierInfo";

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
        return store(session, requestObjectJwt, encryptionKeyJson, state, nonce, rootSessionId, clientId, rebuildParams, false);
    }

    /**
     * Store a request object, optionally skipping index entries (state and kid).
     * Use skipIndexes=true when storing multiple request objects with the same state/kid
     * in the same Keycloak transaction (Infinispan doesn't allow two put() calls for
     * the same key within one transaction).
     *
     * @param skipIndexes If true, skip creating state→id and kid→id index entries
     * @return Unique ID for retrieving the request object
     */
    public String store(KeycloakSession session, String requestObjectJwt, String encryptionKeyJson, String state, String nonce,
                        String rootSessionId, String clientId, RebuildParams rebuildParams, boolean skipIndexes) {
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
            putIfNotNull(notes, KEY_REBUILD_VERIFIER_INFO, rebuildParams.verifierInfo());
        }

        // Store main entry
        singleUseStore.put(KEY_PREFIX + id, lifespanSeconds, notes);

        // Store state and kid indexes for lookup.
        // Skip when another store() in the same transaction already created indexes
        // (Infinispan transactions don't allow two put() calls for the same key).
        if (!skipIndexes) {
            if (state != null && !state.isBlank()) {
                singleUseStore.put(STATE_INDEX_PREFIX + state, lifespanSeconds, Map.of("id", id));
                LOG.infof("[REQUEST-STORE] Stored state index: key=%s%s → id=%s (ttl=%ds)",
                        STATE_INDEX_PREFIX, state, id, lifespanSeconds);
            }

            // Store kid index for resolveByKid lookup (used when state is only inside JWE).
            if (encryptionKeyJson != null) {
                String kid = extractKidFromJwk(encryptionKeyJson);
                if (kid != null) {
                    singleUseStore.put(KID_INDEX_PREFIX + kid, lifespanSeconds, Map.of("id", id));
                    LOG.infof("[REQUEST-STORE] Stored kid index: key=%s%s → id=%s", KID_INDEX_PREFIX, kid, id);
                }
            }
        }

        LOG.infof("[REQUEST-STORE] Stored request object: id=%s, state=%s, rootSessionId=%s, skipIndexes=%b",
                id, state, rootSessionId, skipIndexes);
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

        // Look up ID from state index (non-destructive)
        String indexKey = STATE_INDEX_PREFIX + state;
        Map<String, String> indexEntry = singleUseStore.get(indexKey);
        if (indexEntry == null) {
            LOG.warnf("[REQUEST-STORE] State index NOT FOUND: key=%s", indexKey);
            // Also check if we can find the entry using contains()
            boolean exists = singleUseStore.contains(indexKey);
            LOG.warnf("[REQUEST-STORE] contains(%s) = %b", indexKey, exists);
            return null;
        }

        String id = indexEntry.get("id");
        LOG.infof("[REQUEST-STORE] State index found: key=%s → id=%s", indexKey, id);
        if (id == null || id.isBlank()) {
            return null;
        }

        // Resolve by ID
        StoredRequestObject result = resolve(session, id);
        if (result == null) {
            LOG.warnf("[REQUEST-STORE] Main entry NOT FOUND for id=%s (state index was present)", id);
        }
        return result;
    }

    /**
     * Look up a stored request object by the kid of its encryption key.
     * Used when the wallet sends an encrypted response without external state parameter.
     *
     * @param session The Keycloak session
     * @param kid The JWE key ID from the encrypted response header
     * @return The stored request object, or null if not found or expired
     */
    public StoredRequestObject resolveByKid(KeycloakSession session, String kid) {
        if (kid == null || kid.isBlank()) {
            return null;
        }
        SingleUseObjectProvider singleUseStore = session.singleUseObjects();

        String indexKey = KID_INDEX_PREFIX + kid;
        Map<String, String> indexEntry = singleUseStore.get(indexKey);
        if (indexEntry == null) {
            LOG.warnf("[REQUEST-STORE] Kid index NOT FOUND: key=%s", indexKey);
            return null;
        }

        String id = indexEntry.get("id");
        LOG.infof("[REQUEST-STORE] Kid index found: key=%s → id=%s", indexKey, id);
        if (id == null || id.isBlank()) {
            return null;
        }

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

        // get() is non-destructive — entry remains in store with its TTL
        Map<String, String> notes = singleUseStore.get(KEY_PREFIX + id);
        if (notes == null) {
            return null;
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

        // Read the entry to find the state and kid for index cleanup, then remove all
        Map<String, String> notes = singleUseStore.get(KEY_PREFIX + id);
        if (notes != null) {
            String state = notes.get(KEY_STATE);
            if (state != null && !state.isBlank()) {
                singleUseStore.remove(STATE_INDEX_PREFIX + state);
            }
            String encKeyJson = notes.get(KEY_ENCRYPTION_KEY_JSON);
            if (encKeyJson != null) {
                String kid = extractKidFromJwk(encKeyJson);
                if (kid != null) {
                    singleUseStore.remove(KID_INDEX_PREFIX + kid);
                }
            }
        }
        singleUseStore.remove(KEY_PREFIX + id);
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

        // Read the state index to find the ID, then remove the main entry and all indices
        Map<String, String> indexEntry = singleUseStore.get(STATE_INDEX_PREFIX + state);
        if (indexEntry != null) {
            String id = indexEntry.get("id");
            if (id != null && !id.isBlank()) {
                // Clean up kid index from the main entry before removing it
                Map<String, String> notes = singleUseStore.get(KEY_PREFIX + id);
                if (notes != null) {
                    String encKeyJson = notes.get(KEY_ENCRYPTION_KEY_JSON);
                    if (encKeyJson != null) {
                        String kid = extractKidFromJwk(encKeyJson);
                        if (kid != null) {
                            singleUseStore.remove(KID_INDEX_PREFIX + kid);
                        }
                    }
                }
                singleUseStore.remove(KEY_PREFIX + id);
            }
        }
        singleUseStore.remove(STATE_INDEX_PREFIX + state);
    }

    /**
     * Extract the "kid" field from a JWK JSON string.
     */
    private static String extractKidFromJwk(String jwkJson) {
        try {
            // Simple JSON parsing — avoid pulling in a full JSON library dependency.
            // The JWK JSON is always a flat object produced by our own code.
            int kidIdx = jwkJson.indexOf("\"kid\"");
            if (kidIdx < 0) return null;
            int colon = jwkJson.indexOf(':', kidIdx + 5);
            if (colon < 0) return null;
            int firstQuote = jwkJson.indexOf('"', colon + 1);
            if (firstQuote < 0) return null;
            int secondQuote = jwkJson.indexOf('"', firstQuote + 1);
            if (secondQuote < 0) return null;
            return jwkJson.substring(firstQuote + 1, secondQuote);
        } catch (Exception e) {
            LOG.warnf("[REQUEST-STORE] Failed to extract kid from JWK: %s", e.getMessage());
            return null;
        }
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
                    notes.get(KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON),
                    notes.get(KEY_REBUILD_VERIFIER_INFO)
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
            String encryptionPublicKeyJson,
            String verifierInfo
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
