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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for wallet_nonce support in OID4VP redirect flow.
 * Per OID4VP spec, when wallet POSTs to request_uri with wallet_nonce,
 * the verifier MUST return a new request object containing the wallet_nonce claim.
 */
class Oid4vpWalletNonceTest {

    private KeycloakSession session;
    private SingleUseObjectProvider singleUseProvider;
    private Map<String, Map<String, String>> inMemoryStore;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        singleUseProvider = mock(SingleUseObjectProvider.class);
        inMemoryStore = new ConcurrentHashMap<>();

        when(session.singleUseObjects()).thenReturn(singleUseProvider);

        // Mock put to store in memory
        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            @SuppressWarnings("unchecked")
            Map<String, String> notes = invocation.getArgument(2);
            inMemoryStore.put(key, new ConcurrentHashMap<>(notes));
            return null;
        }).when(singleUseProvider).put(anyString(), anyLong(), anyMap());

        // Mock get to retrieve and remove from memory
        when(singleUseProvider.get(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return inMemoryStore.remove(key);
        });

        // Mock remove
        when(singleUseProvider.remove(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return inMemoryStore.remove(key) != null;
        });
    }

    @Test
    void testRequestObjectStoreWithRebuildParams() {
        Oid4vpRequestObjectStore store = new Oid4vpRequestObjectStore();

        Oid4vpRequestObjectStore.RebuildParams rebuildParams = new Oid4vpRequestObjectStore.RebuildParams(
                "http://localhost:8080/",
                "x509_san_dns",
                "http://localhost:8080/callback",
                "{\"credentials\":[]}",
                "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
                "{\"kty\":\"EC\"}",
                "{\"kty\":\"EC\",\"crv\":\"P-256\"}",
                null
        );

        String id = store.store(
                session,
                "jwt-content",
                "encryption-key-json",
                "state123",
                "nonce456",
                "session-id",
                "client-id",
                rebuildParams
        );

        assertThat(id).isNotNull();

        Oid4vpRequestObjectStore.StoredRequestObject stored = store.resolve(session, id);
        assertThat(stored).isNotNull();
        assertThat(stored.requestObjectJwt()).isEqualTo("jwt-content");
        assertThat(stored.encryptionKeyJson()).isEqualTo("encryption-key-json");
        assertThat(stored.state()).isEqualTo("state123");
        assertThat(stored.nonce()).isEqualTo("nonce456");
        assertThat(stored.rootSessionId()).isEqualTo("session-id");
        assertThat(stored.clientId()).isEqualTo("client-id");
        assertThat(stored.rebuildParams()).isNotNull();
        assertThat(stored.rebuildParams().effectiveClientId()).isEqualTo("http://localhost:8080/");
        assertThat(stored.rebuildParams().clientIdScheme()).isEqualTo("x509_san_dns");
        assertThat(stored.rebuildParams().responseUri()).isEqualTo("http://localhost:8080/callback");
        assertThat(stored.rebuildParams().dcqlQuery()).isEqualTo("{\"credentials\":[]}");
        assertThat(stored.rebuildParams().x509CertPem()).contains("BEGIN CERTIFICATE");
        assertThat(stored.rebuildParams().x509SigningKeyJwk()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(stored.rebuildParams().encryptionPublicKeyJson()).contains("P-256");
    }

    @Test
    void testRequestObjectStoreBackwardCompatibleWithoutRebuildParams() {
        Oid4vpRequestObjectStore store = new Oid4vpRequestObjectStore();

        // Use the old store method without rebuildParams
        String id = store.store(session, "jwt", "enc-key", "state", "nonce");

        Oid4vpRequestObjectStore.StoredRequestObject stored = store.resolve(session, id);
        assertThat(stored).isNotNull();
        assertThat(stored.requestObjectJwt()).isEqualTo("jwt");
        assertThat(stored.encryptionKeyJson()).isEqualTo("enc-key");
        assertThat(stored.state()).isEqualTo("state");
        assertThat(stored.nonce()).isEqualTo("nonce");
        assertThat(stored.rebuildParams()).isNull();
    }

    @Test
    void testRequestObjectStoreWithSessionInfoWithoutRebuildParams() {
        Oid4vpRequestObjectStore store = new Oid4vpRequestObjectStore();

        // Use the store method with session info but without rebuildParams
        String id = store.store(session, "jwt", "enc-key", "state", "nonce", "root-session", "client");

        Oid4vpRequestObjectStore.StoredRequestObject stored = store.resolve(session, id);
        assertThat(stored).isNotNull();
        assertThat(stored.rootSessionId()).isEqualTo("root-session");
        assertThat(stored.clientId()).isEqualTo("client");
        assertThat(stored.rebuildParams()).isNull();
    }

    @Test
    void testRequestObjectStoreResolveByState() {
        Oid4vpRequestObjectStore store = new Oid4vpRequestObjectStore();

        Oid4vpRequestObjectStore.RebuildParams rebuildParams = new Oid4vpRequestObjectStore.RebuildParams(
                "client-id", "plain", "response-uri", null, null, null, null, null
        );

        store.store(session, "jwt1", "enc1", "state-A", "nonce1", null, null, rebuildParams);
        store.store(session, "jwt2", "enc2", "state-B", "nonce2", null, null, rebuildParams);

        Oid4vpRequestObjectStore.StoredRequestObject foundA = store.resolveByState(session, "state-A");
        assertThat(foundA).isNotNull();
        assertThat(foundA.requestObjectJwt()).isEqualTo("jwt1");
        assertThat(foundA.rebuildParams()).isNotNull();

        Oid4vpRequestObjectStore.StoredRequestObject foundB = store.resolveByState(session, "state-B");
        assertThat(foundB).isNotNull();
        assertThat(foundB.requestObjectJwt()).isEqualTo("jwt2");

        Oid4vpRequestObjectStore.StoredRequestObject notFound = store.resolveByState(session, "state-C");
        assertThat(notFound).isNull();
    }

    @Test
    void testRebuildParamsRecord() {
        Oid4vpRequestObjectStore.RebuildParams params = new Oid4vpRequestObjectStore.RebuildParams(
                "effective-client-id",
                "x509_hash",
                "http://response.uri/",
                "{\"credentials\":[{\"id\":\"cred1\"}]}",
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                "{\"kty\":\"EC\",\"d\":\"private\"}",
                "{\"kty\":\"EC\",\"x\":\"public\"}",
                null
        );

        assertThat(params.effectiveClientId()).isEqualTo("effective-client-id");
        assertThat(params.clientIdScheme()).isEqualTo("x509_hash");
        assertThat(params.responseUri()).isEqualTo("http://response.uri/");
        assertThat(params.dcqlQuery()).contains("cred1");
        assertThat(params.x509CertPem()).contains("BEGIN CERTIFICATE");
        assertThat(params.x509SigningKeyJwk()).contains("private");
        assertThat(params.encryptionPublicKeyJson()).contains("public");
    }

    @Test
    void testRebuildParamsWithNullValues() {
        // All optional fields can be null
        Oid4vpRequestObjectStore.RebuildParams params = new Oid4vpRequestObjectStore.RebuildParams(
                "client-id",
                null,  // clientIdScheme optional
                "response-uri",
                null,  // dcqlQuery optional
                null,  // x509CertPem optional
                null,  // x509SigningKeyJwk optional
                null,  // encryptionPublicKeyJson optional
                null   // verifierInfo optional
        );

        assertThat(params.effectiveClientId()).isEqualTo("client-id");
        assertThat(params.clientIdScheme()).isNull();
        assertThat(params.responseUri()).isEqualTo("response-uri");
        assertThat(params.dcqlQuery()).isNull();
        assertThat(params.x509CertPem()).isNull();
        assertThat(params.x509SigningKeyJwk()).isNull();
        assertThat(params.encryptionPublicKeyJson()).isNull();
    }
}
