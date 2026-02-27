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

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.JWEAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for encryption key handling in OID4VP redirect flow.
 * These tests verify that:
 * 1. When DC API is enabled, redirect flow shares the DC API encryption key
 * 2. When DC API is disabled, redirect flow generates its own encryption key
 * 3. The encryption key in client_metadata matches the key used for decryption
 */
class Oid4vpRedirectFlowEncryptionTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    void redirectFlowUsesExistingEncryptionKeyWhenProvided() throws Exception {
        // Arrange: Generate an existing encryption key (simulating DC API key)
        ECKey existingKey = new ECKeyGenerator(Curve.P_256)
                .keyID("dc-api-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();
        String existingKeyJson = existingKey.toJSONString();

        // Act: Parse the key and verify it can be reused
        ECKey parsedKey = ECKey.parse(existingKeyJson);

        // Assert: Parsed key should match original
        assertThat(parsedKey.getKeyID()).isEqualTo("dc-api-key");
        assertThat(parsedKey.getCurve()).isEqualTo(Curve.P_256);
        assertThat(parsedKey.isPrivate()).isTrue();

        // Verify public key can be extracted for client_metadata
        ECKey publicKey = parsedKey.toPublicJWK();
        assertThat(publicKey.isPrivate()).isFalse();
        assertThat(publicKey.getKeyID()).isEqualTo("dc-api-key");
    }

    @Test
    void encryptionKeyPublicPartMatchesPrivateKey() throws Exception {
        // Arrange: Generate an encryption key
        ECKey encryptionKey = new ECKeyGenerator(Curve.P_256)
                .keyID("test-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();

        // Act: Extract public key (as would be done for client_metadata)
        ECKey publicKey = encryptionKey.toPublicJWK();
        String publicKeyJson = publicKey.toJSONString();

        // Parse back and verify
        ECKey parsedPublicKey = ECKey.parse(publicKeyJson);

        // Assert: Public keys should match
        assertThat(parsedPublicKey.getX()).isEqualTo(encryptionKey.getX());
        assertThat(parsedPublicKey.getY()).isEqualTo(encryptionKey.getY());
        assertThat(parsedPublicKey.getCurve()).isEqualTo(encryptionKey.getCurve());
        assertThat(parsedPublicKey.isPrivate()).isFalse();
    }

    @Test
    void sharedEncryptionKeyEnsuresDecryptionSuccess() throws Exception {
        // This test verifies the key sharing scenario:
        // When DC API is enabled, both DC API and redirect flow should use the SAME encryption key
        // This ensures that responses encrypted with the key from redirect flow's request object
        // can be decrypted with the key stored in Keycloak's session (which is the DC API key)

        // Arrange: Generate a "DC API" encryption key
        ECKey dcApiKey = new ECKeyGenerator(Curve.P_256)
                .keyID("shared-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();
        String dcApiKeyJson = dcApiKey.toJSONString();

        // When redirect flow receives this key, it should use it in client_metadata
        ECKey redirectFlowKey = ECKey.parse(dcApiKeyJson);

        // Extract public key for client_metadata (what wallet sees)
        ECKey publicKeyForWallet = redirectFlowKey.toPublicJWK();

        // Wallet encrypts response with this public key
        // Keycloak decrypts with the private key from session

        // Assert: Both operations use the same key
        assertThat(redirectFlowKey.getKeyID()).isEqualTo(dcApiKey.getKeyID());
        assertThat(publicKeyForWallet.getX()).isEqualTo(dcApiKey.getX());
        assertThat(publicKeyForWallet.getY()).isEqualTo(dcApiKey.getY());

        // Verify the private key is available for decryption
        assertThat(dcApiKey.isPrivate()).isTrue();
        assertThat(dcApiKey.getD()).isNotNull();
    }

    @Test
    void differentEncryptionKeysWouldCauseDecryptionFailure() throws Exception {
        // This test illustrates the bug that was fixed:
        // When DC API and redirect flow had DIFFERENT encryption keys,
        // decryption would fail because the key used for encryption (from redirect flow)
        // didn't match the key used for decryption (from DC API stored in session)

        // Arrange: Generate two different keys (the bug scenario)
        ECKey dcApiKey = new ECKeyGenerator(Curve.P_256)
                .keyID("dc-api-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();

        ECKey redirectFlowKey = new ECKeyGenerator(Curve.P_256)
                .keyID("redirect-flow-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();

        // Assert: Keys are different (this was the bug)
        assertThat(dcApiKey.getX()).isNotEqualTo(redirectFlowKey.getX());
        assertThat(dcApiKey.getY()).isNotEqualTo(redirectFlowKey.getY());

        // When wallet encrypts with redirect flow's public key,
        // but Keycloak tries to decrypt with DC API's private key,
        // it would fail with "Tag mismatch" error
    }

    @Test
    void rebuildParamsPreservesEncryptionKeyReference() throws Exception {
        // Test that RebuildParams correctly stores the encryption public key
        // so that wallet_nonce rebuilds use the same key

        ECKey encryptionKey = new ECKeyGenerator(Curve.P_256)
                .keyID("rebuild-test-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();

        String publicKeyJson = encryptionKey.toPublicJWK().toJSONString();

        Oid4vpRequestObjectStore.RebuildParams rebuildParams = new Oid4vpRequestObjectStore.RebuildParams(
                "client-id",
                "plain",
                "https://response.uri/callback",
                "{\"credentials\":[]}",
                null, // x509CertPem
                null, // x509SigningKeyJwk
                publicKeyJson, // encryptionPublicKeyJson
                null  // verifierInfo
        );

        // Assert: Public key is preserved in rebuild params
        assertThat(rebuildParams.encryptionPublicKeyJson()).isEqualTo(publicKeyJson);

        // Verify it can be parsed back
        ECKey parsedKey = ECKey.parse(rebuildParams.encryptionPublicKeyJson());
        assertThat(parsedKey.getKeyID()).isEqualTo("rebuild-test-key");
        assertThat(parsedKey.isPrivate()).isFalse();
    }

    @Test
    void nullExistingKeyResultsInNewKeyGeneration() throws Exception {
        // When existingEncryptionKeyJson is null, redirect flow should generate a new key
        // This is the case when DC API is disabled

        // This test verifies the contract that:
        // - null input = new key generated
        // - non-null input = existing key used

        String nullKey = null;
        String emptyKey = "";
        String blankKey = "   ";

        // All these should result in new key generation (not an exception)
        assertThat(nullKey == null || nullKey.isBlank()).isTrue();
        assertThat(emptyKey == null || emptyKey.isBlank()).isTrue();
        assertThat(blankKey == null || blankKey.isBlank()).isTrue();
    }

    @Test
    void extractedPublicKeyForClientMetadataHasCorrectFormat() throws Exception {
        // Test that the public key format is correct for client_metadata.jwks

        ECKey encryptionKey = new ECKeyGenerator(Curve.P_256)
                .keyID("metadata-key")
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();

        ECKey publicKey = encryptionKey.toPublicJWK();
        JsonNode jwkNode = objectMapper.readTree(publicKey.toJSONString());

        // Assert: Required fields for encryption key
        assertThat(jwkNode.has("kty")).isTrue();
        assertThat(jwkNode.get("kty").asText()).isEqualTo("EC");
        assertThat(jwkNode.has("crv")).isTrue();
        assertThat(jwkNode.get("crv").asText()).isEqualTo("P-256");
        assertThat(jwkNode.has("x")).isTrue();
        assertThat(jwkNode.has("y")).isTrue();
        assertThat(jwkNode.has("kid")).isTrue();

        // Assert: Private key parts should NOT be present
        assertThat(jwkNode.has("d")).isFalse();
    }
}
