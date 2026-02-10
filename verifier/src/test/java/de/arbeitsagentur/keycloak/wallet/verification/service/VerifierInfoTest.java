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
package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for verifier_info in authorization requests.
 */
class VerifierInfoTest {

    private VerifierAuthService verifierAuthService;
    private RequestObjectService requestObjectService;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        VerifierProperties properties = new VerifierProperties(
                null, // dcqlQueryFile
                null, // defaultDcqlQuery
                "http://localhost:3000/oid4vp/auth",
                "test-client-id",
                null, // keysFile
                null, // maxRequestObjectInlineBytes
                null  // etsiTrustListBaseUrl
        );
        VerifierKeyService verifierKeyService = new VerifierKeyService(properties, objectMapper);
        VerifierCryptoService verifierCryptoService = new VerifierCryptoService(verifierKeyService);
        requestObjectService = new RequestObjectService();

        verifierAuthService = new VerifierAuthService(
                verifierKeyService,
                verifierCryptoService,
                requestObjectService,
                properties,
                objectMapper
        );
    }

    @Test
    void shouldIncludeVerifierInfoWhenConfigured() throws Exception {
        // Given
        String verifierInfo = "[{\"format\": \"registration_cert\", \"data\": \"eyJhbGciOiJFUzI1NiJ9.test.signature\"}]";
        URI callback = URI.create("http://localhost:8080/callback");
        UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

        // When - use plain auth with request_uri mode to get a signed request object
        VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                callback,
                "test-state",
                "test-nonce",
                "{\"credentials\":[{\"id\":\"cred1\"}]}",
                null, // walletAuthOverride
                "test-client-id",
                "plain", // use plain auth - no cert required
                null, // clientMetadata
                null, // walletClientCert
                null, // attestationCert
                null, // attestationIssuer
                "vp_token",
                "direct_post",
                "request_uri", // request_uri mode to get a signed request object
                "post",
                null, // walletAudience
                verifierInfo,
                baseUri
        );

        // Then
        assertThat(result).isNotNull();
        assertThat(result.usedRequestUri()).isTrue();

        // Extract the request_uri query parameter from the URI
        String requestUri = extractQueryParam(result.uri(), "request_uri");
        assertThat(requestUri).isNotNull();

        // Extract the request object ID from the request_uri
        String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);

        // Resolve the stored request object
        RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
        assertThat(resolved).isNotNull();

        // Parse and verify the JWT
        SignedJWT signedJWT = SignedJWT.parse(resolved.serialized());
        JsonNode claims = objectMapper.readTree(signedJWT.getPayload().toString());

        assertThat(claims.has("verifier_info")).isTrue();
        JsonNode verifierInfoNode = claims.get("verifier_info");
        assertThat(verifierInfoNode.isArray()).isTrue();
        assertThat(verifierInfoNode.size()).isEqualTo(1);
        assertThat(verifierInfoNode.get(0).get("format").asText()).isEqualTo("registration_cert");
        assertThat(verifierInfoNode.get(0).get("data").asText()).isEqualTo("eyJhbGciOiJFUzI1NiJ9.test.signature");
    }

    @Test
    void shouldOmitVerifierInfoWhenNotConfigured() throws Exception {
        // Given
        URI callback = URI.create("http://localhost:8080/callback");
        UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

        // When
        VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                callback,
                "test-state",
                "test-nonce",
                "{\"credentials\":[{\"id\":\"cred1\"}]}",
                null, // walletAuthOverride
                "test-client-id",
                "plain",
                null, // clientMetadata
                null, // walletClientCert
                null, // attestationCert
                null, // attestationIssuer
                "vp_token",
                "direct_post",
                "request_uri",
                "post",
                null, // walletAudience
                null, // verifierInfo - not configured
                baseUri
        );

        // Then
        assertThat(result).isNotNull();
        assertThat(result.usedRequestUri()).isTrue();

        String requestUri = extractQueryParam(result.uri(), "request_uri");
        assertThat(requestUri).isNotNull();
        String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
        RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
        assertThat(resolved).isNotNull();

        SignedJWT signedJWT = SignedJWT.parse(resolved.serialized());
        JsonNode claims = objectMapper.readTree(signedJWT.getPayload().toString());

        assertThat(claims.has("verifier_info")).isFalse();
    }

    @Test
    void shouldOmitVerifierInfoWhenEmptyString() throws Exception {
        // Given
        URI callback = URI.create("http://localhost:8080/callback");
        UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

        // When
        VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                callback,
                "test-state",
                "test-nonce",
                "{\"credentials\":[{\"id\":\"cred1\"}]}",
                null,
                "test-client-id",
                "plain",
                null,
                null,
                null,
                null,
                "vp_token",
                "direct_post",
                "request_uri",
                "post",
                null,
                "  ", // verifierInfo - empty/blank
                baseUri
        );

        // Then
        assertThat(result).isNotNull();
        assertThat(result.usedRequestUri()).isTrue();

        String requestUri = extractQueryParam(result.uri(), "request_uri");
        assertThat(requestUri).isNotNull();
        String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
        RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
        assertThat(resolved).isNotNull();

        SignedJWT signedJWT = SignedJWT.parse(resolved.serialized());
        JsonNode claims = objectMapper.readTree(signedJWT.getPayload().toString());

        assertThat(claims.has("verifier_info")).isFalse();
    }

    @Test
    void shouldHandleMultipleVerifierInfoEntries() throws Exception {
        // Given
        String verifierInfo = "[" +
                "{\"format\": \"registration_cert\", \"data\": \"jwt1\"}," +
                "{\"format\": \"other_cert\", \"data\": \"jwt2\", \"credential_ids\": [\"cred1\"]}" +
                "]";
        URI callback = URI.create("http://localhost:8080/callback");
        UriComponentsBuilder baseUri = UriComponentsBuilder.fromUriString("http://localhost:8080");

        // When
        VerifierAuthService.WalletAuthRequest result = verifierAuthService.buildWalletAuthorizationUrl(
                callback,
                "test-state",
                "test-nonce",
                "{\"credentials\":[{\"id\":\"cred1\"}]}",
                null,
                "test-client-id",
                "plain",
                null,
                null,
                null,
                null,
                "vp_token",
                "direct_post",
                "request_uri",
                "post",
                null,
                verifierInfo,
                baseUri
        );

        // Then
        String requestUri = extractQueryParam(result.uri(), "request_uri");
        assertThat(requestUri).isNotNull();
        String requestId = requestUri.substring(requestUri.lastIndexOf('/') + 1);
        RequestObjectService.ResolvedRequestObject resolved = requestObjectService.resolve(requestId, null, null);
        assertThat(resolved).isNotNull();

        SignedJWT signedJWT = SignedJWT.parse(resolved.serialized());
        JsonNode claims = objectMapper.readTree(signedJWT.getPayload().toString());

        assertThat(claims.has("verifier_info")).isTrue();
        JsonNode verifierInfoNode = claims.get("verifier_info");
        assertThat(verifierInfoNode.isArray()).isTrue();
        assertThat(verifierInfoNode.size()).isEqualTo(2);

        // First entry
        assertThat(verifierInfoNode.get(0).get("format").asText()).isEqualTo("registration_cert");
        assertThat(verifierInfoNode.get(0).get("data").asText()).isEqualTo("jwt1");

        // Second entry with credential_ids
        assertThat(verifierInfoNode.get(1).get("format").asText()).isEqualTo("other_cert");
        assertThat(verifierInfoNode.get(1).get("data").asText()).isEqualTo("jwt2");
        assertThat(verifierInfoNode.get(1).has("credential_ids")).isTrue();
        assertThat(verifierInfoNode.get(1).get("credential_ids").get(0).asText()).isEqualTo("cred1");
    }

    private String extractQueryParam(URI uri, String paramName) {
        String query = uri.getQuery();
        if (query == null) return null;

        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            if (pair.length == 2 && pair[0].equals(paramName)) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
