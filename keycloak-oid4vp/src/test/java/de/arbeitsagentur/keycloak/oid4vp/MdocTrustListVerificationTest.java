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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocCredentialBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocDeviceResponseBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocVerifier;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocTrustListVerificationTest {
    private static final Logger LOG = LoggerFactory.getLogger(MdocTrustListVerificationTest.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Trust list JWT (ETSI TS 119 602 format) containing the mock issuer certificate
    private static final String TEST_TRUST_LIST_JWT =
            "eyJhbGciOiAibm9uZSJ9.eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IlRlc3QgVHJ1c3QgTGlzdCJ9XSwiTG9URVR5cGUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL0xvVEVUeXBlL2xvY2FsIn0sIlRydXN0ZWRFbnRpdGllc0xpc3QiOlt7IlRydXN0ZWRFbnRpdHlJbmZvcm1hdGlvbiI6eyJURU5hbWUiOlt7ImxhbmciOiJlbiIsInZhbHVlIjoibW9jay1pc3N1ZXItZXMyNTYifV19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvSXNzdWFuY2UiLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUJnVENDQVNlZ0F3SUJBZ0lVQmpFYUloR2NXNXBQWDd2Q3RYYnFNeXFsN2V3d0NnWUlLb1pJemowRUF3SXdGakVVTUJJR0ExVUVBd3dMYlc5amF5MXBjM04xWlhJd0hoY05NalV4TWpBeE1Ea3pPVEkyV2hjTk16VXhNVEk1TURrek9USTJXakFXTVJRd0VnWURWUVFEREF0dGIyTnJMV2x6YzNWbGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJDU0dvMDJmTko0aWx5SUpWc25SOTBVTXZCRWhiRHhwdklOL1grUnE0eTlxakNBMzVJbmJ3bTVqRjB0b3lwb292NGFhZ0pHYVJrd3ptdk95MUpNbGFtS2pVekJSTUIwR0ExVWREZ1FXQkJSMm1PeDI2NTA3OG5CWHNTQ2YwN2U5OVJCbEREQWZCZ05WSFNNRUdEQVdnQlIybU94MjY1MDc4bkJYc1JDZjA3ZTk5UkJsRERBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEYzFFdmI1OFZXQUdUTmdpYWRzdFFtQ0w2WUwzQ2hBU3QvVkxoZ0Evb2diQUlnSzVEakxRdVkwZFZEVGFEY2NFQzlzL3VhS3UrejV1MjhadFFqVks2NXpGVT0ifV19fX1dfV19.";

    @Test
    void mdocVerificationWithTrustList() throws Exception {
        // Load issuer key from test resources (same as mock wallet does)
        ECKey issuerKey;
        try (var is = getClass().getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).isNotNull();
            JsonNode node = objectMapper.readTree(is);
            issuerKey = ECKey.parse(node.get("privateJwk").toString());
        }

        // Build mDoc credential
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder").generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));

        MdocCredentialBuilder credentialBuilder = new MdocCredentialBuilder(issuerKey, Duration.ofMinutes(5));
        String issuerSigned = credentialBuilder.build("mock", "urn:example:pid", "https://issuer.example",
                Map.of("personal_id", "ID-123"), cnf).encoded();

        // Build device response
        MdocDeviceResponseBuilder deviceResponseBuilder = new MdocDeviceResponseBuilder();
        String deviceResponse = deviceResponseBuilder.buildDeviceResponse(
                issuerSigned, holderKey, "client-id", "nonce-123", "https://response.uri", null);

        // Load trust list and create verifier
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(TEST_TRUST_LIST_JWT);
        List<PublicKey> keys = trustListService.publicKeys("trust-list");
        LOG.info("Trust list has {} keys", keys.size());
        for (PublicKey key : keys) {
            LOG.info("  Key type: {}, class: {}", key.getAlgorithm(), key.getClass().getSimpleName());
        }

        MdocVerifier verifier = new MdocVerifier(trustListService);

        // Verify
        Map<String, Object> claims = verifier.verify(deviceResponse, "trust-list", "client-id", "nonce-123",
                "https://response.uri", null, null);

        assertThat(claims).containsEntry("personal_id", "ID-123");
    }

    @Test
    void mdocVerificationWithX5chain() throws Exception {
        // Load issuer key from test resources (same as mock wallet does)
        ECKey issuerKey;
        try (var is = getClass().getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).isNotNull();
            JsonNode node = objectMapper.readTree(is);
            issuerKey = ECKey.parse(node.get("privateJwk").toString());
        }

        // Load the issuer certificate (same as in the test trust list)
        String certBase64 = "MIIBgTCCASegAwIBAgIUBjEaIhGcW5pPX7vCtXbqMyql7ewwCgYIKoZIzj0EAwIw"
                + "FjEUMBIGA1UEAwwLbW9jay1pc3N1ZXIwHhcNMjUxMjAxMDkzOTI2WhcNMzUxMTI5"
                + "MDkzOTI2WjAWMRQwEgYDVQQDDAttb2NrLWlzc3VlcjBZMBMGByqGSM49AgEGCCqG"
                + "SM49AwEHA0IABCSGo02fNJ4ilyIJVsnR90UMvBEhbDxpvIN/X+Rq4y9qjCA35Inb"
                + "wm5jF0toypoov4aagJGaRkwzmvOy1JMlamKjUzBRMB0GA1UdDgQWBBR2mOx26507"
                + "8nBXsMCf07e99RBlDDAfBgNVHSMEGDAWgBR2mOx265078nBXsRCf07e99RBlDDAP"
                + "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDc1Evb58VWAGTNgiad"
                + "stQmCL6YL3ChASt/VLhgA/ogbAIgK5DjLQuY0dVDTaDccEC9s/uaKu+z5u28ZtQj"
                + "VK65zFU=";
        byte[] certBytes = Base64.getDecoder().decode(certBase64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate issuerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

        // Build mDoc credential WITH x5chain
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder").generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));

        MdocCredentialBuilder credentialBuilder = new MdocCredentialBuilder(issuerKey, Duration.ofMinutes(5))
                .issuerCertificateChain(List.of(issuerCert));
        String issuerSigned = credentialBuilder.build("mock", "eu.europa.ec.eudi.pid.1", "https://issuer.example",
                Map.of("family_name", "Doe", "given_name", "John", "document_number", "DOC-123"), cnf).encoded();

        // Build device response with same parameters as E2E same-device flow
        MdocDeviceResponseBuilder deviceResponseBuilder = new MdocDeviceResponseBuilder();
        String deviceResponse = deviceResponseBuilder.buildDeviceResponse(
                issuerSigned, holderKey, "client-id", "nonce-123",
                "http://localhost:8080/realms/wallet-demo/broker/oid4vp/endpoint", null);

        // Load trust list and create verifier
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(TEST_TRUST_LIST_JWT);
        MdocVerifier verifier = new MdocVerifier(trustListService);

        // Verify - this should work with x5chain
        Map<String, Object> claims = verifier.verify(deviceResponse, "trust-list", "client-id", "nonce-123",
                "http://localhost:8080/realms/wallet-demo/broker/oid4vp/endpoint", null, null);

        LOG.info("Verified claims: {}", claims);
        assertThat(claims).containsEntry("family_name", "Doe");
        assertThat(claims).containsEntry("document_number", "DOC-123");
    }
}
