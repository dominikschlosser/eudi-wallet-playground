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
package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MdocVerifierTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ECKey issuerKey;
    private TrustedIssuerResolver resolver;

    // Self-signed CA certificate (CN=Test CA, EC P-256)
    static final String CA_CERT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIBejCCAR+gAwIBAgIUcQCJfQf7DL9c++PXQxqU79eGkdEwCgYIKoZIzj0EAwIw
            EjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAyMjMxNjQ2MDRaFw0zNjAyMjExNjQ2
            MDRaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
            AARLfst4xx538eNupTBSqC17WhpWbnX2Ttyz6oJwTpSDJa1qg+i/b9AFtdUtvuG3
            thenQzf4QGtvCclOlQxa9RKno1MwUTAdBgNVHQ4EFgQUnOJbdrMAg/FWNwA7VCLT
            YtPOY5QwHwYDVR0jBBgwFoAUnOJbdrMAg/FWNwA7VCLTYtPOY5QwDwYDVR0TAQH/
            BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAyAPy5UyY8VWKYN0iXlu18EZaHuUf
            UXOtqMfeSx1kW8ECIQCbRvqAuQo9JpOk3uVwLEK/K2xhtLGjrnr4Wcib45OYRQ==
            -----END CERTIFICATE-----
            """;

    // Issuer certificate signed by the CA (CN=Test Issuer, EC P-256)
    static final String ISSUER_CERT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIBITCByQIUNTN+tRcFPOdthd1+2yBLF91bkvUwCgYIKoZIzj0EAwIwEjEQMA4G
            A1UEAwwHVGVzdCBDQTAeFw0yNjAyMjMxNjQ2MDRaFw0zNjAyMjExNjQ2MDRaMBYx
            FDASBgNVBAMMC1Rlc3QgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
            zDqQjISgYj70l0KHZRMxPfmuHjznIWPshWtU+2GINERurncs82MHDj2P/c4vuXiS
            72AwHAH0RDIMkZjFI6sgqDAKBggqhkjOPQQDAgNHADBEAiBCEBcT7MHLd6GF0GcL
            8F4XxgYTfD4cVX73my+Y5CrscQIgYByeCF0RbVnnLELeuEZeUDACHGFkgkoUXxG8
            oijgQrI=
            -----END CERTIFICATE-----
            """;

    // PKCS8 private key matching the issuer certificate
    static final String ISSUER_PRIVATE_KEY_PEM = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVfpo+155voq23nw+
            cvVOGAG/4K/pLCgqyBscWCMqDM+hRANCAATMOpCMhKBiPvSXQodlEzE9+a4ePOch
            Y+yFa1T7YYg0RG6udyzzYwcOPY/9zi+5eJLvYDAcAfREMgyRmMUjqyCo
            -----END PRIVATE KEY-----
            """;

    @BeforeEach
    void setUp() throws Exception {
        issuerKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("mock-issuer-es256")
                .generate();
        PublicKey issuerPublic = issuerKey.toECPublicKey();
        resolver = new TrustedIssuerResolver() {
            @Override
            public boolean verify(SignedJWT jwt, String trustListId) {
                return TrustedIssuerResolver.verifyWithKey(jwt, issuerPublic);
            }

            @Override
            public List<PublicKey> publicKeys(String trustListId) {
                return Collections.singletonList(issuerPublic);
            }
        };
    }

    @Test
    void verifiesMdocWithDeviceAuthAndSessionTranscript() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("wallet-es256")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.readTree(holderKey.toPublicJWK().toJSONString()));

        MdocCredentialBuilder builder = new MdocCredentialBuilder(issuerKey, Duration.ofMinutes(5));
        CredentialBuildResult result = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), cnf);
        String issuerSigned = result.encoded();

        ECKey handoverJwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .keyID("verifier-enc")
                .generate();
        String expectedClientId = "aud-123";
        String expectedNonce = "nonce-123";
        String expectedResponseUri = "https://verifier.example/callback";
        String deviceResponse = new MdocDeviceResponseBuilder().buildDeviceResponse(
                issuerSigned,
                holderKey,
                expectedClientId,
                expectedNonce,
                expectedResponseUri,
                handoverJwk.toPublicJWK()
        );

        MdocVerifier verifier = new MdocVerifier(resolver);
        Map<String, Object> claims = verifier.verify(deviceResponse,
                "trust-list-mock",
                expectedClientId,
                expectedNonce,
                expectedResponseUri,
                handoverJwk.toPublicJWK().computeThumbprint().decode(),
                null);

        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(claims).containsEntry("docType", "urn:example:pid:mock");
    }

    @Test
    void verifiesMdocViaX5cChainWhenDirectKeyNotInTrustList() throws Exception {
        // Parse the pre-generated CA and issuer certificates
        X509Certificate caCert = parseCert(CA_CERT_PEM);
        X509Certificate issuerCert = parseCert(ISSUER_CERT_PEM);
        ECKey x5cIssuerKey = parseEcKey(ISSUER_CERT_PEM, ISSUER_PRIVATE_KEY_PEM);

        // Resolver only has the CA cert, NOT the issuer's direct public key
        TrustedIssuerResolver x5cResolver = new TrustedIssuerResolver() {
            @Override
            public boolean verify(SignedJWT jwt, String trustListId) {
                return false;
            }

            @Override
            public List<PublicKey> publicKeys(String trustListId) {
                return List.of(); // No direct keys — forces x5c path
            }

            @Override
            public List<X509Certificate> certificates(String trustListId) {
                return List.of(caCert); // Only the CA as trust anchor
            }
        };

        // Build holder key and cnf
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("wallet-es256")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.readTree(holderKey.toPublicJWK().toJSONString()));

        // Build mDoc with x5c chain embedded
        MdocCredentialBuilder builder = new MdocCredentialBuilder(x5cIssuerKey, Duration.ofMinutes(5))
                .issuerCertificateChain(List.of(issuerCert, caCert));
        CredentialBuildResult result = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Bob"), cnf);

        // Build device response
        String deviceResponse = new MdocDeviceResponseBuilder().buildDeviceResponse(
                result.encoded(),
                holderKey,
                "client-x5c",
                "nonce-x5c",
                "https://verifier.example/x5c",
                null
        );

        // Verify — should succeed via x5c chain validation
        MdocVerifier verifier = new MdocVerifier(x5cResolver);
        Map<String, Object> claims = verifier.verify(deviceResponse,
                "trust-list-x5c",
                "client-x5c",
                "nonce-x5c",
                "https://verifier.example/x5c",
                null,
                null);

        assertThat(claims).containsEntry("given_name", "Bob");
    }

    @Test
    void mdocVerificationFailsWhenNoTrustAnchorsMatch() throws Exception {
        X509Certificate issuerCert = parseCert(ISSUER_CERT_PEM);
        ECKey x5cIssuerKey = parseEcKey(ISSUER_CERT_PEM, ISSUER_PRIVATE_KEY_PEM);

        // Resolver has NO trust anchors and NO direct keys — everything fails
        TrustedIssuerResolver emptyResolver = new TrustedIssuerResolver() {
            @Override
            public boolean verify(SignedJWT jwt, String trustListId) {
                return false;
            }

            @Override
            public List<PublicKey> publicKeys(String trustListId) {
                return List.of();
            }

            @Override
            public List<X509Certificate> certificates(String trustListId) {
                return List.of();
            }
        };

        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.readTree(holderKey.toPublicJWK().toJSONString()));

        // Build mDoc with x5c chain — but verifier has no matching trust anchors
        MdocCredentialBuilder builder = new MdocCredentialBuilder(x5cIssuerKey, Duration.ofMinutes(5))
                .issuerCertificateChain(List.of(issuerCert));
        String issuerSigned = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Eve"), cnf).encoded();

        String deviceResponse = new MdocDeviceResponseBuilder().buildDeviceResponse(
                issuerSigned, holderKey, "client-fail", "nonce-fail", "https://verifier.example/fail", null);

        MdocVerifier verifier = new MdocVerifier(emptyResolver);

        assertThatThrownBy(() -> verifier.verify(deviceResponse,
                "trust-list-empty", "client-fail", "nonce-fail", "https://verifier.example/fail", null, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not trusted");
    }

    private static X509Certificate parseCert(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes()));
    }

    private static ECKey parseEcKey(String certPem, String privateKeyPem) throws Exception {
        X509Certificate cert = parseCert(certPem);
        ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();

        String keyBase64 = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(spec);

        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .build();
    }
}
