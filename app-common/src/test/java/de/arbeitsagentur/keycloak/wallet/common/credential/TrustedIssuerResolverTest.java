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
package de.arbeitsagentur.keycloak.wallet.common.credential;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TrustedIssuerResolverTest {

    // Self-signed CA certificate (CN=Test CA, EC P-256, valid 10 years)
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

    @Test
    void verifyX5cChainSucceedsWithValidChain() throws Exception {
        X509Certificate caCert = parseCert(CA_CERT_PEM);
        X509Certificate issuerCert = parseCert(ISSUER_CERT_PEM);

        PublicKey result = TrustedIssuerResolver.verifyX5cChain(
                List.of(issuerCert, caCert), // x5c chain: leaf, then CA
                List.of(caCert)              // trust anchors
        );

        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(issuerCert.getPublicKey());
    }

    @Test
    void verifyX5cChainFailsWhenChainNotSignedByTrustAnchor() throws Exception {
        X509Certificate caCert = parseCert(CA_CERT_PEM);
        X509Certificate issuerCert = parseCert(ISSUER_CERT_PEM);

        // x5c has only the issuer cert, trust anchors has only the issuer cert.
        // Since the issuer cert's key equals the trust anchor key, it gets filtered out,
        // leaving an empty path which passes PKIX. This is expected behavior — the cert
        // IS trusted as an anchor. Test instead: issuer cert with no matching anchor.
        // Use the CA cert (self-signed) as an unrelated anchor that did NOT sign the issuer cert's chain
        // when the chain does not include the actual signer.
        // Actually, the CA *did* sign the issuer cert, so we need a truly unrelated anchor.
        // We'll verify that a chain with only the leaf and NO matching trust anchor fails.

        // issuerCert was signed by the CA. If we present it alone without the CA,
        // and use the issuerCert itself as the trust anchor (it's not self-signed), it should fail.
        // But PKIX filters it out by key match. So use a truly unrelated cert.
        // The simplest: CA cert does not match issuerCert's key, so presenting issuerCert
        // with CA_CERT as the only chain entry and issuerCert as anchor should fail.
        PublicKey result = TrustedIssuerResolver.verifyX5cChain(
                List.of(caCert),       // present CA cert as "leaf"
                List.of(issuerCert)    // issuer cert as anchor — CA was not signed by issuer
        );

        assertThat(result).isNull();
    }

    @Test
    void verifyX5cChainReturnsNullForEmptyInputs() {
        assertThat(TrustedIssuerResolver.verifyX5cChain(List.of(), List.of())).isNull();
        assertThat(TrustedIssuerResolver.verifyX5cChain(null, null)).isNull();
        assertThat(TrustedIssuerResolver.verifyX5cChain(null, List.of())).isNull();
        assertThat(TrustedIssuerResolver.verifyX5cChain(List.of(), null)).isNull();
    }

    @Test
    void verifyX5cChainSucceedsWithSelfSignedLeafAsTrustAnchor() throws Exception {
        X509Certificate caCert = parseCert(CA_CERT_PEM);

        // Self-signed cert used as both leaf and trust anchor
        PublicKey result = TrustedIssuerResolver.verifyX5cChain(
                List.of(caCert),
                List.of(caCert)
        );

        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(caCert.getPublicKey());
    }

    private static X509Certificate parseCert(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes()));
    }
}
