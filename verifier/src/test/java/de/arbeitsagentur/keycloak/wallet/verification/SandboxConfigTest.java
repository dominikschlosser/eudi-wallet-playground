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
package de.arbeitsagentur.keycloak.wallet.verification;

import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierCryptoService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for sandbox configuration: client cert file loading, cert chain preservation,
 * verifier info file loading, and x509_san_dns client ID derivation.
 */
class SandboxConfigTest {

    @TempDir
    Path tempDir;

    private KeyPair leafKeyPair;
    private X509Certificate leafCert;
    private X509Certificate caCert;
    private Path certFile;
    private Path verifierInfoFile;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));

        // Generate CA key pair and self-signed CA cert
        KeyPair caKeyPair = kpg.generateKeyPair();
        X500Name caSubject = new X500Name("CN=Test CA, C=DE");
        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 86400000),
                new Date(System.currentTimeMillis() + 365L * 86400000),
                caSubject, caKeyPair.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caCert = new JcaX509CertificateConverter().getCertificate(caBuilder.build(caSigner));

        // Generate leaf key pair and cert signed by CA, with DNS SAN
        leafKeyPair = kpg.generateKeyPair();
        X500Name leafSubject = new X500Name("CN=Test RP, C=DE");
        ContentSigner leafSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        X509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(2),
                new Date(System.currentTimeMillis() - 86400000),
                new Date(System.currentTimeMillis() + 365L * 86400000),
                leafSubject, leafKeyPair.getPublic());
        leafBuilder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "sandbox.example.com")));
        leafCert = new JcaX509CertificateConverter().getCertificate(leafBuilder.build(leafSigner));

        // Write combined PEM: leaf cert + CA cert + private key
        String leafCertPem = toPem(leafCert.getEncoded(), "CERTIFICATE");
        String caCertPem = toPem(caCert.getEncoded(), "CERTIFICATE");
        String keyPem = toPem(leafKeyPair.getPrivate().getEncoded(), "PRIVATE KEY");
        certFile = tempDir.resolve("sandbox-cert.pem");
        Files.writeString(certFile, leafCertPem + "\n" + caCertPem + "\n" + keyPem);

        // Write verifier info file
        verifierInfoFile = tempDir.resolve("verifier-info.json");
        Files.writeString(verifierInfoFile, "[{\"format\":\"registration_cert\",\"data\":\"eyJ0ZXN0IjoianVzdC1hLXRlc3QifQ\"}]");
    }

    @Test
    void sandboxMaterialIsLoadedFromCertFile() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.loadSandboxMaterial();
        assertThat(material).isNotNull();
        assertThat(material.source()).isEqualTo("client_cert_file");
        assertThat(material.certificatePem()).contains("BEGIN CERTIFICATE");
        assertThat(material.keyPem()).contains("BEGIN PRIVATE KEY");
    }

    @Test
    void sandboxMaterialDerivesCorrectX509SanDns() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.loadSandboxMaterial();
        String sanClientId = cryptoService.deriveX509SanClientId(null, material.certificatePem());
        assertThat(sanClientId).isEqualTo("x509_san_dns:sandbox.example.com");
    }

    @Test
    void sandboxMaterialPreservesFullCertChain() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.loadSandboxMaterial();

        // extractCertChain on combinedPem should find both leaf and CA certs
        var chain = cryptoService.extractCertChain(material.combinedPem());
        assertThat(chain).hasSize(2);
    }

    @Test
    void inlineProvidedPemIsUsedOverSelfSigned() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        // resolveX509Material(null) always returns self-signed (no file fallback)
        var selfSignedMaterial = cryptoService.resolveX509Material(null);
        assertThat(selfSignedMaterial.source()).isEqualTo("verifier_self_signed");

        // Passing inline PEM should use it
        var inlineMaterial = cryptoService.resolveX509Material(selfSignedMaterial.combinedPem());
        assertThat(inlineMaterial.source()).isEqualTo("client_cert");
    }

    @Test
    void resolveX509MaterialReturnsSelfSignedByDefault() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.resolveX509Material(null);
        assertThat(material.source()).isEqualTo("verifier_self_signed");
    }

    @Test
    void loadSandboxMaterialReturnsNullWhenNoFileConfigured() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        assertThat(cryptoService.loadSandboxMaterial()).isNull();
    }

    @Test
    void loadSandboxMaterialReturnsNullWhenFileDoesNotExist() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                tempDir.resolve("nonexistent.pem").toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        assertThat(cryptoService.loadSandboxMaterial()).isNull();
    }

    @Test
    void sandboxDcqlQueryIsStructurallyValid() throws Exception {
        String dcql = "{\"credentials\":[{\"id\":\"pid_sd_jwt\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"urn:eudi:pid:de:1\"]},\"claims\":[{\"path\":[\"given_name\"]}]},{\"id\":\"pid_mdoc\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"eu.europa.ec.eudi.pid.1\"},\"claims\":[{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"given_name\"]}]}],\"credential_sets\":[{\"options\":[[\"pid_sd_jwt\"],[\"pid_mdoc\"]]}]}";
        ObjectMapper mapper = new ObjectMapper();
        var tree = mapper.readTree(dcql);

        assertThat(tree.has("credentials")).isTrue();
        assertThat(tree.get("credentials").isArray()).isTrue();
        assertThat(tree.get("credentials")).hasSize(2);

        // SD-JWT credential
        var sdJwt = tree.get("credentials").get(0);
        assertThat(sdJwt.get("format").asText()).isEqualTo("dc+sd-jwt");
        assertThat(sdJwt.get("meta").get("vct_values").get(0).asText()).isEqualTo("urn:eudi:pid:de:1");

        // mDoc credential
        var mdoc = tree.get("credentials").get(1);
        assertThat(mdoc.get("format").asText()).isEqualTo("mso_mdoc");
        assertThat(mdoc.get("meta").get("doctype_value").asText()).isEqualTo("eu.europa.ec.eudi.pid.1");

        // credential_sets: wallet needs to provide only one
        assertThat(tree.has("credential_sets")).isTrue();
        var sets = tree.get("credential_sets");
        assertThat(sets.isArray()).isTrue();
        assertThat(sets.get(0).get("options")).hasSize(2);
    }

    @Test
    void verifierInfoFileIsReadCorrectly() throws Exception {
        String content = Files.readString(verifierInfoFile);
        ObjectMapper mapper = new ObjectMapper();
        var tree = mapper.readTree(content);

        assertThat(tree.isArray()).isTrue();
        assertThat(tree).hasSize(1);
        assertThat(tree.get(0).get("format").asText()).isEqualTo("registration_cert");
        assertThat(tree.get(0).has("data")).isTrue();
    }

    private static String toPem(byte[] der, String type) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }
}
