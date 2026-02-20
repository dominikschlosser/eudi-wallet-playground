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

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

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
        String dcql = "{\"credentials\":[{\"id\":\"pid_sd_jwt\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"urn:eudi:pid:de:1\"]},\"claims\":[{\"path\":[\"given_name\"]},{\"path\":[\"family_name\"]},{\"path\":[\"address\",\"street_address\"]},{\"path\":[\"address\",\"locality\"]}]},{\"id\":\"pid_mdoc\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"eu.europa.ec.eudi.pid.1\"},\"claims\":[{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"given_name\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"family_name\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"birth_date\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"address\",\"street_address\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"address\",\"locality\"]}]}],\"credential_sets\":[{\"options\":[[\"pid_sd_jwt\"],[\"pid_mdoc\"]]}]}";
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

    @Test
    void sandboxMaterialContainsPrivateKeyForSigning() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.loadSandboxMaterial();

        // The server-side material must contain the private key for request object signing
        assertThat(material.keyPem()).contains("BEGIN PRIVATE KEY");
        assertThat(material.combinedPem()).contains("BEGIN PRIVATE KEY");
        // The JWK must have a private key for signing
        assertThat(material.jwk()).isNotNull();
        assertThat(material.jwk().isPrivate()).isTrue();
    }

    @Test
    void stripPrivateKeyRemovesAllKeyBlocks() {
        // Simulate what VerifierController.stripPrivateKey does
        String combinedPem = toPem(new byte[]{1, 2, 3}, "CERTIFICATE")
                + "\n" + toPem(new byte[]{4, 5, 6}, "PRIVATE KEY");
        String stripped = combinedPem.replaceAll(
                "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----", "").strip();

        assertThat(stripped).contains("BEGIN CERTIFICATE");
        assertThat(stripped).doesNotContain("PRIVATE KEY");
    }

    @Test
    void stripPrivateKeyHandlesRsaAndEcVariants() {
        String rsaPem = "-----BEGIN RSA PRIVATE KEY-----\nMIIdata\n-----END RSA PRIVATE KEY-----";
        String ecPem = "-----BEGIN EC PRIVATE KEY-----\nMIIdata\n-----END EC PRIVATE KEY-----";
        String pkcs8Pem = "-----BEGIN PRIVATE KEY-----\nMIIdata\n-----END PRIVATE KEY-----";
        String certPem = toPem(new byte[]{1, 2, 3}, "CERTIFICATE");

        String combined = certPem + "\n" + rsaPem + "\n" + ecPem + "\n" + pkcs8Pem;
        String stripped = combined.replaceAll(
                "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----", "").strip();

        assertThat(stripped).contains("BEGIN CERTIFICATE");
        assertThat(stripped).doesNotContain("PRIVATE KEY");
        assertThat(stripped).doesNotContain("RSA PRIVATE KEY");
        assertThat(stripped).doesNotContain("EC PRIVATE KEY");
    }

    @Test
    void sandboxCombinedPemWithKeyStrippedOnlyHasCerts() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.loadSandboxMaterial();

        // Verify the real sandbox material combinedPem has private key
        assertThat(material.combinedPem()).contains("PRIVATE KEY");

        // After stripping (as the controller does before sending to browser),
        // no private key should remain but certificates must be preserved
        String stripped = material.combinedPem().replaceAll(
                "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----", "").strip();
        assertThat(stripped).doesNotContain("PRIVATE KEY");
        assertThat(stripped).contains("BEGIN CERTIFICATE");

        // The stripped version should still have both certs in the chain
        var chain = cryptoService.extractCertChain(stripped);
        assertThat(chain).hasSize(2);
    }

    @Test
    void sandboxCertChainIsValidatable() throws Exception {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                certFile.toString(), null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService, props);

        var material = cryptoService.loadSandboxMaterial();
        var chain = cryptoService.extractCertChain(material.combinedPem());
        assertThat(chain).as("Chain must include leaf + intermediate CA").hasSize(2);

        // Parse the certificates and validate the chain
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate leaf = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(chain.get(0))));
        X509Certificate intermediate = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(chain.get(1))));

        // Leaf must be signed by the intermediate CA
        leaf.verify(intermediate.getPublicKey());

        // Intermediate must be a CA
        assertThat(intermediate.getBasicConstraints())
                .as("Intermediate certificate must be a CA")
                .isGreaterThanOrEqualTo(0);

        // Leaf must NOT be a CA
        assertThat(leaf.getBasicConstraints())
                .as("Leaf certificate must not be a CA")
                .isEqualTo(-1);

        // Leaf issuer must match intermediate subject
        assertThat(leaf.getIssuerX500Principal())
                .as("Leaf issuer must match intermediate subject")
                .isEqualTo(intermediate.getSubjectX500Principal());
    }

    @Test
    void encryptionKeyIsEcP256WithEcdhEs() throws Exception {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());

        ECKey encKey = keyService.loadOrCreateEncryptionKey();
        assertThat(encKey.getCurve().getName()).isEqualTo("P-256");
        assertThat(encKey.getAlgorithm().getName()).isEqualTo("ECDH-ES");
        assertThat(encKey.getKeyUse().getValue()).isEqualTo("enc");
        assertThat(encKey.isPrivate()).isTrue();
    }

    @Test
    void publicJwksContainsEcEncryptionKey() throws Exception {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());

        String jwksJson = keyService.publicJwksJson();
        JWKSet jwkSet = JWKSet.parse(jwksJson);

        assertThat(jwkSet.getKeys()).hasSize(1);
        assertThat(jwkSet.getKeys().get(0)).isInstanceOf(ECKey.class);

        ECKey publicKey = (ECKey) jwkSet.getKeys().get(0);
        assertThat(publicKey.getCurve().getName()).isEqualTo("P-256");
        assertThat(publicKey.getAlgorithm().getName()).isEqualTo("ECDH-ES");
        assertThat(publicKey.isPrivate()).as("Public JWKS must not expose private key").isFalse();
    }

    @Test
    void clientMetadataEncryptionAlgMatchesJwksKeyType() throws Exception {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        ObjectMapper mapper = new ObjectMapper();

        // Build the same client_metadata as VerifierController.defaultClientMetadata()
        String jwks = keyService.publicJwksJson();
        JsonNode jwksNode = mapper.readTree(jwks);
        var meta = mapper.createObjectNode();
        meta.set("jwks", jwksNode);
        meta.put("authorization_encrypted_response_alg", "ECDH-ES");
        meta.put("authorization_encrypted_response_enc", "A128GCM");

        // Verify the JWKS key type is compatible with the advertised algorithm
        JsonNode keys = meta.get("jwks").get("keys");
        assertThat(keys.isArray()).isTrue();
        assertThat(keys.size()).isGreaterThan(0);

        String kty = keys.get(0).get("kty").asText();
        String alg = meta.get("authorization_encrypted_response_alg").asText();

        // ECDH-ES requires EC keys, not RSA
        assertThat(kty).as("ECDH-ES requires EC key type, not RSA").isEqualTo("EC");
        assertThat(alg).startsWith("ECDH");
    }

    @Test
    void ecdhEsEncryptDecryptRoundTrip() {
        var props = new VerifierProperties(null, null, null, null, null, null, null,
                null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());

        String payload = "{\"vp_token\":\"test-token-value\"}";
        String encrypted = keyService.encrypt(payload, "ECDH-ES", "A128GCM");

        assertThat(encrypted).isNotEqualTo(payload);
        assertThat(encrypted).contains("."); // JWE compact serialization

        String decrypted = keyService.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(payload);
    }

    @Test
    void legacyRsaEncryptionKeyIsReplacedWithEc() throws Exception {
        // Create a key service without a keys file to get a fresh RSA signing key
        var rsaKeyService = new VerifierKeyService(
                new VerifierProperties(null, null, null, null, null, null, null, null, null, null, null),
                new ObjectMapper());
        var signingKey = rsaKeyService.loadOrCreateSigningKey();

        // Write a legacy keys file with only the RSA signing key (no encryption key)
        Path legacyFile = tempDir.resolve("legacy-rsa-keys.json");
        String legacyJson = "{\"keys\":[" + signingKey.toJSONString() + "]}";
        Files.writeString(legacyFile, legacyJson);

        // Load from the legacy file — should generate a new EC encryption key
        var props2 = new VerifierProperties(null, null, null, null, legacyFile, null, null,
                null, null, null, null);
        var keyService2 = new VerifierKeyService(props2, new ObjectMapper());

        ECKey encKey = keyService2.loadOrCreateEncryptionKey();
        assertThat(encKey).as("Missing RSA encryption key should be regenerated as EC").isNotNull();
        assertThat(encKey.getCurve().getName()).isEqualTo("P-256");
        assertThat(encKey.getAlgorithm().getName()).isEqualTo("ECDH-ES");

        // Verify the persisted file now contains the EC key
        String persisted = Files.readString(legacyFile);
        assertThat(persisted).contains("\"EC\"");
        assertThat(persisted).contains("ECDH-ES");
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
