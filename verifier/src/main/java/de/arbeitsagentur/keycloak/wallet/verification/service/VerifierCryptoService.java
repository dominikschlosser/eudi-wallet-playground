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

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Service;

import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class VerifierCryptoService {
    private final VerifierKeyService verifierKeyService;
    private final VerifierProperties properties;

    public VerifierCryptoService(VerifierKeyService verifierKeyService, VerifierProperties properties) {
        this.verifierKeyService = verifierKeyService;
        this.properties = properties;
    }

    public X509Material resolveX509Material(String providedPem) {
        if (providedPem != null && !providedPem.isBlank()) {
            return parsePemMaterial(providedPem, "client_cert");
        }
        JWK signingJwk = verifierKeyService.loadOrCreateSigningKey();
        try {
            String certPem = verifierKeyService.signingCertificatePem();
            String keyPem = toPem(privateKeyBytes(signingJwk), "PRIVATE KEY");
            String combined = certPem + "\n" + keyPem;
            return new X509Material(certPem, keyPem, combined, "verifier_self_signed", signingJwk);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to prepare verifier x509 material", e);
        }
    }

    public X509Material loadSandboxMaterial() {
        java.nio.file.Path certFile = properties.clientCertFilePath();
        if (certFile != null && Files.exists(certFile)) {
            try {
                String filePem = Files.readString(certFile);
                return parsePemMaterial(filePem, "client_cert_file");
            } catch (Exception e) {
                throw new IllegalStateException("Failed to read client cert file: " + certFile, e);
            }
        }
        return null;
    }

    private X509Material parsePemMaterial(String pem, String source) {
        String certBlock = extractPemBlock(pem, "CERTIFICATE");
        if (certBlock == null || certBlock.isBlank()) {
            throw new IllegalStateException("No certificate found in " + source);
        }
        JWK jwk = parsePrivateKeyWithCertificate(pem);
        try {
            String leafCertPem = toPem(Base64.getMimeDecoder().decode(certBlock), "CERTIFICATE");
            String keyPem = toPem(privateKeyBytes(jwk), "PRIVATE KEY");
            // combinedPem includes the full certificate chain (not just leaf) so that
            // extractCertChain() can build the complete x5c header later.
            List<String> chainDer = extractCertChain(pem);
            StringBuilder combined = new StringBuilder();
            for (String der : chainDer) {
                combined.append(toPem(Base64.getDecoder().decode(der), "CERTIFICATE")).append("\n");
            }
            combined.append(keyPem);
            return new X509Material(leafCertPem, keyPem, combined.toString(), source, jwk);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to prepare " + source + " material", e);
        }
    }

    public String deriveX509ClientId(String existingClientId, String certificatePem) {
        String firstCert = extractPemBlock(certificatePem, "CERTIFICATE");
        if (firstCert == null || firstCert.isBlank()) {
            throw new IllegalStateException("No certificate found in client_cert");
        }
        try {
            X509Certificate cert = toX509(firstCert);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            String computed = "x509_hash:" + hash;
            if (existingClientId != null && existingClientId.startsWith("x509_hash:") && !existingClientId.equals(computed)) {
                throw new IllegalStateException("client_id hash does not match client_cert");
            }
            return computed;
        } catch (Exception e) {
            throw new IllegalStateException("Invalid client_cert for x509_hash client authentication", e);
        }
    }

    public String deriveX509SanClientId(String existingClientId, String certificatePem) {
        String firstCert = extractPemBlock(certificatePem, "CERTIFICATE");
        if (firstCert == null || firstCert.isBlank()) {
            throw new IllegalStateException("No certificate found in client_cert");
        }
        try {
            X509Certificate cert = toX509(firstCert);
            String dns = firstDnsSan(cert);
            if (dns == null || dns.isBlank()) {
                throw new IllegalStateException("Certificate does not contain a DNS SAN entry");
            }
            String computed = "x509_san_dns:" + dns;
            if (existingClientId != null && existingClientId.startsWith("x509_san_dns:") && !existingClientId.equals(computed)) {
                throw new IllegalStateException("client_id SAN does not match certificate SAN");
            }
            return computed;
        } catch (Exception e) {
            throw new IllegalStateException("Invalid client_cert for x509_san_dns client authentication", e);
        }
    }

    public JWK parsePrivateKeyWithCertificate(String pem) {
        try {
            String privBase64 = extractPemBlock(pem, "PRIVATE KEY");
            String certBase64 = extractPemBlock(pem, "CERTIFICATE");
            if (privBase64 == null) {
                throw new IllegalStateException("Certificate must include a private key (PKCS8)");
            }
            byte[] privBytes = Base64.getMimeDecoder().decode(privBase64);
            PrivateKey privateKey = resolvePrivateKey(privBytes);
            PublicKey publicKey = null;
            if (certBase64 != null) {
                byte[] certBytes = Base64.getMimeDecoder().decode(certBase64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                publicKey = cert.getPublicKey();
            }
            if (publicKey == null && privateKey instanceof RSAPrivateCrtKey rsaPrivate) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                publicKey = kf.generatePublic(new RSAPublicKeySpec(
                        rsaPrivate.getModulus(),
                        rsaPrivate.getPublicExponent()
                ));
            }
            if (publicKey == null) {
                throw new IllegalStateException("No public key found in certificate and unable to derive from private key");
            }
            if (publicKey instanceof RSAPublicKey rsaPub && privateKey instanceof RSAPrivateCrtKey) {
                return new RSAKey.Builder(rsaPub)
                        .privateKey(privateKey)
                        .build();
            }
            if (publicKey instanceof ECPublicKey ecPub && privateKey instanceof ECPrivateKey ecPrivate) {
                Curve curve = Curve.forECParameterSpec(ecPub.getParams());
                return new ECKey.Builder(curve, ecPub)
                        .privateKey(ecPrivate)
                        .keyIDFromThumbprint()
                        .build();
            }
            throw new IllegalStateException("Unsupported key type: " + publicKey.getAlgorithm());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate/key", e);
        }
    }

    public List<String> extractCertChain(String pem) {
        if (pem == null || pem.isBlank()) {
            return List.of();
        }
        List<String> chain = new ArrayList<>();
        int idx = 0;
        while (true) {
            int start = pem.indexOf("-----BEGIN CERTIFICATE-----", idx);
            if (start < 0) {
                break;
            }
            int end = pem.indexOf("-----END CERTIFICATE-----", start);
            if (end < 0) {
                break;
            }
            String body = pem.substring(start + "-----BEGIN CERTIFICATE-----".length(), end)
                    .replaceAll("\\s+", "")
                    .replace(' ', '+');
            try {
                byte[] der = Base64.getDecoder().decode(body);
                chain.add(Base64.getEncoder().encodeToString(der));
            } catch (Exception ignored) {
            }
            idx = end + "-----END CERTIFICATE-----".length();
        }
        return chain;
    }

    public String extractPemBlock(String pem, String type) {
        if (pem == null) {
            return null;
        }
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start >= 0 && stop > start) {
            String body = pem.substring(start + begin.length(), stop);
            return body.replaceAll("\\s+", "");
        }
        return null;
    }

    public String toPem(byte[] der, String type) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }

    public record X509Material(String certificatePem, String keyPem, String combinedPem, String source, JWK jwk) {
    }

    private PrivateKey resolvePrivateKey(byte[] privBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privBytes);
        List<String> algorithms = List.of("RSA", "EC");
        for (String alg : algorithms) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (Exception ignored) {
            }
        }
        throw new IllegalStateException("Unsupported private key algorithm");
    }

    private byte[] privateKeyBytes(JWK jwk) throws Exception {
        if (jwk instanceof RSAKey rsaKey && rsaKey.toRSAPrivateKey() != null) {
            return rsaKey.toRSAPrivateKey().getEncoded();
        }
        if (jwk instanceof ECKey ecKey && ecKey.toECPrivateKey() != null) {
            return ecKey.toECPrivateKey().getEncoded();
        }
        throw new IllegalStateException("Private key material missing");
    }

    private X509Certificate toX509(String base64Body) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(base64Body);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private String firstDnsSan(X509Certificate cert) throws Exception {
        if (cert.getSubjectAlternativeNames() == null) {
            return null;
        }
        for (List<?> entry : cert.getSubjectAlternativeNames()) {
            if (entry != null && entry.size() >= 2 && entry.get(0) instanceof Integer type && type == 2) {
                Object value = entry.get(1);
                if (value != null) {
                    return String.valueOf(value);
                }
            }
        }
        return null;
    }
}
