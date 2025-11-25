package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@Service
public class VerifierCryptoService {
    private final VerifierKeyService verifierKeyService;

    public VerifierCryptoService(VerifierKeyService verifierKeyService) {
        this.verifierKeyService = verifierKeyService;
    }

    public X509Material resolveX509Material(String providedPem) {
        if (providedPem != null && !providedPem.isBlank()) {
            String certBlock = extractPemBlock(providedPem, "CERTIFICATE");
            if (certBlock == null || certBlock.isBlank()) {
                throw new IllegalStateException("No certificate found in client_cert");
            }
            RSAKey rsaKey = parsePrivateKeyWithCertificate(providedPem);
            try {
                String normalizedCert = toPem(Base64.getMimeDecoder().decode(certBlock), "CERTIFICATE");
                String keyPem = toPem(rsaKey.toRSAPrivateKey().getEncoded(), "PRIVATE KEY");
                String combined = normalizedCert + "\n" + keyPem;
                return new X509Material(normalizedCert, keyPem, combined, "client_cert", rsaKey);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to prepare client_cert material", e);
            }
        }
        RSAKey signingKey = verifierKeyService.loadOrCreateSigningKey();
        try {
            String certPem = verifierKeyService.signingCertificatePem();
            String keyPem = toPem(signingKey.toRSAPrivateKey().getEncoded(), "PRIVATE KEY");
            String combined = certPem + "\n" + keyPem;
            return new X509Material(certPem, keyPem, combined, "verifier_self_signed", signingKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to prepare verifier x509 material", e);
        }
    }

    public String deriveX509ClientId(String existingClientId, String certificatePem) {
        String firstCert = extractPemBlock(certificatePem, "CERTIFICATE");
        if (firstCert == null || firstCert.isBlank()) {
            throw new IllegalStateException("No certificate found in client_cert");
        }
        try {
            byte[] der = Base64.getMimeDecoder().decode(firstCert);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
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

    public RSAKey parsePrivateKeyWithCertificate(String pem) {
        try {
            String privBase64 = extractPemBlock(pem, "PRIVATE KEY");
            String certBase64 = extractPemBlock(pem, "CERTIFICATE");
            if (privBase64 == null) {
                throw new IllegalStateException("Certificate must include a private key (PKCS8)");
            }
            byte[] privBytes = Base64.getMimeDecoder().decode(privBase64);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);
            java.security.PublicKey publicKey = null;
            if (certBase64 != null) {
                byte[] certBytes = Base64.getMimeDecoder().decode(certBase64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
                publicKey = cert.getPublicKey();
            }
            if (publicKey == null) {
                publicKey = kf.generatePublic(new java.security.spec.RSAPublicKeySpec(
                        ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getModulus(),
                        ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getPublicExponent()
                ));
            }
            return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) publicKey)
                    .privateKey(privateKey)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate/key", e);
        }
    }

    public List<com.nimbusds.jose.util.Base64> extractCertChain(String pem) {
        if (pem == null || pem.isBlank()) {
            return List.of();
        }
        List<com.nimbusds.jose.util.Base64> chain = new java.util.ArrayList<>();
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
                chain.add(com.nimbusds.jose.util.Base64.encode(java.util.Base64.getDecoder().decode(body)));
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

    public record X509Material(String certificatePem, String keyPem, String combinedPem, String source, RSAKey rsaKey) {
    }
}
