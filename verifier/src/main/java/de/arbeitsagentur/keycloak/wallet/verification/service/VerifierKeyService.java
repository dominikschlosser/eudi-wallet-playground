package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class VerifierKeyService {
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    private static final String SIGNING_KID = "verifier-pop";
    private static final String ENCRYPTION_KID = "verifier-enc";

    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;
    private volatile RSAKey signingKey;
    private volatile RSAKey encryptionKey;

    public VerifierKeyService(VerifierProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public RSAKey loadOrCreateSigningKey() {
        ensureKeysLoaded();
        return signingKey;
    }

    public RSAKey loadOrCreateEncryptionKey() {
        ensureKeysLoaded();
        return encryptionKey;
    }

    public String signingCertificatePem() {
        RSAKey key = loadOrCreateSigningKey();
        return certificateFromX5c(key).orElseThrow(() -> new IllegalStateException("Signing certificate missing"));
    }

    public String signingBundlePem() {
        RSAKey key = loadOrCreateSigningKey();
        try {
            String cert = signingCertificatePem();
            String priv = toPem(key.toRSAPrivateKey().getEncoded(), "PRIVATE KEY");
            return cert + "\n" + priv;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize verifier signing key", e);
        }
    }

    public String publicJwksJson() {
        ensureKeysLoaded();
        try {
            return JSONObjectUtils.toJSONString(new JWKSet(encryptionKey.toPublicJWK()).toJSONObject(false));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize JWKS", e);
        }
    }

    public String encrypt(String payload, String alg, String enc) {
        try {
            RSAKey key = loadOrCreateEncryptionKey();
            JWEAlgorithm algorithm = alg != null ? JWEAlgorithm.parse(alg) : JWEAlgorithm.RSA_OAEP_256;
            EncryptionMethod method = enc != null ? EncryptionMethod.parse(enc) : EncryptionMethod.A256GCM;
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(algorithm, method).keyID(key.getKeyID()).build(),
                    new Payload(payload)
            );
            jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to encrypt vp_token", e);
        }
    }

    public String decrypt(String jwe) {
        try {
            JWEObject jweObject = JWEObject.parse(jwe);
            RSAKey key = loadOrCreateEncryptionKey();
            jweObject.decrypt(new RSADecrypter(key.toRSAPrivateKey()));
            return jweObject.getPayload().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt vp_token", e);
        }
    }

    public JWK selectEncryptionKey(String clientMetadataJson) {
        try {
            if (clientMetadataJson == null || clientMetadataJson.isBlank()) {
                return null;
            }
            Map<String, Object> map = JSONObjectUtils.parse(clientMetadataJson);
            Object jwksObject = map.get("jwks");
            if (jwksObject == null && map.get("keys") instanceof Map<?, ?> keysMap) {
                jwksObject = keysMap.get("jwks");
            }
            if (jwksObject instanceof Map<?, ?> jwksMap) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                jwksMap.forEach((k, v) -> normalized.put(String.valueOf(k), v));
                JWKSet set = JWKSet.parse(normalized);
                return set.getKeys().stream()
                        .filter(jwk -> jwk.getKeyUse() == null || KeyUse.ENCRYPTION.equals(jwk.getKeyUse()))
                        .findFirst()
                        .orElse(null);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private void ensureKeysLoaded() {
        if (signingKey != null && encryptionKey != null) {
            return;
        }
        synchronized (this) {
            if (signingKey != null && encryptionKey != null) {
                return;
            }
            Path keyFile = properties.keysFile();
            boolean rewrite = false;
            if (keyFile != null && Files.exists(keyFile)) {
                try {
                    loadExistingKeys(keyFile);
                } catch (Exception e) {
                    throw new IllegalStateException("Unable to load verifier keys", e);
                }
            }
            if (signingKey == null) {
                signingKey = withCertificate(generateSigningKey());
                rewrite = true;
            } else if (KeyUse.ENCRYPTION.equals(signingKey.getKeyUse())) {
                // legacy single-key files: reuse for encryption and mint a dedicated signing key
                if (encryptionKey == null) {
                    encryptionKey = signingKey;
                }
                signingKey = withCertificate(generateSigningKey());
                rewrite = true;
            } else if (certificateFromX5c(signingKey).isEmpty()) {
                signingKey = withCertificate(signingKey);
                rewrite = true;
            }
            if (encryptionKey == null) {
                encryptionKey = generateEncryptionKey();
                rewrite = true;
            }
            if (keyFile != null && rewrite) {
                persistKeys(keyFile);
            }
        }
    }

    private void loadExistingKeys(Path keyFile) throws Exception {
        String json = Files.readString(keyFile);
        try {
            JWKSet set = JWKSet.parse(json);
            signingKey = selectKey(set, KeyUse.SIGNATURE, SIGNING_KID);
            encryptionKey = selectKey(set, KeyUse.ENCRYPTION, ENCRYPTION_KID);
            if (encryptionKey == null) {
                encryptionKey = selectKey(set, null, ENCRYPTION_KID);
            }
            if (signingKey == null) {
                signingKey = selectKey(set, null, SIGNING_KID);
            }
        } catch (ParseException e) {
            // legacy single-key format
            RSAKey parsed = parseKey(json);
            signingKey = parsed;
            encryptionKey = parsed;
        }
    }

    private RSAKey selectKey(JWKSet set, KeyUse use, String preferredKid) {
        return set.getKeys().stream()
                .filter(jwk -> jwk instanceof RSAKey)
                .map(jwk -> (RSAKey) jwk)
                .filter(jwk -> jwk.isPrivate())
                .filter(jwk -> use == null || use.equals(jwk.getKeyUse()))
                .filter(jwk -> preferredKid == null || preferredKid.equals(jwk.getKeyID()) || preferredKid.equalsIgnoreCase(jwk.getKeyID()))
                .findFirst()
                .orElseGet(() -> set.getKeys().stream()
                        .filter(jwk -> jwk instanceof RSAKey)
                        .map(jwk -> (RSAKey) jwk)
                        .filter(JWK::isPrivate)
                        .filter(jwk -> use == null || use.equals(jwk.getKeyUse()))
                        .findFirst()
                        .orElse(null));
    }

    private RSAKey parseKey(String json) throws ParseException {
        try {
            return RSAKey.parse(json);
        } catch (ParseException e) {
            try {
                JsonNode node = objectMapper.readTree(json);
                if (node.has("keys") && node.get("keys").isArray() && node.get("keys").size() > 0) {
                    return RSAKey.parse(node.get("keys").get(0).toString());
                }
                throw e;
            } catch (Exception ex) {
                throw new ParseException("Failed to parse verifier key", 0);
            }
        }
    }

    private RSAKey generateEncryptionKey() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(ENCRYPTION_KID)
                    .algorithm(JWEAlgorithm.RSA_OAEP_256)
                    .keyUse(KeyUse.ENCRYPTION)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate verifier encryption key", e);
        }
    }

    private RSAKey generateSigningKey() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(SIGNING_KID)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate verifier signing key", e);
        }
    }

    private RSAKey withCertificate(RSAKey key) {
        try {
            X509Certificate certificate = selfSignedCertificate(key);
            return new RSAKey.Builder(key.toRSAPublicKey())
                    .privateKey(key.toRSAPrivateKey())
                    .keyUse(key.getKeyUse())
                    .algorithm(key.getAlgorithm())
                    .keyID(key.getKeyID())
                    .x509CertChain(List.of(Base64.encode(certificate.getEncoded())))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to attach verifier signing certificate", e);
        }
    }

    private void persistKeys(Path file) {
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            List<RSAKey> keys = new ArrayList<>();
            keys.add(signingKey);
            if (!signingKey.getKeyID().equals(encryptionKey.getKeyID())) {
                keys.add(encryptionKey);
            }
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("keys", keys.stream().map(RSAKey::toJSONObject).toList());
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), payload);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to persist verifier keys", e);
        }
    }

    private Optional<String> certificateFromX5c(RSAKey key) {
        try {
            if (key.getX509CertChain() == null || key.getX509CertChain().isEmpty()) {
                return Optional.empty();
            }
            byte[] der = key.getX509CertChain().get(0).decode();
            return Optional.of(toPem(der, "CERTIFICATE"));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private X509Certificate selfSignedCertificate(RSAKey key) {
        try {
            Date from = new Date();
            Date to = Date.from(Instant.now().plusSeconds(60L * 60 * 24 * 365 * 10));
            byte[] pubDigest = MessageDigest.getInstance("SHA-256").digest(key.toRSAPublicKey().getEncoded());
            BigInteger serial = new BigInteger(1, pubDigest).add(new BigInteger(130, new SecureRandom()));
            X500Name subject = new X500Name("CN=Verifier Demo");
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BC_PROVIDER)
                    .build(key.toRSAPrivateKey());
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    serial,
                    from,
                    to,
                    subject,
                    key.toRSAPublicKey()
            );
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(holder);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate verifier signing certificate", e);
        }
    }

    private String toPem(byte[] der, String type) {
        String base64 = Base64.encode(der).toString();
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }
}
