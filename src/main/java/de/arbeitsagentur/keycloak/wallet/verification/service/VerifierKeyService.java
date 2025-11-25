package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class VerifierKeyService {
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;
    private volatile RSAKey cachedKey;

    public VerifierKeyService(VerifierProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public RSAKey loadOrCreateKey() {
        if (cachedKey != null) {
            return cachedKey;
        }
        synchronized (this) {
            if (cachedKey != null) {
                return cachedKey;
            }
            try {
                if (properties.encryptionKeyFile() != null && Files.exists(properties.encryptionKeyFile())) {
                    String json = Files.readString(properties.encryptionKeyFile());
                    cachedKey = parseKey(json);
                } else {
                    RSAKey generated = new RSAKeyGenerator(2048)
                            .keyID("verifier-enc")
                            .algorithm(JWEAlgorithm.RSA_OAEP_256)
                            .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
                            .generate();
                    if (properties.encryptionKeyFile() != null) {
                        if (properties.encryptionKeyFile().getParent() != null) {
                            Files.createDirectories(properties.encryptionKeyFile().getParent());
                        }
                        Files.writeString(properties.encryptionKeyFile(), generated.toJSONString());
                    }
                    cachedKey = generated;
                }
            } catch (Exception e) {
                throw new IllegalStateException("Unable to load verifier encryption key", e);
            }
            return cachedKey;
        }
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

    public String publicJwksJson() {
        RSAKey key = loadOrCreateKey();
        try {
            return com.nimbusds.jose.util.JSONObjectUtils.toJSONString(
                    new JWKSet(key.toPublicJWK()).toJSONObject(false));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize JWKS", e);
        }
    }

    public String encrypt(String payload, String alg, String enc) {
        try {
            RSAKey key = loadOrCreateKey();
            JWEAlgorithm algorithm = alg != null ? JWEAlgorithm.parse(alg) : JWEAlgorithm.RSA_OAEP_256;
            EncryptionMethod method = enc != null ? EncryptionMethod.parse(enc) : EncryptionMethod.A256GCM;
            com.nimbusds.jose.JWEObject jwe = new com.nimbusds.jose.JWEObject(
                    new JWEHeader.Builder(algorithm, method).keyID(key.getKeyID()).build(),
                    new com.nimbusds.jose.Payload(payload)
            );
            jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to encrypt vp_token", e);
        }
    }

    public String decrypt(String jwe) {
        try {
            com.nimbusds.jose.JWEObject jweObject = com.nimbusds.jose.JWEObject.parse(jwe);
            RSAKey key = loadOrCreateKey();
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
                        .filter(jwk -> jwk.getKeyUse() == null || com.nimbusds.jose.jwk.KeyUse.ENCRYPTION.equals(jwk.getKeyUse()))
                        .findFirst()
                        .orElse(null);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
