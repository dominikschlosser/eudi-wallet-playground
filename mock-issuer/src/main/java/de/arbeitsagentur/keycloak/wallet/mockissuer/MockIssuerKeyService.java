package de.arbeitsagentur.keycloak.wallet.mockissuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@Component
public class MockIssuerKeyService {
    private final MockIssuerProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private volatile ECKey cached;

    public MockIssuerKeyService(MockIssuerProperties properties) {
        this.properties = properties;
    }

    public ECKey signingKey() {
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (cached != null) {
                return cached;
            }
            Path file = properties.keyFile();
            try {
                if (Files.exists(file)) {
                    cached = normalizeKid(parseExisting(file));
                } else {
                    cached = normalizeKid(generate(file));
                }
            } catch (Exception e) {
                throw new IllegalStateException("Unable to load mock issuer key", e);
            }
        }
        return cached;
    }

    private ECKey parseExisting(Path file) throws IOException, ParseException {
        String json = Files.readString(file);
        try {
            return ECKey.parse(json);
        } catch (ParseException e) {
            JsonNode node = objectMapper.readTree(json);
            if (node.has("privateJwk")) {
                return ECKey.parse(node.get("privateJwk").toString());
            }
            throw e;
        }
    }

    private ECKey generate(Path file) throws Exception {
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        ECKey generated = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("mock-issuer-es256")
                .generate();
        Map<String, JsonNode> payload = new HashMap<>();
        payload.put("privateJwk", objectMapper.readTree(generated.toJSONString()));
        payload.put("publicJwk", objectMapper.readTree(generated.toPublicJWK().toJSONString()));
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), payload);
        return generated;
    }

    private ECKey normalizeKid(ECKey key) {
        if (key == null) {
            return null;
        }
        if (key.getKeyID() != null && key.getAlgorithm() != null) {
            return key;
        }
        return new ECKey.Builder(key)
                .keyID(key.getKeyID() != null ? key.getKeyID() : "mock-issuer-es256")
                .algorithm(key.getAlgorithm() != null ? key.getAlgorithm() : JWSAlgorithm.ES256)
                .build();
    }
}
