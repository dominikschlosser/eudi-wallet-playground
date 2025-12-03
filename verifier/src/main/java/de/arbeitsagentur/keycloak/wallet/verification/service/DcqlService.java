package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;

@Component
public class DcqlService {
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;

    public DcqlService(VerifierProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public String defaultDcqlQuery() {
        String fromFile = readFromFile();
        if (hasText(fromFile)) {
            return minify(fromFile);
        }
        if (hasText(properties.defaultDcqlQuery())) {
            return minify(properties.defaultDcqlQuery());
        }
        String fallback = buildFallbackQuery();
        return hasText(fallback) ? fallback : "";
    }

    private String readFromFile() {
        if (properties.dcqlQueryFile() != null) {
            try {
                if (Files.exists(properties.dcqlQueryFile())) {
                    return Files.readString(properties.dcqlQueryFile());
                }
            } catch (IOException ignored) {
            }
        }
        return null;
    }

    private String buildFallbackQuery() {
        try {
            ObjectNode credential = objectMapper.createObjectNode();
            credential.put("id", "pid_default");
            credential.put("format", "dc+sd-jwt");

            ObjectNode meta = objectMapper.createObjectNode();
            ArrayNode vct = meta.putArray("vct_values");
            vct.add("urn:eudi:pid:1");
            credential.set("meta", meta);

            ArrayNode claims = credential.putArray("claims");
            ObjectNode givenName = objectMapper.createObjectNode();
            givenName.putArray("path").add("given_name");
            claims.add(givenName);

            ObjectNode familyName = objectMapper.createObjectNode();
            familyName.putArray("path").add("family_name");
            claims.add(familyName);

            ObjectNode root = objectMapper.createObjectNode();
            root.putArray("credentials").add(credential);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "";
        }
    }

    private String minify(String json) {
        if (!hasText(json)) {
            return "";
        }
        try {
            return objectMapper.writeValueAsString(objectMapper.readTree(json));
        } catch (Exception e) {
            return json;
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
