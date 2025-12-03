package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * Utility to detect and pretty-print mDoc tokens (CBOR hex) for UI views.
 */
public class MdocViewer {
    private final ObjectMapper objectMapper;
    private final MdocParser parser;

    public MdocViewer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.parser = new MdocParser();
    }

    public boolean hasMdocToken(List<String> tokens, Function<String, String> decryptor) {
        if (tokens == null || tokens.isEmpty()) {
            return false;
        }
        return tokens.stream().anyMatch(token -> extractMdocHex(token, decryptor) != null);
    }

    public List<String> views(List<String> tokens, Function<String, String> decryptor) {
        if (tokens == null || tokens.isEmpty()) {
            return List.of();
        }
        List<String> views = new ArrayList<>();
        for (String token : tokens) {
            String hex = extractMdocHex(token, decryptor);
            if (hex == null) {
                continue;
            }
            String pretty = parser.prettyPrint(hex);
            if (pretty == null || pretty.isBlank()) {
                String sample = hex.length() > 80 ? hex.substring(0, 80) + "..." : hex;
                pretty = "{ \"error\": \"Unable to decode mDoc locally\", \"sample\": \"" + sample + "\" }";
            }
            views.add(pretty);
        }
        return views.isEmpty() ? Collections.emptyList() : views;
    }

    String extractMdocHex(String token, Function<String, String> decryptor) {
        if (token == null || token.isBlank()) {
            return null;
        }
        String decrypted = decryptor != null ? decryptor.apply(token) : token;
        if (isMdocToken(decrypted)) {
            return decrypted;
        }
        String embedded = extractEmbeddedVpToken(decrypted);
        if (isMdocToken(embedded)) {
            return embedded;
        }
        try {
            JsonNode node = objectMapper.readTree(decrypted);
            if (node.isArray() && node.size() > 0 && node.get(0).isTextual()) {
                String candidate = node.get(0).asText();
                if (isMdocToken(candidate)) {
                    return candidate;
                }
            }
            if (node.isTextual() && isMdocToken(node.asText())) {
                return node.asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private boolean isMdocToken(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        if (token.contains(".") || token.contains("~")) {
            return false;
        }
        return token.matches("^[0-9a-fA-F]{8,}$");
    }

    private String extractEmbeddedVpToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        if (!token.contains(".")) {
            return null;
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            JsonNode vp = node.path("vp_token");
            if (vp.isMissingNode() || vp.isNull()) {
                return null;
            }
            if (vp.isTextual()) {
                return vp.asText();
            }
            if (vp.isArray() && vp.size() > 0) {
                JsonNode first = vp.get(0);
                return first.isTextual() ? first.asText() : first.toString();
            }
            if (vp.isObject()) {
                return vp.toString();
            }
            return vp.asText(null);
        } catch (Exception e) {
            return null;
        }
    }
}
