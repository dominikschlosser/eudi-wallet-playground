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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocViewer;
import org.springframework.stereotype.Service;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Objects;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class TokenViewService {
    private final VerifierKeyService verifierKeyService;
    private final ObjectMapper objectMapper;
    private final SdJwtParser sdJwtParser;
    private final MdocViewer mdocViewer;

    public TokenViewService(VerifierKeyService verifierKeyService, ObjectMapper objectMapper) {
        this.verifierKeyService = verifierKeyService;
        this.objectMapper = objectMapper;
        this.sdJwtParser = new SdJwtParser(objectMapper);
        this.mdocViewer = new MdocViewer(objectMapper);
    }

    public List<String> presentableTokens(List<String> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>(tokens.size());
        for (String token : tokens) {
            result.add(presentableToken(token));
        }
        return result;
    }

    public String presentableToken(String token) {
        String decrypted = decryptTokenForView(token);
        String embedded = extractEmbeddedVpToken(decrypted);
        if (embedded != null && !embedded.isBlank()) {
            return embedded;
        }
        return decrypted == null ? "" : decrypted;
    }

    public boolean hasEncryptedToken(List<String> tokens) {
        return tokens != null && tokens.stream().anyMatch(this::isEncryptedJwe);
    }

    public boolean hasSdJwtToken(List<String> tokens) {
        return tokens != null && tokens.stream().anyMatch(sdJwtParser::isSdJwt);
    }

    public boolean hasMdocToken(List<String> tokens) {
        return mdocViewer.hasMdocToken(tokens, this::decryptTokenForView);
    }

    public List<String> mdocViews(List<String> tokens) {
        return mdocViewer.views(tokens, this::decryptTokenForView);
    }

    public String decryptTokenForView(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        if (!isEncryptedJwe(token)) {
            return token;
        }
        try {
            return verifierKeyService.decrypt(token);
        } catch (Exception e) {
            return token;
        }
    }

    public String decodeJwtLike(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        try {
            JsonNode node = null;
            try {
                node = objectMapper.readTree(token);
            } catch (Exception ignored) {
            }
            if (node != null && node.isArray() && node.size() > 0) {
                token = node.get(0).asText();
            }
            if (sdJwtParser.isSdJwt(token)) {
                token = sdJwtParser.signedJwt(token);
            }
            if (!token.contains(".")) {
                return "";
            }
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return "";
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(payload));
        } catch (Exception e) {
            return "";
        }
    }

    public String assembleDecodedForDebug(String vpTokensJson, String keyBindingToken, String dpopToken) {
        StringBuilder sb = new StringBuilder();
        List<String> vpTokens = parsePossibleTokenList(vpTokensJson);
        int tokenIndex = 0;
        for (String token : vpTokens) {
            String decoded = decodeVpTokenForDebug(token);
            if (isBlank(decoded)) {
                continue;
            }
            tokenIndex++;
            String label = vpTokens.size() > 1 ? "vp_token[" + tokenIndex + "]" : "vp_token";
            appendSection(sb, label, decoded);
        }
        appendSection(sb, "key_binding_jwt", decodeJwtLike(keyBindingToken));
        appendSection(sb, "dpop", decodeJwtLike(dpopToken));
        return sb.toString();
    }

    private List<String> parsePossibleTokenList(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        String trimmed = value.trim();
        if (!trimmed.startsWith("[")) {
            return List.of(trimmed);
        }
        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (!node.isArray()) {
                return List.of(trimmed);
            }
            List<String> tokens = new ArrayList<>();
            for (JsonNode item : node) {
                if (item == null || item.isNull()) {
                    continue;
                }
                String token = item.isTextual() ? item.asText() : item.toString();
                if (token != null && !token.isBlank()) {
                    tokens.add(token);
                }
            }
            return tokens;
        } catch (Exception e) {
            return List.of(trimmed);
        }
    }

    private String decodeVpTokenForDebug(String token) {
        String presented = presentableToken(token);
        if (isBlank(presented)) {
            return "";
        }
        if (!sdJwtParser.isSdJwt(presented)) {
            return decodeJwtLike(presented);
        }

        SdJwtUtils.SdJwtParts parts = sdJwtParser.split(presented);
        Map<String, Object> disclosedClaims = sdJwtParser.extractDisclosedClaims(parts);
        List<Map<String, Object>> decodedDisclosures = decodeDisclosures(parts.disclosures(), disclosedClaims);

        StringBuilder sb = new StringBuilder();
        appendSection(sb, "credential_jwt_payload", decodeJwtLike(parts.signedJwt()));
        if (!decodedDisclosures.isEmpty()) {
            appendSection(sb, "disclosures", prettyJson(decodedDisclosures));
        }
        if (disclosedClaims != null && !disclosedClaims.isEmpty()) {
            appendSection(sb, "disclosed_claims", prettyJson(disclosedClaims));
        }
        appendSection(sb, "sd_jwt_key_binding_jwt", decodeJwtLike(parts.keyBindingJwt()));
        return sb.toString();
    }

    private List<Map<String, Object>> decodeDisclosures(List<String> disclosures, Map<String, Object> disclosedClaims) {
        if (disclosures == null || disclosures.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (String raw : disclosures) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            try {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("disclosure", raw);

                JsonNode decoded = decodeDisclosureJson(raw);
                if (decoded != null && decoded.isArray() && decoded.size() >= 2) {
                    entry.put("salt", decoded.get(0).asText(null));
                    if (decoded.size() >= 3) {
                        String claimName = decoded.get(1).asText(null);
                        entry.put("claim_name", claimName);
                        entry.put("claim_value", normalizeJsonStringValue(convertJsonValue(decoded.get(2))));
                        maybeAddResolvedClaimValue(entry, claimName, disclosedClaims);
                    } else {
                        entry.put("claim_name", null);
                        entry.put("claim_value", normalizeJsonStringValue(convertJsonValue(decoded.get(1))));
                    }
                } else {
                    entry.put("claim_name", null);
                    entry.put("claim_value", raw);
                }
                out.add(entry);
            } catch (Exception e) {
                out.add(Map.of("disclosure", raw));
            }
        }
        return out;
    }

    private void maybeAddResolvedClaimValue(Map<String, Object> entry, String claimName, Map<String, Object> disclosedClaims) {
        if (entry == null || claimName == null || claimName.isBlank() || disclosedClaims == null || disclosedClaims.isEmpty()) {
            return;
        }
        Object resolved = disclosedClaims.get(claimName);
        if (resolved == null) {
            return;
        }
        Object current = entry.get("claim_value");
        if (!Objects.equals(current, resolved)) {
            entry.put("resolved_claim_value", resolved);
        }
    }

    private Object convertJsonValue(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        try {
            return objectMapper.convertValue(node, Object.class);
        } catch (Exception e) {
            return node.toString();
        }
    }

    private JsonNode decodeDisclosureJson(String disclosure) {
        if (disclosure == null || disclosure.isBlank()) {
            return null;
        }
        try {
            byte[] bytes = base64UrlDecode(disclosure.trim());
            return objectMapper.readTree(bytes);
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] base64UrlDecode(String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        String trimmed = value.trim();
        int remainder = trimmed.length() % 4;
        if (remainder != 0) {
            trimmed = trimmed + "====".substring(0, 4 - remainder);
        }
        return Base64.getUrlDecoder().decode(trimmed);
    }

    private Object normalizeJsonStringValue(Object value) {
        if (!(value instanceof String text)) {
            return value;
        }
        String trimmed = text.trim();
        if (trimmed.isBlank()) {
            return trimmed;
        }
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return text;
        }
        try {
            JsonNode node = objectMapper.readTree(trimmed);
            return convertJsonValue(node);
        } catch (Exception e) {
            return text;
        }
    }

    private String prettyJson(Object value) {
        if (value == null) {
            return "";
        }
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }

    private void appendSection(StringBuilder sb, String label, String content) {
        if (isBlank(content)) {
            return;
        }
        if (!sb.isEmpty()) {
            sb.append("\n\n");
        }
        sb.append(label).append(":\n").append(content);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private boolean isEncryptedJwe(String token) {
        if (token == null) {
            return false;
        }
        if (token.chars().filter(c -> c == '.').count() == 4) {
            return true;
        }
        try {
            JWEObject.parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
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
