package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocViewer;
import org.springframework.stereotype.Service;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtParser;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

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
        String vpDecoded = decodeJwtLike(vpTokensJson);
        if (vpDecoded != null && !vpDecoded.isBlank()) {
            sb.append("vp_token:\n").append(vpDecoded);
        }
        String kbDecoded = decodeJwtLike(keyBindingToken);
        if (kbDecoded != null && !kbDecoded.isBlank()) {
            if (!sb.isEmpty()) {
                sb.append("\n\n");
            }
            sb.append("key_binding_jwt:\n").append(kbDecoded);
        }
        String dpopDecoded = decodeJwtLike(dpopToken);
        if (dpopDecoded != null && !dpopDecoded.isBlank()) {
            if (!sb.isEmpty()) {
                sb.append("\n\n");
            }
            sb.append("dpop:\n").append(dpopDecoded);
        }
        return sb.toString();
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
