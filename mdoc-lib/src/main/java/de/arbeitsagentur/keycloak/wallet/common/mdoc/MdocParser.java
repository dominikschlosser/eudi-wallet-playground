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
package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import tools.jackson.dataformat.cbor.CBORMapper;
import de.arbeitsagentur.keycloak.wallet.mdoc.util.HexUtils;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import COSE.Sign1Message;

import tools.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Utilities to parse mDoc (CBOR) credentials.
 */
public class MdocParser {
    private final CBORMapper cborMapper = new CBORMapper();
    private final ObjectMapper jsonMapper = new ObjectMapper();

    public boolean isHex(String value) {
        return value != null && value.matches("^[0-9a-fA-F]+$");
    }

    public boolean isBase64Url(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        if (value.contains(".") || value.contains("~")) {
            return false;
        }
        return value.matches("^[A-Za-z0-9_-]+=*$");
    }

    public boolean isIssuerSigned(String token) {
        try {
            CBORObject root = decodeCbor(token);
            return root != null
                    && root.getType() == CBORType.Map
                    && root.ContainsKey("nameSpaces")
                    && root.ContainsKey("issuerAuth");
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isDeviceResponse(String token) {
        try {
            CBORObject root = decodeCbor(token);
            return root != null
                    && root.getType() == CBORType.Map
                    && root.ContainsKey("documents");
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isMdoc(String token) {
        return isIssuerSigned(token) || isDeviceResponse(token);
    }

    public Map<String, Object> extractClaims(String token) {
        try {
            CBORObject root = decodeCbor(token);
            CBORObject issuerSigned = resolveIssuerSigned(root);
            if (issuerSigned == null || issuerSigned.getType() != CBORType.Map) {
                return Collections.emptyMap();
            }
            CBORObject nameSpaces = asMap(issuerSigned.get("nameSpaces"));
            if (nameSpaces == null) {
                return Collections.emptyMap();
            }
            Map<String, Object> claims = new LinkedHashMap<>();
            for (CBORObject nsKey : nameSpaces.getKeys()) {
                CBORObject elements = nameSpaces.get(nsKey);
                if (elements == null || elements.getType() != CBORType.Array) {
                    continue;
                }
                for (int i = 0; i < elements.size(); i++) {
                    CBORObject element = decodeIssuerItem(elements.get(i));
                    if (element == null) {
                        continue;
                    }
                    CBORObject id = element.get("elementIdentifier");
                    CBORObject value = element.get("elementValue");
                    if (id != null && value != null) {
                        claims.put(id.AsString(), convertToJava(value));
                    }
                }
            }
            return claims;
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    public String extractDocType(String token) {
        try {
            CBORObject root = decodeCbor(token);
            CBORObject document = firstDocument(root);
            if (document != null) {
                CBORObject docType = document.get("docType");
                if (docType != null) {
                    return docType.AsString();
                }
            }
            if (root != null && root.getType() == CBORType.Map && root.ContainsKey("docType")) {
                CBORObject fallback = root.get("docType");
                return fallback != null ? fallback.AsString() : null;
            }
            CBORObject issuerSigned = resolveIssuerSigned(root);
            if (issuerSigned == null) {
                return null;
            }
            CBORObject mso = decodeMsoFromIssuerSigned(issuerSigned);
            if (mso == null) {
                return null;
            }
            CBORObject docType = mso.get("docType");
            return docType != null ? docType.AsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    public String prettyPrint(String token) {
        try {
            Map<String, Object> decoded = decode(token);
            return decoded == null ? null : jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(decoded);
        } catch (Exception e) {
            return "{ \"error\": \"Failed to decode mDoc\", \"message\": \"" + e.getMessage() + "\" }";
        }
    }

    public Map<String, Object> decode(String token) throws Exception {
        CBORObject root = decodeCbor(token);
        Map<String, Object> decoded = asJavaMap(root);
        if (root != null && root.getType() == CBORType.Map && root.ContainsKey("issuerAuth") && root.ContainsKey("nameSpaces")) {
            String docType = extractDocType(token);
            if (docType != null && !docType.isBlank() && !decoded.containsKey("docType")) {
                Map<String, Object> enriched = new LinkedHashMap<>(decoded);
                enriched.put("docType", docType);
                return enriched;
            }
        }
        return decoded;
    }

    private CBORObject decodeCbor(String token) throws Exception {
        return CBORObject.DecodeFromBytes(decodeBytes(token));
    }

    private byte[] decodeBytes(String token) {
        if (token == null || token.isBlank()) {
            return new byte[0];
        }
        if (isHex(token)) {
            return HexUtils.decode(token);
        }
        if (!isBase64Url(token)) {
            return new byte[0];
        }
        try {
            return Base64.getUrlDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            try {
                return Base64.getDecoder().decode(token);
            } catch (IllegalArgumentException ignored) {
                return new byte[0];
            }
        }
    }

    private CBORObject firstDocument(CBORObject root) {
        CBORObject docs = root.get("documents");
        if (docs != null && docs.getType() == CBORType.Array && docs.size() > 0) {
            return asMap(docs.get(0));
        }
        return null;
    }

    private CBORObject resolveIssuerSigned(CBORObject root) {
        if (root == null) {
            return null;
        }
        if (root.getType() == CBORType.Map && root.ContainsKey("issuerAuth") && root.ContainsKey("nameSpaces")) {
            return root;
        }
        CBORObject document = firstDocument(root);
        if (document == null) {
            return null;
        }
        return asMap(document.get("issuerSigned"));
    }

    private CBORObject decodeMsoFromIssuerSigned(CBORObject issuerSigned) {
        try {
            CBORObject issuerAuth = issuerSigned.get("issuerAuth");
            if (issuerAuth == null || issuerAuth.getType() != CBORType.ByteString) {
                return null;
            }
            Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(issuerAuth.GetByteString());
            byte[] content = sign1.GetContent();
            if (content == null) {
                return null;
            }
            CBORObject payload = CBORObject.DecodeFromBytes(content);
            if (payload.HasMostOuterTag(24) && payload.getType() == CBORType.ByteString) {
                payload = CBORObject.DecodeFromBytes(payload.GetByteString());
            }
            if (payload.getType() == CBORType.ByteString) {
                payload = CBORObject.DecodeFromBytes(payload.GetByteString());
            }
            return payload.getType() == CBORType.Map ? payload : null;
        } catch (Exception e) {
            return null;
        }
    }

    private CBORObject decodeIssuerItem(CBORObject element) {
        if (element == null) {
            return null;
        }
        if (element.HasMostOuterTag(24) && element.getType() == CBORType.ByteString) {
            return CBORObject.DecodeFromBytes(element.GetByteString());
        }
        if (element.getType() == CBORType.Map) {
            return element;
        }
        return null;
    }

    private CBORObject asMap(CBORObject value) {
        if (value == null || value.getType() != CBORType.Map) {
            return null;
        }
        return value;
    }

    private Map<String, Object> asJavaMap(CBORObject obj) {
        Object converted = convertToJava(obj);
        if (converted instanceof Map<?, ?> map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> cast = (Map<String, Object>) map;
            return cast;
        }
        return Collections.emptyMap();
    }

    private Object convertToJava(CBORObject obj) {
        if (obj == null) {
            return null;
        }
        if (obj.HasMostOuterTag(24) && obj.getType() == CBORType.ByteString) {
            return convertToJava(CBORObject.DecodeFromBytes(obj.GetByteString()));
        }
        if (obj.isNull()) {
            return null;
        }
        return switch (obj.getType()) {
            case Map -> {
                Map<String, Object> map = new LinkedHashMap<>();
                for (CBORObject key : obj.getKeys()) {
                    map.put(mapKey(key), convertToJava(obj.get(key)));
                }
                yield map;
            }
            case Array -> {
                List<Object> list = new ArrayList<>();
                for (int i = 0; i < obj.size(); i++) {
                    list.add(convertToJava(obj.get(i)));
                }
                yield list;
            }
            case ByteString -> obj.GetByteString();
            case TextString -> obj.AsString();
            case Integer -> obj.AsInt64Value();
            case Boolean -> obj.AsBoolean();
            case FloatingPoint -> obj.AsDouble();
            case Number, SimpleValue -> obj.ToObject(Object.class);
            default -> obj.ToObject(Object.class);
        };
    }

    private String mapKey(CBORObject key) {
        if (key == null) {
            return "";
        }
        return switch (key.getType()) {
            case TextString -> key.AsString();
            case Integer -> String.valueOf(key.AsInt64Value());
            default -> key.toString();
        };
    }
}
