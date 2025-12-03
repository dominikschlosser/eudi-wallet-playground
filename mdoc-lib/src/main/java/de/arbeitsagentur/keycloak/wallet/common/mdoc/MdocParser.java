package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.arbeitsagentur.keycloak.wallet.common.util.HexUtils;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import com.fasterxml.jackson.databind.ObjectMapper;

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

    public Map<String, Object> extractClaims(String hex) {
        try {
            CBORObject root = decodeCbor(hex);
            CBORObject document = firstDocument(root);
            if (document == null) {
                return Collections.emptyMap();
            }
            CBORObject issuerSigned = asMap(document.get("issuerSigned"));
            if (issuerSigned == null) {
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

    public String extractDocType(String hex) {
        try {
            CBORObject root = decodeCbor(hex);
            CBORObject document = firstDocument(root);
            if (document != null) {
                CBORObject docType = document.get("docType");
                if (docType != null) {
                    return docType.AsString();
                }
            }
            CBORObject fallback = root.get("docType");
            return fallback != null ? fallback.AsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    public String prettyPrint(String hex) {
        try {
            Map<String, Object> decoded = decode(hex);
            return decoded == null ? null : jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(decoded);
        } catch (Exception e) {
            return "{ \"error\": \"Failed to decode mDoc\", \"message\": \"" + e.getMessage() + "\" }";
        }
    }

    public Map<String, Object> decode(String hex) throws Exception {
        CBORObject root = decodeCbor(hex);
        return asJavaMap(root);
    }

    private CBORObject decodeCbor(String hex) throws Exception {
        return CBORObject.DecodeFromBytes(HexUtils.decode(hex));
    }

    private CBORObject firstDocument(CBORObject root) {
        CBORObject docs = root.get("documents");
        if (docs != null && docs.getType() == CBORType.Array && docs.size() > 0) {
            return asMap(docs.get(0));
        }
        return null;
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
                    map.put(key.AsString(), convertToJava(obj.get(key)));
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
}
