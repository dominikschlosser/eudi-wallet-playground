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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Utilities for converting CBOR objects to Java types.
 * <p>
 * Handles the common patterns needed for mDoc processing:
 * - Tag 24 (embedded CBOR) unwrapping
 * - Recursive conversion of maps and arrays
 * - Key type normalization
 */
public final class CborConversionUtils {
    /** CBOR tag 24 indicates an embedded CBOR data item */
    private static final int TAG_EMBEDDED_CBOR = 24;

    private CborConversionUtils() {
    }

    /**
     * Decodes a CBOR tag-24 container if present, otherwise returns the value unchanged.
     * Tag 24 wraps an embedded CBOR data item as a byte string.
     *
     * @param value the CBOR object to potentially unwrap
     * @return the unwrapped CBOR object, or the original if not tag-24
     */
    public static CBORObject decodeContainer(CBORObject value) {
        if (value == null) {
            return null;
        }
        if (value.HasMostOuterTag(TAG_EMBEDDED_CBOR) && value.getType() == CBORType.ByteString) {
            return CBORObject.DecodeFromBytes(value.GetByteString());
        }
        return value;
    }

    /**
     * Converts a CBOR object to its Java equivalent.
     * Recursively handles maps, arrays, and embedded CBOR containers.
     *
     * @param obj the CBOR object to convert
     * @return the Java representation
     */
    public static Object toJava(CBORObject obj) {
        if (obj == null) {
            return null;
        }
        // Unwrap tag-24 embedded CBOR
        obj = decodeContainer(obj);
        if (obj.isNull()) {
            return null;
        }
        return switch (obj.getType()) {
            case Map -> convertMap(obj);
            case Array -> convertArray(obj);
            case ByteString -> obj.GetByteString();
            case TextString -> obj.AsString();
            case Integer -> obj.AsInt64Value();
            case Boolean -> obj.AsBoolean();
            case FloatingPoint -> obj.AsDouble();
            default -> obj.ToObject(Object.class);
        };
    }

    /**
     * Converts a CBOR object to a Java Map with String keys.
     *
     * @param obj the CBOR object to convert
     * @return the converted map, or empty map if conversion fails
     */
    public static Map<String, Object> toJavaMap(CBORObject obj) {
        Object converted = toJava(obj);
        if (converted instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    result.put(entry.getKey().toString(), entry.getValue());
                }
            }
            return result;
        }
        return Map.of();
    }

    /**
     * Converts a CBOR map key to a String.
     * Handles text, integer, and other key types.
     *
     * @param key the CBOR key object
     * @return the string representation of the key
     */
    public static String mapKey(CBORObject key) {
        if (key == null) {
            return "";
        }
        return switch (key.getType()) {
            case TextString -> key.AsString();
            case Integer -> String.valueOf(key.AsInt64Value());
            default -> key.toString();
        };
    }

    private static Map<String, Object> convertMap(CBORObject obj) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (CBORObject key : obj.getKeys()) {
            map.put(mapKey(key), toJava(obj.get(key)));
        }
        return map;
    }

    private static List<Object> convertArray(CBORObject obj) {
        List<Object> list = new ArrayList<>();
        for (int i = 0; i < obj.size(); i++) {
            list.add(toJava(obj.get(i)));
        }
        return list;
    }
}
