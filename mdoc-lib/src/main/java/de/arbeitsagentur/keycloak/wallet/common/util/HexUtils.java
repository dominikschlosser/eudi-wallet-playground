package de.arbeitsagentur.keycloak.wallet.common.util;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Small helpers to encode/decode hexadecimal values and normalize byte inputs.
 */
public final class HexUtils {
    private static final HexFormat HEX = HexFormat.of();

    private HexUtils() {
    }

    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        return HEX.formatHex(data);
    }

    public static byte[] decode(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[0];
        }
        try {
            return HEX.parseHex(hex);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }

    public static byte[] decode(List<?> bytes) {
        if (bytes == null || bytes.isEmpty()) {
            return new byte[0];
        }
        byte[] result = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            Object value = bytes.get(i);
            if (value instanceof Number number) {
                result[i] = number.byteValue();
            }
        }
        return result;
    }

    /**
     * Coerces common representations (byte[], List<Number>, Base64 string, hex string) to bytes.
     */
    public static byte[] toBytes(Object value) {
        if (value instanceof CBORObject cbor) {
            if (cbor.getType() == CBORType.ByteString) {
                return cbor.GetByteString();
            }
            if (cbor.getType() == CBORType.TextString) {
                return decode(cbor.AsString());
            }
        }
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        if (value instanceof List<?> list) {
            return decode(list);
        }
        if (value instanceof String str) {
            try {
                return Base64.getDecoder().decode(str);
            } catch (IllegalArgumentException ignored) {
                return decode(str);
            }
        }
        return new byte[0];
    }
}
