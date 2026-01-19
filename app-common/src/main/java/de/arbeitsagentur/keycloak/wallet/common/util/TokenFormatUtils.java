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
package de.arbeitsagentur.keycloak.wallet.common.util;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Utilities for detecting and decoding different credential token formats.
 * Supports SD-JWT, mDoc (CBOR), hex, and base64url encoding detection.
 */
public final class TokenFormatUtils {
    /** SD-JWT disclosure separator */
    public static final char SDJWT_SEPARATOR = '~';
    /** JWT segment separator */
    public static final char JWT_SEPARATOR = '.';
    /** Pattern for hexadecimal strings */
    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]+$");
    /** Pattern for base64url encoded strings (allows padding) */
    private static final Pattern BASE64URL_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+=*$");

    private TokenFormatUtils() {
    }

    /**
     * Checks if the value is a valid hexadecimal string.
     *
     * @param value the value to check
     * @return true if the value consists only of hex characters
     */
    public static boolean isHex(String value) {
        return value != null && !value.isEmpty() && HEX_PATTERN.matcher(value).matches();
    }

    /**
     * Checks if the value appears to be base64url encoded.
     * Excludes values that look like JWTs or SD-JWTs (containing '.' or '~').
     *
     * @param value the value to check
     * @return true if the value matches base64url pattern and is not a JWT
     */
    public static boolean isBase64Url(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        // JWTs and SD-JWTs contain these separators
        if (value.indexOf(JWT_SEPARATOR) >= 0 || value.indexOf(SDJWT_SEPARATOR) >= 0) {
            return false;
        }
        return BASE64URL_PATTERN.matcher(value).matches();
    }

    /**
     * Checks if the token appears to be an SD-JWT (contains '~' separator).
     *
     * @param token the token to check
     * @return true if the token contains the SD-JWT separator
     */
    public static boolean isSdJwt(String token) {
        return token != null && token.indexOf(SDJWT_SEPARATOR) >= 0;
    }

    /**
     * Checks if the token appears to be a standard JWT (three dot-separated parts, no '~').
     *
     * @param token the token to check
     * @return true if the token looks like a JWT
     */
    public static boolean isJwt(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        if (token.indexOf(SDJWT_SEPARATOR) >= 0) {
            return false;
        }
        return countChar(token, JWT_SEPARATOR) == 2;
    }

    /**
     * Decodes a token from hex or base64url encoding to bytes.
     *
     * @param token the encoded token
     * @return the decoded bytes, or empty array if decoding fails
     */
    public static byte[] decodeBytes(String token) {
        if (token == null || token.isBlank()) {
            return new byte[0];
        }
        if (isHex(token)) {
            return hexDecode(token);
        }
        if (!isBase64Url(token)) {
            return new byte[0];
        }
        try {
            return Base64.getUrlDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            // Try standard base64 as fallback
            try {
                return Base64.getDecoder().decode(token);
            } catch (IllegalArgumentException ignored) {
                return new byte[0];
            }
        }
    }

    /**
     * Decodes a hex string to bytes.
     */
    private static byte[] hexDecode(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Counts occurrences of a character in a string.
     */
    private static int countChar(String str, char c) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == c) {
                count++;
            }
        }
        return count;
    }
}
