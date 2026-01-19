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

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Parses OID4VCI credential offer URLs and extracts the offer payload or URI.
 * Handles three input formats:
 * <ul>
 *   <li>openid-credential-offer://... URLs with credential_offer or credential_offer_uri parameters</li>
 *   <li>Direct JSON objects starting with "{"</li>
 *   <li>HTTP(S) URLs pointing to credential offer endpoints</li>
 * </ul>
 */
public final class CredentialOfferUrlParser {

    private static final String OPENID_CREDENTIAL_OFFER_SCHEME = "openid-credential-offer://";
    private static final String PARAM_CREDENTIAL_OFFER = "credential_offer";
    private static final String PARAM_CREDENTIAL_OFFER_URI = "credential_offer_uri";

    private CredentialOfferUrlParser() {
    }

    /**
     * Parse a credential offer input and extract the offer JSON or URI.
     *
     * @param input the raw input string (URL, JSON, or URI)
     * @return parsed result containing either offerJson or offerUri, or null if input is blank
     */
    public static ParseResult parse(String input) {
        if (input == null || input.isBlank()) {
            return null;
        }

        String trimmed = input.trim();
        String offerJson = null;
        String offerUri = null;

        if (trimmed.startsWith(OPENID_CREDENTIAL_OFFER_SCHEME)) {
            ParseResult fromUrl = parseOpenIdCredentialOfferUrl(trimmed);
            if (fromUrl != null) {
                offerJson = fromUrl.offerJson();
                offerUri = fromUrl.offerUri();
            }
        } else if (trimmed.startsWith("{")) {
            offerJson = trimmed;
        } else if (trimmed.startsWith("http")) {
            offerUri = trimmed;
        }

        if (offerJson == null && offerUri == null) {
            return null;
        }
        return new ParseResult(offerJson, offerUri);
    }

    private static ParseResult parseOpenIdCredentialOfferUrl(String url) {
        try {
            // Extract query string - handle both with and without authority
            String query;
            if (url.contains("?")) {
                query = url.substring(url.indexOf("?") + 1);
            } else {
                query = url.substring(OPENID_CREDENTIAL_OFFER_SCHEME.length());
            }

            String offerJson = null;
            String offerUri = null;

            for (String param : query.split("&")) {
                String[] parts = param.split("=", 2);
                if (parts.length != 2) {
                    continue;
                }
                String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);

                if (PARAM_CREDENTIAL_OFFER.equals(key)) {
                    offerJson = value;
                } else if (PARAM_CREDENTIAL_OFFER_URI.equals(key)) {
                    offerUri = value;
                }
            }

            return new ParseResult(offerJson, offerUri);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Result of parsing a credential offer input.
     *
     * @param offerJson the credential offer JSON payload (if directly provided)
     * @param offerUri  the URI to fetch the credential offer from (if provided as reference)
     */
    public record ParseResult(String offerJson, String offerUri) {
        /**
         * @return true if the offer JSON is directly available
         */
        public boolean hasOfferJson() {
            return offerJson != null && !offerJson.isBlank();
        }

        /**
         * @return true if the offer must be fetched from a URI
         */
        public boolean hasOfferUri() {
            return offerUri != null && !offerUri.isBlank();
        }
    }
}
