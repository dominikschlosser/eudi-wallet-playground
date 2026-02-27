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
package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Base64;
import java.util.LinkedHashMap;

public final class SdJwtUtils {
    private static final String DEFAULT_HASH_ALGORITHM = "sha-256";

    private SdJwtUtils() {
    }

    public static SdJwtParts split(String token) {
        if (token == null || token.isBlank()) {
            return new SdJwtParts(null, List.of(), null);
        }
        try {
            SDJWT parsed = SDJWT.parse(token);
            List<String> disclosures = parsed.getDisclosures().stream()
                    .map(Disclosure::getDisclosure)
                    .toList();
            return new SdJwtParts(parsed.getCredentialJwt(), disclosures, parsed.getBindingJwt());
        } catch (Exception e) {
            String[] segments = token.split("~");
            String signedJwt = segments.length > 0 ? segments[0] : token;
            List<String> disclosures = new ArrayList<>();
            String keyBindingJwt = null;
            int end = segments.length;
            if (segments.length > 1) {
                String last = segments[segments.length - 1];
                if (looksLikeJwt(last)) {
                    keyBindingJwt = last;
                    end = segments.length - 1;
                }
            }
            for (int i = 1; i < end; i++) {
                String disclosure = segments[i];
                if (disclosure != null && !disclosure.isBlank()) {
                    disclosures.add(disclosure);
                }
            }
            return new SdJwtParts(signedJwt, disclosures, keyBindingJwt);
        }
    }

    /**
     * Computes the {@code sd_hash} for a presented SD-JWT and its selected disclosures,
     * as defined by the SD-JWT specification (hash over {@code <JWT>~<disc1>~...~}).
     */
    public static String computeSdHash(SdJwtParts parts, ObjectMapper mapper) throws Exception {
        if (parts == null || parts.signedJwt() == null || parts.signedJwt().isBlank()) {
            return null;
        }
        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        Map<String, Object> payload = mapper.readValue(jwt.getPayload().toBytes(), new TypeReference<>() {});
        String hashAlgorithm = resolveHashAlgorithm(payload);
        MessageDigest digest = MessageDigest.getInstance(toMessageDigestName(hashAlgorithm));
        StringBuilder toHash = new StringBuilder(parts.signedJwt()).append('~');
        if (parts.disclosures() != null) {
            for (String disclosure : parts.disclosures()) {
                if (disclosure != null && !disclosure.isBlank()) {
                    toHash.append(disclosure).append('~');
                }
            }
        }
        byte[] bytes = toHash.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] hashed = digest.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
    }

    /**
     * Standard JWT claims that should always be preserved from the original payload.
     * These are not selectively disclosable and should be included in the result.
     */
    private static final Set<String> STANDARD_JWT_CLAIMS = Set.of(
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "vct", "cnf"
    );

    public static Map<String, Object> extractDisclosedClaims(SdJwtParts parts, ObjectMapper mapper) throws Exception {
        if (parts == null || parts.signedJwt() == null || parts.signedJwt().isBlank()) {
            return Map.of();
        }
        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        Map<String, Object> payload = mapper.readValue(jwt.getPayload().toBytes(), new TypeReference<>() {});
        SDObjectDecoder decoder = new SDObjectDecoder();
        List<Disclosure> disclosures = parseDisclosures(parts.disclosures());
        Map<String, Object> decodedPayload = decoder.decode(payload, disclosures);
        @SuppressWarnings("unchecked")
        Map<String, Object> fullyDecodedPayload = (Map<String, Object>) deepDecode(decodedPayload, decoder, disclosures);

        // Preserve standard JWT claims from the original payload
        // These are not selectively disclosable but are important for verification
        for (String claim : STANDARD_JWT_CLAIMS) {
            if (payload.containsKey(claim) && !fullyDecodedPayload.containsKey(claim)) {
                fullyDecodedPayload.put(claim, payload.get(claim));
            }
        }

        Map<String, Object> vc = asMap(fullyDecodedPayload.get("vc"));
        Map<String, Object> subject = vc != null ? asMap(vc.get("credentialSubject")) : null;
        if (subject == null) {
            subject = asMap(fullyDecodedPayload.get("credentialSubject"));
        }
        return subject != null ? subject : fullyDecodedPayload;
    }

    public static boolean verifyDisclosures(SignedJWT jwt, SdJwtParts parts, ObjectMapper mapper) throws Exception {
        if (jwt == null || parts == null) {
            return false;
        }
        Map<String, Object> payload = mapper.readValue(jwt.getPayload().toBytes(), new TypeReference<>() {});
        String hashAlgorithm = resolveHashAlgorithm(payload);
        Set<String> availableDigests = new HashSet<>(collectDigests(payload));
        List<Disclosure> remaining = new ArrayList<>(parseDisclosures(parts.disclosures()));

        boolean progress = true;
        while (progress && !remaining.isEmpty()) {
            progress = false;
            for (int i = 0; i < remaining.size(); ) {
                Disclosure disclosure = remaining.get(i);
                String digest = disclosure.digest(hashAlgorithm);
                if (!availableDigests.remove(digest)) {
                    i++;
                    continue;
                }
                collectDigestsRecursive(disclosure.getClaimValue(), availableDigests);
                remaining.remove(i);
                progress = true;
            }
        }

        return remaining.isEmpty();
    }

    public record SdJwtParts(String signedJwt, List<String> disclosures, String keyBindingJwt) {
    }

    private static List<Disclosure> parseDisclosures(Collection<String> disclosures) {
        if (disclosures == null || disclosures.isEmpty()) {
            return Collections.emptyList();
        }
        List<Disclosure> result = new ArrayList<>(disclosures.size());
        for (String disclosure : disclosures) {
            if (disclosure == null || disclosure.isBlank()) {
                continue;
            }
            try {
                result.add(Disclosure.parse(disclosure));
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Object deepDecode(Object node, SDObjectDecoder decoder, Collection<Disclosure> disclosures) {
        if (node instanceof Map<?, ?> map) {
            Map<String, Object> decoded;
            try {
                decoded = decoder.decode((Map<String, Object>) map, disclosures);
            } catch (Exception e) {
                decoded = (Map<String, Object>) map;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : decoded.entrySet()) {
                String key = entry.getKey();
                out.put(key, deepDecode(entry.getValue(), decoder, disclosures));
            }
            return out;
        }
        if (node instanceof List<?> list) {
            List<Object> decoded;
            try {
                decoded = decoder.decode(list, disclosures);
            } catch (Exception e) {
                decoded = new ArrayList<>(list);
            }
            List<Object> out = new ArrayList<>(decoded.size());
            for (Object item : decoded) {
                out.add(deepDecode(item, decoder, disclosures));
            }
            return out;
        }
        return node;
    }

    private static String resolveHashAlgorithm(Map<String, Object> payload) {
        Object alg = payload.get("_sd_alg");
        if (alg instanceof String value && !value.isBlank()) {
            return value;
        }
        return DEFAULT_HASH_ALGORITHM;
    }

    private static String toMessageDigestName(String sdAlg) {
        if (sdAlg == null || sdAlg.isBlank()) {
            return "SHA-256";
        }
        return switch (sdAlg.toLowerCase()) {
            case "sha-256", "sha256" -> "SHA-256";
            case "sha-384", "sha384" -> "SHA-384";
            case "sha-512", "sha512" -> "SHA-512";
            default -> "SHA-256";
        };
    }

    private static boolean looksLikeJwt(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        long dots = candidate.chars().filter(c -> c == '.').count();
        if (dots != 2) {
            return false;
        }
        try {
            SignedJWT.parse(candidate);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Collects all {@code "..."} digests referenced inside the given disclosures' values.
     */
    static Set<String> collectAllDigests(List<Disclosure> disclosures) {
        Set<String> digests = new HashSet<>();
        for (Disclosure d : disclosures) {
            Object value = d.getClaimValue();
            if (value != null) {
                collectDigestsRecursive(value, digests);
            }
        }
        return digests;
    }

    /**
     * Collects all {@code "..."} digests from raw disclosure strings' values.
     */
    static Set<String> collectAllDigestsFromRaw(List<String> disclosures) {
        List<Disclosure> parsed = new ArrayList<>();
        for (String raw : disclosures) {
            try {
                parsed.add(Disclosure.parse(raw));
            } catch (Exception ignored) {
            }
        }
        return collectAllDigests(parsed);
    }

    private static Set<String> collectDigests(Object node) {
        if (node == null) {
            return Set.of();
        }
        Set<String> digests = new HashSet<>();
        collectDigestsRecursive(node, digests);
        return digests;
    }

    @SuppressWarnings("unchecked")
    private static void collectDigestsRecursive(Object node, Set<String> digests) {
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();
                if ("_sd".equals(key) && value instanceof List<?> list) {
                    list.stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .forEach(digests::add);
                } else if ("...".equals(key) && value instanceof String str) {
                    digests.add(str);
                } else {
                    collectDigestsRecursive(value, digests);
                }
            }
        } else if (node instanceof List<?> list) {
            list.forEach(item -> collectDigestsRecursive(item, digests));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return null;
    }
}
