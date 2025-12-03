package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

public final class SdJwtUtils {
    private static final String DEFAULT_HASH_ALGORITHM = "sha-256";

    private SdJwtUtils() {
    }

    public static SdJwtParts split(String token) {
        if (token == null || token.isBlank()) {
            return new SdJwtParts(null, List.of());
        }
        try {
            SDJWT parsed = SDJWT.parse(token);
            List<String> disclosures = parsed.getDisclosures().stream()
                    .map(Disclosure::getDisclosure)
                    .toList();
            return new SdJwtParts(parsed.getCredentialJwt(), disclosures);
        } catch (Exception e) {
            String[] segments = token.split("~");
            String signedJwt = segments.length > 0 ? segments[0] : token;
            List<String> disclosures = new ArrayList<>();
            for (int i = 1; i < segments.length; i++) {
                String disclosure = segments[i];
                if (disclosure != null && !disclosure.isBlank()) {
                    disclosures.add(disclosure);
                }
            }
            return new SdJwtParts(signedJwt, disclosures);
        }
    }

    public static Map<String, Object> extractDisclosedClaims(SdJwtParts parts, ObjectMapper mapper) throws Exception {
        if (parts == null || parts.signedJwt() == null || parts.signedJwt().isBlank()) {
            return Map.of();
        }
        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        Map<String, Object> payload = mapper.readValue(jwt.getPayload().toBytes(), new TypeReference<>() {});
        SDObjectDecoder decoder = new SDObjectDecoder();
        Map<String, Object> decodedPayload = decoder.decode(payload, parseDisclosures(parts.disclosures()));
        Map<String, Object> vc = asMap(decodedPayload.get("vc"));
        Map<String, Object> subject = vc != null ? asMap(vc.get("credentialSubject")) : null;
        if (subject == null) {
            subject = asMap(decodedPayload.get("credentialSubject"));
        }
        return subject != null ? subject : decodedPayload;
    }

    public static boolean verifyDisclosures(SignedJWT jwt, SdJwtParts parts, ObjectMapper mapper) throws Exception {
        if (jwt == null || parts == null) {
            return false;
        }
        Map<String, Object> payload = mapper.readValue(jwt.getPayload().toBytes(), new TypeReference<>() {});
        String hashAlgorithm = resolveHashAlgorithm(payload);
        Set<String> digests = collectDigests(payload);
        for (Disclosure disclosure : parseDisclosures(parts.disclosures())) {
            String digest = disclosure.digest(hashAlgorithm);
            if (!digests.remove(digest)) {
                return false;
            }
        }
        return true;
    }

    public record SdJwtParts(String signedJwt, List<String> disclosures) {
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

    private static String resolveHashAlgorithm(Map<String, Object> payload) {
        Object alg = payload.get("_sd_alg");
        if (alg instanceof String value && !value.isBlank()) {
            return value;
        }
        return DEFAULT_HASH_ALGORITHM;
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
