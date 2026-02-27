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
package de.arbeitsagentur.keycloak.wallet.common.credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.Inflater;

/**
 * Verifies credential revocation status using Token Status List (draft-ietf-oauth-status-list).
 * <p>
 * Credentials may contain a {@code status.status_list} claim with {@code uri} and {@code idx}.
 * The URI points to a JWT whose payload contains a DEFLATE-compressed bitstring.
 * A non-zero value at the credential's index means the credential is revoked.
 * <p>
 * Works with both SD-JWT (JSON payload) and mDoc (MSO CBOR converted to Java Map) credentials.
 */
public class StatusListVerifier {
    private static final Logger LOG = LoggerFactory.getLogger(StatusListVerifier.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Duration CACHE_TTL = Duration.ofMinutes(5);
    private static final int DEFAULT_BITS_PER_STATUS = 1;

    private final HttpClient httpClient;
    private final ConcurrentHashMap<String, CachedStatusList> cache = new ConcurrentHashMap<>();

    public StatusListVerifier() {
        this(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build());
    }

    public StatusListVerifier(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Checks the revocation status of a credential based on its payload claims.
     * If no status claim is present, this method returns silently (credential has no revocation info).
     *
     * @throws IllegalStateException if the credential is revoked or status check fails
     */
    public void checkRevocationStatus(Map<String, Object> payload) {
        StatusReference ref = extractStatusReference(payload);
        if (ref == null) {
            LOG.info("[StatusList] No status_list claim found in credential — skipping revocation check");
            return;
        }

        LOG.info("[StatusList] Checking revocation status: uri={}, idx={}", ref.uri, ref.idx);

        try {
            DecodedStatusList statusList = fetchAndDecodeStatusList(ref.uri);
            int status = getStatusAtIndex(statusList.statusBits, ref.idx, statusList.bitsPerStatus);

            LOG.info("[StatusList] Result: status={} at index {} (bitsPerStatus={}, listSize={} bytes) — {}",
                    status, ref.idx, statusList.bitsPerStatus, statusList.statusBits.length,
                    status == 0 ? "NOT REVOKED" : "REVOKED");

            if (status != 0) {
                throw new IllegalStateException(
                        "Credential has been revoked (status=" + status + " at index " + ref.idx + ")");
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            LOG.warn("[StatusList] Failed to check revocation status from {}: {}", ref.uri, e.getMessage());
            throw new IllegalStateException("Unable to verify credential revocation status: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    StatusReference extractStatusReference(Map<String, Object> payload) {
        if (payload == null) {
            return null;
        }
        Object statusObj = payload.get("status");
        if (!(statusObj instanceof Map<?, ?> statusMap)) {
            return null;
        }
        Object statusListObj = statusMap.get("status_list");
        if (!(statusListObj instanceof Map<?, ?> statusListMap)) {
            return null;
        }
        Object uriObj = statusListMap.get("uri");
        Object idxObj = statusListMap.get("idx");
        if (uriObj == null || idxObj == null) {
            return null;
        }
        String uri = uriObj.toString();
        int idx;
        if (idxObj instanceof Number num) {
            idx = num.intValue();
        } else {
            try {
                idx = Integer.parseInt(idxObj.toString());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return new StatusReference(uri, idx);
    }

    DecodedStatusList fetchAndDecodeStatusList(String uri) throws Exception {
        CachedStatusList cached = cache.get(uri);
        if (cached != null && cached.isValid()) {
            LOG.info("[StatusList] Using cached status list for: {} (expires in {}s)", uri,
                    Duration.between(Instant.now(), cached.expiresAt).toSeconds());
            return cached.decoded;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Accept", "application/statuslist+jwt")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        LOG.info("[StatusList] Fetching status list from: {}", uri);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        LOG.info("[StatusList] HTTP response: status={}, content-type={}, body length={}",
                response.statusCode(),
                response.headers().firstValue("content-type").orElse("(none)"),
                response.body() != null ? response.body().length() : 0);
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Status list fetch failed with HTTP " + response.statusCode() + " from " + uri);
        }

        String jwt = response.body().trim();
        // Parse the JWT payload (we don't verify the status list JWT signature here —
        // it's fetched from the issuer's own URI which is already trusted)
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalStateException("Invalid status list JWT format from " + uri);
        }

        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        JsonNode payload = OBJECT_MAPPER.readTree(payloadBytes);
        LOG.info("[StatusList] Status list JWT payload: sub={}, iat={}, exp={}",
                payload.path("sub").asText("(none)"),
                payload.path("iat").asText("(none)"),
                payload.path("exp").asText("(none)"));
        JsonNode statusListNode = payload.path("status_list");

        String lst = statusListNode.path("lst").textValue();
        if (lst == null) {
            throw new IllegalStateException("Status list JWT missing status_list.lst claim");
        }

        int bitsPerStatus = statusListNode.path("bits").asInt(DEFAULT_BITS_PER_STATUS);

        byte[] compressed = Base64.getUrlDecoder().decode(lst);
        byte[] statusBits = inflate(compressed);
        LOG.info("[StatusList] Decoded status list: bitsPerStatus={}, compressed={} bytes, decompressed={} bytes, capacity={} entries",
                bitsPerStatus, compressed.length, statusBits.length, statusBits.length * 8 / bitsPerStatus);

        var decoded = new DecodedStatusList(statusBits, bitsPerStatus);
        cache.put(uri, new CachedStatusList(decoded, Instant.now().plus(CACHE_TTL)));
        return decoded;
    }

    static byte[] inflate(byte[] compressed) throws Exception {
        // Token Status List specifies ZLIB compression (DEFLATE with zlib header).
        // Try zlib first, fall back to raw DEFLATE for older implementations.
        try {
            return doInflate(compressed, false); // zlib format
        } catch (Exception e) {
            LOG.debug("ZLIB decompression failed, trying raw DEFLATE: {}", e.getMessage());
            return doInflate(compressed, true); // raw DEFLATE (no zlib header)
        }
    }

    private static byte[] doInflate(byte[] compressed, boolean rawDeflate) throws Exception {
        Inflater inflater = new Inflater(rawDeflate);
        inflater.setInput(compressed);
        byte[] buffer = new byte[4096];
        int totalLen = 0;
        byte[] result = new byte[0];
        while (!inflater.finished()) {
            int len = inflater.inflate(buffer);
            if (len == 0 && inflater.needsInput()) {
                break;
            }
            byte[] newResult = new byte[totalLen + len];
            System.arraycopy(result, 0, newResult, 0, totalLen);
            System.arraycopy(buffer, 0, newResult, totalLen, len);
            result = newResult;
            totalLen += len;
        }
        inflater.end();
        return result;
    }

    static int getStatusAtIndex(byte[] statusBits, int idx, int bitsPerStatus) {
        if (statusBits == null || statusBits.length == 0) {
            throw new IllegalStateException("Empty status list");
        }
        if (bitsPerStatus < 1 || bitsPerStatus > 8) {
            throw new IllegalArgumentException("bitsPerStatus must be 1-8, got " + bitsPerStatus);
        }
        int bitOffset = idx * bitsPerStatus;
        int byteIndex = bitOffset / 8;
        int bitIndex = bitOffset % 8;

        if (byteIndex >= statusBits.length) {
            throw new IllegalStateException(
                    "Status index " + idx + " out of range (list has " + (statusBits.length * 8 / bitsPerStatus) + " entries)");
        }

        int mask = ((1 << bitsPerStatus) - 1);
        return (statusBits[byteIndex] >> bitIndex) & mask;
    }

    record StatusReference(String uri, int idx) {}

    record DecodedStatusList(byte[] statusBits, int bitsPerStatus) {}

    private record CachedStatusList(DecodedStatusList decoded, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
