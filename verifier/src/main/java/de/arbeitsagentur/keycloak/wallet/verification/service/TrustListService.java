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
package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.EtsiTrustListParser;
import de.arbeitsagentur.keycloak.wallet.common.credential.EtsiTrustListParser.EtsiTrustList;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class TrustListService implements
        de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver {

    private static final Logger LOG = LoggerFactory.getLogger(TrustListService.class);

    private static final String[] REMOTE_TRUST_LIST_FILES = {
            "pid-provider.jwt", "registrar.jwt", "wallet-provider.jwt",
            "wrpac-provider.jwt", "wrprc-provider.jwt"
    };

    private final VerifierProperties properties;
    private final Map<String, List<TrustedVerifier>> trustLists = new LinkedHashMap<>();
    private final Map<String, List<PublicKey>> trustListKeys = new LinkedHashMap<>();
    private String defaultTrustListId;
    private final Map<String, String> labels = new LinkedHashMap<>();

    public TrustListService(VerifierProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void load() throws Exception {
        // Load classpath trust lists (ETSI JWT format)
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] resources = resolver.getResources("classpath*:trust-list*.jwt");
        for (Resource resource : resources) {
            String id = deriveId(resource);
            try (InputStream is = resource.getInputStream()) {
                String jwtContent = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
                loadTrustListJwt(id, jwtContent);
            }
        }

        // Load remote ETSI trust lists if configured
        String baseUrl = properties.etsiTrustListBaseUrl();
        if (baseUrl != null && !baseUrl.isBlank()) {
            loadRemoteTrustLists(baseUrl);
        }

        if (defaultTrustListId == null) {
            throw new IllegalStateException("No trust-list*.jwt files found on classpath");
        }
        if (trustLists.containsKey("trust-list")) {
            defaultTrustListId = "trust-list";
        }
    }

    private void loadTrustListJwt(String id, String jwtContent) {
        EtsiTrustList parsed = EtsiTrustListParser.parse(jwtContent);

        List<TrustedVerifier> verifiers = new ArrayList<>();
        List<PublicKey> keys = new ArrayList<>();
        for (var entity : parsed.entities()) {
            for (PublicKey key : entity.publicKeys()) {
                addVerifiersForKey(key, verifiers, keys);
            }
        }

        trustLists.put(id, verifiers);
        trustListKeys.put(id, List.copyOf(keys));

        String label = parsed.label();
        labels.put(id, (label == null || label.isBlank()) ? id : label);
        LOG.info("Loaded trust list '{}' with {} keys (label: {})", id, keys.size(), labels.get(id));

        if (defaultTrustListId == null) {
            defaultTrustListId = id;
        }
    }

    private void loadRemoteTrustLists(String baseUrl) {
        String normalizedBase = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        LOG.info("Fetching remote ETSI trust lists from {}", normalizedBase);

        for (String filename : REMOTE_TRUST_LIST_FILES) {
            String url = normalizedBase + filename;
            try {
                String jwtContent = fetchUrl(url);
                String id = filename.replace(".jwt", "");
                loadTrustListJwt(id, jwtContent);
            } catch (Exception e) {
                LOG.warn("Failed to load remote ETSI trust list {}: {}", filename, e.getMessage());
            }
        }
    }

    private String fetchUrl(String url) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("HTTP " + response.statusCode() + " for " + url);
        }
        return response.body().trim();
    }

    private String deriveId(Resource resource) {
        String filename = Objects.requireNonNull(resource.getFilename());
        if (filename.endsWith(".jwt")) {
            filename = filename.substring(0, filename.length() - 4);
        }
        return filename;
    }

    private void addVerifiersForKey(PublicKey publicKey, List<TrustedVerifier> verifiers, List<PublicKey> keys) {
        try {
            if (publicKey instanceof RSAPublicKey rsaPublicKey) {
                verifiers.add(new TrustedVerifier(JWSAlgorithm.RS256, new RSASSAVerifier(rsaPublicKey)));
                verifiers.add(new TrustedVerifier(JWSAlgorithm.PS256, new RSASSAVerifier(rsaPublicKey)));
                verifiers.add(new TrustedVerifier(JWSAlgorithm.PS384, new RSASSAVerifier(rsaPublicKey)));
                verifiers.add(new TrustedVerifier(JWSAlgorithm.PS512, new RSASSAVerifier(rsaPublicKey)));
                keys.add(rsaPublicKey);
            } else if (publicKey instanceof ECPublicKey ecPublicKey) {
                verifiers.add(new TrustedVerifier(JWSAlgorithm.ES256, new ECDSAVerifier(ecPublicKey)));
                keys.add(ecPublicKey);
            }
        } catch (Exception e) {
            LOG.warn("Failed to create verifier for key: {}", e.getMessage());
        }
    }

    public boolean verify(SignedJWT jwt) {
        return verify(jwt, defaultTrustListId);
    }

    @Override
    public boolean verify(SignedJWT jwt, String trustListId) {
        if (isAllowAll(trustListId)) {
            return true;
        }
        if (jwt.getHeader().getAlgorithm() == null) {
            return false;
        }
        List<TrustedVerifier> candidates = trustLists.getOrDefault(
                trustListId != null ? trustListId : defaultTrustListId,
                trustLists.getOrDefault(defaultTrustListId, List.of())
        );
        for (TrustedVerifier trusted : candidates) {
            try {
                if (trusted.algorithm.equals(jwt.getHeader().getAlgorithm()) && jwt.verify(trusted.verifier)) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    public List<TrustListOption> options() {
        List<TrustListOption> opts = new ArrayList<>();
        opts.add(new TrustListOption(ALLOW_ALL_ID, "Allow all (skip signature verification)"));
        for (String id : trustLists.keySet()) {
            String rawLabel = labels.getOrDefault(id, id);
            String label;
            if ("trust-list".equals(id)) {
                label = "Default (Keycloak realm)";
            } else if (rawLabel.equals(id)) {
                label = id;
            } else {
                label = id + " (" + rawLabel + ")";
            }
            opts.add(new TrustListOption(id, label));
        }
        return opts;
    }

    public String defaultTrustListId() {
        return defaultTrustListId;
    }

    @Override
    public List<PublicKey> publicKeys(String trustListId) {
        return trustListKeys.getOrDefault(
                trustListId != null ? trustListId : defaultTrustListId,
                trustListKeys.getOrDefault(defaultTrustListId, List.of())
        );
    }

    public static boolean verifyWithKey(SignedJWT jwt, PublicKey key) {
        try {
            JWSVerifier verifier = null;
            if (key instanceof RSAPublicKey rsa) {
                verifier = new RSASSAVerifier(rsa);
            } else if (key instanceof ECPublicKey ec) {
                verifier = new ECDSAVerifier(ec);
            }
            return verifier != null && jwt.verify(verifier);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Adds keys from a JWKS URL to the default trust list.
     * Useful for tests that need to trust dynamically-generated keys.
     */
    public void addJwksUrl(String jwksUrl) {
        try {
            var jwkSet = com.nimbusds.jose.jwk.JWKSet.load(java.net.URI.create(jwksUrl).toURL());
            List<TrustedVerifier> verifiers = new ArrayList<>(trustLists.getOrDefault(defaultTrustListId, List.of()));
            List<PublicKey> keys = new ArrayList<>(trustListKeys.getOrDefault(defaultTrustListId, List.of()));
            for (var jwk : jwkSet.getKeys()) {
                try {
                    if (jwk instanceof com.nimbusds.jose.jwk.RSAKey rsaKey) {
                        RSAPublicKey pubKey = rsaKey.toRSAPublicKey();
                        addVerifiersForKey(pubKey, verifiers, keys);
                    } else if (jwk instanceof com.nimbusds.jose.jwk.ECKey ecKey) {
                        ECPublicKey pubKey = ecKey.toECPublicKey();
                        addVerifiersForKey(pubKey, verifiers, keys);
                    }
                } catch (Exception ignored) {
                }
            }
            trustLists.put(defaultTrustListId, verifiers);
            trustListKeys.put(defaultTrustListId, List.copyOf(keys));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load JWKS from " + jwksUrl, e);
        }
    }

    public record TrustListOption(String id, String label) {
    }

    private record TrustedVerifier(JWSAlgorithm algorithm, JWSVerifier verifier) {
    }
}
