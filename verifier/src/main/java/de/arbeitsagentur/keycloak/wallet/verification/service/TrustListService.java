package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class TrustListService implements
        de.arbeitsagentur.keycloak.wallet.common.sdjwt.TrustedIssuerResolver,
        de.arbeitsagentur.keycloak.wallet.common.mdoc.TrustedIssuerResolver {
    private final ObjectMapper objectMapper;
    private final Map<String, List<TrustedVerifier>> trustLists = new LinkedHashMap<>();
    private final Map<String, List<PublicKey>> trustListKeys = new LinkedHashMap<>();
    private String defaultTrustListId;
    private final Map<String, String> labels = new LinkedHashMap<>();

    public TrustListService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void load() throws Exception {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] resources = resolver.getResources("classpath*:trust-list*.json");
        for (Resource resource : resources) {
            String id = deriveId(resource);
            JsonNode node;
            try (InputStream is = resource.getInputStream()) {
                node = objectMapper.readTree(is);
            }
            List<TrustedVerifier> verifiers = new ArrayList<>();
            List<PublicKey> keys = new ArrayList<>();
            for (JsonNode issuer : node.path("issuers")) {
                String certPem = issuer.path("certificate").asText();
                PublicKey publicKey = parsePublicKey(certPem);
                if (publicKey instanceof RSAPublicKey rsaPublicKey) {
                    verifiers.add(new TrustedVerifier(JWSAlgorithm.RS256, new RSASSAVerifier(rsaPublicKey)));
                    keys.add(rsaPublicKey);
                } else if (publicKey instanceof ECPublicKey ecPublicKey) {
                    verifiers.add(new TrustedVerifier(JWSAlgorithm.ES256, new ECDSAVerifier(ecPublicKey)));
                    keys.add(ecPublicKey);
                }
            }
            trustLists.put(id, verifiers);
            trustListKeys.put(id, List.copyOf(keys));
            String label = node.path("label").asText(null);
            labels.put(id, (label == null || label.isBlank()) ? id : label);
            if (defaultTrustListId == null) {
                defaultTrustListId = id;
            }
        }
        if (defaultTrustListId == null) {
            throw new IllegalStateException("No trust-list*.json files found on classpath");
        }
        if (trustLists.containsKey("trust-list")) {
            defaultTrustListId = "trust-list";
        }
    }

    private String deriveId(Resource resource) {
        String filename = Objects.requireNonNull(resource.getFilename());
        if (filename.endsWith(".json")) {
            filename = filename.substring(0, filename.length() - 5);
        }
        return filename;
    }

    private PublicKey parsePublicKey(String pem) throws Exception {
        String sanitized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(sanitized);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
                (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        return certificate.getPublicKey();
    }

    public boolean verify(SignedJWT jwt) {
        return verify(jwt, defaultTrustListId);
    }

    @Override
    public boolean verify(SignedJWT jwt, String trustListId) {
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
        for (String id : trustLists.keySet()) {
            String label = labels.getOrDefault(id, id);
            if ("trust-list".equals(id)) {
                label = "Default (Keycloak realm)";
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

    public record TrustListOption(String id, String label) {
    }

    private record TrustedVerifier(JWSAlgorithm algorithm, JWSVerifier verifier) {
    }
}
