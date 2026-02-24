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
package de.arbeitsagentur.keycloak.oid4vp;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.EtsiTrustListParser;
import de.arbeitsagentur.keycloak.wallet.common.credential.EtsiTrustListParser.EtsiTrustList;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class Oid4vpTrustListService implements TrustedIssuerResolver {

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustListService.class);
    private final Map<String, TrustListData> trustListData = new ConcurrentHashMap<>();
    private final String configuredTrustListJwt;

    public Oid4vpTrustListService() {
        this(null);
    }

    public Oid4vpTrustListService(String trustListJwt) {
        this.configuredTrustListJwt = trustListJwt;
    }

    @Override
    public boolean verify(SignedJWT jwt, String trustListId) {
        TrustListData data = resolveData(trustListId);

        // Prefer x5c certificate chain validation when the JWT includes an x5c header
        if (TrustedIssuerResolver.verifyWithX5cChain(jwt, data.certificates())) {
            LOG.infof("[OID4VP-TRUSTLIST] Verified JWT via x5c chain validation");
            return true;
        }

        // Fall back to direct key matching for JWTs without x5c header
        for (PublicKey key : data.keys()) {
            if (TrustedIssuerResolver.verifyWithKey(jwt, key)) {
                LOG.infof("[OID4VP-TRUSTLIST] Verified JWT via direct key match");
                return true;
            }
        }

        return false;
    }

    @Override
    public List<PublicKey> publicKeys(String trustListId) {
        TrustListData data = resolveData(trustListId);
        return data.keys();
    }

    @Override
    public List<X509Certificate> certificates(String trustListId) {
        TrustListData data = resolveData(trustListId);
        return data.certificates();
    }

    private TrustListData resolveData(String trustListId) {
        String id = normalizeTrustListId(trustListId);
        LOG.infof("[OID4VP-TRUSTLIST] resolveData() called for trustListId: %s (normalized: %s)", trustListId, id);
        TrustListData resolved = trustListData.computeIfAbsent(id, this::loadData);
        if (!resolved.found()) {
            throw new IllegalStateException("Trust list not found or empty: " + id);
        }
        LOG.infof("[OID4VP-TRUSTLIST] Returning %d keys, %d certs from trust list %s",
                resolved.keys().size(), resolved.certificates().size(), id);
        return resolved;
    }

    private TrustListData loadData(String trustListId) {
        if (configuredTrustListJwt == null || configuredTrustListJwt.isBlank()) {
            LOG.warnf("[OID4VP-TRUSTLIST] No trust list JWT configured");
            return TrustListData.missing();
        }
        LOG.infof("[OID4VP-TRUSTLIST] Loading trust list from configured JWT");
        return loadDataFromJwt(configuredTrustListJwt);
    }

    /**
     * Dynamically register a public key to a trust list.
     * This is useful for testing where the issuer key isn't pre-configured.
     */
    public void registerKey(String trustListId, PublicKey publicKey) {
        String id = normalizeTrustListId(trustListId);
        LOG.infof("Registering dynamic key to trust list %s: %s", id, publicKey.getAlgorithm());

        trustListData.compute(id, (key, existing) -> {
            List<PublicKey> keys = new ArrayList<>();
            List<X509Certificate> certs = new ArrayList<>();
            if (existing != null && existing.found()) {
                keys.addAll(existing.keys());
                certs.addAll(existing.certificates());
            }
            keys.add(publicKey);
            return new TrustListData(true, List.copyOf(keys), List.copyOf(certs));
        });
    }

    /**
     * Dynamically register a public key from a certificate PEM to a trust list.
     */
    public void registerCertificate(String trustListId, String certificatePem) {
        try {
            X509Certificate cert = parsePemCertificateX509(certificatePem);
            String id = normalizeTrustListId(trustListId);

            trustListData.compute(id, (key, existing) -> {
                List<PublicKey> keys = new ArrayList<>();
                List<X509Certificate> certs = new ArrayList<>();
                if (existing != null && existing.found()) {
                    keys.addAll(existing.keys());
                    certs.addAll(existing.certificates());
                }
                keys.add(cert.getPublicKey());
                certs.add(cert);
                return new TrustListData(true, List.copyOf(keys), List.copyOf(certs));
            });
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate for trust list registration", e);
        }
    }

    private TrustListData loadDataFromJwt(String jwtString) {
        try {
            EtsiTrustList parsed = EtsiTrustListParser.parse(jwtString);
            List<PublicKey> keys = parsed.allPublicKeys();
            List<X509Certificate> certs = parsed.allCertificates();
            LOG.infof("Loaded %d keys, %d certs from ETSI trust list JWT (label: %s)",
                    keys.size(), certs.size(), parsed.label());
            return new TrustListData(true, List.copyOf(keys), List.copyOf(certs));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse ETSI trust list JWT", e);
        }
    }

    private String normalizeTrustListId(String trustListId) {
        if (trustListId == null || trustListId.isBlank()) {
            return DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID;
        }
        String trimmed = trustListId.trim();
        if (trimmed.endsWith(".jwt")) {
            trimmed = trimmed.substring(0, trimmed.length() - 4);
        }
        if (trimmed.endsWith(".json")) {
            trimmed = trimmed.substring(0, trimmed.length() - 5);
        }
        return trimmed.isBlank() ? DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID : trimmed;
    }

    private X509Certificate parsePemCertificateX509(String pem) throws Exception {
        String sanitized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(sanitized);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }

    private record TrustListData(boolean found, List<PublicKey> keys, List<X509Certificate> certificates) {
        static TrustListData missing() {
            return new TrustListData(false, List.of(), List.of());
        }
    }
}
