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
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class Oid4vpTrustListService implements TrustedIssuerResolver {

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustListService.class);
    private final Map<String, TrustListKeys> trustListKeys = new ConcurrentHashMap<>();
    private final String configuredTrustListJwt;

    public Oid4vpTrustListService() {
        this(null);
    }

    public Oid4vpTrustListService(String trustListJwt) {
        this.configuredTrustListJwt = trustListJwt;
    }

    @Override
    public boolean verify(SignedJWT jwt, String trustListId) {
        for (PublicKey key : publicKeys(trustListId)) {
            if (TrustedIssuerResolver.verifyWithKey(jwt, key)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<PublicKey> publicKeys(String trustListId) {
        String id = normalizeTrustListId(trustListId);
        LOG.infof("[OID4VP-TRUSTLIST] publicKeys() called for trustListId: %s (normalized: %s)", trustListId, id);
        TrustListKeys resolved = trustListKeys.computeIfAbsent(id, this::loadKeys);
        if (!resolved.found()) {
            throw new IllegalStateException("Trust list not found or empty: " + id);
        }
        LOG.infof("[OID4VP-TRUSTLIST] Returning %d keys from trust list %s", resolved.keys().size(), id);
        return resolved.keys();
    }

    private TrustListKeys loadKeys(String trustListId) {
        if (configuredTrustListJwt == null || configuredTrustListJwt.isBlank()) {
            LOG.warnf("[OID4VP-TRUSTLIST] No trust list JWT configured");
            return TrustListKeys.missing();
        }
        LOG.infof("[OID4VP-TRUSTLIST] Loading trust list from configured JWT");
        return loadKeysFromJwt(configuredTrustListJwt);
    }

    /**
     * Dynamically register a public key to a trust list.
     * This is useful for testing where the issuer key isn't pre-configured.
     */
    public void registerKey(String trustListId, PublicKey publicKey) {
        String id = normalizeTrustListId(trustListId);
        LOG.infof("Registering dynamic key to trust list %s: %s", id, publicKey.getAlgorithm());

        trustListKeys.compute(id, (key, existing) -> {
            List<PublicKey> keys = new ArrayList<>();
            if (existing != null && existing.found()) {
                keys.addAll(existing.keys());
            }
            keys.add(publicKey);
            return new TrustListKeys(true, List.copyOf(keys));
        });
    }

    /**
     * Dynamically register a public key from a certificate PEM to a trust list.
     */
    public void registerCertificate(String trustListId, String certificatePem) {
        try {
            PublicKey publicKey = parsePemCertificate(certificatePem);
            registerKey(trustListId, publicKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate for trust list registration", e);
        }
    }

    private TrustListKeys loadKeysFromJwt(String jwtString) {
        try {
            EtsiTrustList parsed = EtsiTrustListParser.parse(jwtString);
            List<PublicKey> keys = parsed.allPublicKeys();
            LOG.infof("Loaded %d keys from ETSI trust list JWT (label: %s)", keys.size(), parsed.label());
            return new TrustListKeys(true, List.copyOf(keys));
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

    private PublicKey parsePemCertificate(String pem) throws Exception {
        String sanitized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(sanitized);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
                (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        return certificate.getPublicKey();
    }

    private record TrustListKeys(boolean found, List<PublicKey> keys) {
        static TrustListKeys missing() {
            return new TrustListKeys(false, List.of());
        }
    }
}
