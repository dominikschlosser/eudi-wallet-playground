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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Supplies trusted issuer keys for credential signature verification.
 */
public interface TrustedIssuerResolver {
    Logger LOG = LoggerFactory.getLogger(TrustedIssuerResolver.class);
    String ALLOW_ALL_ID = "allow-all";

    boolean verify(SignedJWT jwt, String trustListId);

    List<PublicKey> publicKeys(String trustListId);

    default List<X509Certificate> certificates(String trustListId) {
        return List.of();
    }

    default boolean isAllowAll(String trustListId) {
        return ALLOW_ALL_ID.equals(trustListId);
    }

    static boolean verifyWithKey(SignedJWT jwt, PublicKey key) {
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
     * Attempts to verify a JWT by validating the x5c certificate chain from the JWT header
     * against the given trust anchor certificates, then verifying the signature with the leaf key.
     *
     * @param jwt              the signed JWT containing an x5c header
     * @param trustAnchors     CA certificates from the trust list
     * @return true if the x5c chain is valid against a trust anchor and the signature verifies
     */
    static boolean verifyWithX5cChain(SignedJWT jwt, List<X509Certificate> trustAnchors) {
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            return false;
        }
        List<X509Certificate> x5cChain = extractX5cCertificates(jwt);
        if (x5cChain.isEmpty()) {
            return false;
        }

        X509Certificate leafCert = x5cChain.get(0);

        // Build trust anchors set from trust list certificates
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate anchor : trustAnchors) {
            anchors.add(new TrustAnchor(anchor, null));
        }

        // Build the certificate path for PKIX validation.
        // The trust anchor itself must NOT be included in the cert path —
        // PKIX validates the path UP TO the anchor.
        // Filter out any cert from x5c that matches a trust anchor.
        Set<java.security.PublicKey> anchorKeys = new HashSet<>();
        for (X509Certificate anchor : trustAnchors) {
            anchorKeys.add(anchor.getPublicKey());
        }
        List<X509Certificate> pathCerts = new ArrayList<>();
        for (X509Certificate cert : x5cChain) {
            if (!anchorKeys.contains(cert.getPublicKey())) {
                pathCerts.add(cert);
            }
        }

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            var certPath = factory.generateCertPath(pathCerts);

            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
        } catch (Exception e) {
            LOG.debug("x5c chain validation failed: {}", e.getMessage());
            return false;
        }

        // Chain is valid — verify the JWT signature against the leaf certificate's key
        return verifyWithKey(jwt, leafCert.getPublicKey());
    }

    /**
     * Validates an x5c certificate chain against trust anchors and returns the leaf certificate's
     * public key if the chain is valid.
     *
     * @param x5cChain      the certificate chain (leaf first)
     * @param trustAnchors  CA certificates from the trust list
     * @return the leaf certificate's public key if the chain validates, or null
     */
    static PublicKey verifyX5cChain(List<X509Certificate> x5cChain, List<X509Certificate> trustAnchors) {
        if (trustAnchors == null || trustAnchors.isEmpty() || x5cChain == null || x5cChain.isEmpty()) {
            return null;
        }

        X509Certificate leafCert = x5cChain.get(0);

        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate anchor : trustAnchors) {
            anchors.add(new TrustAnchor(anchor, null));
        }

        Set<PublicKey> anchorKeys = new HashSet<>();
        for (X509Certificate anchor : trustAnchors) {
            anchorKeys.add(anchor.getPublicKey());
        }
        List<X509Certificate> pathCerts = new ArrayList<>();
        for (X509Certificate cert : x5cChain) {
            if (!anchorKeys.contains(cert.getPublicKey())) {
                pathCerts.add(cert);
            }
        }

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            var certPath = factory.generateCertPath(pathCerts);

            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
        } catch (Exception e) {
            LOG.debug("x5c chain validation failed: {}", e.getMessage());
            return null;
        }

        return leafCert.getPublicKey();
    }

    /**
     * Extracts X.509 certificates from the x5c header of a signed JWT.
     */
    static List<X509Certificate> extractX5cCertificates(SignedJWT jwt) {
        List<Base64> x5c = jwt.getHeader().getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            return List.of();
        }
        List<X509Certificate> certs = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Base64 certB64 : x5c) {
                X509Certificate cert = (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(certB64.decode()));
                certs.add(cert);
            }
        } catch (CertificateException e) {
            LOG.debug("Failed to parse x5c certificates: {}", e.getMessage());
            return List.of();
        }
        return certs;
    }
}
