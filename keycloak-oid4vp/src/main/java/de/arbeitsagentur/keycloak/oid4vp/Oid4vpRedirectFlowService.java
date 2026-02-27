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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.jboss.logging.Logger;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Service for building OID4VP authorization requests for same-device and cross-device flows.
 * Unlike the DC API flow, these flows use HTTP redirects to invoke the wallet.
 */
public class Oid4vpRedirectFlowService {

    private static final Logger LOG = Logger.getLogger(Oid4vpRedirectFlowService.class);
    private static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    private final KeycloakSession session;
    private final ObjectMapper objectMapper;

    public Oid4vpRedirectFlowService(KeycloakSession session, ObjectMapper objectMapper) {
        this.session = Objects.requireNonNull(session);
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    /**
     * Build a wallet authorization URL for same-device or cross-device flow.
     *
     * @param walletBaseUrl HTTPS base URL of wallet (null to use scheme)
     * @param walletScheme Custom URL scheme (e.g., openid4vp://)
     * @param clientId The client_id to use
     * @param clientIdScheme The client_id scheme (plain, x509_san_dns, x509_hash)
     * @param requestUri URI where wallet can fetch the request object
     * @return Full wallet authorization URL
     */
    public URI buildWalletAuthorizationUrl(
            String walletBaseUrl,
            String walletScheme,
            String clientId,
            String clientIdScheme,
            URI requestUri) {

        String effectiveClientId = buildEffectiveClientId(clientId, clientIdScheme);

        StringBuilder url = new StringBuilder();
        if (walletBaseUrl != null && !walletBaseUrl.isBlank() && walletBaseUrl.startsWith("http")) {
            url.append(walletBaseUrl);
            if (!walletBaseUrl.contains("?")) {
                url.append("?");
            } else {
                url.append("&");
            }
        } else {
            String scheme = walletScheme != null && !walletScheme.isBlank() ? walletScheme : "openid4vp://";
            if (!scheme.endsWith("://")) {
                scheme = scheme + "://";
            }
            url.append(scheme).append("?");
        }

        url.append("client_id=").append(urlEncode(effectiveClientId));
        url.append("&request_uri=").append(urlEncode(requestUri.toString()));

        return URI.create(url.toString());
    }

    /**
     * Build a signed request object JWT for the redirect flow.
     *
     * @param config Configuration containing signing key, DCQL query, etc.
     * @param clientId Base client_id
     * @param clientIdScheme Client ID scheme (plain, x509_san_dns, x509_hash)
     * @param responseUri Where wallet should POST the response
     * @param state OAuth state parameter
     * @param nonce Nonce for verification
     * @param x509CertPem PEM certificate for x509 schemes (may be null)
     * @param x509SigningKeyJwk JWK with private key for signing (may be null)
     * @return Signed request object with encryption key
     */
    public SignedRequestObject buildSignedRequestObject(
            Oid4vpConfig config,
            String clientId,
            String clientIdScheme,
            String responseUri,
            String state,
            String nonce,
            String x509CertPem,
            String x509SigningKeyJwk) {
        return buildSignedRequestObject(config, clientId, clientIdScheme, responseUri, state, nonce, x509CertPem, x509SigningKeyJwk, null, 600);
    }

    public SignedRequestObject buildSignedRequestObject(
            Oid4vpConfig config,
            String clientId,
            String clientIdScheme,
            String responseUri,
            String state,
            String nonce,
            String x509CertPem,
            String x509SigningKeyJwk,
            String existingEncryptionKeyJson) {
        return buildSignedRequestObject(config, clientId, clientIdScheme, responseUri, state, nonce, x509CertPem, x509SigningKeyJwk, existingEncryptionKeyJson, 600);
    }

    /**
     * Build a signed request object JWT for the redirect flow.
     *
     * @param config Configuration containing signing key, DCQL query, etc.
     * @param clientId Base client_id
     * @param clientIdScheme Client ID scheme (plain, x509_san_dns, x509_hash)
     * @param responseUri Where wallet should POST the response
     * @param state OAuth state parameter
     * @param nonce Nonce for verification
     * @param x509CertPem PEM certificate for x509 schemes (may be null)
     * @param x509SigningKeyJwk JWK with private key for signing (may be null)
     * @param existingEncryptionKeyJson Optional existing encryption key JWK (private key) to reuse.
     *                                   If provided, this key will be used instead of generating a new one.
     *                                   This is used when DC API is enabled to share the same encryption key.
     * @param lifespanSeconds Lifetime of the request object JWT in seconds
     * @return Signed request object with encryption key
     */
    public SignedRequestObject buildSignedRequestObject(
            Oid4vpConfig config,
            String clientId,
            String clientIdScheme,
            String responseUri,
            String state,
            String nonce,
            String x509CertPem,
            String x509SigningKeyJwk,
            String existingEncryptionKeyJson,
            int lifespanSeconds) {

        // Use the clientId directly - the caller is responsible for providing the correct client_id
        // (including any scheme prefix like x509_san_dns:hostname for x509 schemes)
        String effectiveClientId = clientId;

        // If x509 signing key is provided, use it; otherwise fall back to Keycloak key
        KeyWrapper signingKey = null;
        ECKey ecSigningKey = null;
        boolean useNimbusSigning = false;
        if (x509SigningKeyJwk != null && !x509SigningKeyJwk.isBlank()) {
            try {
                LOG.infof("[OID4VP-REDIRECT-FLOW] Using x509 signing key from config");
                ecSigningKey = ECKey.parse(x509SigningKeyJwk);
                LOG.infof("[OID4VP-REDIRECT-FLOW] Parsed ECKey: kid=%s, hasPrivate=%b, hasX5c=%b, curve=%s",
                        ecSigningKey.getKeyID(),
                        ecSigningKey.isPrivate(),
                        ecSigningKey.getX509CertChain() != null && !ecSigningKey.getX509CertChain().isEmpty(),
                        ecSigningKey.getCurve());
                // Use Nimbus directly for signing when using external key
                useNimbusSigning = true;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse x509 signing key JWK", e);
            }
        } else {
            signingKey = resolveSigningKey(config != null ? config.dcApiSigningKeyId() : null);
        }

        // Use existing encryption key if provided (e.g., when DC API is enabled, share the same key)
        // Otherwise generate a new one
        ECKey responseEncryptionKey;
        if (existingEncryptionKeyJson != null && !existingEncryptionKeyJson.isBlank()) {
            try {
                responseEncryptionKey = ECKey.parse(existingEncryptionKeyJson);
                LOG.infof("[OID4VP-REDIRECT-FLOW] Using existing encryption key (shared with DC API)");
            } catch (Exception e) {
                LOG.warnf("[OID4VP-REDIRECT-FLOW] Failed to parse existing encryption key, generating new one: %s", e.getMessage());
                responseEncryptionKey = createResponseEncryptionKey();
            }
        } else {
            responseEncryptionKey = createResponseEncryptionKey();
        }

        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = Instant.now().plusSeconds(lifespanSeconds).getEpochSecond();

        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", effectiveClientId);
        claims.put("aud", "https://self-issued.me/v2");
        claims.put("client_id", effectiveClientId);
        // Note: client_id_scheme was removed in OID4VP ID3/Final spec
        // The scheme is now determined by the client_id prefix (e.g., x509_san_dns:...)
        claims.put("response_type", "vp_token");
        claims.put("response_mode", "direct_post.jwt");
        claims.put("response_uri", responseUri);
        claims.put("nonce", nonce);
        claims.put("state", state);
        // client_metadata with encryption key for response encryption
        Object clientMeta = buildClientMetadata(responseEncryptionKey);
        if (clientMeta != null && !((java.util.Map<?,?>)clientMeta).isEmpty()) {
            claims.put("client_metadata", clientMeta);
        }

        if (config != null) {
            String dcqlQuery = config.dcqlQuery();
            if (dcqlQuery != null && !dcqlQuery.isBlank()) {
                claims.put("dcql_query", parseJsonClaim(dcqlQuery));
            }

            String verifierInfo = config.verifierInfo();
            if (verifierInfo != null && !verifierInfo.isBlank()) {
                Object parsedVerifierInfo = parseJsonClaim(verifierInfo);
                if (parsedVerifierInfo != null) {
                    claims.put("verifier_info", parsedVerifierInfo);
                }
            }
        }

        try {
            String jwt;

            if (useNimbusSigning && ecSigningKey != null) {
                // Use Nimbus JOSE directly for signing with external x509 key
                LOG.infof("[OID4VP-REDIRECT-FLOW] Using Nimbus signing with ECKey");
                jwt = signWithNimbus(ecSigningKey, claims);
            } else {
                // Fall back to Keycloak's JWSBuilder
                JWSBuilder builder = new JWSBuilder()
                        .type(REQUEST_OBJECT_TYP)
                        .kid(signingKey.getKid());

                // Add x5c for x509 schemes
                // Prefer the certificate from the signing key (which matches the private key)
                // over the separate PEM certificate
                if (signingKey.getCertificateChain() != null && !signingKey.getCertificateChain().isEmpty()) {
                    LOG.infof("[OID4VP-REDIRECT-FLOW] Using x5c from signingKey certificate chain (size=%d)",
                            signingKey.getCertificateChain().size());
                    builder = builder.x5c(signingKey.getCertificateChain());
                } else if (("x509_san_dns".equals(clientIdScheme) || "x509_hash".equals(clientIdScheme))
                        && x509CertPem != null && !x509CertPem.isBlank()) {
                    LOG.infof("[OID4VP-REDIRECT-FLOW] Using x5c from PEM certificate");
                    X509Certificate cert = parsePemCertificate(x509CertPem);
                    builder = builder.x5c(List.of(cert));
                } else if (signingKey.getPublicKey() != null) {
                    LOG.infof("[OID4VP-REDIRECT-FLOW] Using jwk from signingKey public key");
                    builder = builder.jwk(toPublicJwk(signingKey));
                }

                jwt = builder
                        .jsonContent(claims)
                        .sign(new AsymmetricSignatureSignerContext(signingKey));
            }

            // Log JWT header for debugging
            String[] parts = jwt.split("\\.");
            if (parts.length >= 1) {
                String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]), java.nio.charset.StandardCharsets.UTF_8);
                LOG.infof("[OID4VP-REDIRECT-FLOW] JWT header: %s", headerJson);
            }

            return new SignedRequestObject(jwt, responseEncryptionKey.toJSONString(), state, nonce);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign request object for redirect flow", e);
        }
    }

    /**
     * Rebuild a request object with wallet_nonce for spec-compliant request_uri POST handling.
     * Per OID4VP spec, when wallet POSTs to request_uri with wallet_nonce, the verifier
     * MUST return a new request object that includes the wallet_nonce claim.
     *
     * @param rebuildParams Parameters from the original request object
     * @param state OAuth state parameter
     * @param nonce Original nonce for verification
     * @param walletNonce The wallet_nonce to include in the new request object
     * @return New signed request object containing wallet_nonce
     */
    public SignedRequestObject rebuildWithWalletNonce(
            Oid4vpRequestObjectStore.RebuildParams rebuildParams,
            String state,
            String nonce,
            String walletNonce,
            int lifespanSeconds) {

        if (rebuildParams == null) {
            throw new IllegalArgumentException("rebuildParams is required");
        }
        if (walletNonce == null || walletNonce.isBlank()) {
            throw new IllegalArgumentException("walletNonce is required");
        }

        String effectiveClientId = rebuildParams.effectiveClientId();
        String clientIdScheme = rebuildParams.clientIdScheme();
        String responseUri = rebuildParams.responseUri();
        String dcqlQuery = rebuildParams.dcqlQuery();
        String x509CertPem = rebuildParams.x509CertPem();
        String x509SigningKeyJwk = rebuildParams.x509SigningKeyJwk();
        String encryptionPublicKeyJson = rebuildParams.encryptionPublicKeyJson();
        String verifierInfo = rebuildParams.verifierInfo();

        LOG.infof("[OID4VP-REDIRECT-FLOW] Rebuilding request object with wallet_nonce: %s", walletNonce);

        // Parse the encryption key to include in client_metadata
        ECKey encryptionKey = null;
        if (encryptionPublicKeyJson != null && !encryptionPublicKeyJson.isBlank()) {
            try {
                encryptionKey = ECKey.parse(encryptionPublicKeyJson);
            } catch (Exception e) {
                LOG.warnf("[OID4VP-REDIRECT-FLOW] Failed to parse encryption key: %s", e.getMessage());
            }
        }

        // Determine signing key
        KeyWrapper signingKey = null;
        ECKey ecSigningKey = null;
        boolean useNimbusSigning = false;
        if (x509SigningKeyJwk != null && !x509SigningKeyJwk.isBlank()) {
            try {
                ecSigningKey = ECKey.parse(x509SigningKeyJwk);
                useNimbusSigning = true;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse x509 signing key JWK", e);
            }
        } else {
            signingKey = resolveSigningKey(null);
        }

        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = Instant.now().plusSeconds(lifespanSeconds).getEpochSecond();

        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", effectiveClientId);
        claims.put("aud", "https://self-issued.me/v2");
        claims.put("client_id", effectiveClientId);
        claims.put("response_type", "vp_token");
        claims.put("response_mode", "direct_post.jwt");
        claims.put("response_uri", responseUri);
        claims.put("nonce", nonce);
        claims.put("state", state);
        // Include the wallet_nonce per OID4VP spec
        claims.put("wallet_nonce", walletNonce);

        // client_metadata with encryption key
        if (encryptionKey != null) {
            Object clientMeta = buildClientMetadata(encryptionKey);
            if (clientMeta != null && !((Map<?,?>)clientMeta).isEmpty()) {
                claims.put("client_metadata", clientMeta);
            }
        }

        // DCQL query
        if (dcqlQuery != null && !dcqlQuery.isBlank()) {
            claims.put("dcql_query", parseJsonClaim(dcqlQuery));
        }

        if (verifierInfo != null && !verifierInfo.isBlank()) {
            Object parsedVerifierInfo = parseJsonClaim(verifierInfo);
            if (parsedVerifierInfo != null) {
                claims.put("verifier_info", parsedVerifierInfo);
            }
        }

        try {
            String jwt;

            if (useNimbusSigning && ecSigningKey != null) {
                jwt = signWithNimbus(ecSigningKey, claims);
            } else {
                JWSBuilder builder = new JWSBuilder()
                        .type(REQUEST_OBJECT_TYP)
                        .kid(signingKey.getKid());

                if (signingKey.getCertificateChain() != null && !signingKey.getCertificateChain().isEmpty()) {
                    builder = builder.x5c(signingKey.getCertificateChain());
                } else if (("x509_san_dns".equals(clientIdScheme) || "x509_hash".equals(clientIdScheme))
                        && x509CertPem != null && !x509CertPem.isBlank()) {
                    X509Certificate cert = parsePemCertificate(x509CertPem);
                    builder = builder.x5c(List.of(cert));
                } else if (signingKey.getPublicKey() != null) {
                    builder = builder.jwk(toPublicJwk(signingKey));
                }

                jwt = builder
                        .jsonContent(claims)
                        .sign(new AsymmetricSignatureSignerContext(signingKey));
            }

            LOG.infof("[OID4VP-REDIRECT-FLOW] Rebuilt request object with wallet_nonce, JWT length: %d", jwt.length());
            // Note: encryptionKeyJson not returned here as it was already stored
            return new SignedRequestObject(jwt, null, state, nonce);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign rebuilt request object", e);
        }
    }

    /**
     * Sign a JWT using Nimbus JOSE library directly with an ECKey.
     * This is used when an external x509 signing key is provided.
     */
    private String signWithNimbus(ECKey ecSigningKey, LinkedHashMap<String, Object> claims) throws Exception {
        // Build JWS header with x5c if available
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(REQUEST_OBJECT_TYP))
                .keyID(ecSigningKey.getKeyID());

        // Add x5c from the ECKey if present
        if (ecSigningKey.getX509CertChain() != null && !ecSigningKey.getX509CertChain().isEmpty()) {
            LOG.infof("[OID4VP-REDIRECT-FLOW] Nimbus signing: adding x5c with %d certificates",
                    ecSigningKey.getX509CertChain().size());
            headerBuilder.x509CertChain(ecSigningKey.getX509CertChain());
        }

        JWSHeader header = headerBuilder.build();

        // Build JWT claims
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (var entry : claims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        // Create and sign the JWT
        SignedJWT signedJwt = new SignedJWT(header, claimsSet);
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        signedJwt.sign(signer);

        String jwt = signedJwt.serialize();
        LOG.infof("[OID4VP-REDIRECT-FLOW] Nimbus signing complete, JWT length: %d", jwt.length());

        return jwt;
    }

    /**
     * Build the effective client_id based on the scheme.
     */
    private String buildEffectiveClientId(String baseClientId, String clientIdScheme) {
        if (clientIdScheme == null || "plain".equalsIgnoreCase(clientIdScheme)) {
            return baseClientId;
        }
        // For x509_san_dns and x509_hash, the client_id is prefixed
        // The actual value would need to be derived from the certificate
        // For now, we just prefix the base client_id
        if ("x509_san_dns".equalsIgnoreCase(clientIdScheme)) {
            return "x509_san_dns:" + baseClientId;
        }
        if ("x509_hash".equalsIgnoreCase(clientIdScheme)) {
            return "x509_hash:" + baseClientId;
        }
        return baseClientId;
    }

    /**
     * Compute x509_san_dns client_id from a PEM certificate.
     */
    public String computeX509SanDnsClientId(String pemCertificate) {
        try {
            X509Certificate cert = parsePemCertificate(pemCertificate);
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        // DNS SAN (type 2)
                        return "x509_san_dns:" + san.get(1);
                    }
                }
            }
            throw new IllegalStateException("No DNS SAN found in certificate");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract DNS SAN from certificate", e);
        }
    }

    /**
     * Compute x509_hash client_id from a PEM certificate.
     */
    public String computeX509HashClientId(String pemCertificate) {
        try {
            X509Certificate cert = parsePemCertificate(pemCertificate);
            byte[] encoded = cert.getEncoded();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encoded);
            String hashBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return "x509_hash:" + hashBase64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute certificate hash", e);
        }
    }

    private X509Certificate parsePemCertificate(String pem) throws Exception {
        String base64 = extractBase64FromPem(pem);
        byte[] decoded = Base64.getDecoder().decode(base64);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    private String extractBase64FromPem(String pem) {
        return pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }

    private Object parseJsonClaim(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            return json;
        }
    }

    private KeyWrapper resolveSigningKey(String preferredKid) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalStateException("Missing realm context");
        }
        if (preferredKid != null && !preferredKid.isBlank()) {
            return session.keys()
                    .getKeysStream(realm)
                    .filter(key -> preferredKid.equals(key.getKid()))
                    .filter(key -> KeyUse.SIG.equals(key.getUse()))
                    .filter(key -> key.getPrivateKey() != null)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Signing key not found: kid=" + preferredKid));
        }
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, realm.getDefaultSignatureAlgorithm());
        if (key == null) {
            throw new IllegalStateException("No active realm signing key found");
        }
        return key;
    }

    /**
     * Create a Keycloak KeyWrapper from a Nimbus ECKey.
     */
    private KeyWrapper createKeyWrapperFromEcKey(ECKey ecKey) throws Exception {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(ecKey.getKeyID());
        keyWrapper.setAlgorithm("ES256");
        keyWrapper.setType("EC");
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setStatus(org.keycloak.crypto.KeyStatus.ACTIVE);
        keyWrapper.setPublicKey(ecKey.toECPublicKey());
        keyWrapper.setPrivateKey(ecKey.toECPrivateKey());

        // Set certificate chain if present
        if (ecKey.getX509CertChain() != null && !ecKey.getX509CertChain().isEmpty()) {
            List<X509Certificate> certs = ecKey.getX509CertChain().stream()
                    .map(b64 -> {
                        try {
                            byte[] decoded = b64.decode();
                            CertificateFactory factory = CertificateFactory.getInstance("X.509");
                            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded));
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to parse x5c certificate", e);
                        }
                    })
                    .toList();
            keyWrapper.setCertificateChain(certs);
        }

        return keyWrapper;
    }

    private JWK toPublicJwk(KeyWrapper key) {
        if (key == null || key.getPublicKey() == null) {
            throw new IllegalArgumentException("Missing public key");
        }
        String algorithm = key.getAlgorithmOrDefault();
        JWKBuilder builder = JWKBuilder.create()
                .kid(key.getKid())
                .algorithm(algorithm);

        String publicAlgorithm = key.getPublicKey().getAlgorithm();
        if ("RSA".equalsIgnoreCase(publicAlgorithm)) {
            return builder.rsa(key.getPublicKey(), KeyUse.SIG);
        }
        if ("EC".equalsIgnoreCase(publicAlgorithm)) {
            return builder.ec(key.getPublicKey(), KeyUse.SIG);
        }
        throw new IllegalStateException("Unsupported signing key algorithm: " + publicAlgorithm);
    }

    /**
     * Create an EC key for ECDH-ES key agreement.
     * Per HAIP Section 5-2.5, ECDH-ES must be used for response encryption.
     */
    private ECKey createResponseEncryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    private Object buildClientMetadata(ECKey responseEncryptionKey) {
        var meta = new LinkedHashMap<String, Object>();
        if (responseEncryptionKey != null) {
            // Build the public key JWK with explicit alg field
            ECKey publicKey = responseEncryptionKey.toPublicJWK();
            Map<String, Object> jwk = new LinkedHashMap<>(publicKey.toJSONObject());
            // Ensure alg is present (conformance test requires it)
            jwk.put("alg", JWEAlgorithm.ECDH_ES.getName());
            // Add use=enc to indicate this is an encryption key
            jwk.put("use", "enc");
            Map<String, Object> jwks = new LinkedHashMap<>();
            jwks.put("keys", List.of(jwk));
            meta.put("jwks", jwks);

            // OID4VP 1.0: encrypted_response_enc_values_supported declares supported content encryption methods
            // HAIP Section 5-2.5: MUST support A128GCM and A256GCM
            // The key agreement algorithm (ECDH-ES) is conveyed via the JWK's "alg" field
            meta.put("encrypted_response_enc_values_supported", List.of(
                    EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()));

            // vp_formats_supported declares which credential formats the verifier can accept
            // Required per OID4VP 1.0 Section 11.1
            var vpFormats = new LinkedHashMap<String, Object>();
            vpFormats.put("dc+sd-jwt", Map.of("sd-jwt_alg_values", List.of("ES256"), "kb-jwt_alg_values", List.of("ES256")));
            vpFormats.put("mso_mdoc", Map.of("alg", List.of("ES256")));
            meta.put("vp_formats_supported", vpFormats);
        }
        return meta;
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Record containing a signed request object and associated data.
     */
    public record SignedRequestObject(
            String jwt,
            String encryptionKeyJson,
            String state,
            String nonce
    ) {}
}
