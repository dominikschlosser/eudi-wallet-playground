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
package de.arbeitsagentur.keycloak.oid4vp.idp;

import de.arbeitsagentur.keycloak.oid4vp.DefaultOid4vpValues;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpTrustListService;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import tools.jackson.databind.ObjectMapper;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Factory for creating OID4VP Identity Provider instances.
 */
public class Oid4vpIdentityProviderFactory extends AbstractIdentityProviderFactory<Oid4vpIdentityProvider> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderFactory.class);

    public static final String PROVIDER_ID = "oid4vp";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                // HAIP compliance mode toggle
                .property()
                    .name(Oid4vpIdentityProviderConfig.ENFORCE_HAIP)
                    .label("Enforce HAIP Compliance")
                    .helpText("Enable OpenID4VC High Assurance Interoperability Profile (HAIP) compliance. " +
                              "When enabled, overrides config values with HAIP-mandated settings: " +
                              "signed request objects (JAR), ES256 signing algorithm, encrypted responses required, " +
                              "and strict trust anchor verification.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                // Skip trust list verification (for local testing)
                .property()
                    .name(Oid4vpIdentityProviderConfig.SKIP_TRUST_LIST_VERIFICATION)
                    .label("Skip Trust List Verification")
                    .helpText("Skip trust list verification and auto-trust x5c certificates from credentials. " +
                              "Use only for local testing when the trust list server is unavailable. " +
                              "Overrides HAIP enforcement for trust list checks.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("false")
                    .add()
                // Credential set mode for multi-credential requests
                .property()
                    .name(Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE)
                    .label("Credential Set Mode")
                    .helpText("When multiple credential types are configured via mappers: 'optional' requires any one credential, 'all' requires all credentials.")
                    .type(ProviderConfigProperty.LIST_TYPE)
                    .defaultValue(Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE_OPTIONAL)
                    .options(List.of(
                        Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE_OPTIONAL,
                        Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE_ALL
                    ))
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.CREDENTIAL_SET_PURPOSE)
                    .label("Credential Set Purpose")
                    .helpText("Optional purpose description for the credential request (shown to user in wallet).")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                // DCQL query configuration
                .property()
                    .name(Oid4vpIdentityProviderConfig.DCQL_QUERY)
                    .label("DCQL Query (JSON)")
                    .helpText("DCQL query defining which credentials to request. " +
                              "Priority: (1) This explicit JSON query if set, (2) auto-generated from IdP mappers, (3) default empty query. " +
                              "Use explicit JSON for full control (e.g., credential_sets with multiple formats). " +
                              "Leave empty to auto-generate from mappers - each mapper adds claims for its credential type, " +
                              "multiple types create credential_sets based on 'Credential Set Mode'.")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.TRUST_LIST_URL)
                    .label("ETSI Trust List URL")
                    .helpText("URL to fetch ETSI TS 119 602 trust list JWT (e.g., https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt). Takes precedence over inline JWT.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.TRUST_LIST_JWT)
                    .label("Trust List (ETSI JWT)")
                    .helpText("ETSI TS 119 602 trust list in JWT format (compact serialization). Used if Trust List URL is not set.")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM)
                    .label("User Identifier Claim (SD-JWT)")
                    .helpText("Claim name used to identify the user from SD-JWT credentials (e.g., 'sub', 'personal_administrative_number'). " +
                              "When using credential_sets with both SD-JWT and mDoc, configure both claim fields.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue(DefaultOid4vpValues.DEFAULT_USER_MAPPING_CLAIM)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC)
                    .label("User Identifier Claim (mDoc)")
                    .helpText("Claim name used to identify the user from mDoc credentials (e.g., 'document_number'). " +
                              "mDoc credentials often use different claim names than SD-JWT. If not set, falls back to the SD-JWT claim name.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue(DefaultOid4vpValues.DEFAULT_USER_MAPPING_CLAIM_MDOC)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.DC_API_REQUEST_MODE)
                    .label("DC API Request Mode")
                    .helpText("Controls whether to use unsigned requests, signed request objects, or auto-detect.")
                    .type(ProviderConfigProperty.LIST_TYPE)
                    .defaultValue(DefaultOid4vpValues.DEFAULT_DC_API_REQUEST_MODE)
                    .options(List.of("auto", "unsigned", "signed"))
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.DC_API_CLIENT_ID)
                    .label("DC API Client ID")
                    .helpText("Optional: Override the client_id/iss for signed request objects. Defaults to realm base URL.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.DC_API_SIGNING_KEY_ID)
                    .label("DC API Signing Key ID")
                    .helpText("Optional: Specific realm signing key (kid) to use. Defaults to active realm signing key.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.ALLOWED_ISSUERS)
                    .label("Allowed Issuers")
                    .helpText("Comma-separated list of allowed credential issuers. Empty allows all issuers in trust list.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.ALLOWED_CREDENTIAL_TYPES)
                    .label("Allowed Credential Types")
                    .helpText("Comma-separated list of allowed credential types (vct/docType). Empty allows all types.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                // Flow enable/disable options
                .property()
                    .name(Oid4vpIdentityProviderConfig.DC_API_ENABLED)
                    .label("Enable DC API Flow")
                    .helpText("Enable Digital Credentials API flow (browser-based, requires supported browser/extension).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED)
                    .label("Enable Same-Device Flow")
                    .helpText("Enable same-device flow (redirect to wallet app on same device).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED)
                    .label("Enable Cross-Device Flow")
                    .helpText("Enable cross-device flow (QR code for scanning with phone).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                // Same-device flow configuration
                .property()
                    .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_WALLET_URL)
                    .label("Wallet URL (HTTPS)")
                    .helpText("HTTPS URL of the wallet's OID4VP authorization endpoint (e.g., https://example.com/wallet/oid4vp/auth). Required for same-device flow.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_WALLET_SCHEME)
                    .label("Wallet URL Scheme")
                    .helpText("Custom URL scheme for native wallet apps (e.g., openid4vp://, haip://). Leave empty to use HTTPS URL instead.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                // Client ID scheme for redirect flows
                .property()
                    .name(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME)
                    .label("Client ID Scheme")
                    .helpText("Scheme for client_id in redirect flows: plain (just client_id), x509_san_dns (DNS from cert SAN), x509_hash (cert hash).")
                    .type(ProviderConfigProperty.LIST_TYPE)
                    .defaultValue("plain")
                    .options(List.of("plain", "x509_san_dns", "x509_hash"))
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM)
                    .label("X.509 Certificate (PEM)")
                    .helpText("PEM-encoded X.509 certificate chain for x509_san_dns or x509_hash client ID schemes. " +
                              "May also include a PRIVATE KEY block — if present, the signing key JWK is auto-generated.")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_FILE)
                    .label("X.509 Certificate File Path")
                    .helpText("Alternative: path to a combined PEM file (cert chain + private key) on disk. " +
                              "Takes precedence over inline PEM. Useful when secrets are mounted via Kubernetes.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                // Verifier info for EUDI Wallet registration certificates
                .property()
                    .name(Oid4vpIdentityProviderConfig.VERIFIER_INFO_FILE)
                    .label("Verifier Info File")
                    .helpText("Path to JSON file containing verifier attestations. Takes precedence over inline JSON.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(Oid4vpIdentityProviderConfig.VERIFIER_INFO)
                    .label("Verifier Info (JSON)")
                    .helpText("Optional: JSON array of verifier attestations (e.g., registration certificates for EUDI Wallet). Format: [{\"format\": \"registration_cert\", \"data\": \"<JWT>\"}]")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "OID4VP (Wallet Login)";
    }

    @Override
    public Oid4vpIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig(model);
        ObjectMapper objectMapper = new ObjectMapper();

        // Resolve x509 from file if configured
        resolveX509FromFile(config);

        // Resolve verifier info from file if configured (file takes precedence over inline)
        resolveVerifierInfoFromFile(config);

        // Create trust list service: URL takes precedence over inline JWT
        String trustListJwt = resolveTrustListJwt(session, config);
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(trustListJwt);

        // Register additional trusted certificates from config
        String additionalCerts = config.getAdditionalTrustedCertificates();
        if (additionalCerts != null && !additionalCerts.isBlank()) {
            String trustListId = config.getTrustListId();
            registerAdditionalCertificates(trustListService, trustListId, additionalCerts);
        }

        return new Oid4vpIdentityProvider(session, config, objectMapper, trustListService);
    }

    public static String resolveTrustListJwt(KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        String trustListUrl = config.getTrustListUrl();
        if (trustListUrl != null && !trustListUrl.isBlank()) {
            try {
                String jwtContent = SimpleHttp.doGet(trustListUrl, session).asString();
                LOG.infof("[OID4VP-FACTORY] Fetched ETSI trust list from %s (%d chars, preview: %s)",
                        trustListUrl, jwtContent.length(),
                        jwtContent.substring(0, Math.min(100, jwtContent.length())));
                return jwtContent.trim();
            } catch (Exception e) {
                LOG.warnf("[OID4VP-FACTORY] Failed to fetch ETSI trust list from %s: %s, falling back to inline JWT",
                        trustListUrl, e.getMessage());
            }
        }
        String inlineJwt = config.getTrustListJwt();
        LOG.infof("[OID4VP-FACTORY] Using inline trust list JWT: %s",
                inlineJwt != null ? "present (" + inlineJwt.length() + " chars, preview: " +
                        inlineJwt.substring(0, Math.min(100, inlineJwt.length())) + ")" : "null");
        return inlineJwt;
    }

    /**
     * Resolve x509 certificate and signing key from either:
     * 1. x509CertificateFile (combined PEM file on disk)
     * 2. x509CertificatePem (inline combined PEM containing both cert chain and private key)
     *
     * If the PEM (from either source) contains a PRIVATE KEY block, an ECKey JWK is built
     * with the x5c certificate chain and set on the config. This makes the config self-contained
     * for signing request objects with x509_san_dns or x509_hash client ID schemes.
     */
    public static void resolveX509FromFile(Oid4vpIdentityProviderConfig config) {
        // Already have a signing key JWK? Nothing to do.
        String existingJwk = config.getX509SigningKeyJwk();
        if (existingJwk != null && !existingJwk.isBlank()) {
            return;
        }

        String pem = null;
        String source = null;

        // Priority 1: Load from file
        String x509File = config.getX509CertificateFile();
        if (x509File != null && !x509File.isBlank()) {
            Path filePath = Path.of(x509File);
            if (Files.exists(filePath)) {
                try {
                    pem = Files.readString(filePath);
                    source = "file " + x509File;
                } catch (Exception e) {
                    LOG.warnf("Failed to read x509CertificateFile %s: %s", x509File, e.getMessage());
                }
            } else {
                LOG.warnf("x509CertificateFile not found: %s", x509File);
            }
        }

        // Priority 2: Check inline PEM for private key
        if (pem == null) {
            String inlinePem = config.getX509CertificatePem();
            if (inlinePem != null && inlinePem.contains("-----BEGIN PRIVATE KEY-----")) {
                pem = inlinePem;
                source = "inline x509CertificatePem";
            }
        }

        if (pem == null) {
            return;
        }

        try {
            // Extract certificate chain
            List<X509Certificate> certChain = parseCertificateChain(pem);
            if (certChain.isEmpty()) {
                LOG.warnf("No certificates found in %s", source);
                return;
            }

            // Set cert-only PEM (strip private key for the cert field)
            List<String> certPemBlocks = extractPemBlocks(pem, "CERTIFICATE");
            config.setX509CertificatePem(String.join("\n", certPemBlocks));

            // Extract and parse private key
            String privBody = extractPemBlockBody(pem, "PRIVATE KEY");
            if (privBody == null) {
                LOG.infof("No private key in %s (cert-only mode)", source);
                return;
            }

            byte[] privBytes = Base64.getDecoder().decode(privBody);
            PrivateKey privateKey = parsePrivateKey(privBytes);

            // Build ECKey JWK with x5c chain
            X509Certificate leafCert = certChain.get(0);
            if (!(leafCert.getPublicKey() instanceof ECPublicKey ecPub)) {
                LOG.warnf("Leaf certificate is not EC (got %s), cannot build signing key JWK",
                        leafCert.getPublicKey().getAlgorithm());
                return;
            }

            Curve curve = Curve.forECParameterSpec(ecPub.getParams());
            List<com.nimbusds.jose.util.Base64> x5c = new ArrayList<>();
            for (X509Certificate cert : certChain) {
                x5c.add(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()));
            }

            ECKey ecKey = new ECKey.Builder(curve, ecPub)
                    .privateKey((ECPrivateKey) privateKey)
                    .x509CertChain(x5c)
                    .keyIDFromThumbprint()
                    .build();

            config.setX509SigningKeyJwk(ecKey.toJSONString());
            LOG.infof("Resolved x509 signing key from %s (chain size=%d, kid=%s)",
                    source, certChain.size(), ecKey.getKeyID());

        } catch (Exception e) {
            LOG.errorf(e, "Failed to resolve x509 from %s", source);
        }
    }

    public static void resolveVerifierInfoFromFile(Oid4vpIdentityProviderConfig config) {
        String file = config.getVerifierInfoFile();
        if (file == null || file.isBlank()) {
            return;
        }
        Path filePath = Path.of(file);
        if (!Files.exists(filePath)) {
            LOG.warnf("verifierInfoFile not found: %s", file);
            return;
        }
        try {
            String json = Files.readString(filePath).trim();
            config.setVerifierInfo(json);
            LOG.infof("Loaded verifier info from file %s (%d chars)", file, json.length());
        } catch (Exception e) {
            LOG.warnf("Failed to read verifierInfoFile %s: %s", file, e.getMessage());
        }
    }

    private static List<X509Certificate> parseCertificateChain(String pem) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        int idx = 0;
        while (true) {
            int start = pem.indexOf("-----BEGIN CERTIFICATE-----", idx);
            if (start < 0) break;
            int end = pem.indexOf("-----END CERTIFICATE-----", start);
            if (end < 0) break;
            String body = pem.substring(start + "-----BEGIN CERTIFICATE-----".length(), end)
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(body);
            chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
            idx = end + "-----END CERTIFICATE-----".length();
        }
        return chain;
    }

    private static List<String> extractPemBlocks(String pem, String type) {
        List<String> blocks = new ArrayList<>();
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int idx = 0;
        while (true) {
            int start = pem.indexOf(begin, idx);
            if (start < 0) break;
            int stop = pem.indexOf(end, start);
            if (stop < 0) break;
            blocks.add(pem.substring(start, stop + end.length()));
            idx = stop + end.length();
        }
        return blocks;
    }

    private static String extractPemBlockBody(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start < 0 || stop < 0) return null;
        return pem.substring(start + begin.length(), stop).replaceAll("\\s+", "");
    }

    private static PrivateKey parsePrivateKey(byte[] pkcs8Bytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        for (String alg : List.of("EC", "RSA")) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (Exception ignored) {
            }
        }
        throw new IllegalStateException("Unsupported private key algorithm (tried EC, RSA)");
    }

    private void registerAdditionalCertificates(Oid4vpTrustListService trustListService,
                                                 String trustListId, String additionalCerts) {
        // Parse PEM certificates from the config and register them
        // Format: multiple PEM certificates concatenated (-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----)
        String[] parts = additionalCerts.split("(?=-----BEGIN CERTIFICATE-----)");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith("-----BEGIN CERTIFICATE-----") && trimmed.contains("-----END CERTIFICATE-----")) {
                try {
                    trustListService.registerCertificate(trustListId, trimmed);
                } catch (Exception e) {
                    // Log but don't fail - invalid certs should be ignored
                    LOG.warnf("Failed to register additional trusted certificate: %s", e.getMessage());
                }
            }
        }
    }

    @Override
    public Oid4vpIdentityProviderConfig createConfig() {
        return new Oid4vpIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
