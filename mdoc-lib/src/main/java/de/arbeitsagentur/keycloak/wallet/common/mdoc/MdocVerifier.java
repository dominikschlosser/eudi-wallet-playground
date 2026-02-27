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
package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import COSE.OneKey;
import COSE.CoseException;
import COSE.Message;
import COSE.MessageTag;
import COSE.Sign1Message;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import de.arbeitsagentur.keycloak.wallet.common.credential.StatusListVerifier;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import de.arbeitsagentur.keycloak.wallet.common.credential.VerificationStepSink;
import de.arbeitsagentur.keycloak.wallet.mdoc.util.HexUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifies mDoc credentials (CBOR/COSE) including issuer signature, digest integrity and optional holder binding.
 */
public class MdocVerifier {
    private static final Logger LOG = LoggerFactory.getLogger(MdocVerifier.class);
    private static final int COSE_HEADER_PARAM_X5CHAIN = 33;
    private static final CBOREncodeOptions ENCODE_OPTIONS = CBOREncodeOptions.Default;
    private final MdocParser parser = new MdocParser();
    private final TrustedIssuerResolver trustResolver;
    private final StatusListVerifier statusListVerifier;

    public MdocVerifier(TrustedIssuerResolver trustResolver) {
        this(trustResolver, new StatusListVerifier());
    }

    public MdocVerifier(TrustedIssuerResolver trustResolver, StatusListVerifier statusListVerifier) {
        this.trustResolver = trustResolver;
        this.statusListVerifier = statusListVerifier;
    }

    public boolean isMdoc(String token) {
        return parser.isMdoc(token);
    }

    public Map<String, Object> verify(String deviceResponseToken,
                                      String trustListId,
                                      String expectedClientId,
                                      String expectedNonce,
                                      String expectedResponseUri,
                                      byte[] expectedJwkThumbprint,
                                      VerificationStepSink steps) {
        return verify(deviceResponseToken, trustListId, expectedClientId, expectedNonce,
                expectedResponseUri, expectedJwkThumbprint, null, steps);
    }

    public Map<String, Object> verify(String deviceResponseToken,
                                      String trustListId,
                                      String expectedClientId,
                                      String expectedNonce,
                                      String expectedResponseUri,
                                      byte[] expectedJwkThumbprint,
                                      String mdocGeneratedNonce,
                                      VerificationStepSink steps) {
        LOG.debug("verify() called with: expectedClientId={}, expectedNonce={}, expectedResponseUri={}, expectedJwkThumbprint={}, mdocGeneratedNonce={}",
                expectedClientId, expectedNonce, expectedResponseUri,
                expectedJwkThumbprint != null ? Base64.getUrlEncoder().withoutPadding().encodeToString(expectedJwkThumbprint) : "null",
                mdocGeneratedNonce);
        try {
            CBORObject root = decodeToken(deviceResponseToken);
            CBORObject document = firstDocument(root);
            CBORObject issuerSigned = asMap(document.get("issuerSigned"));
            CBORObject nameSpaces = issuerSigned != null ? asMap(issuerSigned.get("nameSpaces")) : null;
            Map<String, Object> claims = new LinkedHashMap<>();
            if (nameSpaces != null) {
                claims.putAll(extractClaims(nameSpaces));
            }
            String docType = extractDocType(root, document);

            Sign1Message sign1 = decodeSign1(issuerSigned != null ? issuerSigned.get("issuerAuth") : null);
            verifySignature(sign1, trustListId, steps);

            CBORObject mso = decodeMso(sign1.GetContent());
            verifyDigests(mso, issuerSigned);
            if (steps != null) {
                steps.add("Digest values validated",
                        "Validated mDoc valueDigests against issuerSigned nameSpaces.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            }
            validateValidity(mso.get("validityInfo"));
            if (steps != null) {
                steps.add("Credential timing rules validated",
                        "Checked validityInfo timestamps to ensure credential is currently valid.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            }
            checkMsoRevocationStatus(mso, steps);

            verifyDeviceAuth(document, mso, docType, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, mdocGeneratedNonce);
            if (steps != null) {
                steps.add("Validated holder binding (mdoc deviceAuth)",
                        "Validated deviceAuth signature and OpenID4VP SessionTranscript binding for the mDoc presentation.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6");
            }
            if (docType != null && !claims.containsKey("docType")) {
                claims.put("docType", docType);
            }
            return claims;
        } catch (Exception e) {
            LOG.info("mDoc verification failed: {}", e.getMessage());
            LOG.debug("mDoc verification stack trace:", e);
            throw new IllegalStateException("Credential signature not trusted", e);
        }
    }

    private Sign1Message decodeSign1(CBORObject value) throws Exception {
        if (value == null) {
            throw new IllegalStateException("Missing issuerAuth in DeviceResponse");
        }
        byte[] encoded;
        if (value.getType() == CBORType.ByteString) {
            encoded = value.GetByteString();
        } else {
            encoded = value.EncodeToBytes(ENCODE_OPTIONS);
        }
        if (encoded == null || encoded.length == 0) {
            throw new IllegalStateException("Invalid issuerAuth in DeviceResponse");
        }
        try {
            return (Sign1Message) Sign1Message.DecodeFromBytes(encoded);
        } catch (CoseException e) {
            return (Sign1Message) Message.DecodeFromBytes(encoded, MessageTag.Sign1);
        }
    }

    private Map<String, Object> extractClaims(CBORObject nameSpaces) {
        Map<String, Object> claims = new LinkedHashMap<>();
        for (CBORObject nsKey : nameSpaces.getKeys()) {
            CBORObject elements = nameSpaces.get(nsKey);
            if (elements == null || elements.getType() != CBORType.Array) {
                continue;
            }
            for (int i = 0; i < elements.size(); i++) {
                CBORObject decoded = decodeIssuerItem(elements.get(i));
                if (decoded == null) {
                    continue;
                }
                CBORObject id = decoded.get("elementIdentifier");
                CBORObject value = decoded.get("elementValue");
                if (id != null && value != null) {
                    claims.put(id.AsString(), convertToJava(value));
                }
            }
        }
        return claims;
    }

    private void verifySignature(Sign1Message sign1, String trustListId, VerificationStepSink steps) throws Exception {
        if (trustResolver.isAllowAll(trustListId)) {
            LOG.debug("Trust list is 'allow-all', skipping signature verification");
            if (steps != null) {
                steps.add("Signature verification skipped (allow-all trust list)",
                        "Trust list set to allow-all; credential signature was not checked.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            }
            return;
        }
        List<PublicKey> keys = trustResolver.publicKeys(trustListId);
        if (keys == null) {
            keys = List.of();
        }
        LOG.debug("verifySignature() checking {} trust list keys for trustListId: {}", keys.size(), trustListId);

        logX5ChainInfo(sign1);

        // Try x5c certificate chain validation (e.g. SPRIND trust lists)
        if (tryVerifyWithX5cChain(sign1, trustListId, steps)) {
            return;
        }

        // Fall back to direct key matching
        if (tryVerifyWithTrustListKeys(sign1, keys, steps)) {
            return;
        }

        throw new IllegalStateException("Credential signature not trusted");
    }

    private void logX5ChainInfo(Sign1Message sign1) {
        List<X509Certificate> x5chainCerts = x5ChainCertificates(sign1);
        if (x5chainCerts.isEmpty()) {
            return;
        }
        X509Certificate cert = x5chainCerts.get(0);
        logPublicKeyInfo(cert.getPublicKey(), "mDoc issuerAuth x5chain");
        logCertificateInfo(cert);
    }

    private void logPublicKeyInfo(PublicKey key, String label) {
        if (key instanceof ECPublicKey ecKey) {
            String x = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    toUnsignedBytes(ecKey.getW().getAffineX()));
            LOG.debug("[OID4VP-MDOC] {} public key x={}", label, x);
        }
    }

    private void logCertificateInfo(X509Certificate cert) {
        try {
            LOG.debug("[OID4VP-MDOC] mDoc issuerAuth x5chain subject: {}, issuer: {}",
                    cert.getSubjectX500Principal().getName(), cert.getIssuerX500Principal().getName());
        } catch (Exception e) {
            LOG.debug("[OID4VP-MDOC] Could not log x5chain certificate: {}", e.getMessage());
        }
    }

    private boolean tryVerifyWithX5cChain(Sign1Message sign1, String trustListId, VerificationStepSink steps) {
        List<X509Certificate> x5cChain = x5ChainCertificates(sign1);
        if (x5cChain.isEmpty()) {
            return false;
        }
        List<X509Certificate> trustAnchors = trustResolver.certificates(trustListId);
        if (trustAnchors.isEmpty()) {
            return false;
        }
        PublicKey leafKey = TrustedIssuerResolver.verifyX5cChain(x5cChain, trustAnchors);
        if (leafKey == null) {
            LOG.debug("x5c chain validation failed against trust list '{}'", trustListId);
            return false;
        }
        OneKey coseKey = OneKeyFromPublicKey.build(leafKey);
        if (coseKey == null) {
            return false;
        }
        try {
            boolean valid = sign1.validate(coseKey);
            if (valid) {
                LOG.debug("Verified mDoc signature via x5c chain validation against trust list '{}'", trustListId);
                if (steps != null) {
                    steps.add("Signature verified via x5c chain against trust list",
                            "Validated mDoc issuerAuth x5c certificate chain against trusted CA certificates, then verified signature with leaf key.",
                            "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
                }
            }
            return valid;
        } catch (Exception e) {
            LOG.debug("x5c chain signature validation exception: {}", e.getMessage());
            return false;
        }
    }

    private boolean tryVerifyWithTrustListKeys(Sign1Message sign1, List<PublicKey> keys, VerificationStepSink steps) {
        for (int i = 0; i < keys.size(); i++) {
            PublicKey key = keys.get(i);
            logPublicKeyInfo(key, "Trust list key[" + i + "]");

            OneKey coseKey = OneKeyFromPublicKey.build(key);
            if (coseKey == null) {
                LOG.debug("Trust list key[{}] could not be converted to OneKey", i);
                continue;
            }

            if (tryValidateSignature(sign1, coseKey, i, steps)) {
                return true;
            }
        }
        return false;
    }

    private boolean tryValidateSignature(Sign1Message sign1, OneKey coseKey, int keyIndex, VerificationStepSink steps) {
        try {
            boolean valid = sign1.validate(coseKey);
            LOG.debug("Trust list key[{}] validation result: {}", keyIndex, valid);
            if (valid && steps != null) {
                steps.add("Signature verified against trust list",
                        "Checked mDoc issuerAuth signature against trusted issuers in the trust list.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            }
            return valid;
        } catch (Exception e) {
            LOG.debug("Trust list key[{}] validation exception: {}", keyIndex, e.getMessage());
            return false;
        }
    }

    private List<X509Certificate> x5ChainCertificates(Sign1Message sign1) {
        if (sign1 == null) {
            return List.of();
        }
        CBORObject x5chain = sign1.findAttribute(CBORObject.FromObject(COSE_HEADER_PARAM_X5CHAIN));
        if (x5chain == null) {
            return List.of();
        }
        List<byte[]> certBytes = new ArrayList<>();
        if (x5chain.getType() == CBORType.ByteString) {
            certBytes.add(x5chain.GetByteString());
        } else if (x5chain.getType() == CBORType.Array) {
            for (int i = 0; i < x5chain.size(); i++) {
                CBORObject entry = x5chain.get(i);
                if (entry != null && entry.getType() == CBORType.ByteString) {
                    certBytes.add(entry.GetByteString());
                }
            }
        }
        if (certBytes.isEmpty()) {
            return List.of();
        }
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            return List.of();
        }
        List<X509Certificate> certs = new ArrayList<>();
        for (byte[] der : certBytes) {
            if (der == null || der.length == 0) {
                continue;
            }
            try {
                X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
                if (certificate != null) {
                    certs.add(certificate);
                }
            } catch (Exception ignored) {
            }
        }
        return List.copyOf(certs);
    }

    private List<PublicKey> x5ChainPublicKeys(Sign1Message sign1) {
        return x5ChainCertificates(sign1).stream()
                .map(X509Certificate::getPublicKey)
                .filter(k -> k != null)
                .toList();
    }

    private String toPemCertificate(X509Certificate certificate) throws Exception {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        String base64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append("\n");
        }
        pem.append("-----END CERTIFICATE-----");
        return pem.toString();
    }

    private CBORObject decodeToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("Invalid mDoc payload");
        }
        try {
            if (parser.isHex(token)) {
                return CBORObject.DecodeFromBytes(HexUtils.decode(token));
            }
            return CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(token));
        } catch (IllegalArgumentException e) {
            try {
                return CBORObject.DecodeFromBytes(Base64.getDecoder().decode(token));
            } catch (IllegalArgumentException ex) {
                throw new IllegalStateException("Invalid mDoc payload", ex);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Invalid mDoc payload", e);
        }
    }

    /**
     * Verifies the deviceAuth signature using dual-format SessionTranscript support.
     * <p>
     * When {@code mdocGeneratedNonce} is present (extracted from JWE {@code apu} header),
     * tries ISO 18013-7 Annex B.4.4 format first, then falls back to OID4VP 1.0.
     * When absent, uses OID4VP 1.0 format only.
     *
     * @see SessionTranscriptBuilder
     */
    private void verifyDeviceAuth(CBORObject document,
                                  CBORObject mso,
                                  String docType,
                                  String expectedClientId,
                                  String expectedNonce,
                                  String expectedResponseUri,
                                  byte[] expectedJwkThumbprint,
                                  String mdocGeneratedNonce) throws Exception {
        // Extract and validate deviceSigned structure
        CBORObject deviceSigned = asMap(document.get("deviceSigned"));
        if (deviceSigned == null) {
            throw new IllegalStateException("Missing deviceSigned in DeviceResponse");
        }

        // Extract device signature and key
        Sign1Message sign1 = extractDeviceSignature(deviceSigned);
        OneKey coseKey = extractAndValidateDeviceKey(mso);

        // Try ISO 18013-7 format first (used by German EUDI wallet), then OID4VP 1.0 format
        CBORObject expectedTranscript;
        if (mdocGeneratedNonce != null && !mdocGeneratedNonce.isBlank()) {
            expectedTranscript = buildSessionTranscriptIso18013_7(expectedClientId, expectedNonce, expectedResponseUri, mdocGeneratedNonce);
        } else {
            expectedTranscript = buildSessionTranscript(expectedClientId, expectedNonce, expectedJwkThumbprint, expectedResponseUri);
        }
        byte[] effectivePayloadBytes = ensurePayloadContent(sign1, expectedTranscript, docType, deviceSigned);

        // Verify signature
        boolean deviceAuthValid = false;
        try {
            deviceAuthValid = coseKey != null && sign1.validate(coseKey);
        } catch (Exception valEx) {
            LOG.debug("[OID4VP-MDOC] deviceAuth validate() threw: {} - {}", valEx.getClass().getSimpleName(), valEx.getMessage());
        }

        // If primary format fails, try the alternative format
        if (!deviceAuthValid && mdocGeneratedNonce != null && !mdocGeneratedNonce.isBlank()) {
            // Primary was ISO 18013-7, try OID4VP 1.0 format as fallback
            LOG.debug("[OID4VP-MDOC] ISO 18013-7 format failed, trying OID4VP 1.0 format");
            try {
                CBORObject oid4vpTranscript = buildSessionTranscript(expectedClientId, expectedNonce, expectedJwkThumbprint, expectedResponseUri);
                byte[] oid4vpPayload = buildDeviceAuthenticationPayload(oid4vpTranscript, docType, deviceSigned.get("nameSpaces"));
                sign1.SetContent(oid4vpPayload);
                deviceAuthValid = sign1.validate(coseKey);
                if (deviceAuthValid) {
                    LOG.debug("deviceAuth verified with OID4VP 1.0 SessionTranscript format (fallback)");
                    effectivePayloadBytes = oid4vpPayload;
                    expectedTranscript = oid4vpTranscript;
                }
            } catch (Exception e) {
                LOG.debug("[OID4VP-MDOC] OID4VP 1.0 fallback failed: {}", e.getMessage());
            }
        } else if (!deviceAuthValid && (mdocGeneratedNonce == null || mdocGeneratedNonce.isBlank())) {
            // Primary was OID4VP 1.0, no ISO 18013-7 fallback possible without mdocGeneratedNonce
            LOG.debug("[OID4VP-MDOC] OID4VP 1.0 format failed, no mdoc_generated_nonce available for ISO 18013-7 fallback");
        }

        if (!deviceAuthValid) {
            LOG.debug("deviceAuth validation FAILED with all transcript formats. coseKey null={}", coseKey == null);
            throw new IllegalStateException("deviceAuth signature invalid");
        }

        // Validate payload contents
        validateDeviceAuthPayload(effectivePayloadBytes, docType, expectedTranscript);
    }

    private Sign1Message extractDeviceSignature(CBORObject deviceSigned) throws Exception {
        CBORObject deviceAuth = deviceSigned.get("deviceAuth");
        // Unwrap tag-24 if present
        if (deviceAuth != null && deviceAuth.HasMostOuterTag(24) && deviceAuth.getType() == CBORType.ByteString) {
            deviceAuth = CBORObject.DecodeFromBytes(deviceAuth.GetByteString());
        }
        CBORObject deviceAuthMap = asMap(deviceAuth);
        CBORObject deviceSignature = deviceAuthMap != null ? deviceAuthMap.get("deviceSignature") : deviceAuth;
        return decodeDeviceSignature(deviceSignature);
    }

    private OneKey extractAndValidateDeviceKey(CBORObject mso) throws Exception {
        PublicKey deviceKey = extractDeviceKey(mso.get("deviceKeyInfo"));
        if (deviceKey == null) {
            throw new IllegalStateException("Missing deviceKeyInfo in MSO");
        }
        return OneKeyFromPublicKey.build(deviceKey);
    }

    private byte[] ensurePayloadContent(Sign1Message sign1, CBORObject expectedTranscript,
                                        String docType, CBORObject deviceSigned) {
        byte[] payloadBytes = sign1.GetContent();
        if (payloadBytes == null || payloadBytes.length == 0) {
            CBORObject nameSpaces = deviceSigned.get("nameSpaces");
            LOG.debug("[OID4VP-MDOC] deviceAuth payload is detached, building from expected transcript");
            payloadBytes = buildDeviceAuthenticationPayload(expectedTranscript, docType, nameSpaces);
            sign1.SetContent(payloadBytes);
        }
        return payloadBytes;
    }

    private void validateDeviceAuthPayload(byte[] payloadBytes, String docType, CBORObject expectedTranscript) {
        CBORObject payload = unwrapPayload(payloadBytes);

        if (payload.getType() != CBORType.Array || payload.size() < 3) {
            throw new IllegalStateException("Invalid deviceAuth payload");
        }

        validateDeviceAuthContext(payload.get(0));
        validateDocType(payload.get(2), docType);
        validateSessionTranscript(payload.get(1), expectedTranscript);
    }

    private CBORObject unwrapPayload(byte[] payloadBytes) {
        CBORObject payload = CBORObject.DecodeFromBytes(payloadBytes);
        // Unwrap tag-24 embedded CBOR if present
        if (payload.HasMostOuterTag(24) && payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        // Unwrap additional byte string wrapper if present
        if (payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        return payload;
    }

    private void validateDeviceAuthContext(CBORObject context) {
        if (context == null || context.getType() != CBORType.TextString) {
            throw new IllegalStateException("Invalid deviceAuth context");
        }
        if (!"DeviceAuthentication".equals(context.AsString())) {
            throw new IllegalStateException("Invalid deviceAuth context");
        }
    }

    private void validateDocType(CBORObject claimedDocType, String expectedDocType) {
        if (expectedDocType == null || claimedDocType == null) {
            return;
        }
        if (claimedDocType.getType() != CBORType.TextString) {
            return;
        }
        if (!expectedDocType.equals(claimedDocType.AsString())) {
            throw new IllegalStateException("DocType mismatch in deviceAuth");
        }
    }

    private void validateSessionTranscript(CBORObject actual, CBORObject expected) {
        if (actual == null) {
            throw new IllegalStateException("SessionTranscript mismatch in deviceAuth");
        }
        byte[] actualBytes = actual.EncodeToBytes(ENCODE_OPTIONS);
        byte[] expectedBytes = expected.EncodeToBytes(ENCODE_OPTIONS);
        if (!Arrays.equals(actualBytes, expectedBytes)) {
            LOG.debug("SessionTranscript MISMATCH! expected={}, actual={}",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(expectedBytes),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(actualBytes));
            throw new IllegalStateException("SessionTranscript mismatch in deviceAuth");
        }
    }

    private Sign1Message decodeDeviceSignature(CBORObject value) throws Exception {
        if (value == null) {
            throw new IllegalStateException("Missing deviceAuth in DeviceResponse");
        }
        byte[] encoded;
        if (value.getType() == CBORType.ByteString) {
            encoded = value.GetByteString();
        } else {
            encoded = value.EncodeToBytes(ENCODE_OPTIONS);
        }
        if (encoded == null || encoded.length == 0) {
            throw new IllegalStateException("Invalid deviceAuth in DeviceResponse");
        }
        try {
            return (Sign1Message) Sign1Message.DecodeFromBytes(encoded);
        } catch (CoseException e) {
            return (Sign1Message) Message.DecodeFromBytes(encoded, MessageTag.Sign1);
        }
    }

    private byte[] buildDeviceAuthenticationPayload(CBORObject expectedTranscript,
                                                    String docType,
                                                    CBORObject deviceNameSpacesBytes) {
        CBORObject deviceAuthentication = CBORObject.NewArray();
        deviceAuthentication.Add("DeviceAuthentication");
        deviceAuthentication.Add(expectedTranscript != null ? expectedTranscript : CBORObject.Null);
        deviceAuthentication.Add(docType != null ? docType : "");
        if (deviceNameSpacesBytes != null) {
            deviceAuthentication.Add(deviceNameSpacesBytes);
        }
        byte[] bytes = deviceAuthentication.EncodeToBytes(ENCODE_OPTIONS);
        return CBORObject.FromObjectAndTag(bytes, 24).EncodeToBytes(ENCODE_OPTIONS);
    }

    private CBORObject buildSessionTranscript(String clientId, String nonce, byte[] jwkThumbprint, String responseUri) throws Exception {
        return SessionTranscriptBuilder.create()
                .clientId(clientId)
                .nonce(nonce)
                .jwkThumbprint(jwkThumbprint)
                .responseUri(responseUri)
                .build();
    }

    private CBORObject buildSessionTranscriptIso18013_7(String clientId, String nonce, String responseUri, String mdocGeneratedNonce) throws Exception {
        return SessionTranscriptBuilder.create()
                .clientId(clientId)
                .nonce(nonce)
                .responseUri(responseUri)
                .mdocGeneratedNonce(mdocGeneratedNonce)
                .buildIso18013_7();
    }

    private void verifyDigests(CBORObject mso, CBORObject issuerSigned) throws Exception {
        CBORObject valueDigests = decodeContainer(asMap(decodeContainer(mso.get("valueDigests"))));
        if (valueDigests == null) {
            return;
        }
        CBORObject nameSpaces = issuerSigned != null ? asMap(decodeContainer(issuerSigned.get("nameSpaces"))) : null;
        if (nameSpaces == null) {
            throw new IllegalStateException("Invalid mDoc payload");
        }
        Map<String, Object> digestContainers = toJavaMap(valueDigests);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (CBORObject nsKey : nameSpaces.getKeys()) {
            CBORObject elements = nameSpaces.get(nsKey);
            Map<Integer, byte[]> digests = collectDigestMapFromJava(digestContainers.get(nsKey.AsString()));
            if (elements == null || elements.getType() != CBORType.Array) {
                continue;
            }
            for (int i = 0; i < elements.size(); i++) {
                CBORObject element = elements.get(i);
                CBORObject decoded = decodeIssuerItem(element);
                Integer digestId = decoded != null ? toInt(decoded.get("digestID")) : null;
                if (digestId == null) {
                    throw new IllegalStateException("Missing digest for element");
                }
                byte[] expectedDigest = digests.get(digestId);
                if (expectedDigest == null) {
                    throw new IllegalStateException("Missing digest for element " + digestId);
                }
                byte[] digest = sha.digest(element.EncodeToBytes(ENCODE_OPTIONS));
                if (!Arrays.equals(expectedDigest, digest)) {
                    throw new IllegalStateException("Digest mismatch for element " + digestId);
                }
            }
        }
    }

    private void validateValidity(CBORObject validityInfo) {
        if (validityInfo == null || validityInfo.getType() != CBORType.Map) {
            return;
        }
        Instant now = Instant.now();
        Long notBefore = toEpochSecond(validityInfo.get("validFrom"));
        if (notBefore != null && Instant.ofEpochSecond(notBefore).isAfter(now)) {
            throw new IllegalStateException("Credential presentation not yet valid");
        }
        Long notAfter = toEpochSecond(validityInfo.get("validUntil"));
        if (notAfter != null && Instant.ofEpochSecond(notAfter).isBefore(now)) {
            throw new IllegalStateException("Credential presentation expired");
        }
    }

    @SuppressWarnings("unchecked")
    private void checkMsoRevocationStatus(CBORObject mso, VerificationStepSink steps) {
        try {
            CBORObject statusCbor = mso.get("status");
            if (statusCbor == null || statusCbor.getType() != CBORType.Map) {
                LOG.debug("No status field in MSO — skipping revocation check");
                return;
            }
            Map<String, Object> statusMap = (Map<String, Object>) convertToJava(statusCbor);
            // Wrap in a map matching the SD-JWT structure: {"status": {...}}
            Map<String, Object> payload = Map.of("status", statusMap);
            statusListVerifier.checkRevocationStatus(payload);
            if (steps != null) {
                steps.add("Revocation status checked",
                        "Verified credential has not been revoked via Token Status List.",
                        "https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/");
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            LOG.debug("Could not check mDoc revocation status (non-fatal): {}", e.getMessage());
            LOG.debug("[OID4VP-MDOC] Revocation check error details:", e);
        }
    }

    private PublicKey extractDeviceKey(CBORObject deviceKeyInfoObj) throws Exception {
        CBORObject deviceKeyInfo = asMap(deviceKeyInfoObj);
        if (deviceKeyInfo == null) {
            return null;
        }
        if (deviceKeyInfo.ContainsKey("deviceKey")) {
            PublicKey coseKey = parseCoseKey(deviceKeyInfo.get("deviceKey"));
            if (coseKey != null) {
                return coseKey;
            }
        }
        Object jwkObj = deviceKeyInfo.ContainsKey("jwk") ? convertToJava(deviceKeyInfo.get("jwk"))
                : convertToJava(deviceKeyInfo);
        if (!(jwkObj instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() != null) {
            normalized.put(entry.getKey().toString(), entry.getValue());
            }
        }
        JWK parsed = JWK.parse(normalized);
        if (parsed instanceof ECKey ecKey) {
            return ecKey.toECPublicKey();
        }
        if (parsed instanceof RSAKey rsaKey) {
            return rsaKey.toRSAPublicKey();
        }
        return null;
    }

    private PublicKey parseCoseKey(CBORObject coseKey) {
        if (coseKey == null || coseKey.getType() != CBORType.Map) {
            return null;
        }
        try {
            CBORObject kty = coseKey.get(CBORObject.FromObject(1));
            if (kty == null || kty.getType() != CBORType.Integer || kty.AsInt32Value() != 2) {
                return null;
            }
            CBORObject crv = coseKey.get(CBORObject.FromObject(-1));
            if (crv == null || crv.getType() != CBORType.Integer || crv.AsInt32Value() != 1) {
                return null;
            }
            CBORObject x = coseKey.get(CBORObject.FromObject(-2));
            CBORObject y = coseKey.get(CBORObject.FromObject(-3));
            if (x == null || y == null || x.getType() != CBORType.ByteString || y.getType() != CBORType.ByteString) {
                return null;
            }
            ECKey jwk = new ECKey.Builder(Curve.P_256, Base64URL.encode(x.GetByteString()), Base64URL.encode(y.GetByteString()))
                    .build();
            return jwk.toECPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

    private CBORObject decodeMso(byte[] content) {
        CBORObject payload = CBORObject.DecodeFromBytes(content);
        if (payload.HasMostOuterTag(24) && payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        if (payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        if (payload.getType() != CBORType.Map) {
            throw new IllegalStateException("Invalid mDoc payload");
        }
        return payload;
    }

    private CBORObject firstDocument(CBORObject root) {
        CBORObject docs = root.get("documents");
        if (docs != null && docs.getType() == CBORType.Array && docs.size() > 0) {
            return asMap(docs.get(0));
        }
        throw new IllegalStateException("Invalid mDoc payload");
    }

    private CBORObject asMap(CBORObject value) {
        if (value == null || value.getType() != CBORType.Map) {
            return null;
        }
        return value;
    }

    private byte[] toByteArray(Object value) {
        if (value instanceof CBORObject cbor) {
            if (cbor.getType() == CBORType.ByteString) {
                return cbor.GetByteString();
            }
            if (cbor.getType() == CBORType.TextString) {
                return HexUtils.toBytes(cbor.AsString());
            }
        }
        return HexUtils.toBytes(value);
    }

    private Integer toInt(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof CBORObject cbor) {
            if (cbor.getType() == CBORType.Integer) {
                return cbor.AsInt32Value();
            }
            if (cbor.getType() == CBORType.TextString) {
                String str = cbor.AsString();
                try {
                    return Integer.parseInt(str);
                } catch (NumberFormatException ignored) {
                }
            }
            return null;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String str) {
            try {
                return Integer.parseInt(str);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Long toEpochSecond(CBORObject value) {
        if (value == null) {
            return null;
        }
        if (value.getType() == CBORType.Integer) {
            return value.AsInt64Value();
        }
        if (value.getType() == CBORType.TextString || value.HasMostOuterTag(0)) {
            String text = value.AsString();
            try {
                return Instant.parse(text).getEpochSecond();
            } catch (DateTimeParseException ignored) {
            }
        }
        return null;
    }

    private CBORObject decodeIssuerItem(CBORObject value) {
        if (value == null) {
            return null;
        }
        value = decodeContainer(value);
        if (value.HasMostOuterTag(24) && value.getType() == CBORType.ByteString) {
            return CBORObject.DecodeFromBytes(value.GetByteString());
        }
        if (value.getType() == CBORType.Map) {
            return value;
        }
        return null;
    }

    private String extractDocType(CBORObject root, CBORObject document) {
        CBORObject docType = document.get("docType");
        if (docType != null) {
            return docType.AsString();
        }
        CBORObject fallback = root.get("docType");
        return fallback != null ? fallback.AsString() : null;
    }

    private Object convertToJava(CBORObject value) {
        return CborConversionUtils.toJava(value);
    }

    private String mapKey(CBORObject key) {
        return CborConversionUtils.mapKey(key);
    }

    private CBORObject decodeContainer(CBORObject value) {
        return CborConversionUtils.decodeContainer(value);
    }

    private Map<String, Object> toJavaMap(CBORObject value) {
        return CborConversionUtils.toJavaMap(value);
    }

    private Map<Integer, byte[]> collectDigestMapFromJava(Object digestContainer) {
        Map<Integer, byte[]> map = new LinkedHashMap<>();
        if (digestContainer instanceof List<?> list) {
            for (Object entry : list) {
                if (entry instanceof Map<?, ?> digest) {
                    Integer id = toInt(digest.get("digestID"));
                    byte[] value = toByteArray(digest.get("digest"));
                    if (id != null && value.length > 0) {
                        map.put(id, value);
                    }
                }
            }
        } else if (digestContainer instanceof Map<?, ?> digestMap) {
            for (Map.Entry<?, ?> entry : digestMap.entrySet()) {
                Integer id = toInt(entry.getKey());
                byte[] value = toByteArray(entry.getValue());
                if (id != null && value.length > 0) {
                    map.put(id, value);
                }
            }
        }
        return map;
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        if (value == null) {
            return new byte[0];
        }
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static final class OneKeyFromPublicKey {
        private OneKeyFromPublicKey() {
        }

        static OneKey build(PublicKey key) {
            try {
                if (key instanceof ECPublicKey ecKey) {
                    ECKey jwk = new ECKey.Builder(Curve.P_256, ecKey).build();
                    CBORObject cborKey = CBORObject.NewMap();
                    cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
                    cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
                    cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(jwk.getX().decode()));
                    cborKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(jwk.getY().decode()));
                    return new OneKey(cborKey);
                }
                if (key instanceof RSAPublicKey rsaKey) {
                    CBORObject cborKey = CBORObject.NewMap();
                    cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(3)); // kty: RSA
                    cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(unsignedBytes(rsaKey.getModulus())));
                    cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(unsignedBytes(rsaKey.getPublicExponent())));
                    return new OneKey(cborKey);
                }
                return null;
            } catch (Exception e) {
                return null;
            }
        }

        private static byte[] unsignedBytes(BigInteger value) {
            if (value == null) {
                return new byte[0];
            }
            byte[] bytes = value.toByteArray();
            if (bytes.length > 1 && bytes[0] == 0) {
                return Arrays.copyOfRange(bytes, 1, bytes.length);
            }
            return bytes;
        }
    }
}
