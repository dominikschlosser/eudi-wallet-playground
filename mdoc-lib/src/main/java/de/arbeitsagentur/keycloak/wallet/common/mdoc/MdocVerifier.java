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

    public MdocVerifier(TrustedIssuerResolver trustResolver) {
        this.trustResolver = trustResolver;
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
        LOG.debug("verify() called with: expectedClientId={}, expectedNonce={}, expectedResponseUri={}, expectedJwkThumbprint={}",
                expectedClientId, expectedNonce, expectedResponseUri,
                expectedJwkThumbprint != null ? Base64.getUrlEncoder().withoutPadding().encodeToString(expectedJwkThumbprint) : "null");
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
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1.2");
            }

            verifyDeviceAuth(document, mso, docType, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint);
            if (steps != null) {
                steps.add("Validated holder binding (mdoc deviceAuth)",
                        "Validated deviceAuth signature and OpenID4VP SessionTranscript binding for the mDoc presentation.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.5");
            }
            if (docType != null && !claims.containsKey("docType")) {
                claims.put("docType", docType);
            }
            return claims;
        } catch (Exception e) {
            LOG.info("[OID4VP-MDOC] Verification FAILED: {} - {}", e.getClass().getSimpleName(), e.getMessage());
            LOG.debug("[OID4VP-MDOC] Full stack trace:", e);
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
        List<PublicKey> keys = trustResolver.publicKeys(trustListId);
        if (keys == null) {
            keys = List.of();
        }
        LOG.info("[OID4VP-MDOC] verifySignature() checking {} trust list keys for trustListId: {}", keys.size(), trustListId);

        // Extract x5chain certificate(s) from mDoc issuerAuth for comparison
        List<X509Certificate> x5chainCerts = x5ChainCertificates(sign1);
        if (!x5chainCerts.isEmpty()) {
            X509Certificate cert = x5chainCerts.get(0);
            if (cert.getPublicKey() instanceof ECPublicKey ecKeyFromX5c) {
                String x5cX = Base64.getUrlEncoder().withoutPadding().encodeToString(
                        toUnsignedBytes(ecKeyFromX5c.getW().getAffineX()));
                LOG.info("[OID4VP-MDOC] mDoc issuerAuth x5chain public key x={}", x5cX);
            }
            // Log the full certificate in base64 for debugging (single line for log parsers)
            try {
                String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());
                LOG.info("[OID4VP-MDOC] mDoc issuerAuth x5chain certificate (base64): {}", certBase64);
                LOG.info("[OID4VP-MDOC] mDoc issuerAuth x5chain subject: {}, issuer: {}",
                        cert.getSubjectX500Principal().getName(), cert.getIssuerX500Principal().getName());
            } catch (Exception e) {
                LOG.warn("[OID4VP-MDOC] Could not log x5chain certificate: {}", e.getMessage());
            }
        }
        List<PublicKey> x5chainKeys = x5chainCerts.stream()
                .map(X509Certificate::getPublicKey)
                .toList();

        for (int i = 0; i < keys.size(); i++) {
            PublicKey key = keys.get(i);
            if (key instanceof ECPublicKey ecKey) {
                String trustKeyX = Base64.getUrlEncoder().withoutPadding().encodeToString(
                        toUnsignedBytes(ecKey.getW().getAffineX()));
                LOG.info("[OID4VP-MDOC] Trust list key[{}] x={}", i, trustKeyX);
            }
            OneKey coseKey = OneKeyFromPublicKey.build(key);
            if (coseKey == null) {
                LOG.info("[OID4VP-MDOC] Trust list key[{}] could not be converted to OneKey", i);
                continue;
            }
            try {
                boolean valid = sign1.validate(coseKey);
                LOG.info("[OID4VP-MDOC] Trust list key[{}] validation result: {}", i, valid);
                if (valid) {
                    if (steps != null) {
                        steps.add("Signature verified against trust-list.json",
                                "Checked mDoc issuerAuth signature against trusted issuers in the trust list.",
                                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
                    }
                    return;
                }
            } catch (Exception e) {
                LOG.info("[OID4VP-MDOC] Trust list key[{}] validation exception: {}", i, e.getMessage());
            }
        }

        // x5chain fallback verification has been removed
        // All trusted issuer certificates must be in the trust list for production-grade verification
        throw new IllegalStateException("Credential signature not trusted");
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

    private void verifyDeviceAuth(CBORObject document,
                                  CBORObject mso,
                                  String docType,
                                  String expectedClientId,
                                  String expectedNonce,
                                  String expectedResponseUri,
                                  byte[] expectedJwkThumbprint) throws Exception {
        CBORObject deviceSigned = asMap(document.get("deviceSigned"));
        if (deviceSigned == null) {
            throw new IllegalStateException("Missing deviceSigned in DeviceResponse");
        }
        CBORObject deviceAuth = deviceSigned.get("deviceAuth");
        CBORObject deviceAuthMap = asMap(deviceAuth);
        CBORObject deviceSignature = deviceAuthMap != null ? deviceAuthMap.get("deviceSignature") : deviceAuth;
        Sign1Message sign1 = decodeDeviceSignature(deviceSignature);
        PublicKey deviceKey = extractDeviceKey(mso.get("deviceKeyInfo"));
        if (deviceKey == null) {
            throw new IllegalStateException("Missing deviceKeyInfo in MSO");
        }
        OneKey coseKey = OneKeyFromPublicKey.build(deviceKey);

        CBORObject expectedTranscript = buildSessionTranscript(expectedClientId, expectedNonce, expectedJwkThumbprint, expectedResponseUri);
        byte[] effectivePayloadBytes = sign1.GetContent();
        if (effectivePayloadBytes == null || effectivePayloadBytes.length == 0) {
            effectivePayloadBytes = buildDeviceAuthenticationPayload(expectedTranscript, docType, deviceSigned.get("nameSpaces"));
            sign1.SetContent(effectivePayloadBytes);
        }

        if (coseKey == null || !sign1.validate(coseKey)) {
            throw new IllegalStateException("deviceAuth signature invalid");
        }

        CBORObject payload = CBORObject.DecodeFromBytes(effectivePayloadBytes);
        if (payload.HasMostOuterTag(24) && payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        if (payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        if (payload.getType() != CBORType.Array || payload.size() < 3) {
            throw new IllegalStateException("Invalid deviceAuth payload");
        }
        CBORObject context = payload.get(0);
        if (context == null || context.getType() != CBORType.TextString || !"DeviceAuthentication".equals(context.AsString())) {
            throw new IllegalStateException("Invalid deviceAuth context");
        }
        CBORObject sessionTranscript = payload.get(1);
        CBORObject claimedDocType = payload.get(2);
        if (docType != null
                && claimedDocType != null
                && claimedDocType.getType() == CBORType.TextString
                && !docType.equals(claimedDocType.AsString())) {
            throw new IllegalStateException("DocType mismatch in deviceAuth");
        }

        if (sessionTranscript == null
                || !Arrays.equals(sessionTranscript.EncodeToBytes(ENCODE_OPTIONS), expectedTranscript.EncodeToBytes(ENCODE_OPTIONS))) {
            LOG.debug("SessionTranscript MISMATCH! expected={}, actual={}",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(expectedTranscript.EncodeToBytes(ENCODE_OPTIONS)),
                    sessionTranscript != null ? Base64.getUrlEncoder().withoutPadding().encodeToString(sessionTranscript.EncodeToBytes(ENCODE_OPTIONS)) : "null");
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
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("Missing expected client_id for SessionTranscript");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalStateException("Missing expected nonce for SessionTranscript");
        }
        if (responseUri == null || responseUri.isBlank()) {
            throw new IllegalStateException("Missing expected response_uri for SessionTranscript");
        }

        CBORObject info = CBORObject.NewArray();
        info.Add(clientId);
        info.Add(nonce);
        if (jwkThumbprint != null && jwkThumbprint.length > 0) {
            info.Add(jwkThumbprint);
        } else {
            info.Add(CBORObject.Null);
        }
        info.Add(responseUri);
        byte[] infoBytes = info.EncodeToBytes(ENCODE_OPTIONS);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(infoBytes);
        LOG.debug("buildSessionTranscript inputs: clientId='{}', nonce='{}', jwkThumbprint={}, responseUri='{}' -> hash={}",
                clientId, nonce,
                jwkThumbprint != null ? Base64.getUrlEncoder().withoutPadding().encodeToString(jwkThumbprint) : "null",
                responseUri,
                Base64.getUrlEncoder().withoutPadding().encodeToString(hash));

        CBORObject handover = CBORObject.NewArray();
        handover.Add("OpenID4VPHandover");
        handover.Add(hash);

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(handover);
        return sessionTranscript;
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
        if (value == null) {
            return null;
        }
        value = decodeContainer(value);
        switch (value.getType()) {
            case TextString:
                return value.AsString();
            case Integer:
                return value.AsInt64Value();
            case Boolean:
                return value.AsBoolean();
            case ByteString:
                return value.GetByteString();
            case Map:
                Map<String, Object> map = new LinkedHashMap<>();
                for (CBORObject key : value.getKeys()) {
                    map.put(mapKey(key), convertToJava(value.get(key)));
                }
                return map;
            case Array:
                List<Object> list = new ArrayList<>();
                for (int i = 0; i < value.size(); i++) {
                    list.add(convertToJava(value.get(i)));
                }
                return list;
            default:
                return value.ToObject(Object.class);
        }
    }

    private String mapKey(CBORObject key) {
        if (key == null) {
            return "";
        }
        return switch (key.getType()) {
            case TextString -> key.AsString();
            case Integer -> String.valueOf(key.AsInt64Value());
            default -> key.toString();
        };
    }

    private CBORObject decodeContainer(CBORObject value) {
        if (value == null) {
            return null;
        }
        if (value.HasMostOuterTag(24) && value.getType() == CBORType.ByteString) {
            return CBORObject.DecodeFromBytes(value.GetByteString());
        }
        return value;
    }

    private Map<String, Object> toJavaMap(CBORObject value) {
        Object converted = convertToJava(value);
        if (converted instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    result.put(entry.getKey().toString(), entry.getValue());
                }
            }
            return result;
        }
        return Map.of();
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
