package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import COSE.OneKey;
import COSE.Sign1Message;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.TrustedIssuerResolver;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.VerificationStepSink;
import de.arbeitsagentur.keycloak.wallet.common.util.HexUtils;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifies mDoc credentials (CBOR/COSE) including issuer signature, digest integrity and optional holder binding.
 */
public class MdocVerifier {
    private static final CBOREncodeOptions CANONICAL = CBOREncodeOptions.DefaultCtap2Canonical;
    private final MdocParser parser = new MdocParser();
    private final TrustedIssuerResolver trustResolver;

    public MdocVerifier(TrustedIssuerResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public boolean isMdoc(String token) {
        return parser.isHex(token);
    }

    public Map<String, Object> verify(String hex,
                                      String trustListId,
                                      String keyBindingJwt,
                                      String expectedAudience,
                                      String expectedNonce,
                                      VerificationStepSink steps) {
        try {
            CBORObject root = CBORObject.DecodeFromBytes(HexUtils.decode(hex));
            CBORObject document = firstDocument(root);
            CBORObject issuerSigned = asMap(document.get("issuerSigned"));
            CBORObject nameSpaces = issuerSigned != null ? asMap(issuerSigned.get("nameSpaces")) : null;
            Map<String, Object> claims = new LinkedHashMap<>();
            if (nameSpaces != null) {
                claims.putAll(extractClaims(nameSpaces));
            }
            String docType = extractDocType(root, document);

            byte[] issuerAuth = issuerAuthBytes(document);
            Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(issuerAuth);
            verifySignature(sign1, trustListId);
            if (steps != null) {
                steps.add("Signature verified against trust-list.json",
                        "Checked mDoc issuerAuth signature against trusted issuers in the trust list.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
            }

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

            if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
                PublicKey deviceKey = extractDeviceKey(mso.get("deviceKeyInfo"));
                verifyHolderBinding(keyBindingJwt, deviceKey, expectedAudience, expectedNonce);
                if (steps != null) {
                    steps.add("Validated holder binding",
                            "Validated KB-JWT holder binding against mDoc deviceKeyInfo.",
                            "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.4");
                }
                claims.put("key_binding_jwt", keyBindingJwt);
            }
            if (docType != null && !claims.containsKey("docType")) {
                claims.put("docType", docType);
            }
            return claims;
        } catch (Exception e) {
            throw new IllegalStateException("Credential signature not trusted", e);
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

    private void verifySignature(Sign1Message sign1, String trustListId) throws Exception {
        List<PublicKey> keys = trustResolver.publicKeys(trustListId);
        if (keys == null) {
            keys = List.of();
        }
        for (PublicKey key : keys) {
            OneKey coseKey = OneKeyFromPublicKey.build(key);
            if (coseKey != null && sign1.validate(coseKey)) {
                return;
            }
        }
        throw new IllegalStateException("Credential signature not trusted");
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
                byte[] digest = sha.digest(element.EncodeToBytes(CANONICAL));
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

    private void verifyHolderBinding(String keyBindingJwt,
                                     PublicKey credentialKey,
                                     String expectedAudience,
                                     String expectedNonce) throws Exception {
        if (credentialKey == null) {
            throw new IllegalStateException("Holder binding key does not match credential cnf");
        }
        SignedJWT holderBinding = SignedJWT.parse(keyBindingJwt);
        if (!TrustedIssuerResolver.verifyWithKey(holderBinding, credentialKey)) {
            throw new IllegalStateException("Holder binding signature invalid");
        }
        if (holderBinding.getJWTClaimsSet().getExpirationTime() != null
                && holderBinding.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
            throw new IllegalStateException("Presentation has expired");
        }
        if (holderBinding.getJWTClaimsSet().getNotBeforeTime() != null
                && holderBinding.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            throw new IllegalStateException("Presentation not yet valid");
        }
        if (expectedAudience != null && holderBinding.getJWTClaimsSet().getAudience() != null
                && !holderBinding.getJWTClaimsSet().getAudience().isEmpty()) {
            String aud = holderBinding.getJWTClaimsSet().getAudience().get(0);
            if (!expectedAudience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = holderBinding.getJWTClaimsSet().getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
    }

    private PublicKey extractDeviceKey(CBORObject deviceKeyInfoObj) throws Exception {
        CBORObject deviceKeyInfo = asMap(deviceKeyInfoObj);
        if (deviceKeyInfo == null) {
            return null;
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

    private byte[] issuerAuthBytes(CBORObject document) {
        CBORObject issuerSigned = asMap(document.get("issuerSigned"));
        CBORObject issuerAuth = issuerSigned != null ? issuerSigned.get("issuerAuth") : null;
        return toByteArray(issuerAuth);
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
                    map.put(key.AsString(), convertToJava(value.get(key)));
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
                return null;
            } catch (Exception e) {
                return null;
            }
        }
    }
}
