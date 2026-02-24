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

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.OneKey;
import COSE.Sign1Message;
import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.cbor.CBORMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import de.arbeitsagentur.keycloak.wallet.mdoc.util.HexUtils;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds ISO 18013-5 compliant mDoc credentials.
 */
public class MdocCredentialBuilder {
    private static final int COSE_HEADER_PARAM_X5CHAIN = 33;
    private static final CBOREncodeOptions ENCODE_OPTIONS = CBOREncodeOptions.Default;
    private final ECKey signingKey;
    private final Duration credentialTtl;
    private final CBORMapper cborMapper = new CBORMapper();
    private final SecureRandom random = new SecureRandom();
    private List<X509Certificate> issuerCertificateChain;

    public MdocCredentialBuilder(ECKey signingKey, Duration credentialTtl) {
        this.signingKey = signingKey;
        this.credentialTtl = credentialTtl;
    }

    public MdocCredentialBuilder issuerCertificateChain(List<X509Certificate> chain) {
        this.issuerCertificateChain = chain;
        return this;
    }

    public CredentialBuildResult build(String configurationId, String vct, String issuer,
                                       Map<String, Object> claims, JsonNode cnf) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            String namespace = resolveNamespace(vct);
            IssuerSignedData issuerSignedData = buildIssuerSigned(namespace, claims, sha);
            CBORObject validityInfo = buildValidityInfo();
            CBORObject valueDigests = buildValueDigests(namespace, issuerSignedData.digestEntries());

            CBORObject mso = CBORObject.NewMap();
            mso.Add("version", "1.0");
            mso.Add("digestAlgorithm", "SHA-256");
            mso.Add("valueDigests", valueDigests);
            mso.Add("docType", vct);
            mso.Add("validityInfo", validityInfo);
            if (cnf != null) {
                CBORObject deviceKeyInfo = buildDeviceKeyInfo(cnf);
                if (deviceKeyInfo != null) {
                    mso.Add("deviceKeyInfo", deviceKeyInfo);
                }
            }
            byte[] msoBytes = mso.EncodeToBytes(ENCODE_OPTIONS);
            byte[] issuerAuth = signMso(CBORObject.FromObjectAndTag(msoBytes, 24).EncodeToBytes(ENCODE_OPTIONS));

            CBORObject issuerSigned = CBORObject.NewMap();
            issuerSigned.Add("nameSpaces", issuerSignedData.nameSpaces());
            issuerSigned.Add("issuerAuth", CBORObject.FromObject(issuerAuth));
            byte[] issuerSignedBytes = issuerSigned.EncodeToBytes(ENCODE_OPTIONS);
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSignedBytes);

            Map<String, Object> decoded = new LinkedHashMap<>();
            decoded.put("iss", issuer);
            decoded.put("credential_configuration_id", configurationId);
            decoded.put("vct", vct);
            decoded.put("docType", vct);
            decoded.put("validityInfo", toDecodedValidity(validityInfo));
            if (cnf != null) {
                decoded.put("cnf", cborMapper.convertValue(cnf, Map.class));
            }
            decoded.put("claims", claims);
            decoded.put("issuerSigned", issuerSignedData.decodedView(HexUtils.encode(issuerAuth), valueDigests));

            return new CredentialBuildResult(encoded, List.of(), decoded, vct, "mso_mdoc");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build mDoc", e);
        }
    }

    private String resolveNamespace(String docType) {
        if (docType != null && docType.startsWith("org.iso.18013.5.1")) {
            return "org.iso.18013.5.1";
        }
        return docType;
    }

    private CBORObject buildValidityInfo() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant validUntil = now.plus(credentialTtl);
        CBORObject validity = CBORObject.NewMap();
        validity.Add("signed", isoDate(now));
        validity.Add("validFrom", isoDate(now));
        validity.Add("validUntil", isoDate(validUntil));
        return validity;
    }

    private Map<String, Object> toDecodedValidity(CBORObject validityInfo) {
        Map<String, Object> decoded = new LinkedHashMap<>();
        decoded.put("signed", validityInfo.get("signed").AsString());
        decoded.put("validFrom", validityInfo.get("validFrom").AsString());
        decoded.put("validUntil", validityInfo.get("validUntil").AsString());
        return decoded;
    }

    private CBORObject isoDate(Instant instant) {
        String text = DateTimeFormatter.ISO_INSTANT.format(instant);
        return CBORObject.FromObjectAndTag(text, 0);
    }

    private IssuerSignedData buildIssuerSigned(String namespace,
                                               Map<String, Object> claims,
                                               MessageDigest sha) {
        List<CBORObject> issuerItems = new ArrayList<>();
        List<Map<String, Object>> decodedItems = new ArrayList<>();
        List<Map<String, Object>> digestEntries = new ArrayList<>();
        int digestId = 0;
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            CBORObject item = CBORObject.NewMap();
            item.Add("digestID", digestId);
            item.Add("random", CBORObject.FromObject(salt));
            item.Add("elementIdentifier", entry.getKey());
            item.Add("elementValue", CBORObject.FromObject(entry.getValue()));
            byte[] encodedItem = item.EncodeToBytes(ENCODE_OPTIONS);
            CBORObject taggedItem = CBORObject.FromObjectAndTag(encodedItem, 24);
            issuerItems.add(taggedItem);

            byte[] digest = sha.digest(taggedItem.EncodeToBytes(ENCODE_OPTIONS));
            Map<String, Object> digestEntry = new LinkedHashMap<>();
            digestEntry.put("digestID", digestId);
            digestEntry.put("digest", digest);
            digestEntries.add(digestEntry);

            Map<String, Object> decodedItem = new LinkedHashMap<>();
            decodedItem.put("digestID", digestId);
            decodedItem.put("elementIdentifier", entry.getKey());
            decodedItem.put("elementValue", entry.getValue());
            decodedItem.put("random", HexUtils.encode(salt));
            decodedItems.add(decodedItem);

            digestId++;
        }
        CBORObject nameSpaces = CBORObject.NewMap();
        CBORObject array = CBORObject.NewArray();
        issuerItems.forEach(array::Add);
        nameSpaces.Add(namespace, array);
        Map<String, Object> decodedNameSpaces = new LinkedHashMap<>();
        decodedNameSpaces.put(namespace, decodedItems);
        return new IssuerSignedData(nameSpaces, digestEntries, decodedNameSpaces);
    }

    private CBORObject buildValueDigests(String namespace, List<Map<String, Object>> digestEntries) {
        CBORObject valueDigests = CBORObject.NewMap();
        CBORObject digests = CBORObject.NewMap();
        for (Map<String, Object> entry : digestEntries) {
            Object digestId = entry.get("digestID");
            if (digestId == null) {
                continue;
            }
            digests.Add(CBORObject.FromObject(digestId), CBORObject.FromObject(entry.get("digest")));
        }
        valueDigests.Add(namespace, digests);
        return valueDigests;
    }

    private CBORObject buildDeviceKeyInfo(JsonNode cnf) {
        try {
            JsonNode jwkNode = cnf.has("jwk") ? cnf.get("jwk") : cnf;
            if (jwkNode == null || jwkNode.isNull() || jwkNode.isMissingNode()) {
                return null;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = cborMapper.convertValue(jwkNode, Map.class);
            JWK jwk = JWK.parse(jwkMap);
            if (!(jwk instanceof ECKey ecKey)) {
                return null;
            }
            CBORObject coseKey = CBORObject.NewMap();
            coseKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
            coseKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
            coseKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(ecKey.getX().decode()));
            coseKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(ecKey.getY().decode()));

            CBORObject info = CBORObject.NewMap();
            info.Add("deviceKey", coseKey);
            return info;
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] signMso(byte[] msoPayload) throws Exception {
        OneKey coseKey = toCoseKey(signingKey);
        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(CBORObject.FromObject(1), AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
        if (signingKey.getKeyID() != null) {
            sign1.addAttribute(CBORObject.FromObject(4), CBORObject.FromObject(signingKey.getKeyID()), Attribute.PROTECTED);
        }
        if (issuerCertificateChain != null && !issuerCertificateChain.isEmpty()) {
            CBORObject x5chain;
            if (issuerCertificateChain.size() == 1) {
                x5chain = CBORObject.FromObject(issuerCertificateChain.get(0).getEncoded());
            } else {
                x5chain = CBORObject.NewArray();
                for (X509Certificate cert : issuerCertificateChain) {
                    x5chain.Add(CBORObject.FromObject(cert.getEncoded()));
                }
            }
            sign1.addAttribute(CBORObject.FromObject(COSE_HEADER_PARAM_X5CHAIN), x5chain, Attribute.UNPROTECTED);
        }
        sign1.SetContent(msoPayload);
        try {
            sign1.sign(coseKey);
            return sign1.EncodeToBytes();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign mDoc MSO", e);
        }
    }

    private OneKey toCoseKey(ECKey key) {
        CBORObject cborKey = CBORObject.NewMap();
        cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
        cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
        cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(key.getX().decode()));
        cborKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(key.getY().decode()));
        cborKey.Add(CBORObject.FromObject(-4), CBORObject.FromObject(key.getD().decode()));
        if (key.getKeyID() != null) {
            cborKey.Add(CBORObject.FromObject(2), CBORObject.FromObject(key.getKeyID()));
        }
        try {
            return new OneKey(cborKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert signing key to COSE format", e);
        }
    }

    private Object toJavaObject(JsonNode node) {
        return cborMapper.convertValue(node, Map.class);
    }

    private record IssuerSignedData(CBORObject nameSpaces,
                                    List<Map<String, Object>> digestEntries,
                                    Map<String, Object> decodedNameSpaces) {
        Map<String, Object> decodedView(String issuerAuthHex, CBORObject valueDigests) {
            Map<String, Object> issuerSigned = new LinkedHashMap<>();
            issuerSigned.put("nameSpaces", decodedNameSpaces);
            issuerSigned.put("valueDigests", toDecodedValueDigests(valueDigests));
            issuerSigned.put("issuerAuth", issuerAuthHex);
            return issuerSigned;
        }

        private Map<String, Object> toDecodedValueDigests(CBORObject valueDigests) {
            Map<String, Object> decoded = new LinkedHashMap<>();
            for (CBORObject key : valueDigests.getKeys()) {
                List<Map<String, Object>> entries = new ArrayList<>();
                CBORObject list = valueDigests.get(key);
                if (list != null && list.getType() == CBORType.Map) {
                    for (CBORObject digestId : list.getKeys()) {
                        CBORObject digestValue = list.get(digestId);
                        if (digestValue == null || digestValue.getType() != CBORType.ByteString) {
                            continue;
                        }
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("digestID", digestId.AsInt32Value());
                        entry.put("digest", HexUtils.encode(digestValue.GetByteString()));
                        entries.add(entry);
                    }
                } else if (list != null) {
                    for (int i = 0; i < list.size(); i++) {
                        CBORObject element = list.get(i);
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("digestID", element.get("digestID").AsInt32Value());
                        entry.put("digest", HexUtils.encode(element.get("digest").GetByteString()));
                        entries.add(entry);
                    }
                }
                decoded.put(key.AsString(), entries);
            }
            return decoded;
        }
    }
}
