package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.OneKey;
import COSE.Sign1Message;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import de.arbeitsagentur.keycloak.wallet.common.util.HexUtils;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.CredentialBuildResult;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds ISO 18013-5 compliant mDoc credentials.
 */
public class MdocCredentialBuilder {
    private static final CBOREncodeOptions CTAP_CANONICAL = CBOREncodeOptions.DefaultCtap2Canonical;
    private static final CBOREncodeOptions DEFAULT_ENCODE = CBOREncodeOptions.Default;
    private final ECKey signingKey;
    private final Duration credentialTtl;
    private final CBORMapper cborMapper = new CBORMapper();
    private final SecureRandom random = new SecureRandom();

    public MdocCredentialBuilder(ECKey signingKey, Duration credentialTtl) {
        this.signingKey = signingKey;
        this.credentialTtl = credentialTtl;
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
                mso.Add("deviceKeyInfo", CBORObject.FromObject(toJavaObject(cnf)));
            }
            byte[] msoBytes = mso.EncodeToBytes(CTAP_CANONICAL);
            byte[] issuerAuth = signMso(CBORObject.FromObjectAndTag(msoBytes, 24).EncodeToBytes(CTAP_CANONICAL));

            CBORObject issuerSigned = CBORObject.NewMap();
            issuerSigned.Add("nameSpaces", issuerSignedData.nameSpaces());
            issuerSigned.Add("issuerAuth", CBORObject.FromObject(issuerAuth));

            CBORObject document = CBORObject.NewMap();
            document.Add("docType", vct);
            document.Add("issuerSigned", issuerSigned);
            document.Add("validityInfo", validityInfo);

            CBORObject mdoc = CBORObject.NewMap();
            mdoc.Add("version", "1.0");
            CBORObject documents = CBORObject.NewArray();
            documents.Add(document);
            mdoc.Add("documents", documents);
            mdoc.Add("status", 0);
            mdoc.Add("issuer", issuer);

            byte[] cbor = mdoc.EncodeToBytes(DEFAULT_ENCODE);
            String encoded = HexUtils.encode(cbor);

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
            byte[] encodedItem = item.EncodeToBytes(CTAP_CANONICAL);
            CBORObject taggedItem = CBORObject.FromObjectAndTag(encodedItem, 24);
            issuerItems.add(taggedItem);

            byte[] digest = sha.digest(taggedItem.EncodeToBytes(CTAP_CANONICAL));
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
        CBORObject digests = CBORObject.NewArray();
        for (Map<String, Object> entry : digestEntries) {
            CBORObject digest = CBORObject.NewMap();
            digest.Add("digestID", entry.get("digestID"));
            digest.Add("digest", CBORObject.FromObject(entry.get("digest")));
            digests.Add(digest);
        }
        valueDigests.Add(namespace, digests);
        return valueDigests;
    }

    private byte[] signMso(byte[] msoPayload) throws Exception {
        OneKey coseKey = toCoseKey(signingKey);
        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(CBORObject.FromObject(1), AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
        if (signingKey.getKeyID() != null) {
            sign1.addAttribute(CBORObject.FromObject(4), CBORObject.FromObject(signingKey.getKeyID()), Attribute.PROTECTED);
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
                for (int i = 0; i < list.size(); i++) {
                    CBORObject element = list.get(i);
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("digestID", element.get("digestID").AsInt32Value());
                    entry.put("digest", HexUtils.encode(element.get("digest").GetByteString()));
                    entries.add(entry);
                }
                decoded.put(key.AsString(), entries);
            }
            return decoded;
        }
    }
}
