package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import de.arbeitsagentur.keycloak.wallet.common.util.HexUtils;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.Set;

/**
 * Filters mDoc issuerSigned nameSpaces to retain only requested claims and re-encodes the mDoc.
 */
public class MdocSelectiveDiscloser {
    private static final CBOREncodeOptions ENCODE_OPTIONS = CBOREncodeOptions.Default;

    public String filter(String hex, Set<String> requestedClaims) {
        if (requestedClaims == null || requestedClaims.isEmpty()) {
            return hex;
        }
        try {
            CBORObject root = CBORObject.DecodeFromBytes(HexUtils.decode(hex));
            CBORObject docs = root.get("documents");
            if (docs == null || docs.getType() != CBORType.Array || docs.size() == 0) {
                return hex;
            }
            boolean changed = false;
            for (int docIndex = 0; docIndex < docs.size(); docIndex++) {
                CBORObject doc = docs.get(docIndex);
                CBORObject issuerSigned = doc != null && doc.getType() == CBORType.Map ? doc.get("issuerSigned") : null;
                CBORObject nameSpaces = issuerSigned != null && issuerSigned.getType() == CBORType.Map
                        ? issuerSigned.get("nameSpaces") : null;
                if (nameSpaces == null || nameSpaces.getType() != CBORType.Map) {
                    continue;
                }
                CBORObject filteredNamespaces = CBORObject.NewMap();
                for (CBORObject nsKey : nameSpaces.getKeys()) {
                    CBORObject elements = nameSpaces.get(nsKey);
                    if (elements == null || elements.getType() != CBORType.Array) {
                        continue;
                    }
                    CBORObject filtered = CBORObject.NewArray();
                    for (int i = 0; i < elements.size(); i++) {
                        CBORObject element = elements.get(i);
                        CBORObject decoded = decodeIssuerItem(element);
                        String id = decoded != null && decoded.get("elementIdentifier") != null
                                ? decoded.get("elementIdentifier").AsString()
                                : null;
                        if (id != null && requested(id, requestedClaims)) {
                            filtered.Add(element);
                        }
                    }
                    if (filtered.size() > 0) {
                        filteredNamespaces.Add(nsKey, filtered);
                        if (filtered.size() != elements.size()) {
                            changed = true;
                        }
                    } else if (elements.size() > 0) {
                        changed = true;
                    }
                }
                if (filteredNamespaces.size() > 0) {
                    issuerSigned.set("nameSpaces", filteredNamespaces);
                }
            }
            if (!changed) {
                return hex;
            }
            byte[] encoded = root.EncodeToBytes(ENCODE_OPTIONS);
            return HexUtils.encode(encoded);
        } catch (Exception e) {
            return hex;
        }
    }

    private boolean requested(String claimName, Set<String> requestedClaims) {
        if (claimName == null || requestedClaims == null || requestedClaims.isEmpty()) {
            return false;
        }
        for (String req : requestedClaims) {
            if (req == null || req.isBlank()) {
                continue;
            }
            if (req.equals(claimName) || req.endsWith("." + claimName) || claimName.endsWith("." + req)) {
                return true;
            }
        }
        return false;
    }

    private CBORObject decodeIssuerItem(CBORObject element) {
        if (element == null) {
            return null;
        }
        if (element.HasMostOuterTag(24) && element.getType() == CBORType.ByteString) {
            return CBORObject.DecodeFromBytes(element.GetByteString());
        }
        if (element.getType() == CBORType.Map) {
            return element;
        }
        return null;
    }
}
