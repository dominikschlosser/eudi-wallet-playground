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

import de.arbeitsagentur.keycloak.wallet.mdoc.util.HexUtils;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.Base64;
import java.util.Set;

/**
 * Filters mDoc issuerSigned nameSpaces to retain only requested claims and re-encodes the mDoc.
 */
public class MdocSelectiveDiscloser {
    private static final CBOREncodeOptions ENCODE_OPTIONS = CBOREncodeOptions.Default;
    private final MdocParser parser = new MdocParser();

    public String filter(String token, Set<String> requestedClaims) {
        if (requestedClaims == null || requestedClaims.isEmpty()) {
            return token;
        }
        try {
            boolean isHex = parser.isHex(token);
            byte[] decoded = isHex ? HexUtils.decode(token) : Base64.getUrlDecoder().decode(token);
            CBORObject root = CBORObject.DecodeFromBytes(decoded);
            if (root == null || root.getType() != CBORType.Map) {
                return token;
            }
            boolean changed = false;
            if (root.ContainsKey("issuerAuth") && root.ContainsKey("nameSpaces")) {
                changed = filterIssuerSigned(root, requestedClaims);
            } else if (root.ContainsKey("documents")) {
                CBORObject docs = root.get("documents");
                if (docs == null || docs.getType() != CBORType.Array || docs.size() == 0) {
                    return token;
                }
                for (int docIndex = 0; docIndex < docs.size(); docIndex++) {
                    CBORObject doc = docs.get(docIndex);
                    CBORObject issuerSigned = doc != null && doc.getType() == CBORType.Map ? doc.get("issuerSigned") : null;
                    if (issuerSigned != null && issuerSigned.getType() == CBORType.Map) {
                        boolean docChanged = filterIssuerSigned(issuerSigned, requestedClaims);
                        changed = changed || docChanged;
                    }
                }
            } else {
                return token;
            }
            if (!changed) {
                return token;
            }
            byte[] encoded = root.EncodeToBytes(ENCODE_OPTIONS);
            return isHex
                    ? HexUtils.encode(encoded)
                    : Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
        } catch (Exception e) {
            return token;
        }
    }

    private boolean filterIssuerSigned(CBORObject issuerSigned, Set<String> requestedClaims) {
        CBORObject nameSpaces = issuerSigned.get("nameSpaces");
        if (nameSpaces == null || nameSpaces.getType() != CBORType.Map) {
            return false;
        }
        boolean changed = false;
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
        return changed;
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
