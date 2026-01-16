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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.Curve;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import de.arbeitsagentur.keycloak.wallet.mdoc.util.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Builds an ISO 18013-5 {@code DeviceResponse} for OID4VP by wrapping an {@code IssuerSigned} credential and adding
 * a {@code deviceAuth} signature over the OpenID4VP SessionTranscript.
 */
public class MdocDeviceResponseBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(MdocDeviceResponseBuilder.class);
    private static final CBOREncodeOptions ENCODE_OPTIONS = CBOREncodeOptions.Default;
    private final MdocParser parser = new MdocParser();
    private final SecureRandom random = new SecureRandom();

    public String buildDeviceResponse(String issuerSignedToken,
                                      ECKey deviceKey,
                                      String clientId,
                                      String nonce,
                                      String responseUri,
                                      JWK handoverJwk) {
        if (issuerSignedToken == null || issuerSignedToken.isBlank()) {
            throw new IllegalArgumentException("issuerSignedToken is required");
        }
        if (deviceKey == null || !deviceKey.isPrivate()) {
            throw new IllegalArgumentException("deviceKey (EC private key) is required");
        }
        if (!Curve.P_256.equals(deviceKey.getCurve())) {
            throw new IllegalArgumentException("deviceKey must use P-256");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId is required");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("nonce is required");
        }
        if (responseUri == null || responseUri.isBlank()) {
            throw new IllegalArgumentException("responseUri is required");
        }
        try {
            CBORObject issuerSigned = decodeIssuerSigned(issuerSignedToken);
            String docType = parser.extractDocType(issuerSignedToken);
            if (docType == null || docType.isBlank()) {
                throw new IllegalStateException("Unable to determine docType from IssuerSigned");
            }

            CBORObject deviceNameSpaces = CBORObject.NewMap();
            CBORObject sessionTranscript = buildSessionTranscript(clientId, nonce, handoverJwk, responseUri);
            byte[] deviceAuth = signDeviceAuth(deviceKey, docType, sessionTranscript, deviceNameSpaces);

            CBORObject deviceSigned = CBORObject.NewMap();
            deviceSigned.Add("nameSpaces", deviceNameSpaces);
            deviceSigned.Add("deviceAuth", CBORObject.FromObject(deviceAuth));

            CBORObject document = CBORObject.NewMap();
            document.Add("docType", docType);
            document.Add("issuerSigned", issuerSigned);
            document.Add("deviceSigned", deviceSigned);

            CBORObject documents = CBORObject.NewArray();
            documents.Add(document);

            CBORObject response = CBORObject.NewMap();
            response.Add("version", "1.0");
            response.Add("documents", documents);
            response.Add("status", 0);

            byte[] bytes = response.EncodeToBytes(ENCODE_OPTIONS);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build DeviceResponse", e);
        }
    }

    private CBORObject decodeIssuerSigned(String token) {
        try {
            byte[] bytes;
            if (parser.isHex(token)) {
                bytes = HexUtils.decode(token);
            } else {
                bytes = Base64.getUrlDecoder().decode(token);
            }
            CBORObject decoded = CBORObject.DecodeFromBytes(bytes);
            if (decoded == null || decoded.getType() != CBORType.Map) {
                throw new IllegalStateException("issuerSignedToken is not a CBOR map");
            }
            if (!decoded.ContainsKey("issuerAuth") || !decoded.ContainsKey("nameSpaces")) {
                throw new IllegalStateException("issuerSignedToken is not an IssuerSigned structure");
            }
            return decoded;
        } catch (Exception e) {
            throw new IllegalStateException("Invalid issuerSignedToken", e);
        }
    }

    private CBORObject buildSessionTranscript(String clientId, String nonce, JWK handoverJwk, String responseUri) throws Exception {
        byte[] jwkThumbprint = handoverJwk != null ? handoverJwk.computeThumbprint().decode() : null;

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

    private byte[] signDeviceAuth(ECKey deviceKey,
                                  String docType,
                                  CBORObject sessionTranscript,
                                  CBORObject deviceNameSpaces) throws Exception {
        OneKey coseKey = toCoseKey(deviceKey);

        CBORObject deviceAuthentication = CBORObject.NewArray();
        deviceAuthentication.Add("DeviceAuthentication");
        deviceAuthentication.Add(sessionTranscript);
        deviceAuthentication.Add(docType);
        deviceAuthentication.Add(deviceNameSpaces);

        byte[] payloadBytes = deviceAuthentication.EncodeToBytes(ENCODE_OPTIONS);
        byte[] taggedPayload = CBORObject.FromObjectAndTag(payloadBytes, 24).EncodeToBytes(ENCODE_OPTIONS);

        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(CBORObject.FromObject(1), AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
        if (deviceKey.getKeyID() != null && !deviceKey.getKeyID().isBlank()) {
            sign1.addAttribute(CBORObject.FromObject(4), CBORObject.FromObject(deviceKey.getKeyID()), Attribute.PROTECTED);
        } else {
            byte[] kid = new byte[8];
            random.nextBytes(kid);
            sign1.addAttribute(CBORObject.FromObject(4), CBORObject.FromObject(kid), Attribute.PROTECTED);
        }
        sign1.SetContent(taggedPayload);
        sign1.sign(coseKey);
        return sign1.EncodeToBytes();
    }

    private OneKey toCoseKey(ECKey key) {
        CBORObject cborKey = CBORObject.NewMap();
        cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
        cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
        cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(key.getX().decode()));
        cborKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(key.getY().decode()));
        cborKey.Add(CBORObject.FromObject(-4), CBORObject.FromObject(key.getD().decode()));
        if (key.getKeyID() != null && !key.getKeyID().isBlank()) {
            cborKey.Add(CBORObject.FromObject(2), CBORObject.FromObject(key.getKeyID()));
        }
        try {
            return new OneKey(cborKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert device key to COSE format", e);
        }
    }
}
