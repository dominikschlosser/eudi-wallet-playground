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

import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;

/**
 * Builder for mDoc SessionTranscript supporting both OpenID4VP 1.0 and ISO 18013-7 formats.
 * <p>
 * The SessionTranscript binds the device authentication signature to the specific presentation
 * request, preventing replay attacks. Two competing specifications define different handover
 * formats for this binding:
 *
 * <h3>OpenID4VP 1.0 (Draft 28+)</h3>
 * Defined in <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.2.2">
 * OpenID4VP 1.0, Appendix B.3.2.2 — OID4VP Handover</a>.
 * <pre>
 * SessionTranscript = [
 *   null,                     // DeviceEngagementBytes (not used in OID4VP)
 *   null,                     // EReaderKeyBytes (not used in OID4VP)
 *   OID4VPHandover
 * ]
 *
 * OID4VPHandover = [
 *   "OpenID4VPHandover",
 *   SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))
 * ]
 * </pre>
 *
 * <h3>ISO 18013-7 Annex B (Working Draft)</h3>
 * Defined in <a href="https://www.iso.org/standard/82772.html">ISO/IEC 18013-7</a>,
 * Annex B.4.4 — SessionTranscript for OID4VP over the Internet.
 * Used by the German EUDI wallet (Bundesdruckerei). The wallet signals use of this format
 * by including an {@code mdoc_generated_nonce} in the JWE {@code apu} (Agreement PartyUInfo) header.
 * <pre>
 * SessionTranscript = [
 *   null,                                                // DeviceEngagementBytes
 *   null,                                                // EReaderKeyBytes
 *   [
 *     SHA-256(CBOR([client_id, mdoc_generated_nonce])),  // OID4VPHandoverClientIdHash
 *     SHA-256(CBOR([response_uri, mdoc_generated_nonce])),// OID4VPHandoverResponseUriHash
 *     nonce                                               // authorization request nonce
 *   ]
 * ]
 * </pre>
 *
 * @see MdocVerifier#verify for the dual-format verification logic
 */
public final class SessionTranscriptBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(SessionTranscriptBuilder.class);
    private static final CBOREncodeOptions ENCODE_OPTIONS = CBOREncodeOptions.Default;
    private static final String HANDOVER_TYPE = "OpenID4VPHandover";
    private static final String HASH_ALGORITHM = "SHA-256";

    private String clientId;
    private String nonce;
    private byte[] jwkThumbprint;
    private String responseUri;
    private String mdocGeneratedNonce;

    public SessionTranscriptBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public SessionTranscriptBuilder nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public SessionTranscriptBuilder jwkThumbprint(byte[] jwkThumbprint) {
        this.jwkThumbprint = jwkThumbprint;
        return this;
    }

    public SessionTranscriptBuilder responseUri(String responseUri) {
        this.responseUri = responseUri;
        return this;
    }

    public SessionTranscriptBuilder mdocGeneratedNonce(String mdocGeneratedNonce) {
        this.mdocGeneratedNonce = mdocGeneratedNonce;
        return this;
    }

    public void validate() {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("Missing expected client_id for SessionTranscript");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalStateException("Missing expected nonce for SessionTranscript");
        }
        if (responseUri == null || responseUri.isBlank()) {
            throw new IllegalStateException("Missing expected response_uri for SessionTranscript");
        }
    }

    /**
     * Builds the SessionTranscript using the OpenID4VP 1.0 format (Appendix B.3.2.2).
     * Requires clientId, nonce, and responseUri; jwkThumbprint is optional.
     */
    public CBORObject build() throws Exception {
        validate();

        byte[] hash = computeHandoverHash();
        LOG.debug("buildSessionTranscript (OID4VP 1.0) inputs: clientId='{}', nonce='{}', responseUri='{}'",
                clientId, nonce, responseUri);

        CBORObject handover = CBORObject.NewArray();
        handover.Add(HANDOVER_TYPE);
        handover.Add(hash);

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(handover);
        return sessionTranscript;
    }

    /**
     * Builds the SessionTranscript using the ISO 18013-7 Annex B.4.4 format.
     * Requires mdocGeneratedNonce (from JWE {@code apu} header) in addition to the standard fields.
     * Used by wallets that implement the ISO 18013-7 handover (e.g. German EUDI wallet).
     */
    public CBORObject buildIso18013_7() throws Exception {
        validate();
        if (mdocGeneratedNonce == null || mdocGeneratedNonce.isBlank()) {
            throw new IllegalStateException("Missing mdoc_generated_nonce for ISO 18013-7 SessionTranscript");
        }

        MessageDigest sha256 = MessageDigest.getInstance(HASH_ALGORITHM);

        // SHA-256(CBOR([clientId, mdocGeneratedNonce]))
        CBORObject clientIdArray = CBORObject.NewArray();
        clientIdArray.Add(clientId);
        clientIdArray.Add(mdocGeneratedNonce);
        byte[] clientIdHash = sha256.digest(clientIdArray.EncodeToBytes(ENCODE_OPTIONS));

        // SHA-256(CBOR([responseUri, mdocGeneratedNonce]))
        CBORObject responseUriArray = CBORObject.NewArray();
        responseUriArray.Add(responseUri);
        responseUriArray.Add(mdocGeneratedNonce);
        byte[] responseUriHash = sha256.digest(responseUriArray.EncodeToBytes(ENCODE_OPTIONS));

        LOG.debug("buildSessionTranscript (ISO 18013-7) inputs: clientId='{}', responseUri='{}', mdocGeneratedNonce='{}', nonce='{}'",
                clientId, responseUri, mdocGeneratedNonce, nonce);

        CBORObject handover = CBORObject.NewArray();
        handover.Add(clientIdHash);
        handover.Add(responseUriHash);
        handover.Add(nonce);

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(handover);
        return sessionTranscript;
    }

    private byte[] computeHandoverHash() throws Exception {
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
        return MessageDigest.getInstance(HASH_ALGORITHM).digest(infoBytes);
    }

    public static SessionTranscriptBuilder create() {
        return new SessionTranscriptBuilder();
    }
}
