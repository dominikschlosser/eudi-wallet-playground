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
import java.util.Base64;

/**
 * Builder for mDoc SessionTranscript as defined in ISO/IEC 18013-5 and OpenID4VP.
 * <p>
 * SessionTranscript structure for OpenID4VP:
 * <pre>
 * SessionTranscript = [
 *   DeviceEngagementBytes: null,
 *   EReaderKeyBytes: null,
 *   Handover: [
 *     "OpenID4VPHandover",
 *     SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))
 *   ]
 * ]
 * </pre>
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

    /**
     * Validates the required inputs for SessionTranscript.
     *
     * @throws IllegalStateException if required inputs are missing
     */
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
     * Builds the SessionTranscript CBOR object.
     *
     * @return the SessionTranscript as CBORObject
     * @throws Exception if hashing fails
     */
    public CBORObject build() throws Exception {
        validate();

        byte[] hash = computeHandoverHash();
        LOG.debug("buildSessionTranscript inputs: clientId='{}', nonce='{}', jwkThumbprint={}, responseUri='{}' -> hash={}",
                clientId, nonce,
                jwkThumbprint != null ? Base64.getUrlEncoder().withoutPadding().encodeToString(jwkThumbprint) : "null",
                responseUri,
                Base64.getUrlEncoder().withoutPadding().encodeToString(hash));

        CBORObject handover = CBORObject.NewArray();
        handover.Add(HANDOVER_TYPE);
        handover.Add(hash);

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null); // DeviceEngagementBytes
        sessionTranscript.Add(CBORObject.Null); // EReaderKeyBytes
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

    /**
     * Creates a new builder instance.
     */
    public static SessionTranscriptBuilder create() {
        return new SessionTranscriptBuilder();
    }
}
