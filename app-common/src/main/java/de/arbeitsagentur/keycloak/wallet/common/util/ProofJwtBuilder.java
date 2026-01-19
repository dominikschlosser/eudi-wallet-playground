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
package de.arbeitsagentur.keycloak.wallet.common.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/**
 * Builder for OID4VCI proof JWTs.
 * <p>
 * Creates ES256-signed JWTs for credential issuance proof-of-possession.
 * Follows the openid4vci-proof+jwt specification.
 */
public final class ProofJwtBuilder {
    /** Default JWT type for OID4VCI proofs */
    public static final String TYPE_OPENID4VCI_PROOF = "openid4vci-proof+jwt";
    /** Default expiration duration */
    public static final Duration DEFAULT_EXPIRATION = Duration.ofSeconds(120);

    private final ECKey signingKey;
    private String audience;
    private String nonce;
    private String issuer;
    private Duration expiration = DEFAULT_EXPIRATION;
    private boolean includePublicKey = true;

    private ProofJwtBuilder(ECKey signingKey) {
        this.signingKey = signingKey;
    }

    /**
     * Creates a new builder with the given signing key.
     *
     * @param signingKey the EC key to sign with
     * @return a new builder instance
     */
    public static ProofJwtBuilder withKey(ECKey signingKey) {
        return new ProofJwtBuilder(signingKey);
    }

    /**
     * Sets the audience (issuer identifier) for the proof.
     */
    public ProofJwtBuilder audience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Sets the nonce from the credential issuer.
     */
    public ProofJwtBuilder nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the issuer claim (typically the wallet DID).
     */
    public ProofJwtBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Sets the expiration duration from now.
     */
    public ProofJwtBuilder expiration(Duration expiration) {
        this.expiration = expiration;
        return this;
    }

    /**
     * Controls whether to include the public JWK in the header.
     */
    public ProofJwtBuilder includePublicKey(boolean include) {
        this.includePublicKey = include;
        return this;
    }

    /**
     * Builds and signs the proof JWT.
     *
     * @return the serialized JWT
     * @throws IllegalStateException if signing fails
     */
    public String build() {
        try {
            JWSHeader header = buildHeader();
            JWTClaimsSet claims = buildClaims();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(signingKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign proof JWT", e);
        }
    }

    private JWSHeader buildHeader() {
        JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(TYPE_OPENID4VCI_PROOF));
        if (includePublicKey) {
            builder.jwk(signingKey.toPublicJWK());
        }
        return builder.build();
    }

    private JWTClaimsSet buildClaims() {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issueTime(new Date());

        if (audience != null && !audience.isBlank()) {
            builder.audience(audience);
        }
        if (issuer != null && !issuer.isBlank()) {
            builder.issuer(issuer);
        }
        if (nonce != null && !nonce.isBlank()) {
            builder.claim("nonce", nonce);
        }
        if (expiration != null && !expiration.isZero()) {
            builder.expirationTime(Date.from(Instant.now().plus(expiration)));
        }
        return builder.build();
    }
}
