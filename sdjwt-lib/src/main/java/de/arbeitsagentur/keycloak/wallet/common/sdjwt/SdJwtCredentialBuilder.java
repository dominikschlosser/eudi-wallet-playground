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
package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.authlete.sd.SDJWT;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtUtils;
import java.time.Duration;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Builds SD-JWT credentials (issuer-facing utility).
 * Supports algorithm negotiation based on the signing key type:
 * - EC keys: ES256 (P-256), ES384 (P-384), ES512 (P-521)
 * - RSA keys: RS256
 */
public class SdJwtCredentialBuilder {
    private final ObjectMapper objectMapper;
    private final JWK signingKey;
    private final Duration credentialTtl;
    private final JWSAlgorithm algorithmOverride;

    public SdJwtCredentialBuilder(ObjectMapper objectMapper,
                                  ECKey signingKey,
                                  Duration credentialTtl) {
        this(objectMapper, (JWK) signingKey, credentialTtl, null);
    }

    public SdJwtCredentialBuilder(ObjectMapper objectMapper,
                                  JWK signingKey,
                                  Duration credentialTtl) {
        this(objectMapper, signingKey, credentialTtl, null);
    }

    public SdJwtCredentialBuilder(ObjectMapper objectMapper,
                                  JWK signingKey,
                                  Duration credentialTtl,
                                  JWSAlgorithm algorithmOverride) {
        this.objectMapper = objectMapper;
        this.signingKey = signingKey;
        this.credentialTtl = credentialTtl;
        this.algorithmOverride = algorithmOverride;
    }

    public CredentialBuildResult build(String configurationId, String vct, String issuer,
                                       Map<String, Object> claims, JsonNode cnf) {
        try {
            SDObjectBuilder builder = new SDObjectBuilder();
            List<Disclosure> disclosures = new ArrayList<>();
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof Map<?, ?> mapValue) {
                    SDObjectBuilder inner = new SDObjectBuilder();
                    for (Map.Entry<?, ?> innerEntry : mapValue.entrySet()) {
                        Disclosure innerDisclosure = inner.putSDClaim(
                                String.valueOf(innerEntry.getKey()), innerEntry.getValue());
                        if (innerDisclosure != null) {
                            disclosures.add(innerDisclosure);
                        }
                    }
                    value = inner.build();
                }
                Disclosure disclosure = builder.putSDClaim(entry.getKey(), value);
                if (disclosure != null) {
                    disclosures.add(disclosure);
                }
            }
            Map<String, Object> payload = builder.build();
            payload.put("vct", vct);
            payload.put("iss", issuer);
            payload.put("iat", Instant.now().getEpochSecond());
            payload.put("exp", Instant.now().plus(credentialTtl).getEpochSecond());
            if (cnf != null) {
                payload.put("cnf", objectMapper.convertValue(cnf, Map.class));
            }
            SignedJWT jwt = sign(payload);
            String sdJwt = new SDJWT(jwt.serialize(), disclosures, null).toString();
            Map<String, Object> disclosed = SdJwtUtils.extractDisclosedClaims(SdJwtUtils.split(sdJwt), objectMapper);
            Map<String, Object> decoded = new LinkedHashMap<>();
            decoded.put("iss", issuer);
            decoded.put("credential_configuration_id", configurationId);
            decoded.put("vct", vct);
            decoded.put("iat", payload.get("iat"));
            decoded.put("exp", payload.get("exp"));
            if (cnf != null) {
                decoded.put("cnf", objectMapper.convertValue(cnf, Map.class));
            }
            decoded.put("claims", disclosed);
            return new CredentialBuildResult(sdJwt,
                    disclosures.stream().map(Disclosure::getDisclosure).toList(),
                    decoded,
                    vct,
                    "dc+sd-jwt");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SD-JWT", e);
        }
    }

    private SignedJWT sign(Map<String, Object> claims) throws JOSEException {
        JWSAlgorithm algorithm = resolveAlgorithm();
        JWSSigner signer = createSigner();
        String keyId = Optional.ofNullable(signingKey.getKeyID())
                .orElse("issuer-" + algorithm.getName().toLowerCase());
        JWSHeader header = new JWSHeader.Builder(algorithm)
                .keyID(keyId)
                .type(new JOSEObjectType("dc+sd-jwt"))
                .build();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getValue() != null) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }
        }
        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(signer);
        return jwt;
    }

    private JWSAlgorithm resolveAlgorithm() {
        if (algorithmOverride != null) {
            return algorithmOverride;
        }
        if (signingKey instanceof ECKey ecKey) {
            Curve curve = ecKey.getCurve();
            if (Curve.P_256.equals(curve)) {
                return JWSAlgorithm.ES256;
            } else if (Curve.P_384.equals(curve)) {
                return JWSAlgorithm.ES384;
            } else if (Curve.P_521.equals(curve)) {
                return JWSAlgorithm.ES512;
            }
            return JWSAlgorithm.ES256;
        }
        if (signingKey instanceof RSAKey) {
            return JWSAlgorithm.RS256;
        }
        return JWSAlgorithm.ES256;
    }

    private JWSSigner createSigner() throws JOSEException {
        if (signingKey instanceof ECKey ecKey) {
            return new ECDSASigner(ecKey);
        }
        if (signingKey instanceof RSAKey rsaKey) {
            return new RSASSASigner(rsaKey);
        }
        throw new JOSEException("Unsupported key type: " + signingKey.getKeyType());
    }
}
