package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.CredentialBuildResult;
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
 */
public class SdJwtCredentialBuilder {
    private final ObjectMapper objectMapper;
    private final ECKey signingKey;
    private final Duration credentialTtl;

    public SdJwtCredentialBuilder(ObjectMapper objectMapper,
                                  ECKey signingKey,
                                  Duration credentialTtl) {
        this.objectMapper = objectMapper;
        this.signingKey = signingKey;
        this.credentialTtl = credentialTtl;
    }

    public CredentialBuildResult build(String configurationId, String vct, String issuer,
                                       Map<String, Object> claims, JsonNode cnf) {
        try {
            SDObjectBuilder builder = new SDObjectBuilder();
            List<Disclosure> disclosures = new ArrayList<>();
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                Disclosure disclosure = builder.putSDClaim(entry.getKey(), entry.getValue());
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
        ECKey key = signingKey;
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(Optional.ofNullable(key.getKeyID()).orElse("mock-issuer-es256"))
                .type(JOSEObjectType.JWT)
                .build();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getValue() != null) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }
        }
        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(key));
        return jwt;
    }
}
