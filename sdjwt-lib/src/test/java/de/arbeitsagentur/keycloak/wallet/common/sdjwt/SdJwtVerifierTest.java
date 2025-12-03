package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.TrustedIssuerResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtVerifierTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ECKey issuerKey;
    private TrustedIssuerResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        issuerKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("mock-issuer-es256")
                .generate();
        PublicKey issuerPublic = issuerKey.toECPublicKey();
        resolver = new TrustedIssuerResolver() {
            @Override
            public boolean verify(SignedJWT jwt, String trustListId) {
                return TrustedIssuerResolver.verifyWithKey(jwt, issuerPublic);
            }

            @Override
            public List<PublicKey> publicKeys(String trustListId) {
                return List.of(issuerPublic);
            }
        };
    }

    @Test
    void verifiesSdJwtWithKeyBinding() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("wallet-es256")
                .generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.readTree(holderKey.toPublicJWK().toJSONString()));

        SdJwtCredentialBuilder builder = new SdJwtCredentialBuilder(objectMapper, issuerKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), cnf);
        String sdJwt = built.encoded();

        String keyBindingJwt = buildKeyBinding(holderKey, sdJwt, "aud-123", "nonce-123");

        SdJwtVerifier verifier = new SdJwtVerifier(objectMapper, resolver);
        Map<String, Object> claims = verifier.verify(sdJwt, "trust-list-mock", "aud-123", "nonce-123", keyBindingJwt, null);

        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(claims).containsEntry("key_binding_jwt", keyBindingJwt);
    }

    private String buildKeyBinding(ECKey holderKey, String vpToken, String audience, String nonce) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .keyID(holderKey.getKeyID())
                .build();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer("did:example:wallet")
                .claim("vp_token", vpToken)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", nonce)
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
        if (audience != null) {
            claims.audience(audience);
        }
        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }
}
