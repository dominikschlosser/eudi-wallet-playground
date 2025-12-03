package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtUtilsTest {

    private SdJwtCredentialBuilder builder() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        return new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));
    }

    @Test
    void splitsAndValidatesDisclosures() throws Exception {
        CredentialBuildResult built = builder().build(
                "cfg-id",
                "urn:example:vct",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"),
                null
        );

        SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(built.encoded());
        assertThat(parts.signedJwt()).isNotBlank();
        assertThat(parts.disclosures()).hasSize(2);

        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        ObjectMapper mapper = new ObjectMapper();
        assertThat(SdJwtUtils.verifyDisclosures(jwt, parts, mapper)).isTrue();

        Map<String, Object> claims = SdJwtUtils.extractDisclosedClaims(parts, mapper);
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("family_name", "Holder");
    }
}
