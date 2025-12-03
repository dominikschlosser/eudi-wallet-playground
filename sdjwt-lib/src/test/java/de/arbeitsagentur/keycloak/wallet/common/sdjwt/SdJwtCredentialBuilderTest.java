package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtCredentialBuilderTest {

    @Test
    void buildsSdJwtWithDisclosuresAndClaims() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        SdJwtCredentialBuilder builder = new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));

        CredentialBuildResult result = builder.build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"), null);

        assertThat(result.format()).isEqualTo("dc+sd-jwt");
        assertThat(result.encoded()).contains("~");
        assertThat(result.disclosures()).isNotEmpty();
        assertThat(result.decoded().get("claims")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.decoded().get("claims");
        assertThat(claims).containsEntry("given_name", "Alice");
    }
}
