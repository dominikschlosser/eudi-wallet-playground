package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtParserTest {

    private final SdJwtParser parser = new SdJwtParser(new ObjectMapper());
    private SdJwtCredentialBuilder builder() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        return new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));
    }

    @Test
    void detectsAndParsesSdJwt() throws Exception {
        CredentialBuildResult built = builder().build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);
        String sdJwt = built.encoded();

        assertThat(parser.isSdJwt(sdJwt)).isTrue();
        assertThat(parser.signedJwt(sdJwt)).isNotBlank();
        assertThat(parser.disclosures(sdJwt)).isNotEmpty();
    }

    @Test
    void extractsClaimsAndRebuilds() throws Exception {
        CredentialBuildResult built = builder().build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("address.country", "DE", "given_name", "Alice"), null);

        Map<String, Object> claims = parser.extractDisclosedClaims(built.encoded());
        assertThat(claims).containsEntry("address.country", "DE");
        assertThat(parser.extractVct(built.encoded())).isEqualTo("urn:example:vct");

        String rebuilt = parser.rebuildForRequestedClaims(built.encoded(), List.of(), Set.of("address.country"));
        Map<String, Object> rebuiltClaims = parser.extractDisclosedClaims(rebuilt);
        assertThat(rebuiltClaims).containsEntry("address.country", "DE");
        assertThat(rebuiltClaims).doesNotContainKey("given_name");
    }

    @Test
    void appendsGivenDisclosures() {
        String base = "h.p.s";
        String disclosureA = "WyJmb28iLCJiYXIiXQ";
        String rebuilt = parser.withDisclosures(base, List.of(disclosureA));
        assertThat(rebuilt).isEqualTo(base + "~" + disclosureA);
    }
}
