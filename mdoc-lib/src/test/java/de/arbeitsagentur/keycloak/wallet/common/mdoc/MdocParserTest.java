package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocParserTest {

    private final MdocParser parser = new MdocParser();

    @Test
    void parsesClaimsAndDocType() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:pid", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);
        String hex = built.encoded();

        assertThat(parser.isHex(hex)).isTrue();
        Map<String, Object> claims = parser.extractClaims(hex);
        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(parser.extractDocType(hex)).isEqualTo("urn:example:pid");
    }
}
