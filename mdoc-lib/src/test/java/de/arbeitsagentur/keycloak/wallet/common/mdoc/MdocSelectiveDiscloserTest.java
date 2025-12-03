package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MdocSelectiveDiscloserTest {

    private final MdocSelectiveDiscloser discloser = new MdocSelectiveDiscloser();
    private final MdocParser parser = new MdocParser();

    @Test
    void filtersRequestedClaimsAndKeepsDocType() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build(
                "cfg-id",
                "urn:example:pid",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder", "document_number", "12345"),
                null
        );

        String filtered = discloser.filter(built.encoded(), Set.of("given_name", "document_number"));
        Map<String, Object> claims = parser.extractClaims(filtered);

        assertThat(filtered).isNotBlank();
        assertThat(parser.extractDocType(filtered)).isEqualTo("urn:example:pid");
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("document_number", "12345")
                .doesNotContainKey("family_name");
    }

    @Test
    void returnsOriginalWhenNoRequests() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build(
                "cfg-id",
                "urn:example:pid",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice"),
                null
        );

        String filtered = discloser.filter(built.encoded(), Set.of());
        assertThat(filtered).isEqualTo(built.encoded());
    }
}
