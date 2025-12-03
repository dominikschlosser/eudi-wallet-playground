package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocViewerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void detectsAndRendersMdoc() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);

        MdocViewer viewer = new MdocViewer(objectMapper);
        assertThat(viewer.hasMdocToken(List.of(built.encoded()), t -> t)).isTrue();

        List<String> views = viewer.views(List.of(built.encoded()), t -> t);
        assertThat(views).isNotEmpty();
        assertThat(views.get(0)).contains("given_name").contains("docType");
    }
}
