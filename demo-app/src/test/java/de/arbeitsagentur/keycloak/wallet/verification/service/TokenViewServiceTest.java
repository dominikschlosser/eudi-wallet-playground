package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocCredentialBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.CredentialBuildResult;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class TokenViewServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void rendersMdocPrettyView() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"), null);
        assertThat(new MdocParser().prettyPrint(built.encoded())).isNotBlank();

        VerifierKeyService verifierKeyService = Mockito.mock(VerifierKeyService.class);
        when(verifierKeyService.decrypt(anyString())).thenAnswer(inv -> inv.getArgument(0));
        TokenViewService service = new TokenViewService(verifierKeyService, objectMapper);

        List<String> views = service.mdocViews(List.of(built.encoded()));
        assertThat(views).isNotEmpty();
        assertThat(views.get(0)).contains("docType").contains("given_name");
    }
}
