package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import de.arbeitsagentur.keycloak.wallet.common.mdoc.CredentialBuildResult;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocCredentialBuilderTest {

    @Test
    void buildsMdocWithHexEncodingAndIssuerSigned() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));

        CredentialBuildResult result = builder.build("cfg-id", "urn:example:pid", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);

        assertThat(result.format()).isEqualTo("mso_mdoc");
        assertThat(result.encoded()).matches("^[0-9a-fA-F]+$");
        assertThat(result.decoded().get("issuerSigned")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.decoded().get("claims");
        assertThat(claims).containsEntry("given_name", "Alice");
    }

    @Test
    void usesIsoNamespaceForMdl() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));

        String docType = "org.iso.18013.5.1.mDL";
        CredentialBuildResult result = builder.build("cfg-mdl", docType, "https://issuer.example/mock",
                Map.of("family_name", "Doe", "given_name", "Jane"), null);

        assertThat(result.vct()).isEqualTo(docType);
        @SuppressWarnings("unchecked")
        Map<String, Object> decoded = (Map<String, Object>) result.decoded().get("issuerSigned");
        assertThat(decoded).isNotNull();
        @SuppressWarnings("unchecked")
        Map<String, Object> nameSpaces = (Map<String, Object>) decoded.get("nameSpaces");
        assertThat(nameSpaces).containsKey("org.iso.18013.5.1");
    }
}
