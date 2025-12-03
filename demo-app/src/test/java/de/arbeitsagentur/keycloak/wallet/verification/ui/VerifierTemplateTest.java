package de.arbeitsagentur.keycloak.wallet.verification.ui;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class VerifierTemplateTest {

    @Test
    void formatOptionsIncludeMdocAndAll() throws Exception {
        String html = resource("templates/verifier.html");
        Document document = Jsoup.parse(html);
        List<String> datalistValues = document.select("datalist#dcql-format-options > option").eachAttr("value");
        assertThat(datalistValues).containsExactlyInAnyOrder("dc+sd-jwt", "mso_mdoc", "all");
        assertThat(html).contains("const knownFormats = [\"dc+sd-jwt\", \"mso_mdoc\", \"all\"]");
        assertThat(html).doesNotContain("jwt_vc");
        assertThat(html).doesNotContain("format-custom");
    }

    @Test
    void verifierResultOffersCborLink() throws Exception {
        String html = resource("templates/verifier-result.html");
        Document document = Jsoup.parse(html);
        assertThat(document.select(".token-hint").eachText())
                .anyMatch(text -> text.toLowerCase().contains("mDoc".toLowerCase()) || text.toLowerCase().contains("mdoc"));
        assertThat(html).contains("Built-in mDoc viewer");
    }

    private String resource(String path) throws Exception {
        var url = VerifierTemplateTest.class.getClassLoader().getResource(path);
        byte[] bytes = url != null ? url.openStream().readAllBytes() : null;
        return new String(Objects.requireNonNull(bytes, "Resource not found: " + path), StandardCharsets.UTF_8);
    }
}
