/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.verification.ui;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    void verifierResultDoesNotRenderTokenHints() throws Exception {
        String html = resource("templates/verifier-result.html");
        Document document = Jsoup.parse(html);
        assertThat(document.select(".token-hint")).isEmpty();
        assertThat(html).contains("Decoded mDoc");
    }

    /**
     * Verifies that every standalone function call statement in the verifier script
     * references a function that is actually defined. This catches stale references
     * like "refreshQueryPanels()" that cause ReferenceErrors at runtime.
     */
    @Test
    void allCalledJsFunctionsAreDefined() throws Exception {
        String html = resource("templates/verifier.html");
        Document document = Jsoup.parse(html);
        String scriptContent = document.select("script").stream()
                .map(el -> el.data())
                .reduce("", (a, b) -> a + "\n" + b);

        // Collect function definitions: "function name(" and "const/let/var name = ..."
        Set<String> defined = new LinkedHashSet<>();
        Matcher defMatcher = Pattern.compile(
                "(?:(?:async\\s+)?function\\s+(\\w+)\\s*\\()" +
                "|(?:(?:const|let|var)\\s+(\\w+)\\s*=)"
        ).matcher(scriptContent);
        while (defMatcher.find()) {
            for (int g = 1; g <= defMatcher.groupCount(); g++) {
                if (defMatcher.group(g) != null) {
                    defined.add(defMatcher.group(g));
                }
            }
        }

        // Match standalone function call statements: lines like "  functionName(...);"
        // These are the calls most likely to cause ReferenceErrors — a bare call at statement level.
        Matcher callMatcher = Pattern.compile("^\\s+([a-zA-Z_]\\w*)\\s*\\(", Pattern.MULTILINE)
                .matcher(scriptContent);
        Set<String> called = new LinkedHashSet<>();
        Set<String> ignore = Set.of(
                "if", "for", "while", "switch", "catch", "return", "throw", "new", "typeof", "delete",
                "function", "async", "const", "let", "var", "class", "import", "export",
                "alert", "fetch", "setTimeout", "setInterval", "clearTimeout", "clearInterval",
                "console", "requestAnimationFrame", "queueMicrotask"
        );
        while (callMatcher.find()) {
            String name = callMatcher.group(1);
            if (!ignore.contains(name)) {
                called.add(name);
            }
        }

        Set<String> undefined = new LinkedHashSet<>(called);
        undefined.removeAll(defined);
        assertThat(undefined)
                .as("Functions called but not defined in verifier.html script")
                .isEmpty();
    }

    private String resource(String path) throws Exception {
        var url = VerifierTemplateTest.class.getClassLoader().getResource(path);
        byte[] bytes = url != null ? url.openStream().readAllBytes() : null;
        return new String(Objects.requireNonNull(bytes, "Resource not found: " + path), StandardCharsets.UTF_8);
    }
}
