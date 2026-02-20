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
package de.arbeitsagentur.keycloak.wallet.common.credential;

import de.arbeitsagentur.keycloak.wallet.common.credential.EtsiTrustListParser.EtsiTrustList;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test that fetches real ETSI trust lists from the BMI test sandbox
 * and verifies that {@link EtsiTrustListParser} can parse them successfully.
 *
 * @see <a href="https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/">BMI Test Trust Lists</a>
 */
@Tag("integration")
class EtsiTrustListBmiIntegrationTest {

    private static final String BMI_BASE_URL =
            "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/";

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "pid-provider.jwt",
            "registrar.jwt",
            "wallet-provider.jwt",
            "wrpac-provider.jwt",
            "wrprc-provider.jwt"
    })
    void parsesBmiTrustList(String filename) throws Exception {
        String jwt = fetchTrustList(BMI_BASE_URL + filename);

        EtsiTrustList result = EtsiTrustListParser.parse(jwt);

        assertThat(result.label()).as("label").isNotBlank();
        assertThat(result.loTEType()).as("loTEType").isNotBlank();
        assertThat(result.entities()).as("entities").isNotEmpty();

        for (var entity : result.entities()) {
            assertThat(entity.name()).as("entity name").isNotBlank();
        }

        List<PublicKey> allKeys = result.allPublicKeys();

        System.out.printf("[%s] label=%s, loTEType=%s, entities=%d, keys=%d%n",
                filename, result.label(), result.loTEType(),
                result.entities().size(), allKeys.size());
    }

    @Test
    void pidProviderTrustListContainsKeys() throws Exception {
        String jwt = fetchTrustList(BMI_BASE_URL + "pid-provider.jwt");

        EtsiTrustList result = EtsiTrustListParser.parse(jwt);

        assertThat(result.label()).isEqualTo("SPRIND GmbH");
        assertThat(result.allPublicKeys()).as("PID provider must have extractable public keys").isNotEmpty();
    }

    private static String fetchTrustList(String url) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assumeTrue(response.statusCode() == 200,
                    "BMI trust list endpoint returned " + response.statusCode() + " for " + url);
            String body = response.body().trim();
            assumeTrue(body != null && !body.isBlank(),
                    "BMI trust list endpoint returned empty body for " + url);
            return body;
        } catch (Exception e) {
            assumeTrue(false, "BMI trust list endpoint not reachable: " + e.getMessage());
            return null; // unreachable
        }
    }
}
