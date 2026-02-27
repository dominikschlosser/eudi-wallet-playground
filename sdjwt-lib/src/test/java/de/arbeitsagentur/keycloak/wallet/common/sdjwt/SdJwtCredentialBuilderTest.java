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
package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtCredentialBuilderTest {

    private SdJwtCredentialBuilder builder() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        return new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));
    }

    @Test
    void buildsSdJwtWithDisclosuresAndClaims() throws Exception {
        CredentialBuildResult result = builder().build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"), null);

        assertThat(result.format()).isEqualTo("dc+sd-jwt");
        assertThat(result.encoded()).contains("~");
        assertThat(result.disclosures()).isNotEmpty();
        assertThat(result.decoded().get("claims")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.decoded().get("claims");
        assertThat(claims).containsEntry("given_name", "Alice");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildsPerElementArrayDisclosuresForListValues() throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Alice");
        claims.put("nationalities", List.of("DE", "FR"));

        CredentialBuildResult result = builder().build("cfg-id", "urn:eudi:pid:1",
                "https://issuer.example/mock", claims, null);

        // Parse the SD-JWT and extract all disclosed claims
        ObjectMapper mapper = new ObjectMapper();
        SdJwtParser parser = new SdJwtParser(mapper);
        Map<String, Object> disclosed = parser.extractDisclosedClaims(result.encoded());

        assertThat(disclosed).containsEntry("given_name", "Alice");
        assertThat(disclosed).containsKey("nationalities");
        List<String> nationalities = (List<String>) disclosed.get("nationalities");
        assertThat(nationalities).containsExactly("DE", "FR");

        // Each array element should have its own disclosure (2 element + 1 parent = at least 3 for nationalities)
        // Plus 1 for given_name = at least 4 total disclosures
        assertThat(result.disclosures().size()).isGreaterThanOrEqualTo(4);
    }

    @Test
    @SuppressWarnings("unchecked")
    void arrayElementDisclosuresAreIndividuallyFilterable() throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Alice");
        claims.put("nationalities", List.of("DE"));

        CredentialBuildResult result = builder().build("cfg-id", "urn:eudi:pid:1",
                "https://issuer.example/mock", claims, null);

        // Filter for only nationalities — given_name should be excluded
        ObjectMapper mapper = new ObjectMapper();
        SdJwtParser parser = new SdJwtParser(mapper);
        SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser(parser);

        String filtered = discloser.filter(
                result.encoded(),
                List.of(new SdJwtSelectiveDiscloser.ClaimRequest("nationalities", null)),
                java.util.Set.of("nationalities"));

        Map<String, Object> filteredClaims = parser.extractDisclosedClaims(filtered);
        assertThat(filteredClaims).containsKey("nationalities");
        assertThat((List<String>) filteredClaims.get("nationalities")).containsExactly("DE");
        assertThat(filteredClaims).doesNotContainKey("given_name");
    }

    @Test
    @SuppressWarnings("unchecked")
    void nestedMapClaimsAreRecursivelyDisclosed() throws Exception {
        Map<String, Object> address = new LinkedHashMap<>();
        address.put("street_address", "Main St 1");
        address.put("locality", "Berlin");

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Alice");
        claims.put("address", address);

        CredentialBuildResult result = builder().build("cfg-id", "urn:eudi:pid:1",
                "https://issuer.example/mock", claims, null);

        ObjectMapper mapper = new ObjectMapper();
        SdJwtParser parser = new SdJwtParser(mapper);
        Map<String, Object> disclosed = parser.extractDisclosedClaims(result.encoded());

        assertThat(disclosed).containsKey("address");
        Map<String, Object> disclosedAddress = (Map<String, Object>) disclosed.get("address");
        assertThat(disclosedAddress)
                .containsEntry("street_address", "Main St 1")
                .containsEntry("locality", "Berlin");
    }
}
