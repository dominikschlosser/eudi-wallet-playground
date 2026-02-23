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
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtSelectiveDiscloserTest {

    private SdJwtCredentialBuilder builder() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        return new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));
    }

    @Test
    void filtersOnlyRequestedClaims() throws Exception {
        CredentialBuildResult built = builder().build(
                "cfg-id",
                "urn:example:vct",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder", "document_number", "DOC-123"),
                null
        );

        SdJwtParser parser = new SdJwtParser(new ObjectMapper());
        SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser(parser);

        String filtered = discloser.filter(
                built.encoded(),
                List.of(
                        new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("document_number", null)
                ),
                Set.of("given_name", "document_number"));

        Map<String, Object> claims = parser.extractDisclosedClaims(filtered);
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("document_number", "DOC-123")
                .doesNotContainKey("family_name");

        List<String> filteredDisclosures = discloser.filterDisclosures(
                SdJwtUtils.split(built.encoded()).disclosures(),
                List.of(new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null)),
                Set.of("given_name"));
        assertThat(filteredDisclosures).hasSize(1);
    }

    @Test
    @SuppressWarnings("unchecked")
    void filtersRecursiveDisclosures() throws Exception {
        Map<String, Object> address = new LinkedHashMap<>();
        address.put("locality", "Berlin");
        address.put("country", "DE");
        address.put("street_address", "Unter den Linden 1");

        Map<String, Object> placeOfBirth = new LinkedHashMap<>();
        placeOfBirth.put("locality", "Hamburg");

        CredentialBuildResult built = builder().build(
                "cfg-id",
                "urn:eudi:pid:de:1",
                "https://issuer.example/mock",
                Map.of(
                        "given_name", "Alice",
                        "family_name", "Holder",
                        "address", address,
                        "place_of_birth", placeOfBirth
                ),
                null
        );

        ObjectMapper mapper = new ObjectMapper();
        SdJwtParser parser = new SdJwtParser(mapper);
        SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser(parser);

        // Verify all claims are correctly extracted from the full SD-JWT
        Map<String, Object> allClaims = parser.extractDisclosedClaims(built.encoded());
        assertThat(allClaims).containsKey("address");
        assertThat((Map<String, Object>) allClaims.get("address"))
                .containsEntry("locality", "Berlin")
                .containsEntry("country", "DE")
                .containsEntry("street_address", "Unter den Linden 1");
        assertThat(allClaims).containsKey("place_of_birth");
        assertThat((Map<String, Object>) allClaims.get("place_of_birth"))
                .containsEntry("locality", "Hamburg");

        // Filter for address + locality (parent + child) — should include both disclosures
        String filtered = discloser.filter(
                built.encoded(),
                List.of(
                        new SdJwtSelectiveDiscloser.ClaimRequest("address", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("locality", null)
                ),
                Set.of("address", "locality"));

        Map<String, Object> filteredClaims = parser.extractDisclosedClaims(filtered);
        assertThat(filteredClaims).containsKey("address");
        assertThat((Map<String, Object>) filteredClaims.get("address"))
                .containsKey("locality");

        // Filter for just given_name — no address-related disclosures
        String onlyName = discloser.filter(
                built.encoded(),
                List.of(new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null)),
                Set.of("given_name"));

        Map<String, Object> nameClaims = parser.extractDisclosedClaims(onlyName);
        assertThat(nameClaims)
                .containsEntry("given_name", "Alice")
                .doesNotContainKey("address")
                .doesNotContainKey("family_name");
    }

    /**
     * Tests parsing and filtering of a real BMI sandbox PID credential with recursive
     * selective disclosure. The address and place_of_birth claims use nested _sd arrays:
     * the parent disclosure value is {"_sd": [hash1, hash2, ...]}, and child disclosures
     * (locality, street_address, etc.) are separate entries with flat names.
     */
    @Test
    @SuppressWarnings("unchecked")
    void parsesAndFiltersBmiSandboxRecursiveDisclosures() throws Exception {
        String bmiCredential = "eyJ4NWMiOlsiTUlJQ1pqQ0NBZzJnQXdJQkFnSUJBVEFLQmdncWhrak9QUVFEQWpCcU1Rc3dDUVlEVlFRR0V3SkVSVEVQTUEwR0ExVUVCd3dHUW1WeWJHbHVNUjB3R3dZRFZRUUtEQlJDZFc1a1pYTmtjblZqYTJWeVpXa2dSMjFpU0RFUk1BOEdBMVVFQ3d3SVZDQkRVeUJKUkVVeEdEQVdCZ05WQkFNTUQxQkpSRkFnVUhKbGNISnZaQ0JEUVRBZUZ3MHlOVEV4TWpZeE5ERXlNVE5hRncweU5qRXlNekV4TkRFeU1UTmFNRTh4Q3pBSkJnTlZCQVlUQWtSRk1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVLTUFnR0ExVUVDd3dCU1RFVk1CTUdBMVVFQXd3TVVFbEVVQ0JRY21Wd2NtOWtNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVMS2l3bm5ycXNCYnpmczM2akR6ZFVrd2gxRGxHL0EwSVMyeFFLdDlMK0VzK3NMZURETnN6VVZBWFdCd09YaUJ6dmk1WlB0WlR4ZVo0dXk2MjArY1JoS09CdmpDQnV6QWRCZ05WSFE0RUZnUVV2ZTlHMng1Q0E0K1B2dlJmZjNNK0NnS1lvUTh3REFZRFZSMFRBUUgvQkFJd0FEQU9CZ05WSFE4QkFmOEVCQU1DQjRBd1d3WURWUjBSQkZRd1VvSW5jSEpsY0hKdlpDNXdhV1F0Y0hKdmRtbGtaWEl1WW5WdVpHVnpaSEoxWTJ0bGNtVnBMbVJsaGlkd2NtVndjbTlrTG5CcFpDMXdjbTkyYVdSbGNpNWlkVzVrWlhOa2NuVmphMlZ5WldrdVpHVXdId1lEVlIwakJCZ3dGb0FVRHd4WFhqQVBqaC9KVERtTXZTaGo5bXh6emQ0d0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ1FUODd2UUo3TGk0NnBmUkdnWTZFV1NFMEJJTTJ1OWE5WFBtRjE4Vnd5Zm9DSUdmNG1CczVrYW8yc3NUTS9CNzVlTHFEVXJXNDRnS21uMjdzNXRRZnZjRFoiXSwia2lkIjoiTUhNd2JxUnNNR294Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEVZTUJZR0ExVUVBd3dQVUVsRVVDQlFjbVZ3Y205a0lFTkJBZ0VCIiwidHlwIjoiZGMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiZHRvNFR3VTZEN3kxMUxYdTBDb05sc0FZS0szODlCeFVWZjFiTXI3VWJtdyIsIlQzZ05tMDZQTjVMNHF1Z1Vxd3Z5ZGFRbnVGeEpXQ2x1T25hNWhaNXR0Q0UiLCJLT2tPRVU3Ri1CT2pkNXdpS0JVZzR0cFZrUkVwMEhxdFJ0NUwyR2pkcGY0IiwiNG44NDRJME9ONTN2cFhaeDhOOTR5Ykc1b0xjUmNvSDhFTXZTdDBmSHAyMCIsInNLWlpKNGhGbUpMeFFaY2ZLRXdPWldoVkxqZlVacF9zT0xRZ3FLbzFibnMiLCI3bUszNTIyQVZzQ2JKRG4wQlNNMms4djRnN1V1RHhIT2dYWE5BbFNicEJjIiwiamROclFxTWVrS1IwRWRJRnpqR2FtVEp2d0tvTjY1d3ZfN2xSODV0VlRINCIsIkRwQ1NOc0E3ajdDdEExd2c2NHRXUndFLVRBYjR3ckdkVjgteXdOLTA1VzAiLCJOc0F6bEZhUWNJenozV1hmakdXT281NFNKcUdHbFhQei0yM2hDZ0hhV09ZIiwiOGd2aF9EMTJicUwxWWs3c01NeUppNUdCR2RGNGRuZTYyZG15UXA4ZGJMSSIsImhvQmQ1T3ZCMlI5SzRicHpuelI3T3JpcTdTS01UOENMTmZnY3FpalEtUDAiXSwidmN0IjoidXJuOmV1ZGk6cGlkOmRlOjEiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6Imh0dHBzOi8vcHJlcHJvZC5waWQtcHJvdmlkZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjRsRUJoa3Q0UzJ2Wl8tMVh4WnotWEd3eWMzLWxPUzdkckx2MVNoaVBHVFEiLCJ5IjoiVkpseWdVWGNHVkR6dlZMUnZYR0dmU3RERzVJbGRzMUgtdnRnMkNJdHBLRSJ9fSwiZXhwIjoxNzcyNzU1MjAwLCJpYXQiOjE3NzE1NDU2MDAsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ1cmkiOiJodHRwczovL3ByZXByb2QucGlkLXByb3ZpZGVyLmJ1bmRlc2RydWNrZXJlaS5kZS9zdGF0dXMvN2M3MmFhYzktZTEyZS00YmVkLTkyYmYtOWUyOTBhZjJlODVmIiwiaWR4Ijo1M319fQ.IKy6xIaSZrHNihVi808p4QhA55FTdcWBritAtWis2jImdvKdryfFBZjfG833yq5GnbGn9fOiGF4j-5cWlB_3NQ~WyJyaGpYN0ExTFZ1ekJkSG1nNWdTQ05RIiwiaXNzdWluZ19jb3VudHJ5IiwiREUiXQ~WyJORWZyYnJoTnkwdjlRWlg2TGZjZjR3IiwiaXNzdWluZ19hdXRob3JpdHkiLCJERSJd~WyJEanJzU0NreUNZTE85WDJSTEtZMXhRIiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJwaFdIQWVQQTc1YVN3blJYVHEyeW53IiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyJsaEo1UDJnTnRvQWE2ODRyY1VqNVB3IiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyJMUmhoM1l4VmtqRmdkeVN2TE4wQnl3IiwiYmlydGhkYXRlIiwiMTk4NC0wOC0xMiJd~WyJkNlVpdkFqQkFaLUxvbHVadldMME1RIiwic291cmNlX2RvY3VtZW50X3R5cGUiLCJJRCJd~WyJRd1k2MUFGUjFCZ0l2ZlA0TEpmVVRBIiwiREUiXQ~WyI3OU5ZNDdrVjNQOVBJTnVjemtFMEJBIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiOFVzSHhOWFVxYk5aQ3F3RmZtSlM5Q2phN1lJQVZ6VXhCakJ4V0hzaDBqQSJ9LHsiLi4uIjoiOUE1Y01iZlRTeFJTc0hURUUxLUQ4UERSNWp1ZEg1VUI3eHIwRFdweDNHbyJ9XV0~WyI4ZHJ6UXdSRG52djBFZS1ON2gwWjdRIiwiMTIiLHRydWVd~WyJNelRoZWJ1MTlfUU9TZjNSZ19oYUNnIiwiMTQiLHRydWVd~WyI0R3Q3RkVEdEFpYll6ZzlMRWM1MVNRIiwiMTYiLHRydWVd~WyI3VktuQi1RUVdzeTh3NHIwcjExT3pRIiwiMTgiLHRydWVd~WyJSUzhKRGRwajJDTHpPUzhXYjhUTF9nIiwiMjEiLHRydWVd~WyJJSi1hSUlVMldZZHFoektORHpSbUV3IiwiNjUiLGZhbHNlXQ~WyI5N0pLMHg5WEhIcmlVVDFma2pGSG9nIiwiYWdlX2VxdWFsX29yX292ZXIiLHsiX3NkIjpbIlhGZzc3Umh2RXh4VnZUQ3Y5V3VWN2FQeEFOeVp3TktrdmVZVVR2QjVyd3ciLCJ1TDhoNk5lVDVaeFRqR19YcjhldWFBNHZQRDVGZ2tBYzNsXzd1VE0tcjJFIiwiSS1oVFA1WjFfbkVqTXZNU1lfdEhyMVA3enZac2xVdmc2NEtNMVdXcVZUayIsIk43TVR3SXJYeC1jQm8tSVlOdUt1eHdNbzNrWmJ3R1hCdm1PczN2dmhQTEEiLCJQNldxUkJDY2N1bWplc2hDT0NRTEpzNU5nbHVQTXV1V0lTUFFmeVZSbFNFIiwiQnlqR2J3RkE0UTZ5OG9peTJwZ05CdGZFYzRWZDlKcjJjUlZlbk5WRjNNMCJdfV0~WyJvcjNpaEN0Y2R0RnBHaVN4ZlQ1UHdnIiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyJldll4QVdMYnlPM29PZjB3N3VFdXhBIiwicGxhY2Vfb2ZfYmlydGgiLHsiX3NkIjpbIko3Y2xLOGc0Ui02UXkzU3Bma3BMQlpLQUk1bHQ5aTAyeTdFLUJuRjd3MGsiXX1d~WyJYLWJWMlJFSGR3RHNXQjNIUWxYYjNnIiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyJ4QlNYN2Z2V0NhWHVwYjdOS0VGYzh3IiwiY291bnRyeSIsIkRFIl0~WyI0cVNyWFFHT2pfSFhJS281U1hxMVl3IiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJKSVZvWmdGd2ZUM1dkbVRJY3F2YmpnIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkHhup5FIDE3Il0~WyI3bFI2d2xXZkVVX0o5UDhjZFFfb3VRIiwiYWRkcmVzcyIseyJfc2QiOlsiMkZNbXQ5b21KU0EtQ1hpcVAzZlhaeEVpZ0I5WVdiRDRsU2d1MmhGVldUZyIsInRVZWltTGZHMFNPemJJdVF3aUhubVJpT1dyVG5mRlp3VzZuZWFybkNHTmMiLCJ4MzhoM25Mcm1Tb2xVYlA4dTRXOEI1Q19yNTdEbk1va3I2cjFWT2xERXVRIiwiOEtSY3UzSnlHMlVPSjlZNnc2Z2lDZFFxYzB0QzlEZ0F1SWY2MFl4dURpcyJdfV0~";

        ObjectMapper mapper = new ObjectMapper();
        SdJwtParser parser = new SdJwtParser(mapper);
        SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser(parser);

        // 1. Verify full extraction resolves all recursive claims
        Map<String, Object> allClaims = parser.extractDisclosedClaims(bmiCredential);
        assertThat(allClaims)
                .containsEntry("given_name", "ERIKA")
                .containsEntry("family_name", "MUSTERMANN")
                .containsEntry("birthdate", "1984-08-12");

        // address should be resolved as a nested object with all sub-claims
        // (digest mapping: locality=KÖLN belongs to address, locality=BERLIN to place_of_birth)
        assertThat(allClaims).containsKey("address");
        Map<String, Object> addressClaims = (Map<String, Object>) allClaims.get("address");
        assertThat(addressClaims)
                .containsEntry("locality", "KÖLN")
                .containsEntry("street_address", "HEIDESTRAẞE 17")
                .containsEntry("postal_code", "51147")
                .containsEntry("country", "DE");

        // place_of_birth should also be resolved recursively
        assertThat(allClaims).containsKey("place_of_birth");
        Map<String, Object> birthPlace = (Map<String, Object>) allClaims.get("place_of_birth");
        assertThat(birthPlace).containsEntry("locality", "BERLIN");

        // 2. Filter for address sub-claims using flat paths (as DCQL would send)
        String filteredAddress = discloser.filter(
                bmiCredential,
                List.of(
                        new SdJwtSelectiveDiscloser.ClaimRequest("address", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("locality", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("street_address", null)
                ),
                Set.of("address", "locality", "street_address"));

        Map<String, Object> filteredClaims = parser.extractDisclosedClaims(filteredAddress);
        assertThat(filteredClaims).containsKey("address");
        Map<String, Object> filteredAddr = (Map<String, Object>) filteredClaims.get("address");
        assertThat(filteredAddr)
                .containsEntry("locality", "KÖLN")
                .containsEntry("street_address", "HEIDESTRAẞE 17");
        // Non-requested claims should be absent
        assertThat(filteredClaims).doesNotContainKey("given_name")
                .doesNotContainKey("family_name");

        // 3. Filter for just given_name + birthdate — no address disclosures
        String filteredNames = discloser.filter(
                bmiCredential,
                List.of(
                        new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("birthdate", null)
                ),
                Set.of("given_name", "birthdate"));

        Map<String, Object> nameOnly = parser.extractDisclosedClaims(filteredNames);
        assertThat(nameOnly)
                .containsEntry("given_name", "ERIKA")
                .containsEntry("birthdate", "1984-08-12")
                .doesNotContainKey("address")
                .doesNotContainKey("family_name");
    }
}
