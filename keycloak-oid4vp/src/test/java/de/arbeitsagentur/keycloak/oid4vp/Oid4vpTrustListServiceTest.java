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
package de.arbeitsagentur.keycloak.oid4vp;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vpTrustListServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Trust list JWT (ETSI TS 119 602 format) containing the mock issuer certificate
    private static final String TEST_TRUST_LIST_JWT =
            "eyJhbGciOiAibm9uZSJ9.eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IlRlc3QgVHJ1c3QgTGlzdCJ9XSwiTG9URVR5cGUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL0xvVEVUeXBlL2xvY2FsIn0sIlRydXN0ZWRFbnRpdGllc0xpc3QiOlt7IlRydXN0ZWRFbnRpdHlJbmZvcm1hdGlvbiI6eyJURU5hbWUiOlt7ImxhbmciOiJlbiIsInZhbHVlIjoibW9jay1pc3N1ZXItZXMyNTYifV19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvSXNzdWFuY2UiLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUJnVENDQVNlZ0F3SUJBZ0lVQmpFYUloR2NXNXBQWDd2Q3RYYnFNeXFsN2V3d0NnWUlLb1pJemowRUF3SXdGakVVTUJJR0ExVUVBd3dMYlc5amF5MXBjM04xWlhJd0hoY05NalV4TWpBeE1Ea3pPVEkyV2hjTk16VXhNVEk1TURrek9USTJXakFXTVJRd0VnWURWUVFEREF0dGIyTnJMV2x6YzNWbGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJDU0dvMDJmTko0aWx5SUpWc25SOTBVTXZCRWhiRHhwdklOL1grUnE0eTlxakNBMzVJbmJ3bTVqRjB0b3lwb292NGFhZ0pHYVJrd3ptdk95MUpNbGFtS2pVekJSTUIwR0ExVWREZ1FXQkJSMm1PeDI2NTA3OG5CWHNTQ2YwN2U5OVJCbEREQWZCZ05WSFNNRUdEQVdnQlIybU94MjY1MDc4bkJYc1JDZjA3ZTk5UkJsRERBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEYzFFdmI1OFZXQUdUTmdpYWRzdFFtQ0w2WUwzQ2hBU3QvVkxoZ0Evb2diQUlnSzVEakxRdVkwZFZEVGFEY2NFQzlzL3VhS3UrejV1MjhadFFqVks2NXpGVT0ifV19fX1dfV19.";

    @Test
    void usesConfiguredTrustListJwtForSignatureVerification() throws Exception {
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(TEST_TRUST_LIST_JWT);

        ECKey issuerKey = loadMockIssuerKey();
        SignedJWT jwt = signJwt(issuerKey);

        assertThat(trustListService.verify(jwt, DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID)).isTrue();
    }

    @Test
    void failsVerificationWithEmptyTrustList() throws Exception {
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(null);

        ECKey issuerKey = loadMockIssuerKey();
        SignedJWT jwt = signJwt(issuerKey);

        // Should throw because no trust list is configured
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> trustListService.verify(jwt, DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID));
    }

    private ECKey loadMockIssuerKey() throws Exception {
        try (var is = Oid4vpTrustListServiceTest.class.getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).isNotNull();
            JsonNode node = OBJECT_MAPPER.readTree(is);
            return ECKey.parse(node.get("privateJwk").toString());
        }
    }

    private SignedJWT signJwt(ECKey issuerKey) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(60)))
                .claim("test", "ok")
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(issuerKey.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(issuerKey));
        return jwt;
    }
}
