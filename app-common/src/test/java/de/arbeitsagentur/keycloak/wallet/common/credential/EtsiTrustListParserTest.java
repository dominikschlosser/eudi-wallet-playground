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
import de.arbeitsagentur.keycloak.wallet.common.credential.EtsiTrustListParser.IssuerEntry;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EtsiTrustListParserTest {

    // EC P-256 test certificate (mock issuer)
    private static final String MOCK_ISSUER_CERT_DER_B64 =
            "MIIBgTCCASegAwIBAgIUBjEaIhGcW5pPX7vCtXbqMyql7ewwCgYIKoZIzj0EAwIw" +
            "FjEUMBIGA1UEAwwLbW9jay1pc3N1ZXIwHhcNMjUxMjAxMDkzOTI2WhcNMzUxMTI5" +
            "MDkzOTI2WjAWMRQwEgYDVQQDDAttb2NrLWlzc3VlcjBZMBMGByqGSM49AgEGCCqG" +
            "SM49AwEHA0IABCSGo02fNJ4ilyIJVsnR90UMvBEhbDxpvIN/X+Rq4y9qjCA35Inb" +
            "wm5jF0toypoov4aagJGaRkwzmvOy1JMlamKjUzBRMB0GA1UdDgQWBBR2mOx26507" +
            "8nBXsRCf07e99RBlDDAfBgNVHSMEGDAWgBR2mOx265078nBXsRCf07e99RBlDDAP" +
            "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDc1Evb58VWAGTNgiad" +
            "stQmCL6YL3ChASt/VLhgA/ogbAIgK5DjLQuY0dVDTaDccEC9s/uaKu+z5u28ZtQj" +
            "VK65zFU=";

    @Test
    void parsesEtsiTrustListJwt() {
        String jwt = EtsiTrustListParser.buildUnsignedJwt("Test Operator", List.of(
                new IssuerEntry("mock-issuer", MOCK_ISSUER_CERT_DER_B64)
        ));

        EtsiTrustList result = EtsiTrustListParser.parse(jwt);

        assertThat(result.label()).isEqualTo("Test Operator");
        assertThat(result.loTEType()).isEqualTo("http://uri.etsi.org/19602/LoTEType/local");
        assertThat(result.entities()).hasSize(1);
        assertThat(result.entities().get(0).name()).isEqualTo("mock-issuer");
        assertThat(result.entities().get(0).publicKeys()).hasSize(1);
        assertThat(result.entities().get(0).publicKeys().get(0)).isInstanceOf(ECPublicKey.class);
    }

    @Test
    void allPublicKeysCollectsFromAllEntities() {
        String jwt = EtsiTrustListParser.buildUnsignedJwt("Multi Issuer", List.of(
                new IssuerEntry("issuer-1", MOCK_ISSUER_CERT_DER_B64),
                new IssuerEntry("issuer-2", MOCK_ISSUER_CERT_DER_B64)
        ));

        EtsiTrustList result = EtsiTrustListParser.parse(jwt);

        assertThat(result.entities()).hasSize(2);
        assertThat(result.allPublicKeys()).hasSize(2);
    }

    @Test
    void parsesEmptyEntitiesList() {
        String jwt = EtsiTrustListParser.buildUnsignedJwt("Empty List", List.of());

        EtsiTrustList result = EtsiTrustListParser.parse(jwt);

        assertThat(result.label()).isEqualTo("Empty List");
        assertThat(result.entities()).isEmpty();
        assertThat(result.allPublicKeys()).isEmpty();
    }

    @Test
    void parsesRealEtsiFormat() {
        // Build a JWT with ETSI payload structure matching production format
        String payload = """
                {"ListAndSchemeInformation":{"LoTEType":"http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList","SchemeOperatorName":[{"lang":"de-DE","value":"SPRIND GmbH"}]},"TrustedEntitiesList":[{"TrustedEntityInformation":{"TEName":[{"lang":"de-DE","value":"Bundesdruckerei GmbH"}]},"TrustedEntityServices":[{"ServiceInformation":{"ServiceTypeIdentifier":"http://uri.etsi.org/19602/SvcType/PID/Issuance","ServiceDigitalIdentity":{"X509Certificates":[{"val":"%s"}]}}}]}]}
                """.formatted(MOCK_ISSUER_CERT_DER_B64).trim();

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
        String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
        String jwt = header + "." + payloadB64 + ".fakesig";

        EtsiTrustList result = EtsiTrustListParser.parse(jwt);

        assertThat(result.label()).isEqualTo("SPRIND GmbH");
        assertThat(result.loTEType()).isEqualTo("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList");
        assertThat(result.entities()).hasSize(1);
        assertThat(result.entities().get(0).name()).isEqualTo("Bundesdruckerei GmbH");
        assertThat(result.entities().get(0).publicKeys()).hasSize(1);
    }

    @Test
    void throwsOnNullInput() {
        assertThatThrownBy(() -> EtsiTrustListParser.parse(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void throwsOnInvalidJwtFormat() {
        assertThatThrownBy(() -> EtsiTrustListParser.parse("not-a-jwt"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void pemToBase64DerStripsHeadersAndWhitespace() {
        String pem = """
                -----BEGIN CERTIFICATE-----
                MIIBgTCCASegAwIBAgI=
                -----END CERTIFICATE-----
                """;
        assertThat(EtsiTrustListParser.pemToBase64Der(pem)).isEqualTo("MIIBgTCCASegAwIBAgI=");
    }

    @Test
    void buildUnsignedJwtProducesValidJwt() {
        String jwt = EtsiTrustListParser.buildUnsignedJwt("Test", List.of(
                new IssuerEntry("test-issuer", MOCK_ISSUER_CERT_DER_B64)
        ));

        // Should have 3 parts (header.payload.empty-signature)
        String[] parts = jwt.split("\\.");
        assertThat(parts.length).isGreaterThanOrEqualTo(2);

        // Header should decode to alg:none
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        assertThat(headerJson).contains("\"alg\":\"none\"");

        // Should be parseable
        EtsiTrustList result = EtsiTrustListParser.parse(jwt);
        assertThat(result.entities()).hasSize(1);
    }
}
