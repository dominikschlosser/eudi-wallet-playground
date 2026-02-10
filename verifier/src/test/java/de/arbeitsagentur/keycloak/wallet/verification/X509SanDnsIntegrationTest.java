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
package de.arbeitsagentur.keycloak.wallet.verification;

import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierCryptoService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

class X509SanDnsIntegrationTest {

    @Test
    void defaultCertificateSupportsLocalSan() {
        var props = new VerifierProperties(null, null, null, null, null, null, null);
        var keyService = new VerifierKeyService(props, new ObjectMapper());
        var cryptoService = new VerifierCryptoService(keyService);

        var material = cryptoService.resolveX509Material(null);
        String certPem = material.certificatePem();

        String derived = cryptoService.deriveX509SanClientId(null, certPem);
        assertThat(derived).isEqualTo("x509_san_dns:verifier.localtest.me");

        // also ensure hash derivation still works on the same cert
        String hashId = cryptoService.deriveX509ClientId(null, certPem);
        assertThat(hashId).startsWith("x509_hash:");
    }
}
