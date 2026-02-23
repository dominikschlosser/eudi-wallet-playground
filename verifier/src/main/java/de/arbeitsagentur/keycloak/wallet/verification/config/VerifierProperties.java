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
package de.arbeitsagentur.keycloak.wallet.verification.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;

@ConfigurationProperties(prefix = "verifier")
@Validated
public record VerifierProperties(
        Path dcqlQueryFile,
        String defaultDcqlQuery,
        String walletAuthEndpoint,
        String clientId,
        Path keysFile,
        Integer maxRequestObjectInlineBytes,
        String etsiTrustListBaseUrl,
        String clientCertFile,
        String sandboxVerifierInfoFile,
        String sandboxDcqlQuery,
        String sandboxWalletAuthEndpoint
) {
    public String clientId() {
        return clientId != null ? clientId : "wallet-verifier";
    }

    public Path clientCertFilePath() {
        return resolveWithFallback(clientCertFile);
    }

    public Path sandboxVerifierInfoFilePath() {
        return resolveWithFallback(sandboxVerifierInfoFile);
    }

    private static Path resolveWithFallback(String filePath) {
        if (filePath == null || filePath.isBlank()) {
            return null;
        }
        Path primary = Path.of(filePath);
        if (java.nio.file.Files.exists(primary)) {
            return primary;
        }
        // Fallback: try ../sandbox/ if sandbox/ was configured, or vice versa
        if (filePath.startsWith("sandbox/")) {
            Path fallback = Path.of("../" + filePath);
            if (java.nio.file.Files.exists(fallback)) {
                return fallback;
            }
        } else if (filePath.startsWith("../sandbox/")) {
            Path fallback = Path.of(filePath.substring(3));
            if (java.nio.file.Files.exists(fallback)) {
                return fallback;
            }
        }
        return primary;
    }

    public int resolvedMaxRequestObjectInlineBytes() {
        return maxRequestObjectInlineBytes != null && maxRequestObjectInlineBytes > 0
                ? maxRequestObjectInlineBytes
                : 12000;
    }
}
