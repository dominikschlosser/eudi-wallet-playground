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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Parses ETSI TS 119 602 trust lists in JWT (JAdES) format.
 * <p>
 * Extracts issuer X.509 certificates from the {@code TrustedEntitiesList} payload.
 * Only the JWT payload is parsed — the signature is <b>not</b> verified.
 *
 * @see <a href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf">ETSI TS 119 602</a>
 * @see <a href="https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/">BMI Test Trust Lists</a>
 */
public final class EtsiTrustListParser {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private EtsiTrustListParser() {
    }

    /**
     * Result of parsing an ETSI trust list JWT.
     *
     * @param label    human-readable label (from SchemeOperatorName), may be null
     * @param loTEType the LoTE type URI (e.g. {@code http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList})
     * @param entities the trusted entities with their public keys
     */
    public record EtsiTrustList(
            String label,
            String loTEType,
            List<TrustedEntity> entities
    ) {
        /** Collects all public keys across all entities into a flat list. */
        public List<PublicKey> allPublicKeys() {
            List<PublicKey> keys = new ArrayList<>();
            for (TrustedEntity entity : entities) {
                keys.addAll(entity.publicKeys());
            }
            return keys;
        }
    }

    /**
     * A single trusted entity with its name and extracted public keys.
     *
     * @param name       entity name (from TEName), may be null
     * @param publicKeys public keys extracted from the entity's service certificates
     */
    public record TrustedEntity(
            String name,
            List<PublicKey> publicKeys
    ) {
    }

    /**
     * Parse a JWT-format ETSI trust list (compact serialization: header.payload.signature).
     * Only the payload is decoded and parsed; the signature is not verified.
     *
     * @param jwtString the complete JWT string
     * @return parsed trust list with entities and their public keys
     * @throws IllegalArgumentException if the JWT format or payload structure is invalid
     */
    public static EtsiTrustList parse(String jwtString) {
        if (jwtString == null || jwtString.isBlank()) {
            throw new IllegalArgumentException("JWT string must not be null or blank");
        }

        String[] parts = jwtString.trim().split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT format: expected at least 2 dot-separated parts");
        }

        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(payloadBytes);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT payload as JSON", e);
        }

        // Extract metadata from ListAndSchemeInformation
        JsonNode schemeInfo = root.path("ListAndSchemeInformation");
        String label = extractLocalizedValue(schemeInfo.path("SchemeOperatorName"));
        String loTEType = schemeInfo.path("LoTEType").asText(null);

        // Extract entities
        List<TrustedEntity> entities = new ArrayList<>();
        for (JsonNode entityNode : root.path("TrustedEntitiesList")) {
            String entityName = extractLocalizedValue(
                    entityNode.path("TrustedEntityInformation").path("TEName"));

            List<PublicKey> publicKeys = new ArrayList<>();
            for (JsonNode serviceNode : entityNode.path("TrustedEntityServices")) {
                JsonNode certs = serviceNode
                        .path("ServiceInformation")
                        .path("ServiceDigitalIdentity")
                        .path("X509Certificates");
                for (JsonNode certNode : certs) {
                    String certBase64 = certNode.path("val").asText(null);
                    if (certBase64 != null && !certBase64.isBlank()) {
                        PublicKey key = parseCertificate(certBase64);
                        if (key != null) {
                            publicKeys.add(key);
                        }
                    }
                }
            }

            entities.add(new TrustedEntity(entityName, List.copyOf(publicKeys)));
        }

        return new EtsiTrustList(label, loTEType, List.copyOf(entities));
    }

    /**
     * Build an unsigned JWT string (alg=none) with an ETSI trust list payload.
     * Useful for creating mock/test trust lists in the same format as production.
     *
     * @param label    human-readable label for the trust list
     * @param issuers  list of issuer entries (name + base64-DER certificate)
     * @return JWT string in compact serialization (header.payload.)
     */
    public static String buildUnsignedJwt(String label, List<IssuerEntry> issuers) {
        var sb = new StringBuilder();
        sb.append("{\"ListAndSchemeInformation\":{");
        sb.append("\"SchemeOperatorName\":[{\"lang\":\"en\",\"value\":\"").append(escapeJson(label)).append("\"}],");
        sb.append("\"LoTEType\":\"http://uri.etsi.org/19602/LoTEType/local\"");
        sb.append("},\"TrustedEntitiesList\":[");

        for (int i = 0; i < issuers.size(); i++) {
            IssuerEntry issuer = issuers.get(i);
            if (i > 0) sb.append(",");
            sb.append("{\"TrustedEntityInformation\":{");
            sb.append("\"TEName\":[{\"lang\":\"en\",\"value\":\"").append(escapeJson(issuer.name())).append("\"}]");
            sb.append("},\"TrustedEntityServices\":[{\"ServiceInformation\":{");
            sb.append("\"ServiceTypeIdentifier\":\"http://uri.etsi.org/19602/SvcType/Issuance\",");
            sb.append("\"ServiceDigitalIdentity\":{\"X509Certificates\":[");
            sb.append("{\"val\":\"").append(issuer.certificateBase64Der()).append("\"}");
            sb.append("]}}}]}");
        }

        sb.append("]}");

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sb.toString().getBytes());

        return header + "." + payload + ".";
    }

    /**
     * An issuer entry for building mock trust lists.
     *
     * @param name                 human-readable issuer name
     * @param certificateBase64Der base64-encoded DER certificate (same as PEM content without headers/whitespace)
     */
    public record IssuerEntry(String name, String certificateBase64Der) {
    }

    /**
     * Convert a PEM certificate string to base64-DER (strip headers and whitespace).
     */
    public static String pemToBase64Der(String pem) {
        return pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
    }

    // --- internal helpers ---

    private static String extractLocalizedValue(JsonNode array) {
        if (array.isArray() && !array.isEmpty()) {
            return array.get(0).path("value").asText(null);
        }
        return null;
    }

    private static PublicKey parseCertificate(String base64Der) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Der);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate =
                    (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
            return certificate.getPublicKey();
        } catch (Exception e) {
            // Skip unparseable certificates
            return null;
        }
    }

    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
