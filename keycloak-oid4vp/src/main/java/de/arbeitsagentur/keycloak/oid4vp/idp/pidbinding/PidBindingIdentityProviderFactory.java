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
package de.arbeitsagentur.keycloak.oid4vp.idp.pidbinding;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpTrustListService;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import tools.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * Factory for creating German PID Binding Identity Provider instances.
 * <p>
 * This IdP implements the correct German PID binding flow where:
 * <ol>
 *   <li>First login: User presents PID, gets issued a login credential with Keycloak user ID</li>
 *   <li>Subsequent logins: User presents both PID and login credential</li>
 * </ol>
 * <p>
 * The login credential's user_id becomes the persistent subject identifier,
 * solving the problem that German PID has no suitable claim for user identification.
 */
public class PidBindingIdentityProviderFactory extends AbstractIdentityProviderFactory<PidBindingIdentityProvider> {

    private static final Logger LOG = Logger.getLogger(PidBindingIdentityProviderFactory.class);

    public static final String PROVIDER_ID = "pid-binding";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                // PID Binding specific configuration
                .property()
                    .name(PidBindingIdentityProviderConfig.PID_CREDENTIAL_TYPE)
                    .label("PID Credential Type")
                    .helpText("VCT (Verifiable Credential Type) for German PID credentials. " +
                              "Default: urn:eudi:pid:de:1")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue(PidBindingIdentityProviderConfig.DEFAULT_PID_CREDENTIAL_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.LOGIN_CREDENTIAL_TYPE)
                    .label("Login Credential Type")
                    .helpText("VCT for the login credential issued by this verifier. " +
                              "This credential contains the Keycloak user ID. " +
                              "Default: urn:arbeitsagentur:user_credential:1")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue(PidBindingIdentityProviderConfig.DEFAULT_LOGIN_CREDENTIAL_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.CREDENTIAL_ISSUER_URL)
                    .label("Credential Issuer URL")
                    .helpText("URL of the OID4VCI credential issuer. This is typically the Keycloak realm URL. " +
                              "Leave empty to auto-detect from realm configuration.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.CREDENTIAL_CONFIGURATION_ID)
                    .label("Credential Configuration ID")
                    .helpText("The credential_configuration_id to use when issuing login credentials. " +
                              "This must match a configured OID4VC client scope. " +
                              "Default: user-binding-credential")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue(PidBindingIdentityProviderConfig.DEFAULT_CREDENTIAL_CONFIGURATION_ID)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.PID_REQUESTED_CLAIMS)
                    .label("PID Claims to Request")
                    .helpText("Claims to request from the PID credential (comma or newline separated). " +
                              "These are mapped to user attributes. " +
                              "Default: given_name, family_name, birthdate")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .defaultValue(PidBindingIdentityProviderConfig.DEFAULT_PID_CLAIMS)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.ALWAYS_REQUEST_BOTH_CREDENTIALS)
                    .label("Always Request Both Credentials")
                    .helpText("When enabled, always request both PID and login credential. " +
                              "When disabled, first-time users only need to present PID.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("false")
                    .add()
                // Inherited configuration from OID4VP IdP
                .property()
                    .name(PidBindingIdentityProviderConfig.ENFORCE_HAIP)
                    .label("Enforce HAIP Compliance")
                    .helpText("Enable OpenID4VC High Assurance Interoperability Profile (HAIP) compliance.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.TRUST_LIST_URL)
                    .label("ETSI Trust List URL")
                    .helpText("URL to fetch ETSI TS 119 602 trust list JWT (e.g., https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt). Takes precedence over inline JWT.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.TRUST_LIST_JWT)
                    .label("Trust List (ETSI JWT)")
                    .helpText("ETSI TS 119 602 trust list in JWT format. Used if Trust List URL is not set.")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.DC_API_ENABLED)
                    .label("Enable DC API Flow")
                    .helpText("Enable Digital Credentials API flow (browser-based, requires supported browser/extension).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.SAME_DEVICE_ENABLED)
                    .label("Enable Same-Device Flow")
                    .helpText("Enable same-device flow (redirect to wallet app on same device).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.CROSS_DEVICE_ENABLED)
                    .label("Enable Cross-Device Flow")
                    .helpText("Enable cross-device flow (QR code for scanning with phone).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("true")
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.SAME_DEVICE_WALLET_URL)
                    .label("Wallet URL (HTTPS) for OID4VP")
                    .helpText("HTTPS URL of the wallet's OID4VP authorization endpoint (e.g., https://example.com/wallet/oid4vp/auth). Required for same-device flow.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.CREDENTIAL_ISSUANCE_WALLET_URL)
                    .label("Wallet URL (HTTPS) for Credential Issuance")
                    .helpText("HTTPS URL of the wallet for OID4VCI credential offers (e.g., https://example.com/wallet). Set to 'native' for openid-credential-offer:// URI. Required for credential issuance.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.SAME_DEVICE_WALLET_SCHEME)
                    .label("Wallet URL Scheme")
                    .helpText("Custom URL scheme for native wallet apps (e.g., openid4vp://, haip://). " +
                              "Leave empty to use HTTPS URL instead.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.DC_API_REQUEST_MODE)
                    .label("DC API Request Mode")
                    .helpText("Controls whether to use unsigned requests, signed request objects, or auto-detect.")
                    .type(ProviderConfigProperty.LIST_TYPE)
                    .defaultValue("auto")
                    .options(List.of("auto", "unsigned", "signed"))
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.DC_API_SIGNING_KEY_ID)
                    .label("DC API Signing Key ID")
                    .helpText("Optional: Specific realm signing key (kid) to use. Defaults to active realm signing key.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.TRUST_X5C_FROM_CREDENTIAL)
                    .label("Trust x5c from Credential")
                    .helpText("When enabled, trust certificates embedded in credentials (for testing only).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE)
                    .defaultValue("false")
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.ADDITIONAL_TRUSTED_CERTIFICATES)
                    .label("Additional Trusted Certificates")
                    .helpText("Additional PEM-encoded certificates to trust (for testing).")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .property()
                    .name(PidBindingIdentityProviderConfig.VERIFIER_INFO)
                    .label("Verifier Info (JSON)")
                    .helpText("Optional: JSON array of verifier attestations (e.g., registration certificates for EUDI Wallet).")
                    .type(ProviderConfigProperty.TEXT_TYPE)
                    .add()
                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "German PID Binding (Wallet Login)";
    }

    @Override
    public PidBindingIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig(model);
        ObjectMapper objectMapper = new ObjectMapper();

        // Create trust list service: URL takes precedence over inline JWT
        String trustListJwt = Oid4vpIdentityProviderFactory.resolveTrustListJwt(session, config);
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(trustListJwt);

        // Register additional trusted certificates from config
        String additionalCerts = config.getAdditionalTrustedCertificates();
        if (additionalCerts != null && !additionalCerts.isBlank()) {
            String trustListId = config.getTrustListId();
            registerAdditionalCertificates(trustListService, trustListId, additionalCerts);
        }

        return new PidBindingIdentityProvider(session, config, objectMapper, trustListService);
    }

    private void registerAdditionalCertificates(Oid4vpTrustListService trustListService,
                                                 String trustListId, String additionalCerts) {
        String[] parts = additionalCerts.split("(?=-----BEGIN CERTIFICATE-----)");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith("-----BEGIN CERTIFICATE-----") && trimmed.contains("-----END CERTIFICATE-----")) {
                try {
                    trustListService.registerCertificate(trustListId, trimmed);
                } catch (Exception e) {
                    LOG.warnf("Failed to register additional trusted certificate: %s", e.getMessage());
                }
            }
        }
    }

    @Override
    public PidBindingIdentityProviderConfig createConfig() {
        return new PidBindingIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
