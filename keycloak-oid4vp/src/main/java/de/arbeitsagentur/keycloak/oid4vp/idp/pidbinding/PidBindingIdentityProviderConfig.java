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

import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * Configuration for the German PID Binding Identity Provider.
 * <p>
 * This IdP implements a two-phase authentication flow for German PID credentials:
 * <ol>
 *   <li>First login: Present PID → create user → issue login credential</li>
 *   <li>Subsequent logins: Present PID + login credential → use login credential's user_id</li>
 * </ol>
 * <p>
 * The key insight is that German PID has no claim suitable as a persistent unique subject identifier.
 * Instead, we issue a "login credential" containing the Keycloak user ID, which becomes the
 * federated identity anchor for subsequent logins.
 */
public class PidBindingIdentityProviderConfig extends Oid4vpIdentityProviderConfig {

    // PID credential type (e.g., German PID VCT)
    public static final String PID_CREDENTIAL_TYPE = "pidCredentialType";
    public static final String DEFAULT_PID_CREDENTIAL_TYPE = "urn:eudi:pid:de:1";

    // Login credential type issued by this verifier
    public static final String LOGIN_CREDENTIAL_TYPE = "loginCredentialType";
    public static final String DEFAULT_LOGIN_CREDENTIAL_TYPE = "urn:arbeitsagentur:user_credential:1";

    // Credential issuer URL for OID4VCI credential issuance
    public static final String CREDENTIAL_ISSUER_URL = "credentialIssuerUrl";

    // Credential configuration ID to use for issuance
    public static final String CREDENTIAL_CONFIGURATION_ID = "credentialConfigurationId";
    public static final String DEFAULT_CREDENTIAL_CONFIGURATION_ID = "user-binding-credential";

    // OID4VCI client ID (must be a client with oid4vci.enabled=true)
    public static final String OID4VCI_CLIENT_ID = "oid4vciClientId";
    public static final String DEFAULT_OID4VCI_CLIENT_ID = "pid-binding-wallet";

    // Wallet URL for same-device credential issuance (OID4VCI)
    // Options:
    //   - "native" or empty: Use openid-credential-offer:// URI directly (for mobile wallets)
    //   - Web URL (e.g., https://example.com/wallet): Wrap offer in web wallet URL
    public static final String CREDENTIAL_ISSUANCE_WALLET_URL = "credentialIssuanceWalletUrl";
    public static final String NATIVE_WALLET_URL = "native";

    // Whether to always request both credentials (even for potential first-time users)
    // When false, first request PID only, then on subsequent logins request both
    public static final String ALWAYS_REQUEST_BOTH_CREDENTIALS = "alwaysRequestBothCredentials";

    // PID claims to request (comma-separated or newline-separated)
    public static final String PID_REQUESTED_CLAIMS = "pidRequestedClaims";
    public static final String DEFAULT_PID_CLAIMS = "given_name,family_name,birthdate";

    public PidBindingIdentityProviderConfig() {
        super();
    }

    public PidBindingIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    /**
     * Get the PID credential type (VCT for German PID).
     * Default: urn:eudi:pid:de:1
     */
    public String getPidCredentialType() {
        String value = getConfig().get(PID_CREDENTIAL_TYPE);
        return value != null && !value.isBlank() ? value : DEFAULT_PID_CREDENTIAL_TYPE;
    }

    public void setPidCredentialType(String pidCredentialType) {
        getConfig().put(PID_CREDENTIAL_TYPE, pidCredentialType);
    }

    /**
     * Get the login credential type (VCT for the credential issued by this verifier).
     * Default: urn:arbeitsagentur:user_credential:1
     */
    public String getLoginCredentialType() {
        String value = getConfig().get(LOGIN_CREDENTIAL_TYPE);
        return value != null && !value.isBlank() ? value : DEFAULT_LOGIN_CREDENTIAL_TYPE;
    }

    public void setLoginCredentialType(String loginCredentialType) {
        getConfig().put(LOGIN_CREDENTIAL_TYPE, loginCredentialType);
    }

    /**
     * Get the credential issuer URL for OID4VCI credential issuance.
     * This is typically the Keycloak realm's issuer URL.
     */
    public String getCredentialIssuerUrl() {
        return getConfig().get(CREDENTIAL_ISSUER_URL);
    }

    public void setCredentialIssuerUrl(String credentialIssuerUrl) {
        getConfig().put(CREDENTIAL_ISSUER_URL, credentialIssuerUrl);
    }

    /**
     * Get the credential configuration ID to use for issuance.
     * Default: user-binding-credential
     */
    public String getCredentialConfigurationId() {
        String value = getConfig().get(CREDENTIAL_CONFIGURATION_ID);
        return value != null && !value.isBlank() ? value : DEFAULT_CREDENTIAL_CONFIGURATION_ID;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {
        getConfig().put(CREDENTIAL_CONFIGURATION_ID, credentialConfigurationId);
    }

    /**
     * Get the OID4VCI client ID for pre-authorized code flow.
     * This client must have oid4vci.enabled=true in Keycloak.
     * Default: pid-binding-wallet
     */
    public String getOid4vciClientId() {
        String value = getConfig().get(OID4VCI_CLIENT_ID);
        return value != null && !value.isBlank() ? value : DEFAULT_OID4VCI_CLIENT_ID;
    }

    public void setOid4vciClientId(String clientId) {
        getConfig().put(OID4VCI_CLIENT_ID, clientId);
    }

    /**
     * Get the wallet URL for same-device credential issuance.
     * This URL should open the wallet app with credential offer handling.
     * Set to "native" to use openid-credential-offer:// URI directly.
     * Must be configured explicitly - no default value.
     */
    public String getCredentialIssuanceWalletUrl() {
        return getConfig().get(CREDENTIAL_ISSUANCE_WALLET_URL);
    }

    /**
     * Check if native wallet mode is enabled.
     * When true, the openid-credential-offer:// URI is used directly.
     */
    public boolean isNativeWalletMode() {
        String value = getConfig().get(CREDENTIAL_ISSUANCE_WALLET_URL);
        return NATIVE_WALLET_URL.equalsIgnoreCase(value);
    }

    public void setCredentialIssuanceWalletUrl(String walletUrl) {
        getConfig().put(CREDENTIAL_ISSUANCE_WALLET_URL, walletUrl);
    }

    /**
     * Check if both credentials should always be requested.
     * When true, the DCQL query always includes both PID and login credential.
     * When false (default), first-time users are only asked for PID.
     */
    public boolean isAlwaysRequestBothCredentials() {
        String value = getConfig().get(ALWAYS_REQUEST_BOTH_CREDENTIALS);
        return "true".equalsIgnoreCase(value);
    }

    public void setAlwaysRequestBothCredentials(boolean always) {
        getConfig().put(ALWAYS_REQUEST_BOTH_CREDENTIALS, String.valueOf(always));
    }

    /**
     * Get the PID claims to request (comma or newline separated).
     * Default: given_name, family_name, birthdate
     */
    public String getPidRequestedClaims() {
        String value = getConfig().get(PID_REQUESTED_CLAIMS);
        return value != null && !value.isBlank() ? value : DEFAULT_PID_CLAIMS;
    }

    public void setPidRequestedClaims(String claims) {
        getConfig().put(PID_REQUESTED_CLAIMS, claims);
    }

    /**
     * Get the PID claims as a list.
     */
    public java.util.List<String> getPidRequestedClaimsList() {
        String claims = getPidRequestedClaims();
        java.util.List<String> result = new java.util.ArrayList<>();
        for (String claim : claims.split("[,\\n\\r]+")) {
            String trimmed = claim.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}
