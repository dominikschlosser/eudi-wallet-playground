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
package de.arbeitsagentur.keycloak.oid4vp.idp;

import org.keycloak.models.IdentityProviderModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Configuration for the OID4VP Identity Provider.
 * Unlike OAuth2-based IdPs, OID4VP doesn't require client credentials.
 */
public class Oid4vpIdentityProviderConfig extends IdentityProviderModel {

    public static final String TRUST_LIST_ID = "trustListId";
    public static final String TRUST_LIST_JWT = "trustListJwt";
    public static final String TRUST_LIST_URL = "trustListUrl";
    public static final String DCQL_QUERY = "dcqlQuery";
    public static final String USER_MAPPING_CLAIM = "userMappingClaim";
    public static final String USER_MAPPING_CLAIM_MDOC = "userMappingClaimMdoc"; // Separate claim name for mDoc format

    // Component-based DCQL configuration (replaces direct DCQL_QUERY editing)
    public static final String CREDENTIAL_FORMAT = "credentialFormat";
    public static final String CREDENTIAL_TYPE_PRESET = "credentialTypePreset";
    public static final String CREDENTIAL_TYPE_CUSTOM = "credentialTypeCustom";
    public static final String REQUESTED_CLAIMS = "requestedClaims";

    // Credential format constants
    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";
    public static final String FORMAT_MSO_MDOC = "mso_mdoc";

    // Preset credential type constants
    public static final String PRESET_EUDI_PID = "eu.europa.ec.eudi.pid.1";
    public static final String PRESET_MDL = "org.iso.18013.5.1.mDL";
    public static final String PRESET_ANY = "any";
    public static final String PRESET_CUSTOM = "custom";
    public static final String DC_API_REQUEST_MODE = "dcApiRequestMode";
    public static final String DC_API_CLIENT_ID = "dcApiClientId";
    public static final String DC_API_SIGNING_KEY_ID = "dcApiSigningKeyId";
    public static final String ALLOWED_ISSUERS = "allowedIssuers";
    public static final String ALLOWED_CREDENTIAL_TYPES = "allowedCredentialTypes";

    // Flow enable/disable options
    public static final String DC_API_ENABLED = "dcApiEnabled";
    public static final String SAME_DEVICE_ENABLED = "sameDeviceEnabled";
    public static final String CROSS_DEVICE_ENABLED = "crossDeviceEnabled";

    // Same-device flow configuration
    public static final String SAME_DEVICE_WALLET_URL = "sameDeviceWalletUrl";
    public static final String SAME_DEVICE_WALLET_SCHEME = "sameDeviceWalletScheme";

    // Client ID scheme for redirect flows (plain, x509_san_dns, x509_hash)
    public static final String CLIENT_ID_SCHEME = "clientIdScheme";
    public static final String X509_CERTIFICATE_PEM = "x509CertificatePem";
    public static final String X509_SIGNING_KEY_JWK = "x509SigningKeyJwk";

    // Credential set mode: "optional" (any one credential) or "all" (all credentials required)
    public static final String CREDENTIAL_SET_MODE = "credentialSetMode";
    public static final String CREDENTIAL_SET_MODE_OPTIONAL = "optional";
    public static final String CREDENTIAL_SET_MODE_ALL = "all";
    public static final String CREDENTIAL_SET_PURPOSE = "credentialSetPurpose";

    // Trust x5c from credential (useful for testing)
    public static final String TRUST_X5C_FROM_CREDENTIAL = "trustX5cFromCredential";

    // Additional trusted issuer certificates (PEM format, for testing)
    public static final String ADDITIONAL_TRUSTED_CERTIFICATES = "additionalTrustedCertificates";

    // Verifier info: array of attestation objects about the verifier (e.g., registration certificates)
    public static final String VERIFIER_INFO = "verifierInfo";

    // HAIP compliance mode: when enabled, overrides config values with HAIP-compliant settings
    public static final String ENFORCE_HAIP = "enforceHaip";

    // HAIP-mandated values (OpenID4VC High Assurance Interoperability Profile)
    // Section 7: Digital Signatures - ES256 (ECDSA with P-256 and SHA-256)
    public static final String HAIP_SIGNING_ALGORITHM = "ES256";
    // Section 5.1: Response mode for redirect flows must be direct_post.jwt (encrypted)
    public static final String HAIP_RESPONSE_MODE = "direct_post.jwt";
    // Section 5.2: DC API response mode must be dc_api.jwt
    public static final String HAIP_DC_API_RESPONSE_MODE = "dc_api.jwt";
    // Section 5.1: JAR (JWT Secured Authorization Request) required
    public static final String HAIP_REQUEST_MODE = "signed";

    public Oid4vpIdentityProviderConfig() {
        super();
    }

    public Oid4vpIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getTrustListId() {
        return getConfig().get(TRUST_LIST_ID);
    }

    public void setTrustListId(String trustListId) {
        getConfig().put(TRUST_LIST_ID, trustListId);
    }

    /**
     * Get the trust list JWT (ETSI TS 119 602 format).
     * This JWT defines which credential issuers are trusted for verification.
     */
    public String getTrustListJwt() {
        return getConfig().get(TRUST_LIST_JWT);
    }

    public void setTrustListJwt(String trustListJwt) {
        getConfig().put(TRUST_LIST_JWT, trustListJwt);
    }

    /**
     * Get the trust list URL for fetching an ETSI trust list JWT remotely.
     */
    public String getTrustListUrl() {
        return getConfig().get(TRUST_LIST_URL);
    }

    public void setTrustListUrl(String url) {
        getConfig().put(TRUST_LIST_URL, url);
    }

    public String getDcqlQuery() {
        return getConfig().get(DCQL_QUERY);
    }

    public void setDcqlQuery(String dcqlQuery) {
        getConfig().put(DCQL_QUERY, dcqlQuery);
    }

    // Component-based DCQL configuration getters/setters

    /**
     * Get the credential format: "dc+sd-jwt" (SD-JWT VC) or "mso_mdoc" (ISO mDL/mdoc).
     * Defaults to "dc+sd-jwt".
     */
    public String getCredentialFormat() {
        String format = getConfig().get(CREDENTIAL_FORMAT);
        return format != null && !format.isBlank() ? format : FORMAT_SD_JWT_VC;
    }

    public void setCredentialFormat(String format) {
        getConfig().put(CREDENTIAL_FORMAT, format);
    }

    /**
     * Get the preset credential type selection.
     * Options: "eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1.mDL", or "custom".
     */
    public String getCredentialTypePreset() {
        String preset = getConfig().get(CREDENTIAL_TYPE_PRESET);
        return preset != null && !preset.isBlank() ? preset : PRESET_EUDI_PID;
    }

    public void setCredentialTypePreset(String preset) {
        getConfig().put(CREDENTIAL_TYPE_PRESET, preset);
    }

    /**
     * Get the custom credential type (vct for SD-JWT or docType for mDoc).
     * Only used when credentialTypePreset is "custom".
     */
    public String getCredentialTypeCustom() {
        return getConfig().get(CREDENTIAL_TYPE_CUSTOM);
    }

    public void setCredentialTypeCustom(String custom) {
        getConfig().put(CREDENTIAL_TYPE_CUSTOM, custom);
    }

    /**
     * Get the effective credential type based on preset/custom selection.
     * Returns the custom value if preset is "custom", "any" for no restriction, otherwise the preset value.
     */
    public String getEffectiveCredentialType() {
        String preset = getCredentialTypePreset();
        if (PRESET_ANY.equals(preset)) {
            return PRESET_ANY; // No restriction
        }
        if (PRESET_CUSTOM.equals(preset)) {
            String custom = getCredentialTypeCustom();
            return custom != null && !custom.isBlank() ? custom : PRESET_EUDI_PID;
        }
        return preset;
    }

    /**
     * Get the requested claims as a newline-separated string.
     * Each line is a claim path (e.g., "given_name", "address.city").
     */
    public String getRequestedClaims() {
        return getConfig().get(REQUESTED_CLAIMS);
    }

    public void setRequestedClaims(String claims) {
        getConfig().put(REQUESTED_CLAIMS, claims);
    }

    /**
     * Get the requested claims as a list, parsing the newline-separated config value.
     * Returns empty list if no claims configured.
     */
    public List<String> getRequestedClaimsList() {
        String claims = getRequestedClaims();
        if (claims == null || claims.isBlank()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String line : claims.split("[\n\r]+")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    public String getUserMappingClaim() {
        String claim = getConfig().get(USER_MAPPING_CLAIM);
        return claim != null && !claim.isBlank() ? claim : "sub";
    }

    public void setUserMappingClaim(String userMappingClaim) {
        getConfig().put(USER_MAPPING_CLAIM, userMappingClaim);
    }

    /**
     * Get the user mapping claim for mDoc format.
     * Falls back to the default userMappingClaim if not set.
     * This allows using different claim names for SD-JWT and mDoc credentials
     * (e.g., "personal_administrative_number" for SD-JWT, "document_number" for mDoc).
     */
    public String getUserMappingClaimMdoc() {
        String claim = getConfig().get(USER_MAPPING_CLAIM_MDOC);
        return claim != null && !claim.isBlank() ? claim : getUserMappingClaim();
    }

    public void setUserMappingClaimMdoc(String userMappingClaimMdoc) {
        getConfig().put(USER_MAPPING_CLAIM_MDOC, userMappingClaimMdoc);
    }

    /**
     * Get the appropriate user mapping claim based on the credential format.
     * @param format The credential format ("dc+sd-jwt" or "mso_mdoc")
     * @return The claim name to use for user identification
     */
    public String getUserMappingClaimForFormat(String format) {
        if (FORMAT_MSO_MDOC.equalsIgnoreCase(format)) {
            return getUserMappingClaimMdoc();
        }
        return getUserMappingClaim();
    }

    public String getDcApiRequestMode() {
        String mode = getConfig().get(DC_API_REQUEST_MODE);
        return mode != null && !mode.isBlank() ? mode : "auto";
    }

    public void setDcApiRequestMode(String dcApiRequestMode) {
        getConfig().put(DC_API_REQUEST_MODE, dcApiRequestMode);
    }

    public String getDcApiClientId() {
        return getConfig().get(DC_API_CLIENT_ID);
    }

    public void setDcApiClientId(String dcApiClientId) {
        getConfig().put(DC_API_CLIENT_ID, dcApiClientId);
    }

    public String getDcApiSigningKeyId() {
        return getConfig().get(DC_API_SIGNING_KEY_ID);
    }

    public void setDcApiSigningKeyId(String dcApiSigningKeyId) {
        getConfig().put(DC_API_SIGNING_KEY_ID, dcApiSigningKeyId);
    }

    public String getAllowedIssuers() {
        return getConfig().get(ALLOWED_ISSUERS);
    }

    public void setAllowedIssuers(String allowedIssuers) {
        getConfig().put(ALLOWED_ISSUERS, allowedIssuers);
    }

    public String getAllowedCredentialTypes() {
        return getConfig().get(ALLOWED_CREDENTIAL_TYPES);
    }

    public void setAllowedCredentialTypes(String allowedCredentialTypes) {
        getConfig().put(ALLOWED_CREDENTIAL_TYPES, allowedCredentialTypes);
    }

    // Flow enable/disable getters

    public boolean isDcApiEnabled() {
        String value = getConfig().get(DC_API_ENABLED);
        return value == null || !"false".equalsIgnoreCase(value); // default true
    }

    public void setDcApiEnabled(boolean enabled) {
        getConfig().put(DC_API_ENABLED, String.valueOf(enabled));
    }

    public boolean isSameDeviceEnabled() {
        String value = getConfig().get(SAME_DEVICE_ENABLED);
        return value == null || !"false".equalsIgnoreCase(value); // default true
    }

    public void setSameDeviceEnabled(boolean enabled) {
        getConfig().put(SAME_DEVICE_ENABLED, String.valueOf(enabled));
    }

    public boolean isCrossDeviceEnabled() {
        String value = getConfig().get(CROSS_DEVICE_ENABLED);
        return value == null || !"false".equalsIgnoreCase(value); // default true
    }

    public void setCrossDeviceEnabled(boolean enabled) {
        getConfig().put(CROSS_DEVICE_ENABLED, String.valueOf(enabled));
    }

    // Same-device flow configuration getters/setters

    public String getSameDeviceWalletUrl() {
        return getConfig().get(SAME_DEVICE_WALLET_URL);
    }

    public void setSameDeviceWalletUrl(String url) {
        getConfig().put(SAME_DEVICE_WALLET_URL, url);
    }

    public String getSameDeviceWalletScheme() {
        String scheme = getConfig().get(SAME_DEVICE_WALLET_SCHEME);
        // Default to empty (use wallet URL instead of custom scheme)
        return scheme != null && !scheme.isBlank() ? scheme : "";
    }

    public void setSameDeviceWalletScheme(String scheme) {
        getConfig().put(SAME_DEVICE_WALLET_SCHEME, scheme);
    }

    // Client ID scheme for redirect flows

    public String getClientIdScheme() {
        String scheme = getConfig().get(CLIENT_ID_SCHEME);
        return scheme != null && !scheme.isBlank() ? scheme : "plain";
    }

    public void setClientIdScheme(String scheme) {
        getConfig().put(CLIENT_ID_SCHEME, scheme);
    }

    public String getX509CertificatePem() {
        return getConfig().get(X509_CERTIFICATE_PEM);
    }

    public void setX509CertificatePem(String pem) {
        getConfig().put(X509_CERTIFICATE_PEM, pem);
    }

    /**
     * Get the x509 signing key in JWK format (with private part).
     * Used to sign request objects when using x509 client_id schemes.
     */
    public String getX509SigningKeyJwk() {
        return getConfig().get(X509_SIGNING_KEY_JWK);
    }

    public void setX509SigningKeyJwk(String jwk) {
        getConfig().put(X509_SIGNING_KEY_JWK, jwk);
    }

    /**
     * Whether to trust x5c certificates embedded in credentials.
     * When enabled, credential signatures are verified against the x5c certificate in the credential itself,
     * rather than requiring the issuer to be in the trust list.
     * This is useful for testing but should be used with caution in production.
     */
    public boolean isTrustX5cFromCredential() {
        String value = getConfig().get(TRUST_X5C_FROM_CREDENTIAL);
        return "true".equalsIgnoreCase(value); // default false
    }

    public void setTrustX5cFromCredential(boolean trust) {
        getConfig().put(TRUST_X5C_FROM_CREDENTIAL, String.valueOf(trust));
    }

    /**
     * Get additional trusted issuer certificates (PEM format).
     * These certificates will be added to the trust list at runtime.
     */
    public String getAdditionalTrustedCertificates() {
        return getConfig().get(ADDITIONAL_TRUSTED_CERTIFICATES);
    }

    public void setAdditionalTrustedCertificates(String certificates) {
        getConfig().put(ADDITIONAL_TRUSTED_CERTIFICATES, certificates);
    }

    /**
     * Get the credential set mode for DCQL queries with multiple credential types.
     * - "optional": Any one of the requested credentials satisfies the request (default)
     * - "all": All requested credentials must be presented
     */
    public String getCredentialSetMode() {
        String mode = getConfig().get(CREDENTIAL_SET_MODE);
        return mode != null && !mode.isBlank() ? mode : CREDENTIAL_SET_MODE_OPTIONAL;
    }

    public void setCredentialSetMode(String mode) {
        getConfig().put(CREDENTIAL_SET_MODE, mode);
    }

    /**
     * Check if all credentials are required (credential_set mode = "all").
     */
    public boolean isAllCredentialsRequired() {
        return CREDENTIAL_SET_MODE_ALL.equals(getCredentialSetMode());
    }

    /**
     * Get the purpose string for credential_sets in DCQL.
     * This is optional and describes why the credentials are being requested.
     */
    public String getCredentialSetPurpose() {
        return getConfig().get(CREDENTIAL_SET_PURPOSE);
    }

    public void setCredentialSetPurpose(String purpose) {
        getConfig().put(CREDENTIAL_SET_PURPOSE, purpose);
    }

    /**
     * Check if a given issuer is allowed by this configuration.
     * If no issuers are configured, all issuers in the trust list are allowed.
     */
    public boolean isIssuerAllowed(String issuer) {
        String allowed = getAllowedIssuers();
        if (allowed == null || allowed.isBlank()) {
            return true; // No restriction, defer to trust list
        }
        for (String entry : allowed.split("[,\\s]+")) {
            if (entry.trim().equalsIgnoreCase(issuer)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a given credential type is allowed by this configuration.
     * If no types are configured, all types are allowed.
     */
    public boolean isCredentialTypeAllowed(String credentialType) {
        String allowed = getAllowedCredentialTypes();
        if (allowed == null || allowed.isBlank()) {
            return true; // No restriction
        }
        for (String entry : allowed.split("[,\\s]+")) {
            if (entry.trim().equals(credentialType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get verifier_info JSON containing attestations about the verifier.
     * This is an array of attestation objects (e.g., registration certificates for EUDI Wallet).
     * Format: [{"format": "registration_cert", "data": "<JWT>"}]
     */
    public String getVerifierInfo() {
        return getConfig().get(VERIFIER_INFO);
    }

    public void setVerifierInfo(String verifierInfo) {
        getConfig().put(VERIFIER_INFO, verifierInfo);
    }

    // HAIP compliance mode

    /**
     * Check if HAIP (High Assurance Interoperability Profile) compliance is enforced.
     * When enabled, various configuration values are overridden with HAIP-compliant settings.
     */
    public boolean isEnforceHaip() {
        String value = getConfig().get(ENFORCE_HAIP);
        return value == null || !"false".equalsIgnoreCase(value); // default true
    }

    public void setEnforceHaip(boolean enforce) {
        getConfig().put(ENFORCE_HAIP, String.valueOf(enforce));
    }

    // HAIP-enforced effective getters
    // These return HAIP-mandated values when enforce mode is enabled, otherwise the configured value

    /**
     * Get the effective DC API request mode.
     * When HAIP is enforced, always returns "signed" (JAR required per HAIP Section 5.1).
     */
    public String getEffectiveDcApiRequestMode() {
        if (isEnforceHaip()) {
            return HAIP_REQUEST_MODE;
        }
        return getDcApiRequestMode();
    }

    /**
     * Get the effective signing algorithm.
     * When HAIP is enforced, returns "ES256" (required per HAIP Section 7).
     * Note: The actual signing algorithm is determined by the realm key configuration,
     * but this value can be used to validate/warn about non-HAIP-compliant keys.
     */
    public String getEffectiveSigningAlgorithm() {
        if (isEnforceHaip()) {
            return HAIP_SIGNING_ALGORITHM;
        }
        return null; // No specific algorithm enforced
    }

    /**
     * Check if encrypted responses are required.
     * When HAIP is enforced, encrypted responses are always required (Section 5-2.5).
     */
    public boolean isEncryptedResponseRequired() {
        return isEnforceHaip();
    }

    /**
     * Check if trust from x5c is allowed.
     * When HAIP is enforced, trusting arbitrary x5c certificates is disabled
     * (credentials must be verified against the configured trust list per Section 5-2.7).
     */
    public boolean getEffectiveTrustX5cFromCredential() {
        if (isEnforceHaip()) {
            return false; // HAIP requires trust anchor verification
        }
        return isTrustX5cFromCredential();
    }

    /**
     * Get a summary of HAIP-enforced settings for debugging/display.
     */
    public String getHaipEnforcementSummary() {
        if (!isEnforceHaip()) {
            return "HAIP enforcement disabled";
        }
        return String.format(
                "HAIP enforcement enabled: request_mode=%s, signing_alg=%s, encrypted_response=required, trust_x5c=disabled",
                HAIP_REQUEST_MODE, HAIP_SIGNING_ALGORITHM
        );
    }
}
