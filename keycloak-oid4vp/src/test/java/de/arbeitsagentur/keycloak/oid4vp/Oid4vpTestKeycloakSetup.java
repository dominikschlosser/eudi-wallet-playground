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

import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Test setup utilities for configuring OID4VP Identity Provider in Keycloak.
 */
final class Oid4vpTestKeycloakSetup {

    // Default DCQL query requesting EUDI PID in either SD-JWT or mDoc format
    // Uses credential_sets to allow the wallet to present either format
    static final String DEFAULT_DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "pid_sd_jwt",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:1"] },
                  "claims": [
                    { "path": ["document_number"] },
                    { "path": ["family_name"] },
                    { "path": ["given_name"] },
                    { "path": ["birthdate"] }
                  ]
                },
                {
                  "id": "pid_mdoc",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                  "claims": [
                    { "path": ["eu.europa.ec.eudi.pid.1", "document_number"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                  ]
                }
              ],
              "credential_sets": [
                {
                  "options": [["pid_sd_jwt"], ["pid_mdoc"]],
                  "required": true
                }
              ]
            }
            """;

    // DCQL query with claim_sets for testing optional claims
    // Demonstrates alternative combinations of claims the wallet can present
    static final String DCQL_QUERY_WITH_CLAIM_SETS = """
            {
              "credentials": [
                {
                  "id": "pid_sd_jwt",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:1"] },
                  "claims": [
                    { "id": "doc_num", "path": ["document_number"] },
                    { "id": "family", "path": ["family_name"] },
                    { "id": "given", "path": ["given_name"] },
                    { "id": "birth", "path": ["birthdate"] },
                    { "id": "nationality", "path": ["nationalities"] }
                  ],
                  "claim_sets": [
                    ["doc_num", "family", "given", "birth", "nationality"],
                    ["doc_num", "family", "given", "birth"]
                  ]
                }
              ]
            }
            """;

    // Trust list JWT (ETSI TS 119 602 format) for testing - contains the mock issuer certificate
    static final String TEST_TRUST_LIST_JWT = "eyJhbGciOiAibm9uZSJ9.eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IlRlc3QgVHJ1c3QgTGlzdCJ9XSwiTG9URVR5cGUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL0xvVEVUeXBlL2xvY2FsIn0sIlRydXN0ZWRFbnRpdGllc0xpc3QiOlt7IlRydXN0ZWRFbnRpdHlJbmZvcm1hdGlvbiI6eyJURU5hbWUiOlt7ImxhbmciOiJlbiIsInZhbHVlIjoibW9jay1pc3N1ZXItZXMyNTYifV19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvSXNzdWFuY2UiLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUJnVENDQVNlZ0F3SUJBZ0lVQmpFYUloR2NXNXBQWDd2Q3RYYnFNeXFsN2V3d0NnWUlLb1pJemowRUF3SXdGakVVTUJJR0ExVUVBd3dMYlc5amF5MXBjM04xWlhJd0hoY05NalV4TWpBeE1Ea3pPVEkyV2hjTk16VXhNVEk1TURrek9USTJXakFXTVJRd0VnWURWUVFEREF0dGIyTnJMV2x6YzNWbGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJDU0dvMDJmTko0aWx5SUpWc25SOTBVTXZCRWhiRHhwdklOL1grUnE0eTlxakNBMzVJbmJ3bTVqRjB0b3lwb292NGFhZ0pHYVJrd3ptdk95MUpNbGFtS2pVekJSTUIwR0ExVWREZ1FXQkJSMm1PeDI2NTA3OG5CWHNTQ2YwN2U5OVJCbEREQWZCZ05WSFNNRUdEQVdnQlIybU94MjY1MDc4bkJYc1JDZjA3ZTk5UkJsRERBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEYzFFdmI1OFZXQUdUTmdpYWRzdFFtQ0w2WUwzQ2hBU3QvVkxoZ0Evb2diQUlnSzVEakxRdVkwZFZEVGFEY2NFQzlzL3VhS3UrejV1MjhadFFqVks2NXpGVT0ifV19fX1dfV19.";

    // DCQL query for German PID only (no unique identifiers like document_number)
    // This simulates the real German PID which doesn't have globally unique identifiers
    static final String GERMAN_PID_DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "german_pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                  "claims": [
                    { "path": ["family_name"] },
                    { "path": ["given_name"] },
                    { "path": ["birthdate"] },
                    { "path": ["nationalities"] },
                    { "path": ["issuing_country"] }
                  ]
                }
              ]
            }
            """;

    // DCQL query for multi-credential flow: German PID + Verifier User Credential
    // Both credentials are required for login (credential_sets with both mandatory)
    static final String MULTI_CREDENTIAL_DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "german_pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                  "claims": [
                    { "path": ["family_name"] },
                    { "path": ["given_name"] },
                    { "path": ["birthdate"] }
                  ]
                },
                {
                  "id": "user_binding",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:arbeitsagentur:user_credential:1"] },
                  "claims": [
                    { "path": ["user_id"] }
                  ]
                }
              ],
              "credential_sets": [
                {
                  "options": [["german_pid", "user_binding"]],
                  "required": true
                }
              ]
            }
            """;

    static void addRedirectUriToClient(KeycloakAdminClient admin, String realm, String clientId, String redirectUri) throws Exception {
        List<Map<String, Object>> clients = admin.getJsonList(
                "/admin/realms/" + realm + "/clients?clientId=" + urlEncode(clientId));
        Map<String, Object> client = clients.stream()
                .filter(entry -> clientId.equals(entry.get("clientId")))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Client not found: " + clientId));
        String id = String.valueOf(client.get("id"));

        Map<String, Object> rep = admin.getJson("/admin/realms/" + realm + "/clients/" + id);
        Object raw = rep.get("redirectUris");
        List<String> redirectUris = raw instanceof List<?> list
                ? list.stream().map(String::valueOf).distinct().collect(Collectors.toCollection(ArrayList::new))
                : new ArrayList<>();
        if (!redirectUris.contains(redirectUri)) {
            redirectUris.add(redirectUri);
        }
        rep.put("redirectUris", redirectUris);
        admin.putJson("/admin/realms/" + realm + "/clients/" + id, rep);
    }

    /**
     * Configure OID4VP Identity Provider and add it to the browser flow.
     */
    static void configureOid4vpIdentityProvider(KeycloakAdminClient admin, String realm) throws Exception {
        // Create OID4VP Identity Provider
        Map<String, Object> idpConfig = new LinkedHashMap<>();
        idpConfig.put("alias", "oid4vp");
        idpConfig.put("displayName", "Sign in with Wallet");
        idpConfig.put("providerId", Oid4vpIdentityProviderFactory.PROVIDER_ID);
        idpConfig.put("enabled", true);
        idpConfig.put("trustEmail", false);
        idpConfig.put("storeToken", false);
        idpConfig.put("addReadTokenRoleOnCreate", false);
        idpConfig.put("authenticateByDefault", false);
        idpConfig.put("linkOnly", false);
        idpConfig.put("firstBrokerLoginFlowAlias", "first broker login");

        Map<String, String> config = new LinkedHashMap<>();
        // clientId/clientSecret are required by Keycloak UI but not used by OID4VP
        config.put("clientId", "not-used");
        config.put("clientSecret", "not-used");
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, DEFAULT_DCQL_QUERY);
        config.put(Oid4vpIdentityProviderConfig.TRUST_LIST_JWT, TEST_TRUST_LIST_JWT);
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, DefaultOid4vpValues.DEFAULT_USER_MAPPING_CLAIM);
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC, DefaultOid4vpValues.DEFAULT_USER_MAPPING_CLAIM_MDOC);
        config.put(Oid4vpIdentityProviderConfig.DC_API_REQUEST_MODE, "signed");
        idpConfig.put("config", config);

        // Delete existing if present
        admin.deleteIfExists("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");

        admin.postJson("/admin/realms/" + realm + "/identity-provider/instances", idpConfig);

        // Set login theme
        Map<String, Object> realmRep = admin.getJson("/admin/realms/" + realm);
        realmRep.put("loginTheme", "oid4vp");
        admin.putJson("/admin/realms/" + realm, realmRep);
    }

    /**
     * Update the DCQL query for the OID4VP Identity Provider.
     */
    static void configureDcqlQuery(KeycloakAdminClient admin, String realm, String dcqlQuery) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, dcqlQuery);
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    /**
     * Configure same-device (redirect) flow for the OID4VP Identity Provider.
     */
    static void configureSameDeviceFlow(KeycloakAdminClient admin, String realm, boolean enabled, String walletAuthEndpoint) throws Exception {
        configureSameDeviceFlow(admin, realm, "oid4vp", enabled, walletAuthEndpoint);
    }

    static void configureSameDeviceFlow(KeycloakAdminClient admin, String realm, String idpAlias, boolean enabled, String walletAuthEndpoint) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/" + idpAlias);
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, String.valueOf(enabled));
        if (walletAuthEndpoint != null) {
            config.put(Oid4vpIdentityProviderConfig.SAME_DEVICE_WALLET_URL, walletAuthEndpoint);
        }
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/" + idpAlias, idp);
    }

    /**
     * Configure cross-device (QR code) flow for the OID4VP Identity Provider.
     */
    static void configureCrossDeviceFlow(KeycloakAdminClient admin, String realm, boolean enabled) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, String.valueOf(enabled));
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    /**
     * Delete ALL users that have an OID4VP federated identity from the realm.
     * This ensures a clean state for first-broker-login tests by removing both
     * the federated identity link AND the user itself.
     */
    static void deleteAllOid4vpUsers(KeycloakAdminClient admin, String realm) throws Exception {
        List<Map<String, Object>> users = admin.getJsonList(
                "/admin/realms/" + realm + "/users?max=100");
        for (Map<String, Object> user : users) {
            String userId = String.valueOf(user.get("id"));
            String username = String.valueOf(user.get("username"));
            // Skip built-in admin users
            if ("admin".equals(username) || "test".equals(username)) continue;
            try {
                List<Map<String, Object>> identities = admin.getJsonList(
                        "/admin/realms/" + realm + "/users/" + userId + "/federated-identity");
                boolean hasOid4vp = identities.stream()
                        .anyMatch(id -> "oid4vp".equals(id.get("identityProvider")));
                if (hasOid4vp) {
                    admin.delete("/admin/realms/" + realm + "/users/" + userId);
                }
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Remove all federated identities for a user (for testing clean state).
     */
    static void removeAllFederatedIdentities(KeycloakAdminClient admin, String realm, String username) throws Exception {
        String userId = resolveUserId(admin, realm, username);
        List<Map<String, Object>> identities = admin.getJsonList(
                "/admin/realms/" + realm + "/users/" + userId + "/federated-identity");
        for (Map<String, Object> identity : identities) {
            String idpAlias = String.valueOf(identity.get("identityProvider"));
            admin.delete("/admin/realms/" + realm + "/users/" + userId + "/federated-identity/" + idpAlias);
        }
    }

    /**
     * Remove the OID4VP credential metadata user attribute (for testing clean state).
     */
    static void removeOid4vpCredentialMetadata(KeycloakAdminClient admin, String realm, String username) throws Exception {
        String userId = resolveUserId(admin, realm, username);
        Map<String, Object> user = admin.getJson("/admin/realms/" + realm + "/users/" + userId);
        @SuppressWarnings("unchecked")
        Map<String, Object> attributes = (Map<String, Object>) user.get("attributes");
        if (attributes != null) {
            attributes.remove("oid4vp_credentials");
            admin.putJson("/admin/realms/" + realm + "/users/" + userId, user);
        }
    }

    /**
     * Configure allowed credential types for the OID4VP Identity Provider.
     * Use "*" to allow all types, or comma-separated list of VCT/doctype values.
     */
    static void configureAllowedCredentialTypes(KeycloakAdminClient admin, String realm, String allowedTypes) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.ALLOWED_CREDENTIAL_TYPES, allowedTypes);
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    /**
     * Configure allowed issuers for the OID4VP Identity Provider.
     * Use "*" to allow all issuers, or comma-separated list of issuer identifiers.
     */
    static void configureAllowedIssuers(KeycloakAdminClient admin, String realm, String allowedIssuers) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.ALLOWED_ISSUERS, allowedIssuers);
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    /**
     * Configure the user mapping claim for the OID4VP Identity Provider.
     * This claim is used to match users across logins.
     */
    static void configureUserMappingClaim(KeycloakAdminClient admin, String realm, String claimName) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, claimName);
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    /**
     * Configure the IdP for German PID flow (no unique identifiers).
     * Sets up DCQL query for German PID and configures user mapping to use given_name as fallback.
     */
    static void configureGermanPidFlow(KeycloakAdminClient admin, String realm) throws Exception {
        configureDcqlQuery(admin, realm, GERMAN_PID_DCQL_QUERY);
        configureUserMappingClaim(admin, realm, "given_name");
        configureAllowedCredentialTypes(admin, realm, "urn:eudi:pid:de:1");
    }

    /**
     * Configure the IdP for multi-credential flow (German PID + verifier user credential).
     * Both credentials are required for login.
     * The user_id from the verifier credential is used for user mapping.
     */
    static void configureMultiCredentialFlow(KeycloakAdminClient admin, String realm) throws Exception {
        configureDcqlQuery(admin, realm, MULTI_CREDENTIAL_DCQL_QUERY);
        configureUserMappingClaim(admin, realm, "user_id");
        configureAllowedCredentialTypes(admin, realm, "urn:eudi:pid:de:1,urn:arbeitsagentur:user_credential:1");
    }

    /**
     * Reset the IdP to default configuration (standard EUDI PID with document_number).
     */
    static void resetToDefaultConfiguration(KeycloakAdminClient admin, String realm) throws Exception {
        configureDcqlQuery(admin, realm, DEFAULT_DCQL_QUERY);
        configureUserMappingClaim(admin, realm, DefaultOid4vpValues.DEFAULT_USER_MAPPING_CLAIM);
        configureAllowedCredentialTypes(admin, realm, "*");
    }

    static String resolveUserId(KeycloakAdminClient admin, String realm, String username) throws Exception {
        List<Map<String, Object>> users = admin.getJsonList(
                "/admin/realms/" + realm + "/users?username=" + urlEncode(username));
        return users.stream()
                .filter(u -> username.equals(u.get("username")))
                .map(u -> String.valueOf(u.get("id")))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));
    }

    /**
     * Get the most recently created user (by created timestamp) that has a federated identity
     * from the OID4VP provider. This is useful for finding the user created during first broker login.
     */
    static String findMostRecentOid4vpUser(KeycloakAdminClient admin, String realm) throws Exception {
        List<Map<String, Object>> users = admin.getJsonList(
                "/admin/realms/" + realm + "/users?max=100");

        // Sort by createdTimestamp descending and find first with oid4vp federated identity
        for (Map<String, Object> user : users) {
            String userId = String.valueOf(user.get("id"));
            try {
                List<Map<String, Object>> identities = admin.getJsonList(
                        "/admin/realms/" + realm + "/users/" + userId + "/federated-identity");
                boolean hasOid4vp = identities.stream()
                        .anyMatch(id -> "oid4vp".equals(id.get("identityProvider")));
                if (hasOid4vp) {
                    return userId;
                }
            } catch (Exception ignored) {
                // User might not have federated identities
            }
        }
        throw new IllegalStateException("No user found with OID4VP federated identity");
    }

    /**
     * Get user by ID.
     */
    static Map<String, Object> getUser(KeycloakAdminClient admin, String realm, String userId) throws Exception {
        return admin.getJson("/admin/realms/" + realm + "/users/" + userId);
    }

    /**
     * Update the federated identity for a user to use a new identity value.
     * This simulates what would happen after OID4VCI credential issuance -
     * the user's federated identity is updated to use the verifier-issued user_id.
     *
     * @param admin The admin client
     * @param realm The realm name
     * @param userId The Keycloak user ID
     * @param idpAlias The identity provider alias (e.g., "oid4vp")
     * @param newIdentityUserId The new user ID to set as the federated identity
     */
    static void updateFederatedIdentity(KeycloakAdminClient admin, String realm, String userId,
                                        String idpAlias, String newIdentityUserId) throws Exception {
        // First, get the existing federated identity
        List<Map<String, Object>> identities = admin.getJsonList(
                "/admin/realms/" + realm + "/users/" + userId + "/federated-identity");

        // Find and remove the existing oid4vp identity
        for (Map<String, Object> identity : identities) {
            if (idpAlias.equals(identity.get("identityProvider"))) {
                admin.delete("/admin/realms/" + realm + "/users/" + userId + "/federated-identity/" + idpAlias);
                break;
            }
        }

        // Create a new federated identity with the updated user ID
        Map<String, Object> newIdentity = new LinkedHashMap<>();
        newIdentity.put("identityProvider", idpAlias);
        newIdentity.put("userId", newIdentityUserId);
        newIdentity.put("userName", newIdentityUserId);

        admin.postJson("/admin/realms/" + realm + "/users/" + userId + "/federated-identity/" + idpAlias, newIdentity);
    }

    /**
     * Update the federated identity to use the verifier credential lookup key.
     * This computes the same lookup key that the IdP will compute when processing
     * the multi-credential VP token with the verifier credential.
     *
     * @param admin The admin client
     * @param realm The realm name
     * @param keycloakUserId The Keycloak user ID
     * @param idpAlias The identity provider alias (e.g., "oid4vp")
     */
    static void updateFederatedIdentityForVerifierCredential(KeycloakAdminClient admin, String realm,
                                                              String keycloakUserId, String idpAlias) throws Exception {
        // The lookup key is computed from: issuer + credentialType + subject (user_id)
        // For verifier credentials:
        // - issuer: https://mock-issuer.example (same as mock wallet uses)
        // - credentialType: urn:arbeitsagentur:user_credential:1
        // - subject: the user_id claim value (which is the Keycloak user ID)
        String issuer = "https://mock-issuer.example";
        String credentialType = "urn:arbeitsagentur:user_credential:1";
        String subject = keycloakUserId;

        String lookupKey = computeLookupKey(issuer, credentialType, subject);
        updateFederatedIdentity(admin, realm, keycloakUserId, idpAlias, lookupKey);
    }

    /**
     * Update the federated identity to use the verifier credential lookup key with custom issuer.
     * This is used for PID binding flow where the issuer is the Keycloak realm URL.
     *
     * @param admin The admin client
     * @param realm The realm name
     * @param keycloakUserId The Keycloak user ID
     * @param idpAlias The identity provider alias (e.g., "german-pid")
     * @param keycloakBaseUrl The Keycloak base URL (e.g., "http://127.0.0.1:8080")
     */
    static void updateFederatedIdentityForVerifierCredential(KeycloakAdminClient admin, String realm,
                                                              String keycloakUserId, String idpAlias,
                                                              String keycloakBaseUrl) throws Exception {
        // The lookup key is computed from: issuer + credentialType + subject (user_id)
        // For PID binding flow:
        // - issuer: Keycloak realm URL (e.g., http://127.0.0.1:8080/realms/pid-binding-demo)
        // - credentialType: urn:arbeitsagentur:user_credential:1
        // - subject: the user_id claim value (which is the Keycloak user ID)
        String issuer = keycloakBaseUrl + "/realms/" + realm;
        String credentialType = "urn:arbeitsagentur:user_credential:1";
        String subject = keycloakUserId;

        String lookupKey = computeLookupKey(issuer, credentialType, subject);
        updateFederatedIdentity(admin, realm, keycloakUserId, idpAlias, lookupKey);
    }

    /**
     * Get the federated identity for a user from a specific IdP.
     *
     * @return The federated identity map, or null if not found
     */
    static Map<String, Object> getFederatedIdentity(KeycloakAdminClient admin, String realm,
                                                     String userId, String idpAlias) throws Exception {
        List<Map<String, Object>> identities = admin.getJsonList(
                "/admin/realms/" + realm + "/users/" + userId + "/federated-identity");
        return identities.stream()
                .filter(id -> idpAlias.equals(id.get("identityProvider")))
                .findFirst()
                .orElse(null);
    }

    /**
     * Verify the federated identity has the expected lookup key.
     *
     * @return true if the federated identity exists with the expected lookup key
     */
    static boolean verifyFederatedIdentityLookupKey(KeycloakAdminClient admin, String realm,
                                                     String keycloakUserId, String idpAlias,
                                                     String keycloakBaseUrl) throws Exception {
        Map<String, Object> identity = getFederatedIdentity(admin, realm, keycloakUserId, idpAlias);
        if (identity == null) {
            return false;
        }
        String actualLookupKey = String.valueOf(identity.get("userId"));
        String expectedLookupKey = computeExpectedLookupKey(keycloakBaseUrl, realm, keycloakUserId);
        return expectedLookupKey.equals(actualLookupKey);
    }

    /**
     * Compute the expected lookup key for the PID binding credential.
     */
    static String computeExpectedLookupKey(String keycloakBaseUrl, String realm, String keycloakUserId) {
        String issuer = keycloakBaseUrl + "/realms/" + realm;
        String credentialType = "urn:arbeitsagentur:user_credential:1";
        return computeLookupKey(issuer, credentialType, keycloakUserId);
    }

    /**
     * Compute the lookup key from issuer, credential type, and subject.
     * This must match the algorithm in Oid4vpIdentityProvider.computeLookupKey().
     */
    static String computeLookupKey(String issuer, String credentialType, String subject) {
        String combined = issuer + "\0" + credentialType + "\0" + subject;
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(combined.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute lookup key", e);
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private Oid4vpTestKeycloakSetup() {
    }
}
