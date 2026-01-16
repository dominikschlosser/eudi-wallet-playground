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

import de.arbeitsagentur.keycloak.oid4vp.FederatedIdentityKeyGenerator;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpQrCodeService;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage.CredentialOfferState;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedCode;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedGrant;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Authenticator for credential issuance during PID Binding first-broker-login flow.
 * <p>
 * This authenticator should run AFTER the standard username/password authenticator.
 * It handles:
 * <ol>
 *   <li>Updating the federated identity with the permanent lookup key (based on user ID)</li>
 *   <li>Showing the credential issuance page with QR code</li>
 *   <li>Handling continue/skip actions</li>
 * </ol>
 */
public class PidBindingCredentialIssuanceAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(PidBindingCredentialIssuanceAuthenticator.class);
    private static final int DEFAULT_PRE_AUTHORIZED_CODE_LIFESPAN_S = 300; // 5 minutes

    private final Oid4vpQrCodeService qrCodeService = new Oid4vpQrCodeService();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LOG.infof("[PID-CREDENTIAL-ISSUANCE] ========== authenticate called ==========");

        UserModel user = context.getUser();
        if (user == null) {
            LOG.warnf("[PID-CREDENTIAL-ISSUANCE] No user in context - this authenticator must run after username/password auth");
            context.success();
            return;
        }

        String idpAlias = context.getAuthenticationSession().getAuthNote("identity_provider");
        LOG.infof("[PID-CREDENTIAL-ISSUANCE] User: %s, IdP: %s", user.getUsername(), idpAlias);

        // Show credential issuance page
        // Note: Federated identity is updated only when user clicks "Continue" (received credential)
        LOG.infof("[PID-CREDENTIAL-ISSUANCE] Showing credential issuance page");

        // For re-issuance flow: Remove existing federated identity if present.
        // This prevents duplicate key errors when Keycloak's afterFirstBrokerLogin
        // tries to create a new federated identity.
        removeExistingFederatedIdentityIfPresent(context, user, idpAlias);

        // Set user_id attribute for OID4VCI mapper
        user.setSingleAttribute("user_id", user.getId());

        // Show credential issuance page
        showCredentialIssuancePage(context, user);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        LOG.infof("[PID-CREDENTIAL-ISSUANCE] ========== action called ==========");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        // Check if this is a "continue" action (user received credential)
        String continueAction = formData.getFirst("continue");
        if (continueAction != null) {
            LOG.infof("[PID-CREDENTIAL-ISSUANCE] Continue action - user has received credential");
            // Update the BrokeredIdentityContext with the correct lookup key.
            // Keycloak's afterFirstBrokerLogin() will use this to create the federated identity.
            UserModel user = context.getUser();
            if (user != null) {
                updateBrokeredIdentityContextWithCorrectLookupKey(context, user);
            }
            context.success();
            return;
        }

        // Check if this is a "skip" action (user skipped credential)
        String skipAction = formData.getFirst("skip");
        if (skipAction != null) {
            LOG.infof("[PID-CREDENTIAL-ISSUANCE] Skip action - completing flow (federated identity NOT updated)");
            // Don't update federated identity - user doesn't have the credential
            context.success();
            return;
        }

        // Unknown action - show form again
        LOG.warnf("[PID-CREDENTIAL-ISSUANCE] Unknown action, showing form again");
        showCredentialIssuancePage(context, context.getUser());
    }

    /**
     * Show the credential issuance page with QR code.
     */
    private void showCredentialIssuancePage(AuthenticationFlowContext context, UserModel user) {
        // Build credential offer
        String credentialOfferUri = buildCredentialOfferUri(context, user.getId());

        // Build openid-credential-offer:// URI
        String openidCredentialOfferUri = "openid-credential-offer://?credential_offer_uri=" +
                java.net.URLEncoder.encode(credentialOfferUri, StandardCharsets.UTF_8);

        // Get wallet URL for same-device flow
        String sameDeviceWalletUrl;
        if (isNativeWalletMode(context)) {
            sameDeviceWalletUrl = openidCredentialOfferUri;
        } else {
            String walletUrl = getWalletUrl(context);
            sameDeviceWalletUrl = walletUrl + "?credentialOffer=" +
                    java.net.URLEncoder.encode(openidCredentialOfferUri, StandardCharsets.UTF_8);
        }

        // Generate QR code
        String qrCodeBase64 = null;
        try {
            qrCodeBase64 = qrCodeService.generateQrCode(openidCredentialOfferUri, 200, 200);
        } catch (Exception e) {
            LOG.warnf(e, "[PID-CREDENTIAL-ISSUANCE] Failed to generate QR code: %s", e.getMessage());
        }

        LOG.infof("[PID-CREDENTIAL-ISSUANCE] Showing credential issuance page. Offer URI: %s", credentialOfferUri);

        Response response = context.form()
                .setAttribute("credentialOfferUri", credentialOfferUri)
                .setAttribute("openidCredentialOfferUri", openidCredentialOfferUri)
                .setAttribute("sameDeviceWalletUrl", sameDeviceWalletUrl)
                .setAttribute("qrCodeBase64", qrCodeBase64)
                .setAttribute("userName", user.getUsername())
                .createForm("login-pid-binding-credential.ftl");
        context.challenge(response);
    }

    /**
     * Build the OID4VCI credential offer URI.
     */
    private String buildCredentialOfferUri(AuthenticationFlowContext context, String userId) {
        KeycloakSession session = context.getSession();
        String issuer = session.getContext().getUri().getBaseUri().toString() +
                "realms/" + context.getRealm().getName();

        String configId = getCredentialConfigurationId(context);
        String preAuthorizedCode = "urn:oid4vci:code:" + SecretGenerator.getInstance().randomString(64);

        CredentialsOffer credOffer = new CredentialsOffer()
                .setCredentialIssuer(issuer)
                .setCredentialConfigurationIds(List.of(configId));

        credOffer.setGrants(new PreAuthorizedGrant().setPreAuthorizedCode(
                new PreAuthorizedCode().setPreAuthorizedCode(preAuthorizedCode)));

        int expiration = Time.currentTime() + DEFAULT_PRE_AUTHORIZED_CODE_LIFESPAN_S;
        String clientId = getOid4vciClientId(context);

        CredentialOfferState offerState = new CredentialOfferState(credOffer, clientId, userId, expiration);

        CredentialOfferStorage offerStorage = session.getProvider(CredentialOfferStorage.class);
        if (offerStorage == null) {
            throw new RuntimeException("CredentialOfferStorage provider not available");
        }
        offerStorage.putOfferState(session, offerState);

        return issuer + "/protocol/oid4vc/credential-offer/" + offerState.getNonce();
    }

    private String getCredentialConfigurationId(AuthenticationFlowContext context) {
        String idpAlias = context.getAuthenticationSession().getAuthNote("identity_provider");
        if (idpAlias != null) {
            var idp = context.getRealm().getIdentityProviderByAlias(idpAlias);
            if (idp != null) {
                PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig(idp);
                String configId = config.getCredentialConfigurationId();
                if (configId != null && !configId.isBlank()) {
                    return configId;
                }
            }
        }
        return "user-binding-credential";
    }

    private String getOid4vciClientId(AuthenticationFlowContext context) {
        String idpAlias = context.getAuthenticationSession().getAuthNote("identity_provider");
        if (idpAlias != null) {
            var idp = context.getRealm().getIdentityProviderByAlias(idpAlias);
            if (idp != null) {
                PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig(idp);
                String clientId = config.getOid4vciClientId();
                if (clientId != null && !clientId.isBlank()) {
                    return clientId;
                }
            }
        }
        return "pid-binding-wallet";
    }

    private String getWalletUrl(AuthenticationFlowContext context) {
        String idpAlias = context.getAuthenticationSession().getAuthNote("identity_provider");
        if (idpAlias != null) {
            var idp = context.getRealm().getIdentityProviderByAlias(idpAlias);
            if (idp != null) {
                PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig(idp);
                return config.getCredentialIssuanceWalletUrl();
            }
        }
        return PidBindingIdentityProviderConfig.DEFAULT_CREDENTIAL_ISSUANCE_WALLET_URL;
    }

    private boolean isNativeWalletMode(AuthenticationFlowContext context) {
        String idpAlias = context.getAuthenticationSession().getAuthNote("identity_provider");
        if (idpAlias != null) {
            var idp = context.getRealm().getIdentityProviderByAlias(idpAlias);
            if (idp != null) {
                PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig(idp);
                return config.isNativeWalletMode();
            }
        }
        return false;
    }

    /**
     * Remove existing federated identity if present (to handle re-issuance flow).
     * This prevents duplicate key errors when Keycloak's afterFirstBrokerLogin
     * tries to create a new federated identity.
     */
    private void removeExistingFederatedIdentityIfPresent(AuthenticationFlowContext context, UserModel user, String idpAlias) {
        try {
            if (idpAlias == null || idpAlias.isBlank()) {
                idpAlias = "german-pid";
            }

            FederatedIdentityModel existingIdentity = context.getSession().users()
                    .getFederatedIdentity(context.getRealm(), user, idpAlias);

            if (existingIdentity != null) {
                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Removing existing federated identity for re-issuance: user=%s, idp=%s",
                        user.getUsername(), idpAlias);
                context.getSession().users().removeFederatedIdentity(context.getRealm(), user, idpAlias);
            }
        } catch (Exception e) {
            LOG.warnf(e, "[PID-CREDENTIAL-ISSUANCE] Error checking/removing existing federated identity: %s", e.getMessage());
        }
    }

    @Override
    public boolean requiresUser() {
        return true; // Requires user to be authenticated first
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Nothing to close
    }

    /**
     * Update the BrokeredIdentityContext with the correct lookup key.
     * Keycloak's afterFirstBrokerLogin() will use this to create the federated identity.
     */
    private void updateBrokeredIdentityContextWithCorrectLookupKey(AuthenticationFlowContext context, UserModel user) {
        try {
            // Compute the correct lookup key using issuer, login credential type, and user ID
            String baseUri = context.getSession().getContext().getUri().getBaseUri().toString();
            if (!baseUri.endsWith("/")) {
                baseUri = baseUri + "/";
            }
            String issuer = baseUri + "realms/" + context.getRealm().getName();
            String loginCredentialType = getLoginCredentialType(context);
            String lookupKey = FederatedIdentityKeyGenerator.computeLookupKey(issuer, loginCredentialType, user.getId());

            LOG.infof("[PID-CREDENTIAL-ISSUANCE] Updating context: issuer=%s, type=%s, userId=%s, lookupKey=%s",
                    issuer, loginCredentialType, user.getId(), lookupKey);

            // Update the BrokeredIdentityContext
            SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                    context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

            if (serializedCtx != null) {
                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Found BrokeredIdentityContext, setting correct ID...");
                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Old ID: %s", serializedCtx.getId());

                // IMPORTANT: setId() sets the field that Keycloak uses for federated identity creation
                // setBrokerUserId() is a different field and won't affect the lookup key
                serializedCtx.setId(lookupKey);
                serializedCtx.setBrokerUsername(user.getId());
                serializedCtx.saveToAuthenticationSession(context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Set BrokeredIdentityContext ID to: %s", lookupKey);
            } else {
                LOG.warnf("[PID-CREDENTIAL-ISSUANCE] No BrokeredIdentityContext found in session!");
            }

        } catch (Exception e) {
            LOG.warnf(e, "[PID-CREDENTIAL-ISSUANCE] Error updating BrokeredIdentityContext: %s", e.getMessage());
        }
    }

    private String getLoginCredentialType(AuthenticationFlowContext context) {
        String idpAlias = context.getAuthenticationSession().getAuthNote("identity_provider");
        if (idpAlias != null) {
            var idp = context.getRealm().getIdentityProviderByAlias(idpAlias);
            if (idp != null) {
                PidBindingIdentityProviderConfig config = new PidBindingIdentityProviderConfig(idp);
                String type = config.getLoginCredentialType();
                if (type != null && !type.isBlank()) {
                    return type;
                }
            }
        }
        return "urn:arbeitsagentur:user_credential:1";
    }
}
