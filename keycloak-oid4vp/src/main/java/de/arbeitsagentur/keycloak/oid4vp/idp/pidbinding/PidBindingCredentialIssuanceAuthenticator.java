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
 *   <li>Updating the BrokeredIdentityContext with the permanent lookup key (based on user ID)</li>
 *   <li>Showing the credential issuance page with QR code</li>
 *   <li>Handling continue/skip actions</li>
 * </ol>
 * <p>
 * <b>Important:</b> Custom auth notes set by the identity provider (e.g. SESSION_IDP_ALIAS) are
 * cleared by Keycloak's {@code AuthenticationProcessor.resetFlow()} before the first-broker-login
 * flow starts. This authenticator therefore reads the IDP alias from the
 * {@code BROKERED_CONTEXT_NOTE} (the serialized BrokeredIdentityContext), which IS preserved.
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

        String idpAlias = resolveIdpAlias(context);
        LOG.infof("[PID-CREDENTIAL-ISSUANCE] User: %s, IdP: %s", user.getUsername(), idpAlias);

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
            UserModel user = context.getUser();
            if (user != null) {
                // Update the BrokeredIdentityContext with the correct lookup key.
                // Keycloak's afterFirstBrokerLogin() will use this to create the federated identity.
                updateBrokeredIdentityContextWithCorrectLookupKey(context, user);
                // For re-issuance: remove any existing federated identity so that
                // afterFirstBrokerLogin() can create the new one without duplicate key error.
                removeExistingFederatedIdentity(context, user);
            }
            context.success();
            return;
        }

        // Check if this is a "skip" action (user skipped credential)
        String skipAction = formData.getFirst("skip");
        if (skipAction != null) {
            LOG.infof("[PID-CREDENTIAL-ISSUANCE] Skip action - completing flow");
            UserModel user = context.getUser();
            if (user != null) {
                removeExistingFederatedIdentity(context, user);
            }
            context.success();
            return;
        }

        // Unknown action - show form again
        LOG.warnf("[PID-CREDENTIAL-ISSUANCE] Unknown action, showing form again");
        showCredentialIssuancePage(context, context.getUser());
    }

    /**
     * Resolve the IDP alias from the BrokeredIdentityContext stored in the auth session.
     * <p>
     * We cannot use custom auth notes (like SESSION_IDP_ALIAS) because Keycloak's
     * {@code AuthenticationProcessor.resetFlow()} clears all auth notes before the
     * first-broker-login flow starts. The BrokeredIdentityContext is saved AFTER the reset,
     * so its identity provider ID is always available.
     */
    private String resolveIdpAlias(AuthenticationFlowContext context) {
        SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        if (serializedCtx != null) {
            String alias = serializedCtx.getIdentityProviderId();
            if (alias != null && !alias.isBlank()) {
                return alias;
            }
        }

        // Fallback: find the first pid-binding IDP in the realm
        for (var idp : context.getRealm().getIdentityProvidersStream().toList()) {
            if (PidBindingIdentityProviderFactory.PROVIDER_ID.equals(idp.getProviderId())) {
                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Resolved IDP by provider type fallback: %s", idp.getAlias());
                return idp.getAlias();
            }
        }

        LOG.warnf("[PID-CREDENTIAL-ISSUANCE] Could not resolve IDP alias");
        return null;
    }

    /**
     * Get the PID binding IDP config, resolving the alias from the BrokeredIdentityContext.
     */
    private PidBindingIdentityProviderConfig getPidBindingIdpConfig(AuthenticationFlowContext context) {
        String idpAlias = resolveIdpAlias(context);
        if (idpAlias != null) {
            var idp = context.getRealm().getIdentityProviderByAlias(idpAlias);
            if (idp != null) {
                return new PidBindingIdentityProviderConfig(idp);
            }
        }
        return null;
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
        PidBindingIdentityProviderConfig config = getPidBindingIdpConfig(context);
        String walletUrl = config != null ? config.getCredentialIssuanceWalletUrl() : null;
        boolean nativeWallet = config != null && config.isNativeWalletMode();

        if (nativeWallet || walletUrl == null || walletUrl.isBlank()) {
            sameDeviceWalletUrl = openidCredentialOfferUri;
        } else {
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
     * Remove any existing federated identity for this user+provider.
     * Uses the correct IDP alias resolved from the BrokeredIdentityContext.
     * This is a no-op on first login (no existing identity to remove).
     */
    private void removeExistingFederatedIdentity(AuthenticationFlowContext context, UserModel user) {
        try {
            String idpAlias = resolveIdpAlias(context);
            if (idpAlias == null) {
                return;
            }
            boolean removed = context.getSession().users()
                    .removeFederatedIdentity(context.getRealm(), user, idpAlias);
            if (removed) {
                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Removed existing federated identity for re-issuance: user=%s, idp=%s",
                        user.getUsername(), idpAlias);
            }
        } catch (Exception e) {
            LOG.warnf(e, "[PID-CREDENTIAL-ISSUANCE] Error removing existing federated identity: %s", e.getMessage());
        }
    }

    /**
     * Build the OID4VCI credential offer URI.
     */
    private String buildCredentialOfferUri(AuthenticationFlowContext context, String userId) {
        KeycloakSession session = context.getSession();
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        String issuer = baseUri + "realms/" + context.getRealm().getName();

        PidBindingIdentityProviderConfig config = getPidBindingIdpConfig(context);
        String configId = (config != null && config.getCredentialConfigurationId() != null && !config.getCredentialConfigurationId().isBlank())
                ? config.getCredentialConfigurationId()
                : "user-binding-credential";
        String clientId = (config != null && config.getOid4vciClientId() != null && !config.getOid4vciClientId().isBlank())
                ? config.getOid4vciClientId()
                : "pid-binding-wallet";

        String preAuthorizedCode = "urn:oid4vci:code:" + SecretGenerator.getInstance().randomString(64);

        CredentialsOffer credOffer = new CredentialsOffer()
                .setCredentialIssuer(issuer)
                .setCredentialConfigurationIds(List.of(configId));

        credOffer.setGrants(new PreAuthorizedGrant().setPreAuthorizedCode(
                new PreAuthorizedCode().setPreAuthorizedCode(preAuthorizedCode)));

        int expiration = Time.currentTime() + DEFAULT_PRE_AUTHORIZED_CODE_LIFESPAN_S;

        CredentialOfferState offerState = new CredentialOfferState(credOffer, clientId, userId, expiration);

        CredentialOfferStorage offerStorage = session.getProvider(CredentialOfferStorage.class);
        if (offerStorage == null) {
            throw new RuntimeException("CredentialOfferStorage provider not available");
        }
        offerStorage.putOfferState(session, offerState);

        return issuer + "/protocol/oid4vc/credential-offer/" + offerState.getNonce();
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
     * <p>
     * Keycloak's {@code afterFirstBrokerLogin()} reads this context and uses {@code context.getId()}
     * as the federated user ID when calling {@code addFederatedIdentity()}. We replace the
     * temporary ID (set during processFirstLogin) with the permanent lookup key based on the
     * authenticated user's ID.
     */
    private void updateBrokeredIdentityContextWithCorrectLookupKey(AuthenticationFlowContext context, UserModel user) {
        try {
            String baseUri = context.getSession().getContext().getUri().getBaseUri().toString();
            if (!baseUri.endsWith("/")) {
                baseUri = baseUri + "/";
            }
            String issuer = baseUri + "realms/" + context.getRealm().getName();
            String loginCredentialType = getLoginCredentialType(context);
            String lookupKey = FederatedIdentityKeyGenerator.computeLookupKey(issuer, loginCredentialType, user.getId());

            LOG.infof("[PID-CREDENTIAL-ISSUANCE] Updating context: issuer=%s, type=%s, userId=%s, lookupKey=%s",
                    issuer, loginCredentialType, user.getId(), lookupKey);

            SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                    context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

            if (serializedCtx != null) {
                LOG.infof("[PID-CREDENTIAL-ISSUANCE] Old ID: %s, setting to: %s", serializedCtx.getId(), lookupKey);
                serializedCtx.setId(lookupKey);
                serializedCtx.setBrokerUsername(user.getId());
                serializedCtx.saveToAuthenticationSession(context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
            } else {
                LOG.warnf("[PID-CREDENTIAL-ISSUANCE] No BrokeredIdentityContext found in session!");
            }

        } catch (Exception e) {
            LOG.warnf(e, "[PID-CREDENTIAL-ISSUANCE] Error updating BrokeredIdentityContext: %s", e.getMessage());
        }
    }

    private String getLoginCredentialType(AuthenticationFlowContext context) {
        PidBindingIdentityProviderConfig config = getPidBindingIdpConfig(context);
        if (config != null) {
            String type = config.getLoginCredentialType();
            if (type != null && !type.isBlank()) {
                return type;
            }
        }
        return "urn:arbeitsagentur:user_credential:1";
    }
}
