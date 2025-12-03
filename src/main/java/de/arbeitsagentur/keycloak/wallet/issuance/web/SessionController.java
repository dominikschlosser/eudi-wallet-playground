package de.arbeitsagentur.keycloak.wallet.issuance.web;

import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.issuance.oidc.OidcClient;
import de.arbeitsagentur.keycloak.wallet.issuance.service.CredentialService;
import de.arbeitsagentur.keycloak.wallet.issuance.service.MockIssuerFlowService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.SessionService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.TokenSet;
import de.arbeitsagentur.keycloak.wallet.issuance.session.WalletSession;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SessionController {
    private final SessionService sessionService;
    private final CredentialStore credentialStore;
    private final CredentialService credentialService;
    private final OidcClient oidcClient;
    private final MockIssuerFlowService mockIssuerFlowService;

    public SessionController(SessionService sessionService, CredentialStore credentialStore,
                             CredentialService credentialService,
                             OidcClient oidcClient,
                             MockIssuerFlowService mockIssuerFlowService) {
        this.sessionService = sessionService;
        this.credentialStore = credentialStore;
        this.credentialService = credentialService;
        this.oidcClient = oidcClient;
        this.mockIssuerFlowService = mockIssuerFlowService;
    }

    @GetMapping("/session")
    public Map<String, Object> session(HttpSession httpSession) {
        WalletSession session = sessionService.getSession(httpSession);
        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", session.isAuthenticated());
        response.put("user", session.getUserProfile());
        response.put("credentials", credentialStore.listCredentialEntries(
                session.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER)));
        return response;
    }

    @PostMapping("/issue")
    public ResponseEntity<?> issue(HttpSession httpSession,
                                   @org.springframework.web.bind.annotation.RequestParam(
                                           value = "credentialConfigurationId", required = false) String configId) {
        WalletSession session = sessionService.getSession(httpSession);
        if (!session.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        TokenSet tokens = session.getTokenSet();
        if (tokens.needsRefresh()) {
            tokens = oidcClient.refreshTokens(tokens);
            session.setTokenSet(tokens);
        }
        if (tokens == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Missing tokens"));
        }
        Map<String, Object> credential = credentialService.issueCredential(
                session.getUserProfile().sub(),
                tokens.accessToken(),
                tokens.cNonce(),
                configId
        );
        if (credential.get("cNonce") instanceof String cNonce && !cNonce.isBlank()) {
            session.setTokenSet(new TokenSet(
                    tokens.accessToken(),
                    tokens.refreshToken(),
                    tokens.scope(),
                    tokens.expiresAt(),
                    cNonce,
                    tokens.cNonceExpiresAt()
            ));
        }
        return ResponseEntity.ok(credential);
    }

    @PostMapping("/mock-issue")
    public ResponseEntity<?> mockIssue(HttpSession httpSession, jakarta.servlet.http.HttpServletRequest request) {
        WalletSession session = sessionService.getSession(httpSession);
        String configurationId = request.getParameter("configurationId");
        String credentialOffer = request.getParameter("credentialOffer");
        try {
            Map<String, Object> credential = mockIssuerFlowService.issueWithMockIssuer(
                    CredentialStore.MOCK_ISSUER_OWNER,
                    request,
                    null,
                    configurationId,
                    null,
                    credentialOffer
            );
            return ResponseEntity.ok(credential);
        } catch (org.springframework.web.server.ResponseStatusException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .body(Map.of("error", e.getReason() != null ? e.getReason() : "Mock issuance failed"));
        }
    }

    @PostMapping("/credentials/delete")
    public ResponseEntity<?> deleteCredential(@org.springframework.web.bind.annotation.RequestParam("file") String file,
                                              HttpSession httpSession) {
        WalletSession session = sessionService.getSession(httpSession);
        List<String> ownerIds = session.ownerIdsIncluding(CredentialStore.MOCK_ISSUER_OWNER);
        boolean deleted = credentialStore.deleteCredential(ownerIds, file);
        if (!deleted) {
            return ResponseEntity.status(404).body(Map.of("error", "Credential not found"));
        }
        return ResponseEntity.ok(Map.of("deleted", file));
    }
}
