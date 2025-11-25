package de.arbeitsagentur.keycloak.wallet.issuance.web;

import de.arbeitsagentur.keycloak.wallet.common.storage.CredentialStore;
import de.arbeitsagentur.keycloak.wallet.issuance.oidc.OidcClient;
import de.arbeitsagentur.keycloak.wallet.issuance.service.CredentialService;
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

    public SessionController(SessionService sessionService, CredentialStore credentialStore,
                             CredentialService credentialService,
                             OidcClient oidcClient) {
        this.sessionService = sessionService;
        this.credentialStore = credentialStore;
        this.credentialService = credentialService;
        this.oidcClient = oidcClient;
    }

    @GetMapping("/session")
    public Map<String, Object> session(HttpSession httpSession) {
        WalletSession session = sessionService.getSession(httpSession);
        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", session.isAuthenticated());
        response.put("user", session.getUserProfile());
        List<?> credentials = session.getUserProfile() != null
                ? credentialStore.listCredentialEntries(session.getUserProfile().sub())
                : List.of();
        response.put("credentials", credentials);
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

    @PostMapping("/credentials/delete")
    public ResponseEntity<?> deleteCredential(@org.springframework.web.bind.annotation.RequestParam("file") String file,
                                              HttpSession httpSession) {
        WalletSession session = sessionService.getSession(httpSession);
        if (!session.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        boolean deleted = credentialStore.deleteCredential(session.getUserProfile().sub(), file);
        if (!deleted) {
            return ResponseEntity.status(404).body(Map.of("error", "Credential not found"));
        }
        return ResponseEntity.ok(Map.of("deleted", file));
    }
}
