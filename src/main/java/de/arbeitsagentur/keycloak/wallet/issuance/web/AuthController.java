package de.arbeitsagentur.keycloak.wallet.issuance.web;

import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import de.arbeitsagentur.keycloak.wallet.issuance.oidc.OidcClient;
import de.arbeitsagentur.keycloak.wallet.issuance.oidc.PkceUtils;
import de.arbeitsagentur.keycloak.wallet.issuance.session.PkceSession;
import de.arbeitsagentur.keycloak.wallet.issuance.session.SessionService;
import de.arbeitsagentur.keycloak.wallet.issuance.session.TokenSet;
import de.arbeitsagentur.keycloak.wallet.issuance.session.UserProfile;
import de.arbeitsagentur.keycloak.wallet.issuance.session.WalletSession;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

@Controller
public class AuthController {
    private final SessionService sessionService;
    private final WalletProperties properties;
    private final OidcClient oidcClient;
    private final DebugLogService debugLogService;

    public AuthController(SessionService sessionService, WalletProperties properties, OidcClient oidcClient,
                          DebugLogService debugLogService) {
        this.sessionService = sessionService;
        this.properties = properties;
        this.oidcClient = oidcClient;
        this.debugLogService = debugLogService;
    }

    @GetMapping("/auth/login")
    public ResponseEntity<Void> login(HttpServletRequest request) {
        WalletSession session = sessionService.getSession(request.getSession());
        String state = PkceUtils.randomState();
        String nonce = PkceUtils.randomState();
        String codeVerifier = PkceUtils.generateCodeVerifier();
        String codeChallenge = PkceUtils.generateCodeChallenge(codeVerifier);
        URI redirectUri = currentBaseUri(request).resolve("/auth/callback");
        session.setPkceSession(new PkceSession(state, nonce, codeVerifier));
        URI authorize = oidcClient.buildAuthorizationUrl(state, nonce, codeChallenge, redirectUri);
        debugLogService.addIssuance("OIDC Login", "Authorization",
                "OIDC authorization request",
                "GET",
                authorize.toString(),
                Map.of(),
                "",
                302,
                Map.of("Location", authorize.toString()),
                "Redirecting to wallet",
                "https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint",
                null);
        return ResponseEntity.status(302).location(authorize).build();
    }

    @GetMapping("/auth/callback")
    public ResponseEntity<?> callback(@RequestParam("code") String code, @RequestParam("state") String state,
                                      HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        WalletSession session = sessionService.getSession(httpSession);
        PkceSession pkce = session.getPkceSession();
        if (pkce == null || !pkce.state().equals(state)) {
            return ResponseEntity.badRequest().body("Invalid state");
        }
        URI redirectUri = currentBaseUri(request).resolve("/auth/callback");
        TokenSet tokens = oidcClient.exchangeCode(code, pkce.codeVerifier(), redirectUri);
        UserProfile profile = oidcClient.fetchUserInfo(tokens.accessToken());
        session.setUserProfile(profile);
        session.setTokenSet(tokens);
        session.setPkceSession(null);
        debugLogService.addIssuance("OIDC Login", "Callback",
                "OIDC callback handled",
                "GET",
                redirectUri.toString(),
                Map.of(),
                "code=%s\nstate=%s".formatted(code, state),
                302,
                Map.of("Location", "/"),
                "user=%s\nscope=%s".formatted(profile.sub(), tokens.scope()),
                "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth",
                null);
        Object postLogin = httpSession.getAttribute("postLoginRedirect");
        if (postLogin instanceof String target && !target.isBlank()) {
            httpSession.removeAttribute("postLoginRedirect");
            return ResponseEntity.status(302).location(URI.create(target)).build();
        }
        return ResponseEntity.status(302).location(URI.create("/")).build();
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(HttpSession httpSession, HttpServletRequest request) {
        WalletSession session = sessionService.getSession(httpSession);
        URI redirect = currentBaseUri(request);
        URI endSession = UriComponentsBuilder.fromUriString(properties.keycloakBaseUrl())
                .path("/realms/")
                .path(properties.realm())
                .path("/protocol/openid-connect/logout")
                .queryParam("client_id", properties.clientId())
                .queryParam("post_logout_redirect_uri", redirect.toString())
                .build(true)
                .toUri();
        httpSession.invalidate();
        return ResponseEntity.status(302).location(endSession).build();
    }

    private URI currentBaseUri(HttpServletRequest request) {
        return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString());
    }
}
