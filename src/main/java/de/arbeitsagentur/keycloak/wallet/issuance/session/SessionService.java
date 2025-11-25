package de.arbeitsagentur.keycloak.wallet.issuance.session;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

@Component
public class SessionService {
    private static final String ATTRIBUTE_KEY = "walletSession";

    public WalletSession getSession(HttpSession httpSession) {
        WalletSession session = (WalletSession) httpSession.getAttribute(ATTRIBUTE_KEY);
        if (session == null) {
            session = new WalletSession();
            httpSession.setAttribute(ATTRIBUTE_KEY, session);
        }
        return session;
    }
}
