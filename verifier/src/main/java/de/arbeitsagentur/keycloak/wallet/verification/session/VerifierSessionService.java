package de.arbeitsagentur.keycloak.wallet.verification.session;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

@Component
public class VerifierSessionService {
    private static final String KEY = "verifierSession";

    public void saveSession(HttpSession session, VerifierSession verifierSession) {
        session.setAttribute(KEY, verifierSession);
    }

    public VerifierSession getSession(HttpSession session) {
        Object value = session.getAttribute(KEY);
        return value instanceof VerifierSession ? (VerifierSession) value : null;
    }
}
