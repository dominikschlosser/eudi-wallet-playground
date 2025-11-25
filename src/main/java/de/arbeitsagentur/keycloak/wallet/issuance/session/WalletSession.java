package de.arbeitsagentur.keycloak.wallet.issuance.session;

public class WalletSession {
    private PkceSession pkceSession;
    private TokenSet tokenSet;
    private UserProfile userProfile;

    public PkceSession getPkceSession() {
        return pkceSession;
    }

    public void setPkceSession(PkceSession pkceSession) {
        this.pkceSession = pkceSession;
    }

    public TokenSet getTokenSet() {
        return tokenSet;
    }

    public void setTokenSet(TokenSet tokenSet) {
        this.tokenSet = tokenSet;
    }

    public UserProfile getUserProfile() {
        return userProfile;
    }

    public void setUserProfile(UserProfile userProfile) {
        this.userProfile = userProfile;
    }

    public boolean isAuthenticated() {
        return userProfile != null && tokenSet != null;
    }
}
