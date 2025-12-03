package de.arbeitsagentur.keycloak.wallet.issuance.session;

import java.util.ArrayList;
import java.util.List;

public class WalletSession {
    private PkceSession pkceSession;
    private TokenSet tokenSet;
    private UserProfile userProfile;
    private String localId;

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

    public String getLocalId() {
        return localId;
    }

    public void setLocalId(String localId) {
        this.localId = localId;
    }

    public boolean isAuthenticated() {
        return userProfile != null && tokenSet != null;
    }

    public String ownerId() {
        if (userProfile != null) {
            return userProfile.sub();
        }
        return localId;
    }

    public List<String> ownerIds() {
        List<String> ids = new ArrayList<>();
        if (userProfile != null && userProfile.sub() != null) {
            ids.add(userProfile.sub());
        }
        if (localId != null && !localId.isBlank() && (ids.isEmpty() || !ids.contains(localId))) {
            ids.add(localId);
        }
        return ids;
    }

    public List<String> ownerIdsIncluding(String... additionalOwnerIds) {
        List<String> ids = ownerIds();
        if (additionalOwnerIds != null) {
            for (String id : additionalOwnerIds) {
                if (id != null && !id.isBlank() && !ids.contains(id)) {
                    ids.add(id);
                }
            }
        }
        return ids;
    }
}
