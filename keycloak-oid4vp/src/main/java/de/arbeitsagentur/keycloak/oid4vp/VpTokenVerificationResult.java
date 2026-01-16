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

import java.util.Map;

/**
 * Result of VP token verification containing all extracted credentials and their claims.
 */
public record VpTokenVerificationResult(
        VpTokenFormat.Type format,
        Map<String, VerifiedCredential> credentials,
        Map<String, Object> mergedClaims
) {
    /**
     * A single verified credential with its metadata and claims.
     */
    public record VerifiedCredential(
            String credentialId,
            String issuer,
            String credentialType,
            Map<String, Object> claims,
            Oid4vpVerifierService.PresentationType presentationType
    ) {}

    /**
     * Returns true if this is a multi-credential response.
     */
    public boolean isMultiCredential() {
        return format == VpTokenFormat.Type.MULTI_CREDENTIAL;
    }

    /**
     * Gets a credential by its ID, or null if not found.
     */
    public VerifiedCredential getCredential(String credentialId) {
        return credentials.get(credentialId);
    }

    /**
     * Gets the first (or only) credential. Useful for single-credential responses.
     */
    public VerifiedCredential getPrimaryCredential() {
        if (credentials.isEmpty()) {
            return null;
        }
        return credentials.values().iterator().next();
    }

    /**
     * Finds a credential by its vct (verifiable credential type) claim.
     */
    public VerifiedCredential findCredentialByVct(String vct) {
        for (VerifiedCredential cred : credentials.values()) {
            Object credVct = cred.claims().get("vct");
            if (vct.equals(credVct)) {
                return cred;
            }
        }
        return null;
    }
}
