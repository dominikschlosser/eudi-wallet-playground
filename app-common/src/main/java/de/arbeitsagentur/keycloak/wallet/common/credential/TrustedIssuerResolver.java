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
package de.arbeitsagentur.keycloak.wallet.common.credential;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Supplies trusted issuer keys for credential signature verification.
 */
public interface TrustedIssuerResolver {
    String ALLOW_ALL_ID = "allow-all";

    boolean verify(SignedJWT jwt, String trustListId);

    List<PublicKey> publicKeys(String trustListId);

    default boolean isAllowAll(String trustListId) {
        return ALLOW_ALL_ID.equals(trustListId);
    }

    static boolean verifyWithKey(SignedJWT jwt, PublicKey key) {
        try {
            JWSVerifier verifier = null;
            if (key instanceof RSAPublicKey rsa) {
                verifier = new RSASSAVerifier(rsa);
            } else if (key instanceof ECPublicKey ec) {
                verifier = new ECDSAVerifier(ec);
            }
            return verifier != null && jwt.verify(verifier);
        } catch (Exception e) {
            return false;
        }
    }
}
