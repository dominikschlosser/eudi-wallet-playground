package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Supplies trusted issuer keys for SD-JWT signature verification.
 */
public interface TrustedIssuerResolver {
    boolean verify(SignedJWT jwt, String trustListId);

    List<PublicKey> publicKeys(String trustListId);

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
