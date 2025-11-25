package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps.StepDetail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PresentationVerificationServiceTest {

    @Mock
    private TrustListService trustListService;

    private PresentationVerificationService verificationService;
    private VerifierKeyService verifierKeyService;
    private VerifierProperties properties;
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        properties = new VerifierProperties(null, "{}", null, "wallet-verifier",
                tempDir.resolve("enc-key.json"));
        verifierKeyService = new VerifierKeyService(properties, new ObjectMapper());
        verificationService = new PresentationVerificationService(trustListService, properties, new ObjectMapper(), verifierKeyService);
        when(trustListService.verify(any(SignedJWT.class), anyString())).thenReturn(true);
    }

    @Test
    void acceptsPresentationWithMatchingNonceAndAudience() throws Exception {
        String token = buildJwt("nonce-123", "wallet-verifier", Instant.now().plusSeconds(60), null);
        VerificationSteps steps = new VerificationSteps();

        Map<String, Object> claims = verificationService.verifySinglePresentation(
                token,
                "nonce-123",
                "nonce-123",
                "trust-list",
                properties.clientId(),
                steps
        );

        assertThat(claims.get("nonce")).isEqualTo("nonce-123");
        assertThat(steps.titles()).anySatisfy(step -> assertThat(step).contains("Credential timing rules validated"));
        assertThat(steps.details())
                .anySatisfy(detail -> {
                    assertThat(detail.title()).contains("Credential timing rules validated");
                    assertThat(detail.detail()).contains("exp/nbf");
                });
    }

    @Test
    void rejectsNonceMismatch() throws Exception {
        String token = buildJwt("wallet-nonce", "wallet-verifier", Instant.now().plusSeconds(60), null);

        assertThatThrownBy(() -> verificationService.verifySinglePresentation(
                token,
                "other-nonce",
                "other-nonce",
                "trust-list",
                properties.clientId(),
                new VerificationSteps()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Nonce mismatch");
    }

    @Test
    void rejectsAudienceMismatch() throws Exception {
        String token = buildJwt("nonce-1", "other-audience", Instant.now().plusSeconds(60), null);

        assertThatThrownBy(() -> verificationService.verifySinglePresentation(
                token,
                "nonce-1",
                "nonce-1",
                "trust-list",
                properties.clientId(),
                new VerificationSteps()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Audience mismatch");
    }

    @Test
    void rejectsExpiredPresentations() throws Exception {
        String token = buildJwt("nonce-1", "wallet-verifier", Instant.now().minusSeconds(5), null);

        assertThatThrownBy(() -> verificationService.verifySinglePresentation(
                token,
                "nonce-1",
                "nonce-1",
                "trust-list",
                properties.clientId(),
                new VerificationSteps()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void decryptsEncryptedVpToken() throws Exception {
        String token = buildJwt("nonce-enc", "wallet-verifier", Instant.now().plusSeconds(60), null);
        RSAKey rsaKey = verifierKeyService.loadOrCreateKey();
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                new com.nimbusds.jose.Payload(token)
        );
        jwe.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));

        Map<String, Object> claims = verificationService.verifySinglePresentation(
                jwe.serialize(),
                "nonce-enc",
                "nonce-enc",
                "trust-list",
                properties.clientId(),
                new VerificationSteps()
        );

        assertThat(claims.get("nonce")).isEqualTo("nonce-enc");
    }

    private String buildJwt(String nonce, String audience, Instant expiration, Instant notBefore) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .issueTime(new Date());
        if (audience != null) {
            claims.audience(audience);
        }
        if (expiration != null) {
            claims.expirationTime(Date.from(expiration));
        }
        if (notBefore != null) {
            claims.notBeforeTime(Date.from(notBefore));
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
        jwt.sign(new MACSigner("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }
}
