package de.arbeitsagentur.keycloak.wallet.mockissuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.BuilderRequest;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.ClaimInput;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerConfigurationStore;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MockIssuerServiceTest {
    private MockIssuerService mockIssuerService;
    private MockIssuerKeyService keyService;
    private MockIssuerProperties props;
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        MockIssuerProperties.CredentialConfiguration cfg = new MockIssuerProperties.CredentialConfiguration(
                "mock-pid-sdjwt", "dc+sd-jwt", "mock-scope", "Mock PID (SD-JWT)", "urn:example:pid:mock",
                List.of(
                        new MockIssuerProperties.ClaimTemplate("given_name", "Given name", "Alice", true),
                        new MockIssuerProperties.ClaimTemplate("family_name", "Family name", "Wallet", true)
                )
        );
        Path configurationFile = tempDir.resolve("mock-issuer-configurations.json");
        ObjectMapper objectMapper = new ObjectMapper();
        props = new MockIssuerProperties(true,
                Path.of("config/mock-issuer-keys.json"),
                Duration.ofMinutes(5),
                "http://localhost:3000/mock-issuer",
                configurationFile,
                List.of(cfg));
        WalletProperties walletProps = new WalletProperties(
                "http://localhost:8080",
                "realm",
                "client",
                "secret",
                "did:example:wallet",
                tempDir,
                tempDir.resolve("wallet.jwk"),
                null,
                null,
                null,
                List.of(),
                true
        );
        keyService = new MockIssuerKeyService(props);
        MockIssuerConfigurationStore configurationStore = new MockIssuerConfigurationStore(props, walletProps, objectMapper);
        mockIssuerService = new MockIssuerService(props, objectMapper, keyService, configurationStore);
    }

    @Test
    void previewBuildsSdJwtWithClaims() {
        BuilderRequest req = new BuilderRequest("mock-pid-sdjwt", "dc+sd-jwt", "urn:example:pid:mock",
                List.of(new ClaimInput("given_name", "Alice"), new ClaimInput("family_name", "Wallet")));
        var preview = mockIssuerService.preview(req, "http://localhost:3000/mock-issuer");
        assertThat(preview.encoded()).isNotBlank();
        assertThat(preview.decoded()).isNotEmpty();
        assertThat(preview.decoded().get("claims")).isNotNull();
    }

    @Test
    void fullIssuanceFlowReturnsCredential() throws Exception {
        BuilderRequest req = new BuilderRequest("mock-pid-sdjwt", "dc+sd-jwt", "urn:example:pid:mock",
                List.of(new ClaimInput("given_name", "Alice"), new ClaimInput("family_name", "Wallet")));
        var offer = mockIssuerService.createOffer(req, "http://localhost:3000/mock-issuer");
        assertThat(offer.preAuthorizedCode()).isNotBlank();

        var token = mockIssuerService.exchangePreAuthorizedCode(offer.preAuthorizedCode());
        assertThat(token.accessToken()).isNotBlank();
        assertThat(token.cNonce()).isNotBlank();

        String proofJwt = buildProof(token.cNonce(), props.issuerId());

        var credential = mockIssuerService.issueCredential("Bearer " + token.accessToken(),
                Map.of(
                        "credential_configuration_id", "mock-pid-sdjwt",
                        "proof", Map.of("proof_type", "jwt", "jwt", proofJwt)
                ),
                "http://localhost:3000/mock-issuer");
        assertThat(credential.body().get("credentials")).isInstanceOf(List.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> creds = (List<Map<String, Object>>) credential.body().get("credentials");
        assertThat(creds).isNotEmpty();
        assertThat(creds.get(0).get("credential").toString()).contains("~");
        assertThat(credential.decoded().get("claims")).isNotNull();
    }

    private String buildProof(String nonce, String audience) throws Exception {
        ECKey key = keyService.signingKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(key.toPublicJWK())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("did:example:wallet")
                .audience(audience)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                .claim("nonce", nonce)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}
