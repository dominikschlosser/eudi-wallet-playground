package de.arbeitsagentur.keycloak.wallet.mockissuer;

import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.BuilderRequest;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.CredentialResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.NonceResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.OfferResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.PreviewResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerService.TokenResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerConfigurationStore;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.List;
import java.util.Map;

@Controller
public class MockIssuerController {
    private final MockIssuerService mockIssuerService;
    private final MockIssuerProperties properties;
    private final MockIssuerConfigurationStore configurationStore;

    public MockIssuerController(MockIssuerService mockIssuerService,
                                MockIssuerProperties properties,
                                MockIssuerConfigurationStore configurationStore) {
        this.mockIssuerService = mockIssuerService;
        this.properties = properties;
        this.configurationStore = configurationStore;
    }

    @GetMapping("/mock-issuer")
    public String builder(Model model, HttpServletRequest request) {
        String issuer = issuerBase(request);
        List<MockIssuerProperties.CredentialConfiguration> configs = configurationStore.configurations();
        model.addAttribute("issuer", issuer);
        model.addAttribute("configurations", configs);
        model.addAttribute("defaultConfigurationId", configs.isEmpty() ? "" : configs.get(0).id());
        model.addAttribute("configurationFile", properties.configurationFile());
        model.addAttribute("userConfigurationFile", configurationStore.userConfigurationFile());
        return "mock-issuer";
    }

    @GetMapping({"/mock-issuer/.well-known/openid-credential-issuer", "/.well-known/openid-credential-issuer/mock-issuer"})
    @ResponseBody
    public Map<String, Object> metadata(HttpServletRequest request) {
        return mockIssuerService.metadata(issuerBase(request));
    }

    @GetMapping("/mock-issuer/credential-offer/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> credentialOffer(@PathVariable("id") String id, HttpServletRequest request) {
        var offer = mockIssuerService.findOfferById(id);
        if (offer == null) {
            return ResponseEntity.notFound().build();
        }
        if (offer.expiresAt().isBefore(java.time.Instant.now())) {
            return ResponseEntity.status(HttpStatus.GONE).build();
        }
        return ResponseEntity.ok(mockIssuerService.credentialOfferPayload(offer));
    }

    @PostMapping(value = "/mock-issuer/offers", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public OfferResult createOffer(@RequestBody BuilderRequest request, HttpServletRequest http) {
        return mockIssuerService.createOffer(request, issuerBase(http));
    }

    @PostMapping(value = "/mock-issuer/preview", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public PreviewResult preview(@RequestBody BuilderRequest request, HttpServletRequest http) {
        return mockIssuerService.preview(request, issuerBase(http));
    }

    @PostMapping(value = "/mock-issuer/configurations", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public MockIssuerProperties.CredentialConfiguration createConfiguration(@RequestBody CreateConfigurationRequest request) {
        return configurationStore.addConfiguration(toConfiguration(request));
    }

    @PostMapping(value = "/mock-issuer/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public Map<String, Object> token(@RequestBody MultiValueMap<String, String> form) {
        String grantType = form.getFirst("grant_type");
        if (grantType != null && !"urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported grant_type");
        }
        String preAuth = form.getFirst("pre-authorized_code");
        TokenResult result = mockIssuerService.exchangePreAuthorizedCode(preAuth);
        return Map.of(
                "access_token", result.accessToken(),
                "token_type", result.tokenType(),
                "expires_in", result.expiresIn(),
                "c_nonce", result.cNonce(),
                "c_nonce_expires_in", result.cNonceExpiresIn()
        );
    }

    @PostMapping("/mock-issuer/nonce")
    @ResponseBody
    public Map<String, Object> nonce(@RequestHeader(name = "Authorization", required = false) String authorization) {
        NonceResult result = mockIssuerService.issueNonce(authorization);
        return Map.of(
                "c_nonce", result.cNonce(),
                "c_nonce_expires_in", result.cNonceExpiresIn()
        );
    }

    @PostMapping(value = "/mock-issuer/credential", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> credential(@RequestHeader(name = "Authorization", required = false) String authorization,
                                          @RequestBody Map<String, Object> body,
                                          HttpServletRequest http) {
        CredentialResult result = mockIssuerService.issueCredential(authorization, body, issuerBase(http));
        return result.body();
    }

    private String issuerBase(HttpServletRequest request) {
        if (properties.issuerId() != null && !properties.issuerId().isBlank()) {
            return properties.issuerId();
        }
        return ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(request.getContextPath())
                .path("/mock-issuer")
                .build()
                .toUriString();
    }

    private MockIssuerProperties.CredentialConfiguration toConfiguration(CreateConfigurationRequest request) {
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing request body");
        }
        List<MockIssuerProperties.ClaimTemplate> claims = request.claims() == null ? List.of() : request.claims().stream()
                .filter(c -> c != null && c.name() != null && !c.name().isBlank())
                .map(c -> new MockIssuerProperties.ClaimTemplate(c.name(), c.label(), c.defaultValue(), c.required()))
                .toList();
        return new MockIssuerProperties.CredentialConfiguration(
                request.id(),
                request.format(),
                request.scope(),
                request.name(),
                request.vct(),
                claims
        );
    }

    public record CreateConfigurationRequest(String id, String format, String scope, String name, String vct,
                                             List<CreateClaimRequest> claims) {
    }

    public record CreateClaimRequest(String name, String label, String defaultValue, Boolean required) {
    }
}
