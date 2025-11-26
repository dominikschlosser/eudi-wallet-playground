package de.arbeitsagentur.keycloak.wallet.verification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Service
public class VerifierAuthService {
    private final VerifierKeyService verifierKeyService;
    private final VerifierCryptoService verifierCryptoService;
    private final RequestObjectService requestObjectService;
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;

    public VerifierAuthService(VerifierKeyService verifierKeyService,
                               VerifierCryptoService verifierCryptoService,
                               RequestObjectService requestObjectService,
                               VerifierProperties properties,
                               ObjectMapper objectMapper) {
        this.verifierKeyService = verifierKeyService;
        this.verifierCryptoService = verifierCryptoService;
        this.requestObjectService = requestObjectService;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public WalletAuthRequest buildWalletAuthorizationUrl(URI callback, String state, String nonce,
                                                         String dcqlQuery,
                                                         String walletAuthOverride,
                                                         String effectiveClientId,
                                                         String authType,
                                                         String clientMetadata,
                                                         String walletClientCert,
                                                         String attestationCert,
                                                         String attestationIssuer,
                                                         String responseTypeOverride,
                                                         String requestObjectMode,
                                                         UriComponentsBuilder baseUri) {
        String effectiveWalletAuth = walletAuthOverride != null && !walletAuthOverride.isBlank()
                ? walletAuthOverride
                : properties.walletAuthEndpoint();
        String attestationValue = null;
        String effectiveResponseType = responseTypeOverride != null && !responseTypeOverride.isBlank()
                ? responseTypeOverride
                : "vp_token";
        boolean usedRequestUri = false;
        if ("verifier_attestation".equalsIgnoreCase(authType)) {
            requestObjectMode = "request_uri";
        }
        RequestObjectMode parsedMode = RequestObjectMode.fromString(requestObjectMode);
        UriComponentsBuilder builder = effectiveWalletAuth != null && !effectiveWalletAuth.isBlank()
                ? UriComponentsBuilder.fromUriString(effectiveWalletAuth)
                : baseUri.cloneBuilder().path("/oid4vp/auth");
        UriComponentsBuilder populated = builder.queryParam("client_id", qp(effectiveClientId));

        if ("x509_hash".equalsIgnoreCase(authType)) {
            RSAKey popKey = verifierCryptoService.parsePrivateKeyWithCertificate(walletClientCert);
            List<com.nimbusds.jose.util.Base64> x5c = verifierCryptoService.extractCertChain(walletClientCert);
            if (x5c.isEmpty()) {
                throw new IllegalStateException("client_cert must include a certificate chain for x509_hash");
            }
            BuiltRequestObject requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType, dcqlQuery, clientMetadata, null, x5c, popKey);
            populateWithRequestObject(populated, requestObject, requestObjectMode, baseUri);
        } else if ("verifier_attestation".equalsIgnoreCase(authType)) {
            RSAKey attestationKey = verifierKeyService.loadOrCreateSigningKey();
            if (attestationCert != null && !attestationCert.isBlank()) {
                attestationKey = verifierCryptoService.parsePrivateKeyWithCertificate(attestationCert);
            }
            attestationValue = createVerifierAttestation(effectiveClientId, attestationIssuer, attestationKey, callback.toString());
            BuiltRequestObject requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType, dcqlQuery, clientMetadata, attestationValue, null, attestationKey);
            usedRequestUri = populateWithRequestObject(populated, requestObject, requestObjectMode, baseUri);
        } else {
            if (parsedMode == RequestObjectMode.REQUEST_URI) {
                RSAKey signerKey = verifierKeyService.loadOrCreateSigningKey();
                BuiltRequestObject requestObject = buildRequestObject(callback.toString(), state, nonce, effectiveClientId, effectiveResponseType, dcqlQuery, clientMetadata, null, null, signerKey);
                usedRequestUri = populateWithRequestObject(populated, requestObject, requestObjectMode, baseUri);
            } else {
                populated
                        .queryParam("response_type", qp(effectiveResponseType))
                        .queryParam("nonce", qp(nonce))
                        .queryParam("response_mode", qp("direct_post"))
                        .queryParam("response_uri", qp(callback.toString()))
                        .queryParam("state", qp(state))
                        .queryParam("dcql_query", qp(dcqlQuery));
                if (clientMetadata != null && !clientMetadata.isBlank()) {
                    populated.queryParam("client_metadata", qp(clientMetadata));
                }
                if (walletClientCert != null && !walletClientCert.isBlank()) {
                    populated.queryParam("client_cert", qp(walletClientCert));
                }
            }
        }
        return new WalletAuthRequest(populated.build(true).toUri(), authType != null && authType.equalsIgnoreCase("verifier_attestation") ? attestationValue : null, usedRequestUri);
    }

    private boolean populateWithRequestObject(UriComponentsBuilder builder, BuiltRequestObject requestObject, String requestObjectMode, UriComponentsBuilder baseUri) {
        RequestObjectMode mode = RequestObjectMode.fromString(requestObjectMode);
        if (mode == RequestObjectMode.REQUEST_URI) {
            String id = requestObjectService.store(requestObject.jwt(), requestObject.signerKey());
            URI requestUri = baseUri.cloneBuilder()
                    .path("/verifier/request-object/{id}")
                    .buildAndExpand(id)
                    .toUri();
            builder.queryParam("request_uri", qp(requestUri.toString()));
            return true;
        } else {
            builder.queryParam("request", qp(requestObject.jwt().serialize()));
            return false;
        }
    }

    private BuiltRequestObject buildRequestObject(String responseUri, String state, String nonce,
                                                  String clientId, String responseType, String dcqlQuery,
                                                  String clientMetadata, String attestationJwt,
                                                  List<com.nimbusds.jose.util.Base64> x5c,
                                                  RSAKey signerKey) {
        try {
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new JOSEObjectType("oauth-authz-req+jwt"))
                    .jwk(signerKey.toPublicJWK());
            if (attestationJwt != null && !attestationJwt.isBlank()) {
                headerBuilder.customParam("jwt", attestationJwt);
            }
            if (x5c != null && !x5c.isEmpty()) {
                headerBuilder.x509CertChain(x5c);
            }
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .claim("client_id", clientId)
                    .claim("response_type", responseType)
                    .claim("response_mode", "direct_post")
                    .claim("response_uri", responseUri)
                    .claim("state", state)
                    .claim("nonce", nonce)
                    .claim("dcql_query", dcqlQuery);
            if (clientMetadata != null && !clientMetadata.isBlank()) {
                try {
                    claims.claim("client_metadata", objectMapper.readTree(clientMetadata));
                } catch (Exception e) {
                    claims.claim("client_metadata", clientMetadata);
                }
            }
            claims.expirationTime(java.util.Date.from(java.time.Instant.now().plusSeconds(600)));
            SignedJWT jwt = new SignedJWT(headerBuilder.build(), claims.build());
            jwt.sign(new RSASSASigner(signerKey));
            return new BuiltRequestObject(jwt, signerKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build request object", e);
        }
    }

    private String createVerifierAttestation(String clientIdWithPrefix, String issuerOverride, RSAKey signerKey, String responseUri) {
        try {
            String issuer = issuerOverride != null && !issuerOverride.isBlank() ? issuerOverride : "demo-attestation-issuer";
            String baseClientId = clientIdWithPrefix.startsWith("verifier_attestation:")
                    ? clientIdWithPrefix.substring("verifier_attestation:".length())
                    : clientIdWithPrefix;
            String kid = signerKey.getKeyID();
            if (kid == null || kid.isBlank()) {
                kid = com.nimbusds.jose.util.Base64URL.encode(signerKey.toRSAPublicKey().getEncoded()).toString();
                signerKey = new RSAKey.Builder(signerKey.toRSAPublicKey())
                        .privateKey(signerKey.toRSAPrivateKey())
                        .keyID(kid)
                        .build();
            }
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .jwk(signerKey.toPublicJWK())
                    .build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(baseClientId)
                    .issueTime(new java.util.Date())
                    .expirationTime(java.util.Date.from(java.time.Instant.now().plusSeconds(600)))
                    .claim("cnf", Map.of("jwk", signerKey.toPublicJWK().toJSONObject()))
                    .claim("redirect_uris", responseUri != null && !responseUri.isBlank() ? java.util.List.of(responseUri) : java.util.List.of())
                    .build();
            SignedJWT att = new SignedJWT(header, claims);
            att.sign(new RSASSASigner(signerKey));
            return att.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create verifier attestation", e);
        }
    }

    private String qp(String value) {
        return value == null ? null : UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }

    public record WalletAuthRequest(URI uri, String attestationJwt, boolean usedRequestUri) {
    }

    public record BuiltRequestObject(SignedJWT jwt, JWK signerKey) {
    }

    public enum RequestObjectMode {
        BY_VALUE,
        REQUEST_URI;

        static RequestObjectMode fromString(String value) {
            if (value != null && value.equalsIgnoreCase("request_uri")) {
                return REQUEST_URI;
            }
            return BY_VALUE;
        }
    }
}
