# EUDI Wallet Keycloak Demo

Spring Boot demo/mock of an EUDI wallet that authenticates against Keycloak 26.4.5 (with `oid4vc-vci` enabled), issues SD-JWT and mDoc credentials (Keycloak or the mock issuer), and stores them on the filesystem.  
It also exposes an OID4VP 1.0 “same device” presentation endpoint and a verifier UI that use DCQL (`dcql_query`) instead of legacy presentation definitions. SD-JWT and mDoc presentations are validated against the trust list.  
The sd-jwt and mdoc implementations live in reusable `sdjwt-lib` and `mdoc-lib` modules; the wallet, mock issuer, and verifier services depend on these libraries. The verifier can be pointed at any external wallet that implements the OID4VP 1.0/DCQL profile (for example a sandbox or a real mobile wallet) by switching `VERIFIER_WALLET_AUTH_ENDPOINT`.  
Integration tests spin up Keycloak in a Testcontainer and exercise the complete SD-JWT and mDoc issuance + presentation flow end-to-end.

## Credential formats: SD-JWT vs mDoc

- **SD-JWT (`dc+sd-jwt`)** – A signed JWT whose payload carries digests for selectively disclosable claims. Each hidden claim is sent as a Base64URL “disclosure” and the presentation string concatenates the signed JWT and every disclosure with `~`. Verifiers check the issuer signature, then recompute each digest to ensure the disclosures belong to the signed token.
- **mDoc/CBOR (`mso_mdoc`)** – ISO/IEC 18013-5 Mobile Security Objects. Every claim is an issuer-signed data element (`digestID`, 16-byte `random`, `elementIdentifier`, `elementValue`) encoded as tagged CBOR. The MSO contains SHA-256 `valueDigests` for each element plus `validityInfo`; a COSE_Sign1 (`issuerAuth`) signs the tagged MSO. `issuerSigned.nameSpaces` embeds the tagged elements that can be selectively disclosed.
- **Key differences** – SD-JWT is pure JSON/JWT with Base64URL disclosures; mDoc is CBOR/COSE with tagged elements and digests. Holder binding uses KB-JWT (`cnf`) for SD-JWT and `deviceKeyInfo` for mDoc. Presentations may be hex/base64 for mDoc, whereas SD-JWT stays URL-safe text.
- **Examples**
  - SD-JWT (presentation string):
    ```
    <signed-jwt>~<disclosure-1>~<disclosure-2>
    ```
  - mDoc (conceptual CBOR shape):
    ```
    {
      "version": "1.0",
      "documents": [{
        "docType": "org.iso.18013.5.1.mDL",
        "issuerSigned": {
          "nameSpaces": {
            "org.iso.18013.5.1": [
              h'D8184f'({ "digestID":0,"random":h'..',"elementIdentifier":"given_name","elementValue":"Alice" })
            ]
          },
          "issuerAuth": "COSE_Sign1(...)"
        }
      }]
    }
    ```
    `issuerAuth` decodes to the MSO with `valueDigests` (hashes of the tagged elements) and `validityInfo`, which the COSE signature protects.

 ## Prerequisites

 - Java 21+
 - Maven 3.9+
 - Docker (for Keycloak and integration tests)

## Running Keycloak

The repository contains a realm export under `demo-app/config/keycloak/realm-export.json` that configures:

- Realm `wallet-demo`
- Client `wallet-mock`
- Client scopes `mock-identity-credential`, `mock-alternate-credential`, and `pid-credential` (PID SD-JWT with core claims like name, birthdate, nationality, address, document info)
- Test users `test` / `test` and `test2` / `test2` with PID attributes filled for demos

Start Keycloak (from the repo root, the compose file mounts `demo-app/config/keycloak`):

```bash
docker compose up -d keycloak
```

Keycloak will be available on port 8080 of the host running Docker (for example http://your-hostname:8080) with admin credentials `admin` / `admin`.

## Running the wallet

Export `KEYCLOAK_BASE_URL` to the reachable Keycloak base URL first (for Docker Compose on the same host: `http://localhost:8080`; for deployments: `https://your-keycloak.example.com`).

```bash
mvn -pl demo-app -am spring-boot:run
```

Visit your deployed host (for example http://your-hostname:3000) and:

1. Click “Sign in with Keycloak”, authenticate as `test` / `test`.
2. Press “Issue Credential”; the issued SD-JWT credential (the signed JWT plus all disclosures) is saved under `data/credentials/<subject>-<timestamp>.json`.  
   The wallet stores both the SD-JWT token and the reconstructed `credentialSubject` so DCQL queries and the UI can work with the disclosed values.

### End-to-end flow (Mermaid)

```mermaid
sequenceDiagram
    participant User
    participant WalletUI as Wallet UI (Spring)
    participant Keycloak as Keycloak (OID4VCI)
    participant Store as Credential Store

    User->>WalletUI: Login (OIDC)
    WalletUI-->>Keycloak: Authorization Code + pkce
    Keycloak-->>WalletUI: Tokens (access, refresh, c_nonce)
    User->>WalletUI: Click "Issue PID"
    WalletUI-->>Keycloak: OID4VCI credential request (scope/authorization_details)
    Keycloak-->>WalletUI: SD-JWT credential + disclosures
    WalletUI-->>Store: Persist raw credential + reconstructed credentialSubject
```

```mermaid
sequenceDiagram
    participant VerifierUI as Verifier UI (DCQL)
    participant WalletUI as Wallet UI (OID4VP)
    participant Store as Credential Store
    participant Keycloak as Issuer Cert (trust)

    VerifierUI->>WalletUI: OID4VP auth req (dcql_query)
    WalletUI-->>Store: Find matching credentials (DCQL)
    WalletUI-->>WalletUI: Build vp_token (sd-jwt + disclosures)
    WalletUI-->>VerifierUI: direct_post response (vp_token, state, nonce)
    VerifierUI-->>Keycloak: Verify signature against trust list cert
    VerifierUI-->>VerifierUI: Display verified claims
```

### Spec compliance and code map

- **OID4VCI 1.0** – Credential proof building and issuance request body: `wallet/src/main/java/de/arbeitsagentur/keycloak/wallet/issuance/service/CredentialService.java`. Authorization details and scope handling: `wallet/src/main/java/de/arbeitsagentur/keycloak/wallet/issuance/oidc/OidcClient.java`.
- **OID4VP 1.0 + DCQL** – Wallet-side presentation flow and consent: `wallet/src/main/java/de/arbeitsagentur/keycloak/wallet/demo/oid4vp/Oid4vpController.java`, request parsing/matching: `wallet/src/main/java/de/arbeitsagentur/keycloak/wallet/demo/oid4vp/PresentationService.java`, verifier endpoints: `verifier/src/main/java/de/arbeitsagentur/keycloak/wallet/verification/web/VerifierController.java`.
- **PID Rulebook (urn:eudi:pid:1)** – PID credential scope and claim mapping defined in `demo-app/config/keycloak/realm-export.json`; default DCQL query built in `verifier/src/main/java/de/arbeitsagentur/keycloak/wallet/verification/service/DcqlService.java` requests only `given_name` and `family_name`.

### Requesting and verifying a presentation (OID4VP)

1. **Authorization Request** – `https://<your-host>/verifier/` issues an OID4VP 1.0 request with:
   - `response_type=vp_token` (or `vp_token id_token`)
   - `response_mode=direct_post` and `response_uri` back to `/verifier/callback`
   - `client_id` (environment variable `VERIFIER_CLIENT_ID`, supports plain IDs, `x509_hash:<hash>`, or `verifier_attestation:<sub>`)
   - `state` and `nonce` (fresh per request)
   - `dcql_query` (pasted into the verifier UI or provided via `DEFAULT_DCQL_QUERY` / `DCQL_QUERY_FILE`)
2. **Wallet Authorization Endpoint** – If `VERIFIER_WALLET_AUTH_ENDPOINT` is unset, the request targets the built-in wallet (`/oid4vp/auth`). Otherwise, the same request is sent to the external wallet you configured.
3. **Wallet Response** – The wallet evaluates the DCQL query against its credential store, selects matching SD-JWT credentials, and posts them back as the `vp_token` JSON object (`{ "<credential-id>": ["<dc+sd-jwt>", ...] }`) alongside `state`/`nonce`. DCQL already binds credentials to request IDs.
4. **Verification** – `/verifier/callback` verifies `state`/`nonce`, validates the SD-JWT signature against the configured trust list (`verifier/src/main/resources/trust-list.json`), and recomputes the disclosure digests. Only issuers listed in the trust list (Keycloak by default) are accepted.

### Pointing the verifier at an external wallet

```
VERIFIER_CLIENT_ID=my-eudi-verifier
VERIFIER_WALLET_AUTH_ENDPOINT=https://wallet.example.com/oid4vp

# Choose auth mode in the UI:
# - Plain client_id (default)
# - x509_hash:<hash> with a matching certificate (request signed with that key)
# - verifier_attestation:<sub> with an attestation signed for that subject
```

The verifier forwards the `dcql_query` verbatim, so any compliant OID4VP wallet can consume it as-is.

### Certificate-based client authentication

Mutual TLS is often required when the wallet calls an issuer. `RestClientConfig` wires an `HttpClient` that loads a client certificate if `WALLET_TLS_KEY_STORE` is configured. Supply a keystore so outbound HTTPS connections present the correct certificate:

```
WALLET_TLS_KEY_STORE=demo-app/config/holder-client.p12
WALLET_TLS_KEY_STORE_PASSWORD=changeit
WALLET_TLS_KEY_STORE_TYPE=PKCS12
```

The `RestTemplate` in `RestClientConfig` loads this keystore and attaches it to Keycloak (or any other issuer) calls.

### Requesting credentials via DCQL

Paste a `dcql_query` into the verifier UI (or provide one via `DEFAULT_DCQL_QUERY`) to describe the claims you expect. Example requesting a specific `personal_id`:

```json
{
  "credentials": [
    {
      "id": "personal-id",
      "format": "dc+sd-jwt",
      "claims": [
        { "path": ["personal_id"], "value": "ID-123" }
      ]
    }
  ]
}
```

Claims requested in the DCQL query drive selective disclosure when the wallet rebuilds the SD-JWT.

Optional DCQL helpers:

- `credential_set` lets you narrow acceptable credentials by id/vct/format (array of objects such as `{ "id": "pid" }` or `{ "vct": "https://credentials.example.com/identity_credential" }`).
- `claim_set` lets you express claim groups that must be satisfied together (array of objects like `{ "claims": [ { "path": ["given_name"] }, { "path": ["family_name"] } ] }`).

The trust list anchors verification to the Keycloak realm certificate stored under `demo-app/config/keycloak/keys/wallet-demo-ec-cert.pem` (ES256). Add further certificates to `verifier/src/main/resources/trust-list.json` when integrating additional issuers (for example, a sandbox or a production EUDI wallet).

### Using an external wallet

Set `VERIFIER_WALLET_AUTH_ENDPOINT` to the authorization endpoint of the wallet you want to test. The verifier continues to issue the same `dcql_query`, so any compliant wallet (mobile, sandbox, or web) can answer. The verifier still validates the SD-JWT signature and disclosures against the trust list.

### Mock OID4VCI issuer with credential builder

- Open `/mock-issuer` (or click “Issue with Mock Issuer” in the wallet) to build SD-JWT credentials without authenticating. Pick a credential configuration, fill the pre-configured claim fields, and preview the SD-JWT in encoded/decoded form.
- Credential types and claims come from `mock-issuer.configurations` (`demo-app/config/mock-issuer-configurations.json` by default; see `MockIssuerProperties`). You can create new credential types ad-hoc in the builder UI—they are persisted to that config file and instantly available.
- Generate a credential offer to receive a `pre-authorized_code`, `credential_offer_uri`, and `openid-credential-offer://` deep link. The mock issuer advertises metadata at `/mock-issuer/.well-known/openid-credential-issuer` and exposes `/mock-issuer/token`, `/mock-issuer/credential`, and `/mock-issuer/nonce`.
- The mock issuer signs with `demo-app/config/mock-issuer-keys.json`; the verifier can trust it by selecting the “Mock Issuer (local)” trust list from `verifier/src/main/resources/trust-list-mock.json`.

 ### Configuration

Spring Boot properties are exposed as environment variables; copy `.env.example` or export the variables before running:

```
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=wallet-demo
OIDC_CLIENT_ID=wallet-mock
OIDC_CLIENT_SECRET=secret-wallet
CREDENTIAL_STORAGE_DIR=data/credentials
WALLET_DID=did:example:mock-wallet
WALLET_KEY_FILE=demo-app/config/wallet-keys.json
VERIFIER_CLIENT_ID=wallet-verifier
VERIFIER_CLIENT_ID_SCHEME=pre-registered
VERIFIER_WALLET_AUTH_ENDPOINT=
DCQL_QUERY_FILE=
DEFAULT_DCQL_QUERY=
MAX_HTTP_REQUEST_HEADER_SIZE=64KB
MAX_HTTP_RESPONSE_HEADER_SIZE=64KB
VERIFIER_MAX_REQUEST_OBJECT_INLINE_BYTES=12000
```

Credential configurations and scopes are discovered from the issuer metadata (`credential_configurations_supported`); no manual list is maintained in `application.yml`.
The built-in same-device demo wallet endpoints (`/oid4vp/auth`) stay enabled to support quick flows; point the verifier at an external wallet by setting `VERIFIER_WALLET_AUTH_ENDPOINT`.

Mock issuer credential types live under `mock-issuer.configurations` (see `MockIssuerProperties`) and default to `demo-app/config/mock-issuer-configurations.json`. Each entry defines `id`, `format`, `scope`, `name`, `vct`, and a list of `claims` (`name`, `label`, `defaultValue`, `required`). The builder UI renders only these claims, so you can lock the mock credentials to a known schema.

## Integration tests

The project uses Testcontainers to spin up Keycloak and run the complete issuance and presentation flow:

```bash
mvn verify
```

Always run the tests after you modify the codebase (see `AGENTS.md`). The test performs the HTML form login against Keycloak, stores a credential, requests a presentation (using the same parameters as the verifier UI), and verifies both a success case and a tampered `vp_token` against the trust list.

## AWS smoke test

Run `mvn verify -Paws-smoke -Daws.wallet.base-url=https://wallet.example.com/wallet` (or set `AWS_WALLET_BASE_URL`) to exercise the deployed EKS stack end-to-end (login, issuance, presentation). The test uses `AWS_WALLET_USERNAME` / `AWS_WALLET_PASSWORD` when set, otherwise defaults to `test` / `test`.

## Project structure

- `demo-app/` – Spring Boot entry point aggregating all modules, integration tests, and runtime config defaults.
- `demo-app/config/` – key material (`wallet-keys.json`, `verifier-keys.json`, mock-issuer keys/configs) and Keycloak assets (`keycloak/realm-export.json`, `keycloak/keys/...`).
- `app-common/` – shared helpers (key handling, debug logging, wallet properties).
- `sdjwt-lib/` – SD-JWT credential builder/parser/verifier and selective disclosure utilities.
- `mdoc-lib/` – mDoc/CBOR credential builder/parser/verifier/viewer utilities.
- `wallet/` – wallet issuance flow, credential storage, and OID4VP consent UI.
- `mock-issuer/` – mock issuer API and credential builder UI.
- `verifier/` – verifier endpoints, DCQL builder UI, trust-list handling.
- `docker-compose.yml` – Keycloak setup with realm import (mounts `demo-app/config/keycloak`).

## Deploying to Kubernetes (AWS/EKS)

Use the bundled Helm chart under `charts/eudi-wallet-demo` to deploy Keycloak (with the realm import) and the Spring Boot wallet to Kubernetes. The chart is simplified for the AWS sandbox `wallet-demo` namespace and fronts the services with an AWS ALB (HTTP).

```bash
AWS_PROFILE=AccountAdministratorAccess-207613817683 helm upgrade --install wallet-demo charts/eudi-wallet-demo -n wallet-demo \
  --set keycloak.publicHost=<public-host> \
  --set wallet.publicBaseUrl=<https-wallet-base-url> \
  --set wallet.keycloakBaseUrl=<https-keycloak-base-url> \
  --set wallet.image.repository=<wallet-image-repo> \
  --set wallet.image.tag=<wallet-image-tag> \
  --set keycloak.image.repository=<keycloak-image-repo> \
  --set keycloak.image.tag=<keycloak-image-tag> \
  --set-file keycloak.realmJson=demo-app/config/keycloak/realm-export.json \
  --set-file wallet.files.walletKeys=demo-app/config/wallet-keys.json \
  --set-file wallet.files.verifierKeys=demo-app/config/verifier-keys.json \
  --set-file wallet.files.mockIssuerKeys=demo-app/config/mock-issuer-keys.json \
  --set-file wallet.files.mockIssuerConfigurations=demo-app/config/mock-issuer-configurations.json
```

See `charts/eudi-wallet-demo/README.md` for the small set of remaining values (image tags, storage class, TLS/truststore, and host/ingress settings).
