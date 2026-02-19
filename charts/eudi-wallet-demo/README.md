# eudi-wallet-demo Helm chart

This chart targets the AWS sandbox `wallet-demo` namespace. It deploys Keycloak (with the bundled `wallet-demo` realm) and the wallet under `/wallet`, fronted by an AWS ALB ingress (HTTP).

## Required values only
- `keycloak.publicHost` (external host for Keycloak)
- `wallet.publicBaseUrl`, `wallet.keycloakBaseUrl`, `wallet.keycloakRealm`
- Images: `wallet.image.repository/tag`, `keycloak.image.repository/tag`
- Wallet env flags under `wallet.env` (DID, verifier config, header sizes, etc.)
- Realm/config/keys provided via `--set-file` flags (no in-chart defaults)

Everything else is fixed to the AWS ALB HTTP setup used in the sandbox (no TLS in the ingress; ALB name and subnets are inlined).

## OIDF conformance suite (Verifier)

To drive the OIDF conformance suite from the deployed verifier UI, configure the suite API:

- `wallet.conformance.baseUrl` (defaults to `https://demo.certification.openid.net`)
- `wallet.conformance.apiKey` (optional; stored in the `wallet-demo-wallet` secret as `verifier-conformance-api-key`)

These values are exposed to the container as `VERIFIER_CONFORMANCE_BASE_URL` and `VERIFIER_CONFORMANCE_API_KEY`.

You can also enter/override the suite base URL and API key directly in `/verifier/conformance` (stored in the HTTP session), which is useful if you do not want to persist the API key as a Kubernetes secret.

## Images

Both images are built and pushed automatically by CI on tagged releases:
- **Wallet**: `ghcr.io/ba-itsys/eudi-wallet-keycloak-demo:<version>`
- **Keycloak** (with oid4vp provider): `ghcr.io/ba-itsys/eudi-wallet-keycloak-demo-keycloak:<version>`

### Manual build

**Wallet image:**
```
mvn spring-boot:build-image -pl demo-app -am -Dspring-boot.build-image.imageName=<repo>:<tag> -DskipTests
docker push <repo>:<tag>
```

**Keycloak image:**
```
mvn package -pl keycloak-oid4vp -am -DskipTests
docker build -t <repo>:<tag> keycloak-oid4vp
docker push <repo>:<tag>
```

## Install/upgrade
```
helm upgrade --install wallet-demo charts/eudi-wallet-demo \
  --set keycloak.publicHost=<public-host> \
  --set wallet.publicBaseUrl=<https-url-to-wallet> \
  --set wallet.keycloakBaseUrl=<https-url-to-keycloak> \
  --set wallet.image.repository=ghcr.io/ba-itsys/eudi-wallet-keycloak-demo \
  --set wallet.image.tag=<version> \
  --set keycloak.image.repository=ghcr.io/ba-itsys/eudi-wallet-keycloak-demo-keycloak \
  --set keycloak.image.tag=<version> \
  --set-file keycloak.realmJson=demo-app/config/keycloak/realm-export.json \
  --set-file keycloak.realmPidBindingJson=demo-app/config/keycloak/realm-pid-binding-export.json \
  --set-file wallet.files.walletKeys=demo-app/config/wallet-keys.json \
  --set-file wallet.files.verifierKeys=demo-app/config/verifier-keys.json \
  --set-file wallet.files.mockIssuerKeys=demo-app/config/mock-issuer-keys.json \
  --set-file wallet.files.mockIssuerConfigurations=demo-app/config/mock-issuer-configurations.json
```

## SPRIND Sandbox deployment

The `sandbox/` directory (gitignored) contains the sandbox certificate, private key, and verifier_info files. When running locally, these are picked up automatically.

To create or update the sandbox files, place your SPRIND-provided materials in `sandbox/`:

```bash
# Copy certificate and key into sandbox/:
cp sandbox.crt sandbox/sandbox.crt
cp rp.key sandbox/rp.key

# Create combined PEM (cert chain + private key):
cat sandbox/sandbox.crt sandbox/rp.key > sandbox/sandbox-combined.pem

# Create verifier_info JSON (registration certificate from SPRIND):
echo '[{"format":"registration_cert","data":"<registration cert JWT>"}]' > sandbox/sandbox-verifier-info.json
```

For Helm deployment, pass these files as secrets:

```bash
helm upgrade --install wallet-demo charts/eudi-wallet-demo \
  ... (existing flags) ...
  --set-file wallet.files.sandboxCert=sandbox/sandbox-combined.pem \
  --set-file wallet.files.sandboxVerifierInfo=sandbox/sandbox-verifier-info.json
```

The verifier UI will show a **"Use Sandbox Defaults"** button that fills in all sandbox-specific settings (x509_san_dns auth type, DCQL query for PID, verifier_info with registration certificate, request_uri mode). The BMI trust lists are loaded by default.

## Keycloak realm files

The chart supports importing multiple Keycloak realm files:
- `keycloak.realmJson` (required) - Main realm export (e.g., `realm-export.json`)
- `keycloak.realmPidBindingJson` (optional) - Additional realm for PID binding (e.g., `realm-pid-binding-export.json`)

Both files are mounted to `/opt/keycloak/data/import/` and imported on Keycloak startup via `--import-realm`.
