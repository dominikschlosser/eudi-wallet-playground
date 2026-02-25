# OID4VP Conformance (Verifier) with the OIDF demo suite

The OIDF demo server (`https://demo.certification.openid.net`) runs remotely, so it must be able to fetch your `request_uri` and POST the `direct_post` response to your `response_uri`.

That means the verifier must be reachable from the public internet:
- either run the suite locally, or
- expose the verifier via a tunnel (e.g., ngrok) / deploy it to a public host.

## 0) Using the built-in “OIDF Conformance Suite” page (recommended)

Open `/verifier/conformance` and set:
- **Conformance API base URL** (suite root; defaults to `https://demo.certification.openid.net`)
- **Conformance API key** (optional; stored server-side in your session and never echoed back into the HTML)

Optionally, you can preconfigure the defaults via env vars:
- `VERIFIER_CONFORMANCE_BASE_URL`
- `VERIFIER_CONFORMANCE_API_KEY`

Paste the plan ID into “OIDF Conformance Suite” and click “Load plan”. The UI will:
- after you start a run, show the suite’s `/authorize` endpoint for that run (and use it as the default wallet endpoint in `/verifier`),
- switch defaults to `x509_san_dns`, `request_uri`, and `direct_post.jwt`, and
- show module JSON/results; use “Refresh” while runs are in progress.

## 1) Make the verifier publicly reachable

### Using the helper script (recommended)

```bash
scripts/run-demo-ngrok.sh
```

The script automatically:
- reads the dNSName SAN from `sandbox/sandbox-ngrok-combined.pem` and starts ngrok with that domain (e.g. `wallet-test.ngrok.dev`)
- sets `VERIFIER_CLIENT_CERT_FILE` so the verifier's sandbox defaults use the ngrok certificate
- starts the demo app with the correct env vars

If `sandbox/sandbox-ngrok-combined.pem` does not exist, ngrok starts with a random URL and the verifier falls back to its default certificate (`sandbox/sandbox-combined.pem`).

Use `--domain <name>` to override the auto-detected domain, or `--ngrok-only` to start just the tunnel.

### Manual setup

```bash
# start the app locally (example: 3000)
. ~/.sdkman/bin/sdkman-init.sh
mvn -pl demo-app spring-boot:run

# in a second terminal: expose it
ngrok http 3000
```

Then open the ngrok `https://…` URL in your browser and use `/verifier/conformance` from there.

## 2) x509_san_dns certificate + client_id

The verifier auto-generates a self-signed cert with SANs:
- `verifier.localtest.me`
- `verifier.localhost`
- `localhost`

For x509_san_dns, use `client_id=x509_san_dns:verifier.localtest.me` and paste the combined PEM (cert + private key) from the Verifier UI.

## 3) Verifier UI settings for conformance
- `Wallet Authorization Endpoint`: use the suite’s exported `authorization_endpoint` (shown after you start a test run).
- `Client authentication`: `x509_san_dns`.
- `Client ID`: `x509_san_dns:verifier.localtest.me` (helper pre-fills when you paste the cert).
- `Client certificate`: paste the PEM (cert + private key) from the UI default or your own SAN-matching cert.
- `Response mode`: `direct_post.jwt`.
- `Request object delivery`: `request_uri` (use `GET` if you see suite warnings about `request_uri_method=post`).
- `DCQL query`: keep the default `dcql_query` unless the suite requires a specific one.

## 4) Test plan creation in the OIDF suite
Common causes of failing runs are *plan configuration errors*.

### 4.1) Avoid double-prefixing the client_id
If your plan variants contain `client_id_prefix=x509_san_dns`, do **not** also prefix `config.client.client_id`.

Fix by using:
- `variant.client_id_prefix = "x509_san_dns"`
- `config.client.client_id = "verifier.localtest.me"` (host only)

If you set `config.client.client_id` to `x509_san_dns:verifier.localtest.me` *and* keep `client_id_prefix=x509_san_dns`, the suite will expect `x509_san_dns:x509_san_dns:…` and the run will fail at `EnsureMatchingClientId`.

### 4.2) Provide a private key for `credential.signing_jwk`
The suite needs a private signing key to mint the SD-JWT credential it will present to your verifier.

If the plan only contains `{n,e,x5c}` (public key), you’ll see a failure like `Failed to create JWK from credential signing_jwk`.

Use a full private signing JWK (ES256 / P-256 is expected for SD-JWT), e.g. an EC key including `crv`, `x`, `y`, and private `d` (only for test environments).

## 5) Running locally
From the repo root:
```bash
export VERIFIER_CLIENT_ID=x509_san_dns:verifier.localtest.me
export VERIFIER_WALLET_AUTH_ENDPOINT=<suite-authorization-endpoint>  # from Exported Values
export PORT=3000  # or your choice
```
Then start the verifier (or demo app) per README. In the UI, select the conformance settings above and paste the PEM if you’re not using the default.

## 6) Notes
- The suite and wallets validate that the dNSName SAN matches the `client_id` value after `x509_san_dns:`.
- With self-signed certs, the suite still accepts x5c for SAN matching; if your wallet enforces trust, add the cert to its trust store.
- If your existing `verifier-keys.json` was created before SAN support was added, the verifier refreshes the self-signed certificate (keeping the same RSA key) on startup.
- If you use the remote demo suite, your `request_uri` / `response_uri` must be reachable from the suite. Use a public host (ngrok/Ingress) even if the verifier itself listens on `localhost`.

## 7) AWS / EKS notes
- Ensure `wallet.publicBaseUrl` is set to the public hostname you use to reach the verifier (so the verifier’s self-signed signing certificate includes that host as a dNSName SAN).
- In the conformance plan config (when using `variant.client_id_prefix=x509_san_dns`), set `client.client_id` to `<public-host>` (host only, no scheme/path, no `x509_san_dns:` prefix).
- Copy the verifier certificate from `/verifier` (“Client Binding Preview” → “Copy certificate”) if you need to pin it as a trust anchor in your plan configuration.
