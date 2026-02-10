# Trust Lists (ETSI TS 119 602)

This project uses trust lists based on the [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) data model to anchor credential verification. A trust list enumerates trusted issuers and their X.509 certificates, so verifiers can check that a credential was signed by a recognised authority.

## Overview

In the EUDI wallet ecosystem, trust lists are published as signed JWTs (JAdES format). Each JWT payload follows the ETSI TS 119 602 "List of Trusted Entities" (LoTE) structure:

```
header.payload.signature
```

- **Header** — contains `alg` (e.g. `ES256`) and optionally `x5c` (signer certificate chain)
- **Payload** — the ETSI trust list data (see below)
- **Signature** — JWS signature over header + payload (or empty for unsigned local lists)

### JWT Payload Structure

```json
{
  "ListAndSchemeInformation": {
    "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
    "SchemeOperatorName": [
      { "lang": "de-DE", "value": "SPRIND GmbH" }
    ],
    "ListIssueDatetime": "2026-02-09T23:04:42.539Z"
  },
  "TrustedEntitiesList": [
    {
      "TrustedEntityInformation": {
        "TEName": [
          { "lang": "de-DE", "value": "Bundesdruckerei GmbH" }
        ]
      },
      "TrustedEntityServices": [
        {
          "ServiceInformation": {
            "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
            "ServiceDigitalIdentity": {
              "X509Certificates": [
                { "val": "<base64-DER-encoded-certificate>" }
              ]
            }
          }
        }
      ]
    }
  ]
}
```

Key fields:

| Field | Description |
|-------|-------------|
| `ListAndSchemeInformation.SchemeOperatorName` | Display label for the trust list operator |
| `ListAndSchemeInformation.LoTEType` | Type URI (e.g. `EUPIDProvidersList`, `local`) |
| `TrustedEntitiesList[].TrustedEntityInformation.TEName` | Display name of the trusted entity |
| `TrustedEntitiesList[].TrustedEntityServices[].ServiceInformation.ServiceDigitalIdentity.X509Certificates[].val` | Base64-DER encoded X.509 certificate |

Certificates are base64-encoded DER (not PEM). The public key from each certificate is used to verify credential signatures (SD-JWT, mDoc issuerAuth).

## BMI Test Sandbox Trust Lists

The German BMI publishes trust lists for the EUDI wallet test sandbox at:

**Base URL:** `https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/`

Available trust lists:

| File | Description |
|------|-------------|
| `pid-provider.jwt` | PID (Personal Identification Data) issuers |
| `registrar.jwt` | Registrar entities |
| `wallet-provider.jwt` | Wallet providers |
| `wrpac-provider.jwt` | WRPAC providers |
| `wrprc-provider.jwt` | WRPRC providers |

These are signed JWTs with real issuer certificates from the German test infrastructure.

## How Trust Lists Work in This Project

### EtsiTrustListParser

The shared parser in `app-common` (`EtsiTrustListParser.java`) handles all trust list loading:

1. Splits the JWT on `.` and Base64URL-decodes the payload (part[1])
2. Parses the JSON payload using Jackson
3. Extracts the label from `SchemeOperatorName[0].value`
4. Iterates all `TrustedEntitiesList[].TrustedEntityServices[].ServiceDigitalIdentity.X509Certificates[].val`
5. Decodes each base64-DER certificate via `CertificateFactory.getInstance("X.509")`
6. Returns an `EtsiTrustList` record with the label and a list of `TrustedEntity` objects (each with a name and public keys)

The parser does **not** verify JWT signatures — it only extracts the payload. This is intentional for the playground setup; a production system would verify the trust list JWT signature against a known trust anchor.

### Building Mock Trust Lists

For local/test use, `EtsiTrustListParser.buildUnsignedJwt(label, issuers)` generates unsigned JWTs (`{"alg":"none"}`) with the ETSI payload structure. The static `.jwt` files in `verifier/src/main/resources/` were generated this way.

To convert a PEM certificate to base64-DER (for inclusion in a trust list), use `EtsiTrustListParser.pemToBase64Der(pem)` — this strips the PEM headers/footers and whitespace.

## Standalone Verifier Configuration

### Local Trust Lists (Classpath)

The verifier automatically loads all `trust-list*.jwt` files from the classpath at startup:

- `verifier/src/main/resources/trust-list.jwt` — Keycloak realm issuers (ES256, RSA) + mock issuer
- `verifier/src/main/resources/trust-list-mock.jwt` — Mock issuer only
- `verifier/src/main/resources/trust-list-invalid.jwt` — Empty list (for testing failure cases)

Each file becomes a selectable trust list in the verifier UI dropdown. The trust list ID is derived from the filename (e.g. `trust-list-mock`), and the display label comes from the ETSI `SchemeOperatorName`.

### Remote Trust Lists (ETSI)

To fetch trust lists from a remote URL at startup, set:

```bash
VERIFIER_ETSI_TRUST_LIST_BASE_URL=https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/
```

Or in `application.yml`:

```yaml
verifier:
  etsi-trust-list-base-url: https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/
```

When configured, the verifier fetches all 5 known trust list files (`pid-provider.jwt`, `registrar.jwt`, etc.) from the base URL at startup. Remote trust lists appear alongside local ones in the UI dropdown.

If a remote fetch fails, a warning is logged but startup continues — the verifier remains usable with local trust lists.

## Keycloak Extension Configuration

The OID4VP Identity Provider in Keycloak supports two ways to configure trust lists:

### Trust List URL (recommended)

Set the **Trust List URL** in the IdP configuration to fetch the trust list JWT from a remote URL at IdP creation time. This is fetched via Keycloak's `SimpleHttp` utility.

### Inline Trust List JWT

Alternatively, paste the full JWT string directly into the **Trust List JWT** field. This is useful for testing or when the trust list is not available via URL.

### Configuration Properties

| Property | Description |
|----------|-------------|
| `trustListUrl` | URL to fetch the ETSI trust list JWT from |
| `trustListJwt` | Inline ETSI trust list JWT string |
| `trustListId` | Identifier for the trust list (default: `trust-list`) |

If both `trustListUrl` and `trustListJwt` are set, the URL is tried first. If the URL fetch fails, the inline JWT is used as fallback.

## Adding a New Trusted Issuer

### To a local `.jwt` file

1. Obtain the issuer's X.509 certificate (DER or PEM format)
2. If PEM, convert to base64-DER: strip `-----BEGIN/END CERTIFICATE-----` headers and all whitespace
3. Use `EtsiTrustListParser.buildUnsignedJwt()` in a test or script to generate a new JWT containing the issuer
4. Replace the `.jwt` file content

### To a Keycloak IdP

1. In the Keycloak admin console, navigate to the OID4VP Identity Provider settings
2. Either update the Trust List URL to point to a trust list containing the new issuer, or paste an updated JWT into the Trust List JWT field

## References

- [ETSI TS 119 602 — Trusted Lists Data Model (PDF)](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf)
- [ETSI TS 119 612 — Trusted Lists (XML format) discussion](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/41)
- [ETSI TS 119 602 issue tracker](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/278)
- [EUDI Trust List Service documentation](https://docs.eudi.dev/latest/build/supporting-ecosystem-services/trusted-list-service/)
- [BMI test trust lists](https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/)
- [EUDI Wallet Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [EWC Trust Mechanism RFC](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc012-trust-mechanism.md)
