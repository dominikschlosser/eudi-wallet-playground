# OID4VP Identity Provider Configuration

This document covers configuration options for the Keycloak OID4VP Identity Provider.

## DCQL Query Configuration

The DCQL (Digital Credentials Query Language) query defines which credentials are requested from the wallet.

### Configuration Priority

The IdP determines the DCQL query using this priority order:

1. **Explicit DCQL Query** - If set in IdP config (`dcqlQuery`), it's used directly
2. **Auto-generated from Mappers** - If IdP mappers are configured, DCQL is built from them
3. **Default Query** - Empty DCQL query as fallback

This allows:
- **Full control**: Set explicit JSON for complex queries (e.g., credential_sets)
- **Automatic generation**: Let mappers define credentials and claims
- **Override for testing**: Set explicit query to override mapper-based generation

### Credential Sets (Multiple Credential Types)

To accept either SD-JWT or mDoc format for the same credential type (e.g., PID):

```json
{
  "credentials": [
    {
      "id": "pid_sd_jwt",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:1"] },
      "claims": [
        { "path": ["personal_administrative_number"] },
        { "path": ["family_name"] },
        { "path": ["given_name"] }
      ]
    },
    {
      "id": "pid_mdoc",
      "format": "mso_mdoc",
      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
      "claims": [
        { "path": ["administrative_number"] },
        { "path": ["family_name"] },
        { "path": ["given_name"] }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [["pid_sd_jwt"], ["pid_mdoc"]],
      "required": true
    }
  ]
}
```

The `credential_sets` section specifies that the wallet can present **either** `pid_sd_jwt` OR `pid_mdoc` to satisfy the request.

### Different Claim Names per Format

SD-JWT and mDoc credentials often use different claim names for the same data:

| Data | SD-JWT Claim | mDoc Claim |
|------|--------------|------------|
| Birth date | `birthdate` | `birth_date` |
| User ID | `personal_administrative_number` | `administrative_number` |

Configure IdP mappers for both formats to map them to the same Keycloak attribute:

```
Mapper 1: SD-JWT birthdate → Keycloak birthdate attribute
Mapper 2: mDoc birth_date → Keycloak birthdate attribute
```

### User Identifier Claims

When using credential_sets with different formats, configure both identifier claims in the IdP settings:

- **User Identifier Claim (SD-JWT)**: e.g., `personal_administrative_number`
- **User Identifier Claim (mDoc)**: e.g., `administrative_number`

The IdP automatically uses the correct claim based on the credential format presented.

### Auto-Generation from Mappers

When DCQL Query is left empty, the IdP builds it from configured mappers:

1. Each mapper specifies: credential format, credential type, and claim path
2. Mappers are grouped by credential type (format + vct/docType)
3. If multiple types exist, `credential_sets` is added based on **Credential Set Mode**:
   - `optional` (default): Wallet presents any one credential
   - `all`: Wallet must present all credentials

## IdP Mappers

IdP mappers extract claims from verified credentials and map them to Keycloak user attributes.

### Mapper Configuration

Each mapper has:
- **Credential Format**: `dc+sd-jwt` or `mso_mdoc`
- **Credential Type**: vct (SD-JWT) or docType (mDoc)
- **Claim Path**: Path to the claim (e.g., `family_name`, `address/city`)
- **User Attribute**: Target Keycloak attribute (e.g., `lastName`, `firstName`)

### Example: Supporting Both SD-JWT and mDoc PID

```
# SD-JWT mappers
sd-jwt-family_name → lastName
sd-jwt-given_name → firstName
sd-jwt-birthdate → birthdate

# mDoc mappers (note different claim names)
mdoc-family_name → lastName
mdoc-given_name → firstName
mdoc-birth_date → birthdate  # Different claim name, same attribute
```

## Trust Configuration

### Trust List

The IdP verifies credential issuers against a trust list in [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) JWT format. Two configuration options are available:

- **Trust List URL** (`trustListUrl`): URL to fetch the trust list JWT from (e.g. `https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt`). The JWT is fetched when the IdP is created.
- **Trust List JWT** (`trustListJwt`): Inline ETSI trust list JWT string. Paste the full JWT content directly.

If both URL and inline JWT are configured, the URL is tried first with the inline JWT as fallback.

Additional configuration:
- **Trust List ID**: Identifier for the trust list (default: `trust-list`)
- **Additional Trusted Certificates**: PEM certificates to add dynamically

See [docs/trust-lists.md](../docs/trust-lists.md) for full details on the ETSI trust list format and available trust lists.

### Allowed Issuers/Types

Optionally restrict accepted credentials:
- **Allowed Issuers**: Comma-separated list of issuer identifiers
- **Allowed Credential Types**: Comma-separated list of vct/docType values

## Flow Configuration

### DC API Flow (Browser-based)
- Requires browser with Digital Credentials API support or bridge extension
- See [DC-API-INTEGRATION.md](DC-API-INTEGRATION.md) for details

### Same-Device Flow (Redirect)
- Redirects to wallet app on same device
- Configure wallet URL and optional custom scheme

### Cross-Device Flow (QR Code)
- Shows QR code for scanning with phone wallet
- Not yet fully implemented

## References

- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [DCQL Query Language](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-credential-query-language)
- [SD-JWT Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [ISO 18013-5 mDL](https://www.iso.org/standard/69084.html)
