# SD-JWT: Complete Flow from Issuance to Verification

This document provides a comprehensive technical reference for SD-JWT (Selective Disclosure JWT) credentials, covering the complete lifecycle from issuance through storage to presentation and verification.

## Table of Contents

1. [Overview](#overview)
2. [Credential Structure](#credential-structure)
3. [Issuance Flow (OID4VCI)](#issuance-flow-oid4vci)
4. [Wallet Storage](#wallet-storage)
5. [Presentation Flow (OID4VP)](#presentation-flow-oid4vp)
6. [Key Binding JWT (KB-JWT)](#key-binding-jwt-kb-jwt)
7. [Verification Process](#verification-process)
8. [Trust Mechanisms](#trust-mechanisms)
9. [Client ID Schemes](#client-id-schemes)
10. [DC API Integration](#dc-api-integration)
11. [Response Modes](#response-modes)
12. [Troubleshooting](#troubleshooting)
13. [Specification References](#specification-references)

---

## Overview

SD-JWT is a credential format that enables **selective disclosure** - the holder can choose which claims to reveal during presentation while the verifier can still cryptographically verify the credential's authenticity.

### Key Properties

| Property | Description |
|----------|-------------|
| Format identifier | `dc+sd-jwt` (preferred) or `vc+sd-jwt` (legacy) |
| Base format | JSON Web Token (JWT) |
| Selective disclosure | Via SHA-256 hashed disclosures |
| Holder binding | Optional via `cnf` claim and KB-JWT |
| Signature algorithms | ES256, ES384, RS256, etc. |

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SD-JWT Credential                         │
├─────────────────────────────────────────────────────────────────┤
│  Issuer JWT (signed)                                            │
│  ├── Header: {alg, typ, kid}                                    │
│  ├── Payload: {iss, iat, exp, vct, cnf, _sd, _sd_alg, ...}     │
│  └── Signature                                                  │
├─────────────────────────────────────────────────────────────────┤
│  Disclosures (base64url encoded)                                │
│  ├── ~WyJzYWx0IiwgImdpdmVuX25hbWUiLCAiSm9obiJd                  │
│  ├── ~WyJzYWx0IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd                  │
│  └── ...                                                        │
├─────────────────────────────────────────────────────────────────┤
│  Key Binding JWT (optional, for presentation)                   │
│  └── ~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9...              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Credential Structure

### Issuer JWT Header

```json
{
  "alg": "ES256",
  "typ": "dc+sd-jwt",
  "kid": "issuer-key-1"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `alg` | Yes | Signature algorithm (ES256, RS256, etc.) |
| `typ` | Yes | Must be `dc+sd-jwt` (preferred) or `vc+sd-jwt` (legacy) |
| `kid` | Recommended | Key identifier for signature verification |
| `x5c` | Optional | X.509 certificate chain for issuer authentication |

### Issuer JWT Payload

```json
{
  "iss": "https://issuer.example.com",
  "iat": 1704067200,
  "exp": 1735689600,
  "nbf": 1704067200,
  "vct": "urn:eu.europa.ec.eudi:pid:1",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
      "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    }
  },
  "_sd_alg": "sha-256",
  "_sd": [
    "JnuSJQZQhMF-4spaJNXbX3c68Jv3XP2VHDkPNDKYd14",
    "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"
  ],
  "given_name": "John"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | Issuer identifier (URL) |
| `iat` | Yes | Issued at timestamp |
| `exp` | Recommended | Expiration timestamp |
| `nbf` | Optional | Not before timestamp |
| `vct` | Yes | Verifiable Credential Type identifier |
| `cnf` | For holder binding | Confirmation claim with holder's public key |
| `_sd_alg` | Yes | Hash algorithm for disclosures (sha-256) |
| `_sd` | Yes | Array of disclosure digests |

### Disclosure Structure

Each disclosure is a base64url-encoded JSON array:

```json
["salt", "claim_name", "claim_value"]
```

**Example:**
```
Original: ["6Ij7tM-a5iVPGboS5tmvVA", "given_name", "John"]
Encoded:  WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImdpdmVuX25hbWUiLCAiSm9obiJd
```

**Digest Computation:**
```
digest = base64url(SHA-256(disclosure_string))
```

The digest is included in the `_sd` array of the JWT payload.

### Complete SD-JWT Example

```
eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCIsImtpZCI6Imlzc3Vlci1rZXktMSJ9
.
eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTcwNDA2NzIwMCwiZXhwIjoxNzM1Njg5NjAwLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJjbmYiOnsiand rIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsInkiOiJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19LCJfc2RfYWxnIjoic2hhLTI1NiIsIl9zZCI6WyJKbnVTSlFaUWhNRi00c3BhSk5YYlgzYzY4SnYzWFAyVkhEa1BOREtZZDE0IiwiN0NmNkprUHVkcnkzbGNid0hnZVo4a2hBdjFVMU9TbGVyUDBWa0JKcldaMCJdfQ
.
MEUCIQDXQOJh7w8xL9dJXQOvd4hLnE4X-tCb8n_gGk8XwQIgQi5oJxBqWbfNtZS9QR8aA1L1nQOJh7w8xL9dJXQOvd4hLn
~
WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImdpdmVuX25hbWUiLCAiSm9obiJd
~
WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd
~
```

**Structure:** `<issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>`

---

## Issuance Flow (OID4VCI)

### Protocol Overview

OpenID for Verifiable Credential Issuance (OID4VCI) defines how credentials are issued to wallets.

```
┌────────┐                    ┌────────┐                    ┌────────┐
│  User  │                    │ Wallet │                    │ Issuer │
└───┬────┘                    └───┬────┘                    └───┬────┘
    │                             │                             │
    │  1. Initiate issuance       │                             │
    │─────────────────────────────>                             │
    │                             │                             │
    │                             │  2. Discover metadata       │
    │                             │─────────────────────────────>
    │                             │                             │
    │                             │  3. Metadata response       │
    │                             │<─────────────────────────────
    │                             │                             │
    │                             │  4. Authorization request   │
    │                             │─────────────────────────────>
    │                             │                             │
    │  5. User authentication     │                             │
    │<────────────────────────────┼─────────────────────────────>
    │                             │                             │
    │                             │  6. Token request           │
    │                             │─────────────────────────────>
    │                             │                             │
    │                             │  7. Access token + c_nonce  │
    │                             │<─────────────────────────────
    │                             │                             │
    │                             │  8. Credential request      │
    │                             │     (with proof-of-possession)
    │                             │─────────────────────────────>
    │                             │                             │
    │                             │  9. SD-JWT credential       │
    │                             │<─────────────────────────────
    │                             │                             │
```

### Issuance Models: Push vs Pull

OID4VCI supports two primary issuance models:

| Model | Grant Type | User Authentication | Use Case |
|-------|------------|---------------------|----------|
| **Push (Pre-authorized)** | `urn:ietf:params:oauth:grant-type:pre-authorized_code` | Already done before offer | Issuer initiates after user authenticated elsewhere |
| **Pull (Authorization Code)** | `authorization_code` | During issuance flow | Wallet initiates, user authenticates at issuer |

### Step 1a: Credential Offer (Push Model)

The issuance can start with a credential offer from the issuer (push model):

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["pid-sd-jwt"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA"
    }
  }
}
```

**Credential Offer URI:**
```
openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offer/abc123
```

### Step 1b: Authorization Request (Pull Model)

Alternatively, the wallet can initiate issuance using the authorization code flow (pull model):

```
┌────────┐                    ┌────────┐                    ┌────────┐
│  User  │                    │ Wallet │                    │ Issuer │
└───┬────┘                    └───┬────┘                    └───┬────┘
    │                             │                             │
    │  1. User wants credential   │                             │
    │─────────────────────────────>                             │
    │                             │                             │
    │                             │  2. Discover metadata       │
    │                             │─────────────────────────────>
    │                             │                             │
    │                             │  3. Authorization request   │
    │                             │     (scope, code_challenge) │
    │                             │─────────────────────────────>
    │                             │                             │
    │  4. User authentication     │                             │
    │     (login at issuer)       │                             │
    │<────────────────────────────┼─────────────────────────────>
    │                             │                             │
    │                             │  5. Authorization code      │
    │                             │<─────────────────────────────
    │                             │                             │
    │                             │  6. Token request           │
    │                             │     (code, code_verifier)   │
    │                             │─────────────────────────────>
    │                             │                             │
    │                             │  7. Access token + c_nonce  │
    │                             │<─────────────────────────────
    │                             │                             │
    │                             │  8. Credential request      │
    │                             │─────────────────────────────>
    │                             │                             │
```

**Authorization Request (Pull Model):**
```http
GET /authorize?
  response_type=code
  &client_id=wallet-app
  &redirect_uri=eudi-wallet://callback
  &scope=openid pid-sd-jwt
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &state=xyz123
  &authorization_details=[{
    "type": "openid_credential",
    "format": "dc+sd-jwt",
    "credential_configuration_id": "pid-sd-jwt"
  }]
HTTP/1.1
Host: issuer.example.com
```

**Token Request (Pull Model with PKCE):**
```http
POST /token HTTP/1.1
Host: issuer.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=eudi-wallet://callback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&client_id=wallet-app
```

**Key Difference:** In the pull model, the user authenticates at the issuer during the flow, while in the push model, authentication happened beforehand (e.g., the user logged into a government portal before receiving the credential offer).

### Step 2: Issuer Metadata Discovery

**Request:**
```http
GET /.well-known/openid-credential-issuer HTTP/1.1
Host: issuer.example.com
```

**Response:**
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "credential_configurations_supported": {
    "pid-sd-jwt": {
      "format": "dc+sd-jwt",
      "vct": "urn:eu.europa.ec.eudi:pid:1",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      },
      "claims": {
        "given_name": {"display": [{"name": "Given Name"}]},
        "family_name": {"display": [{"name": "Family Name"}]},
        "birthdate": {"display": [{"name": "Date of Birth"}]}
      }
    }
  }
}
```

### Step 3: Token Request

**Pre-authorized Code Flow:**
```http
POST /token HTTP/1.1
Host: issuer.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 300,
  "c_nonce": "fGFF7UkhLa",
  "c_nonce_expires_in": 300
}
```

### Step 4: Credential Request with Proof

The wallet creates a **proof of possession** JWT to bind the credential to its key:

**Proof JWT Header:**
```json
{
  "alg": "ES256",
  "typ": "openid4vci-proof+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
    "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
  }
}
```

**Proof JWT Payload:**
```json
{
  "iss": "https://wallet.example.com",
  "aud": "https://issuer.example.com",
  "iat": 1704067200,
  "exp": 1704067500,
  "nonce": "fGFF7UkhLa"
}
```

**Credential Request:**
```http
POST /credential HTTP/1.1
Host: issuer.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "format": "dc+sd-jwt",
  "credential_configuration_id": "pid-sd-jwt",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsInkiOiJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19.eyJpc3MiOiJodHRwczovL3dhbGxldC5leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNzA0MDY3MjAwLCJleHAiOjE3MDQwNjc1MDAsIm5vbmNlIjoiZkdGRjdVa2hMYSJ9.SIGNATURE"
  }
}
```

### Step 5: Credential Response

```json
{
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTcwNDA2NzIwMCwiZXhwIjoxNzM1Njg5NjAwLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJjbmYiOnsiand rIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsInkiOiJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19LCJfc2RfYWxnIjoic2hhLTI1NiIsIl9zZCI6WyJKbnVTSlFaUWhNRi00c3BhSk5YYlgzYzY4SnYzWFAyVkhEa1BOREtZZDE0IiwiN0NmNkprUHVkcnkzbGNid0hnZVo4a2hBdjFVMU9TbGVyUDBWa0JKcldaMCJdfQ.MEUCIQDXQOJh7w8xL9dJXQOvd4hLnE4X-tCb8n_gGk8XwQ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~",
  "c_nonce": "newNonce123",
  "c_nonce_expires_in": 300
}
```

---

## Wallet Storage

### Storage Requirements

The wallet must securely store:

1. **The complete SD-JWT** (issuer JWT + all disclosures)
2. **The holder's private key** (corresponding to `cnf.jwk`)
3. **Metadata** (issuer, vct, expiry, etc.)

### Storage Structure Example

```json
{
  "id": "credential-uuid-123",
  "format": "dc+sd-jwt",
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9...",
  "holder_key_id": "wallet-key-456",
  "issuer": "https://issuer.example.com",
  "vct": "urn:eu.europa.ec.eudi:pid:1",
  "issued_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z",
  "claims": {
    "given_name": "John",
    "family_name": "Doe",
    "birthdate": "1990-01-15"
  }
}
```

### Security Considerations

- Store private keys in secure hardware (TEE, Secure Enclave) when available
- Encrypt credentials at rest
- Implement biometric/PIN protection for credential access
- Support credential deletion/revocation

---

## Presentation Flow (OID4VP)

### Protocol Overview

OpenID for Verifiable Presentations (OID4VP) defines how credentials are presented to verifiers.

```
┌────────┐                    ┌────────┐                    ┌──────────┐
│  User  │                    │ Wallet │                    │ Verifier │
└───┬────┘                    └───┬────┘                    └────┬─────┘
    │                             │                              │
    │                             │  1. Authorization request    │
    │                             │     (with DCQL query)        │
    │                             │<─────────────────────────────│
    │                             │                              │
    │  2. Consent request         │                              │
    │<─────────────────────────────                              │
    │                             │                              │
    │  3. User approves           │                              │
    │─────────────────────────────>                              │
    │                             │                              │
    │                             │  4. Build presentation       │
    │                             │     (select disclosures,     │
    │                             │      create KB-JWT)          │
    │                             │                              │
    │                             │  5. Authorization response   │
    │                             │     (vp_token)               │
    │                             │─────────────────────────────>│
    │                             │                              │
    │                             │  6. Verification result      │
    │                             │<─────────────────────────────│
    │                             │                              │
```

### Authorization Request

**Request Parameters:**
```
GET /authorize?
  response_type=vp_token
  &client_id=https://verifier.example.com
  &response_uri=https://verifier.example.com/callback
  &response_mode=direct_post
  &nonce=n-0S6_WzA2Mj
  &state=af0ifjsldkj
  &dcql_query={"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu.europa.ec.eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}
```

### DCQL Query Structure

Digital Credentials Query Language (DCQL) specifies what credentials and claims are requested:

```json
{
  "credentials": [
    {
      "id": "pid",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["urn:eu.europa.ec.eudi:pid:1"]
      },
      "claims": [
        {"path": ["given_name"], "intent_to_retain": false},
        {"path": ["family_name"], "intent_to_retain": false},
        {"path": ["birthdate"], "intent_to_retain": false}
      ]
    }
  ]
}
```

### Building the Presentation

The wallet performs selective disclosure by:

1. **Selecting disclosures** to reveal (based on DCQL query)
2. **Creating KB-JWT** (if holder binding is required)
3. **Assembling the presentation**

**Presentation Structure:**
```
<issuer-jwt>~<selected-disclosure-1>~<selected-disclosure-2>~<kb-jwt>
```

---

## Key Binding JWT (KB-JWT)

### Holder Binding: Issuance-Time vs Presentation-Time

SD-JWT uses **issuance-time holder binding**: the holder's public key is embedded in the credential at issuance via the `cnf` claim.

| Aspect | SD-JWT | mDoc |
|--------|--------|------|
| **When bound** | At issuance | At issuance (but proven at presentation) |
| **Where stored** | `cnf.jwk` in credential payload | `deviceKeyInfo.deviceKey` in MSO |
| **How proven** | KB-JWT signature | DeviceAuth signature |
| **Session binding** | KB-JWT contains `aud`, `nonce` | DeviceAuth signs SessionTranscript |
| **Replay protection** | `nonce` in KB-JWT | `nonce` in SessionTranscript hash |

**Why this matters:**

1. **SD-JWT**: The credential is permanently bound to a specific key at issuance. The KB-JWT proves the holder has that key AND binds the presentation to a specific session (via `aud` and `nonce`).

2. **mDoc**: The credential is also bound to a device key at issuance, but the DeviceAuth signature provides stronger session binding because it signs over the entire SessionTranscript (which includes `client_id`, `nonce`, `response_uri`, and optionally `jwk_thumbprint`).

**Practical implication:** With SD-JWT, the credential cannot be transferred to a different key after issuance. The same is true for mDoc. However, mDoc's DeviceAuth provides more context about the presentation session, making it easier to detect replay across different verifiers.

### Purpose

KB-JWT proves that the presenter controls the private key bound to the credential via the `cnf` claim.

### KB-JWT Structure

**Header:**
```json
{
  "alg": "ES256",
  "typ": "kb+jwt"
}
```

**Payload:**
```json
{
  "iat": 1704067200,
  "exp": 1704067500,
  "aud": "https://verifier.example.com",
  "nonce": "n-0S6_WzA2Mj",
  "sd_hash": "fOBUSQvo46yTQgV9_7-TqA..."
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `iat` | Yes | Issued at timestamp |
| `exp` | Recommended | Expiration timestamp |
| `aud` | Yes | Verifier's client_id |
| `nonce` | Yes | Nonce from authorization request |
| `sd_hash` | Yes | Hash of issuer JWT + disclosures (before KB-JWT) |

### sd_hash Computation

```
sd_hash = base64url(SHA-256(
  ASCII(issuer_jwt + "~" + disclosure_1 + "~" + disclosure_2 + "~")
))
```

See `SdJwtUtils.computeSdHash()` for the implementation.

---

## Verification Process

### Verification Steps

```
┌─────────────────────────────────────────────────────────────────┐
│                    SD-JWT Verification Flow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Parse SD-JWT                                                │
│     ├── Split into: issuer_jwt, disclosures[], kb_jwt          │
│     └── Decode issuer JWT header and payload                   │
│                                                                 │
│  2. Verify Issuer Signature                                     │
│     ├── Check typ header is "dc+sd-jwt" or "vc+sd-jwt"         │
│     ├── Resolve issuer public key (trust list or x5c)          │
│     └── Verify JWT signature                                   │
│                                                                 │
│  3. Validate Timestamps                                         │
│     ├── Check iat is in the past                               │
│     ├── Check exp is in the future (if present)                │
│     └── Check nbf is in the past (if present)                  │
│                                                                 │
│  4. Verify Disclosures                                          │
│     ├── For each disclosure:                                   │
│     │   ├── Decode base64url to JSON array [salt, name, value] │
│     │   ├── Compute digest: base64url(SHA-256(disclosure))     │
│     │   └── Verify digest exists in _sd array                  │
│     └── No duplicate disclosures allowed                       │
│                                                                 │
│  5. Verify Holder Binding (if cnf present)                      │
│     ├── Parse KB-JWT                                           │
│     ├── Verify typ is "kb+jwt"                                 │
│     ├── Verify signature with cnf.jwk                          │
│     ├── Verify aud matches verifier's client_id                │
│     ├── Verify nonce matches request nonce                     │
│     ├── Verify iat is recent (within max_age, e.g., 5 min)     │
│     └── Verify sd_hash matches computed hash                   │
│                                                                 │
│  6. Extract Disclosed Claims                                    │
│     └── Build final claims object from disclosed values        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

See `SdJwtVerifier.java` for the full implementation. Key methods:
- `verify()` - main entry point
- `validateSdJwtType()` - checks typ header
- `verifyDisclosures()` - validates disclosure digests
- `verifyHolderBinding()` - validates KB-JWT

### Verification Checks Summary

| Check | Required | Failure Reason |
|-------|----------|----------------|
| JWT signature | Yes | Untrusted issuer |
| typ header | Yes | Invalid credential format |
| exp timestamp | If present | Credential expired |
| nbf timestamp | If present | Credential not yet valid |
| Disclosure digests | Yes | Tampered disclosures |
| KB-JWT signature | If cnf present | Invalid holder binding |
| KB-JWT aud | If KB-JWT present | Wrong verifier |
| KB-JWT nonce | If KB-JWT present | Replay attack |
| KB-JWT sd_hash | If KB-JWT present | Tampered presentation |

---

## Trust Mechanisms

### Trust List

A trust list contains public keys of trusted issuers:

```json
{
  "issuers": [
    {
      "id": "issuer-es256",
      "certificate": "MIIBgTCCASegAwIBAgIU...",
      "kid": "issuer-key-1"
    },
    {
      "id": "issuer-rsa",
      "jwk": {
        "kty": "RSA",
        "n": "0vx7agoebGc...",
        "e": "AQAB",
        "kid": "issuer-rsa-key"
      }
    }
  ]
}
```

### X.509 Certificate Chain (x5c)

Issuers can embed their certificate chain in the JWT header:

```json
{
  "alg": "ES256",
  "typ": "dc+sd-jwt",
  "x5c": [
    "MIIBgTCCASegAwIBAgIU...",
    "MIICmTCCAYGgAwIBAgIU..."
  ]
}
```

**Verification:**
1. Parse certificates from x5c array
2. Verify certificate chain validity
3. Check leaf certificate against trusted roots
4. Verify JWT signature with leaf certificate's public key

### Issuer Discovery

**OpenID Federation:**
```http
GET /.well-known/openid-federation HTTP/1.1
Host: issuer.example.com
```

**Returns entity statement with signing keys.**

---

## Client ID Schemes

OID4VP supports multiple client identification schemes:

### 1. Pre-registered (redirect_uri)

```
client_id=https://verifier.example.com
```
- Client is pre-registered with the wallet
- redirect_uri must match registered values

### 2. Web Origin (for DC API)

```
client_id=https://verifier.example.com
```
or with explicit origin prefix:
```
client_id=origin:https://verifier.example.com
```
- Browser enforces same-origin policy
- Used with Digital Credentials API

### 3. x509_san_dns

```
client_id=x509_san_dns:verifier.example.com
```
- Request object must be signed with X.509 certificate
- Certificate SAN dNSName must match client_id value
- response_uri host must match

### 4. x509_san_uri

```
client_id=x509_san_uri:https://verifier.example.com
```
- Similar to x509_san_dns but uses URI SAN

### 5. verifier_attestation

```
client_id=verifier_attestation:https://verifier.example.com
```
- Request object header contains attestation JWT
- Attestation is signed by trusted attestation issuer
- Contains verifier's public key in `cnf` claim

### 6. x509_hash

```
client_id=x509_hash:abc123...
```
- Request must be signed with X.509 certificate
- Hash value is base64url(SHA-256(leaf certificate DER encoding))
- More flexible than x509_san_dns/x509_san_uri - no SAN requirements
- Verifier computes SHA-256 of leaf cert from x5c header and compares

---

## DC API Integration

### Digital Credentials API Overview

The W3C Digital Credentials API enables browser-mediated credential presentation:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    providers: [{
      protocol: "openid4vp",
      request: {
        client_id: "https://verifier.example.com",
        nonce: "n-0S6_WzA2Mj",
        dcql_query: {...}
      }
    }]
  }
});
```

### Request Modes

**Unsigned Request (for same-origin):**
- Parameters passed directly in `request` object
- Browser provides origin-based client_id

**Signed Request Object:**
- Full JWT with cryptographic binding
- Supports x509_san_dns, verifier_attestation schemes

```json
{
  "alg": "ES256",
  "typ": "oauth-authz-req+jwt",
  "x5c": ["..."]
}
```

### Response Modes for DC API

| Mode | Description |
|------|-------------|
| `dc_api` | Unencrypted response via DC API |
| `dc_api.jwt` | JWE-encrypted response via DC API |

### Encrypted Response Flow

1. Verifier includes encryption key in `client_metadata.jwks`
2. Wallet encrypts response as JWE
3. Response contains encrypted `vp_token` and `state`

**client_metadata:**
```json
{
  "jwks": {
    "keys": [{
      "kty": "RSA",
      "n": "...",
      "e": "AQAB",
      "alg": "RSA-OAEP-256",
      "kid": "response-enc-key"
    }]
  },
  "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"]
}
```

---

## Response Modes

### direct_post

Wallet POSTs response directly to `response_uri`:

```http
POST /callback HTTP/1.1
Host: verifier.example.com
Content-Type: application/x-www-form-urlencoded

vp_token=eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9...
&state=af0ifjsldkj
```

### direct_post.jwt

Same as direct_post but response is JWE-encrypted:

```http
POST /callback HTTP/1.1
Host: verifier.example.com
Content-Type: application/x-www-form-urlencoded

response=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0...
```

**Decrypted payload:**
```json
{
  "vp_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9...",
  "state": "af0ifjsldkj"
}
```

### fragment

Response in URL fragment (for browser-based flows):

```
https://verifier.example.com/callback#vp_token=...&state=...
```

---

## Troubleshooting

### Common Issues

#### 1. "Credential signature not trusted"

**Causes:**
- Issuer not in trust list
- Wrong trust list ID configured
- Certificate chain validation failed

**Debug:**
```
LOG.debug("verifySignature() checking {} trust list keys", keys.size());
```

**Solution:**
- Verify issuer's public key/certificate is in trust list
- Check trust list configuration

#### 2. "Disclosure verification failed"

**Causes:**
- Disclosure digest doesn't match _sd array
- Disclosure was modified
- Wrong salt in disclosure

**Debug:**
```java
String computedDigest = base64url(SHA-256(disclosure));
boolean found = sdArray.contains(computedDigest);
```

#### 3. "Holder binding signature invalid"

**Causes:**
- KB-JWT signed with wrong key
- cnf.jwk doesn't match signing key

**Debug:**
- Compare cnf.jwk with KB-JWT signing key
- Verify key type and curve match

#### 4. "KB-JWT audience mismatch"

**Causes:**
- KB-JWT `aud` doesn't match verifier's client_id
- Wrong client_id in request

**Solution:**
- Ensure KB-JWT audience matches exactly

#### 5. "KB-JWT nonce mismatch"

**Causes:**
- Wrong nonce in KB-JWT
- Request nonce not propagated correctly

**Solution:**
- Verify nonce flows from request to KB-JWT

#### 6. "sd_hash mismatch"

**Causes:**
- KB-JWT created before/after disclosures changed
- Hash computation error

**Debug:**
```java
String expected = computeSdHash(parts);
String actual = kbJwt.getJWTClaimsSet().getStringClaim("sd_hash");
```

### Verification Checklist

- [ ] Trust list contains issuer's key
- [ ] JWT typ header is correct
- [ ] JWT signature verifies
- [ ] Credential not expired
- [ ] All disclosure digests found in _sd
- [ ] KB-JWT signature verifies with cnf.jwk
- [ ] KB-JWT aud matches client_id
- [ ] KB-JWT nonce matches request
- [ ] KB-JWT iat is recent
- [ ] KB-JWT sd_hash matches

---

## Specification References

| Specification | URL |
|--------------|-----|
| SD-JWT | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt |
| SD-JWT VC | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc |
| OID4VCI | https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html |
| OID4VP | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| DCQL | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l |
| DC API | https://wicg.github.io/digital-credentials/ |
| JWT | https://datatracker.ietf.org/doc/html/rfc7519 |
| JWS | https://datatracker.ietf.org/doc/html/rfc7515 |
| JWE | https://datatracker.ietf.org/doc/html/rfc7516 |

---

## Implementation Files Reference

| Component | File |
|-----------|------|
| SD-JWT Parser | `sdjwt-lib/src/main/java/.../SdJwtParser.java` |
| SD-JWT Verifier | `sdjwt-lib/src/main/java/.../SdJwtVerifier.java` |
| SD-JWT Builder | `sdjwt-lib/src/main/java/.../SdJwtCredentialBuilder.java` |
| Trust List | `keycloak-oid4vp/src/main/java/.../Oid4vpTrustListService.java` |
| OID4VP Verifier | `keycloak-oid4vp/src/main/java/.../Oid4vpVerifierService.java` |
| Wallet Presentation | `wallet/src/main/java/.../Oid4vpController.java` |
