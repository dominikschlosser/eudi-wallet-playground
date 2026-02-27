#!/usr/bin/env python3
"""
SD-JWT parser for debugging. Decodes and displays the structure of an SD-JWT token.

Usage:
    python3 scripts/parse-sdjwt.py <sd-jwt-token>
    echo "<sd-jwt-token>" | python3 scripts/parse-sdjwt.py
    python3 scripts/parse-sdjwt.py --file <path-to-file>
"""

import base64
import hashlib
import json
import sys


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_json(b64: str) -> dict | list | None:
    try:
        return json.loads(b64url_decode(b64))
    except Exception:
        return None


def looks_like_jwt(s: str) -> bool:
    return s.count(".") == 2


def compute_disclosure_hash(disclosure_b64: str, alg: str = "sha-256") -> str:
    digest = hashlib.sha256(disclosure_b64.encode("ascii")).digest()
    return b64url_encode(digest)


def resolve_sd_claims(payload: dict, disclosure_map: dict, depth: int = 0) -> dict:
    """Recursively resolve _sd entries and nested structures."""
    result = {}
    sd_hashes = payload.get("_sd", [])

    for key, value in payload.items():
        if key in ("_sd", "_sd_alg"):
            continue
        if isinstance(value, dict):
            result[key] = resolve_sd_claims(value, disclosure_map, depth + 1)
        elif isinstance(value, list):
            result[key] = resolve_array(value, disclosure_map, depth + 1)
        else:
            result[key] = value

    for h in sd_hashes:
        if h in disclosure_map:
            d = disclosure_map[h]
            name = d["claim_name"]
            value = d["claim_value"]
            if isinstance(value, dict):
                result[name] = resolve_sd_claims(value, disclosure_map, depth + 1)
            elif isinstance(value, list):
                result[name] = resolve_array(value, disclosure_map, depth + 1)
            else:
                result[name] = value

    return result


def resolve_array(arr: list, disclosure_map: dict, depth: int = 0) -> list:
    """Resolve array element digests {"...": hash}."""
    result = []
    for item in arr:
        if isinstance(item, dict) and len(item) == 1 and "..." in item:
            h = item["..."]
            if h in disclosure_map:
                d = disclosure_map[h]
                value = d["claim_value"]
                if isinstance(value, dict):
                    result.append(resolve_sd_claims(value, disclosure_map, depth + 1))
                elif isinstance(value, list):
                    result.append(resolve_array(value, disclosure_map, depth + 1))
                else:
                    result.append(value)
            else:
                result.append(f"<UNRESOLVED: {h[:16]}...>")
        elif isinstance(item, dict):
            result.append(resolve_sd_claims(item, disclosure_map, depth + 1))
        elif isinstance(item, list):
            result.append(resolve_array(item, disclosure_map, depth + 1))
        else:
            result.append(item)
    return result


def parse_sdjwt(token: str):
    token = token.strip()
    parts = token.split("~")

    jwt_part = parts[0]
    disclosure_parts = []
    kb_jwt = None

    for i, part in enumerate(parts[1:], 1):
        if not part:
            continue
        if looks_like_jwt(part):
            kb_jwt = part
        else:
            disclosure_parts.append(part)

    # Decode JWT
    jwt_segments = jwt_part.split(".")
    if len(jwt_segments) != 3:
        print("ERROR: JWT part does not have 3 segments")
        return

    header = decode_json(jwt_segments[0])
    payload = decode_json(jwt_segments[1])

    print("=" * 80)
    print("SD-JWT STRUCTURE")
    print("=" * 80)

    print("\n--- HEADER ---")
    print(json.dumps(header, indent=2, ensure_ascii=False))

    print("\n--- PAYLOAD (raw) ---")
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    sd_alg = payload.get("_sd_alg", "sha-256") if payload else "sha-256"
    sd_hashes = set(payload.get("_sd", [])) if payload else set()

    # Parse disclosures
    print(f"\n--- DISCLOSURES ({len(disclosure_parts)}) ---")
    disclosure_map = {}
    for i, disc in enumerate(disclosure_parts):
        decoded = decode_json(disc)
        h = compute_disclosure_hash(disc, sd_alg)

        if decoded is None:
            print(f"  [{i+1}] FAILED to decode: {disc[:40]}...")
            continue

        if isinstance(decoded, list) and len(decoded) == 3:
            salt, name, value = decoded
            print(f"  [{i+1}] {name} = {json.dumps(value, ensure_ascii=False)}")
            print(f"       hash: {h}")
            print(f"       type: named claim disclosure")
            disclosure_map[h] = {"claim_name": name, "claim_value": value}
        elif isinstance(decoded, list) and len(decoded) == 2:
            salt, value = decoded
            print(f"  [{i+1}] <array element> = {json.dumps(value, ensure_ascii=False)}")
            print(f"       hash: {h}")
            print(f"       type: array element disclosure")
            disclosure_map[h] = {"claim_name": None, "claim_value": value}
        else:
            print(f"  [{i+1}] UNKNOWN format: {json.dumps(decoded, ensure_ascii=False)}")

    # Key binding JWT
    if kb_jwt:
        kb_segments = kb_jwt.split(".")
        kb_header = decode_json(kb_segments[0])
        kb_payload = decode_json(kb_segments[1]) if len(kb_segments) > 1 else None
        print("\n--- KEY BINDING JWT ---")
        print(f"  Header: {json.dumps(kb_header, ensure_ascii=False)}")
        print(f"  Payload: {json.dumps(kb_payload, indent=2, ensure_ascii=False)}")

    # Check for unresolvable digests
    print("\n--- DIGEST RESOLUTION ---")
    all_digests = set()
    collect_digests(payload, all_digests)
    resolved = all_digests & set(disclosure_map.keys())
    unresolved = all_digests - set(disclosure_map.keys())
    print(f"  Total digests in payload+disclosures: {len(all_digests)}")
    print(f"  Resolved: {len(resolved)}")
    print(f"  Unresolved: {len(unresolved)}")
    if unresolved:
        print(f"  Unresolved hashes:")
        for h in unresolved:
            print(f"    - {h}")

    # Resolve all claims
    print("\n--- RESOLVED CLAIMS ---")
    resolved_claims = resolve_sd_claims(payload, disclosure_map)
    # Remove internal fields
    for key in ("iss", "iat", "exp", "cnf", "vct", "status"):
        resolved_claims.pop(key, None)
    print(json.dumps(resolved_claims, indent=2, ensure_ascii=False))


def collect_digests(node, digests: set):
    """Recursively collect all SD digests from payload and disclosure values."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "_sd" and isinstance(value, list):
                for h in value:
                    if isinstance(h, str):
                        digests.add(h)
            elif key == "..." and isinstance(value, str):
                digests.add(value)
            else:
                collect_digests(value, digests)
    elif isinstance(node, list):
        for item in node:
            collect_digests(item, digests)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--file":
        if len(sys.argv) < 3:
            print("Usage: parse-sdjwt.py --file <path>")
            sys.exit(1)
        with open(sys.argv[2]) as f:
            token = f.read().strip()
    elif len(sys.argv) > 1 and sys.argv[1] != "-":
        token = sys.argv[1]
    else:
        token = sys.stdin.read().strip()

    if not token:
        print("No token provided")
        sys.exit(1)

    parse_sdjwt(token)


if __name__ == "__main__":
    main()
