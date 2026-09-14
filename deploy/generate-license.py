#!/usr/bin/env python3
"""
Linux Health Sentinel — Commercial License Generator
Version: 2.2.11 (updated 2026-09-14 23:45)

Generates tamper-proof cryptographic license keys for Sentinel Pro and Agency tiers.
Usage:
  python3 deploy/generate-license.py --tier pro --email user@example.com
  python3 deploy/generate-license.py --tier agency --email agency@example.com --nodes 50
  python3 deploy/generate-license.py --tier agency --email agency@example.com --days 365
"""

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_SECRET = "hs_master_sec_2026_x89a_prod_sentinel_signing_root"

def generate_key(tier: str, email: str, nodes: int = 1, days: int = None, secret: str = DEFAULT_SECRET) -> dict:
    tier = tier.lower().strip()
    if tier not in ("pro", "agency"):
        raise ValueError("Tier must be either 'pro' or 'agency'")

    now = datetime.now(timezone.utc)
    expires = None
    if days:
        expires = (now + timedelta(days=days)).strftime("%Y-%m-%d")

    license_id = f"HS-{tier.upper()}-{secrets.token_hex(4).upper()}"

    payload = {
        "id": license_id,
        "email": email.strip().lower(),
        "tier": tier,
        "nodes": nodes,
        "created": now.strftime("%Y-%m-%d"),
        "expires": expires
    }

    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')

    sig = hmac.new(secret.encode(), f"{tier}.{payload_b64}".encode(), hashlib.sha256).hexdigest().upper()
    license_key = f"HS-{tier.upper()}-{payload_b64}-{sig}"

    return {
        "license_key": license_key,
        "license_id": license_id,
        "tier": tier,
        "email": email,
        "nodes": nodes,
        "expires": expires or "Lifetime (Never)",
        "created": payload["created"]
    }

def main():
    parser = argparse.ArgumentParser(description="Sentinel Commercial License Generator")
    parser.add_argument("--tier", choices=["pro", "agency"], default="pro", help="License tier")
    parser.add_argument("--email", required=True, help="Customer email address")
    parser.add_argument("--nodes", type=int, default=1, help="Max servers / nodes allowed")
    parser.add_argument("--days", type=int, default=None, help="Validity period in days (omitted for lifetime)")
    parser.add_argument("--secret", default=DEFAULT_SECRET, help="Master signing secret")
    parser.add_argument("--key-only", action="store_true", help="Output raw license key string only")
    args = parser.parse_args()

    res = generate_key(args.tier, args.email, args.nodes, args.days, args.secret)

    if args.key_only:
        print(res["license_key"])
        return

    print("\n╔════════════════════════════════════════════════════════════════════════════╗")
    print("║  🛡  LINUX HEALTH SENTINEL — CRYPTOGRAPHIC LICENSE ISSUER                  ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝\n")
    print(f"  Customer Email : {res['email']}")
    print(f"  License Tier   : {res['tier'].upper()}")
    print(f"  Licensed Nodes : {res['nodes']}")
    print(f"  Expiration     : {res['expires']}")
    print(f"  License ID     : {res['license_id']}\n")
    print("  🔑 LICENSE KEY:")
    print(f"  \033[1;32m{res['license_key']}\033[0m\n")
    print("  Activate via Dashboard: Settings -> License -> Paste Key")
    print(f"  Activate via CLI:       sudo python3 sentinel.py --activate-license '{res['license_key']}'\n")

if __name__ == "__main__":
    main()
