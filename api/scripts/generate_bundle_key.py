#!/usr/bin/env python3
"""
Operator-side bootstrap CLI to generate the portal's bundle-signing
ed25519 keypair.

Writes:
  - Private key (32-byte seed, base64) to <out>/portal_bundle_signing.key
  - Public key (base64) to <out>/portal_bundle_signing.pub

The private key path is then set in the portal API's settings
(bundle_signing_key_path) via environment or .env. The public key is
distributed to each customer's AAC bridge at tenant onboarding;
embed it once and the bridge can verify every future bundle pull
without an online lookup.

Rotation: re-run with --rotate to mint a new keypair under a new
key_id; bump `bundle_signing_key_id` in the portal config. Old
bundles signed by the previous key remain verifiable as long as
the bridge keeps both keys embedded.

Usage:
    python scripts/generate_bundle_key.py --out /etc/aac-portal/keys
"""
from __future__ import annotations

import argparse
import base64
import os
import stat
import sys
from pathlib import Path

from nacl.signing import SigningKey


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--out",
        default=".",
        help="Output directory for the keypair files (default: current dir).",
    )
    p.add_argument(
        "--rotate",
        action="store_true",
        help="Overwrite existing key files. Default behaviour is to refuse.",
    )
    args = p.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / "portal_bundle_signing.key"
    pub_path = out_dir / "portal_bundle_signing.pub"

    if (priv_path.exists() or pub_path.exists()) and not args.rotate:
        print(
            f"ERROR: keypair already exists at {out_dir}. "
            "Pass --rotate to overwrite.",
            file=sys.stderr,
        )
        return 1

    signing_key = SigningKey.generate()
    seed_b64 = base64.b64encode(bytes(signing_key)).decode("ascii")
    verify_b64 = base64.b64encode(signing_key.verify_key.encode()).decode("ascii")

    priv_path.write_text(seed_b64)
    pub_path.write_text(verify_b64)

    # Lock down the private key. We can't make it 0600 reliably across
    # platforms, but on POSIX systems we tighten.
    try:
        os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    print(f"Private key (seed):  {priv_path}")
    print(f"Public key:          {pub_path}  -> {verify_b64}")
    print("")
    print("Next steps:")
    print(f"  1. Set bundle_signing_key_path={priv_path} in the portal env/.env")
    print( "  2. Set bundle_signing_key_id to a value like "
           "'portal-2026-06' (or your rotation policy's id)")
    print( "  3. Distribute the public key to each tenant's AAC bridge "
           "at onboarding (embedded for offline verification)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
