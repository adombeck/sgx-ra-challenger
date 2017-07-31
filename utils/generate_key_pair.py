#! /usr/bin/env python3.5

import argparse
import os
import sh

from sgx_ra_challenger import crypto
from sgx_ra_challenger.config import KEY_DIR


def parse_args():
    parser = argparse.ArgumentParser("Generates key files for the challenger")
    parser.add_argument("--outdir", "-o", default=KEY_DIR, help="Output directory")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.outdir == KEY_DIR:
        sh.install("-m", "700", "-d", KEY_DIR)

    pubkey_path = os.path.join(args.outdir, "challenger_public.key")
    privkey_path = os.path.join(args.outdir, "challenger_private.key")

    if os.path.exists(pubkey_path):
        raise FileExistsError("File %r already exists" % pubkey_path)

    if os.path.exists(privkey_path):
        raise FileExistsError("File %r already exists" % privkey_path)

    public_key, private_key = crypto.generate_ecdh_key_pair()

    with open(pubkey_path, "w+") as pubkey_file:
        pubkey_file.write(public_key.hex())

    with open(privkey_path, "w+") as privkey_file:
        privkey_file.write(private_key.hex())


if __name__ == "__main__":
    main()
