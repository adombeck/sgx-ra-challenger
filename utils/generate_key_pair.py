#! /usr/bin/env python3.5

import argparse
import os
import sh
import pyelliptic

from sgx_attester.config import CURVE, KEY_DIR


def parse_args():
    parser = argparse.ArgumentParser("Generates key files for the attester")
    parser.add_argument("--outdir", "-o", default=KEY_DIR, help="Output directory")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.outdir == KEY_DIR:
        sh.install("-m", "700", "-d", KEY_DIR)

    ecc = pyelliptic.ECC(curve=CURVE)

    pubkey_path = os.path.join(args.outdir, "attester_public.key")

    if os.path.exists(pubkey_path):
        raise FileExistsError("File %r already exists" % pubkey_path)

    with open(pubkey_path, "w+") as pubkey_file:
        pubkey_file.write(ecc.get_pubkey()[1:].hex())

    privkey_path = os.path.join(args.outdir, "attester_private.key")

    if os.path.exists(privkey_path):
        raise FileExistsError("File %r already exists" % privkey_path)

    with open(privkey_path, "w+") as privkey_file:
        privkey_file.write(ecc.get_privkey().hex())


if __name__ == "__main__":
    main()