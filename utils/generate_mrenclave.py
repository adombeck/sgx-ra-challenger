#!/usr/bin/env python3

import argparse
import sh
import os

from sgx_attester.config import KEY_DIR

# XXX: Is the offset fixed?
MRENCLAVE_OFFSET = 960  # Offset of MRENCLAVE value in manifest signature file
MRENCLAVE_SIZE = 32  # Size of MRENCLAVE value


def parse_args():
    parser = argparse.ArgumentParser("Extract MRENCLAVE from a manifest signature file created with Graphene's pal-sgx-sign")
    parser.add_argument("--outdir", "-o", default=KEY_DIR, help="Output directory")
    parser.add_argument("MANIFEST_SIGNATURE_FILE")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.outdir == KEY_DIR:
        sh.install("-m", "700", "-d", KEY_DIR)

    mrenclave_path = os.path.join(args.outdir, "mrenclave")

    with open(args.MANIFEST_SIGNATURE_FILE, "rb") as f:
        mrenclave = f.read()[MRENCLAVE_OFFSET:MRENCLAVE_OFFSET + MRENCLAVE_SIZE]

    with open(mrenclave_path, "w+") as f:
        f.write(mrenclave.hex())


if __name__ == "__main__":
    main()
