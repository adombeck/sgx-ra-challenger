import os

from sgx_attester.config import KEY_DIR


def get_private_key():
    privkey_path = os.path.join(KEY_DIR, "attester_private.key")
    with open(privkey_path) as privkey_file:
        return bytes.fromhex(privkey_file.read())


def get_public_key():
    pubkey_path = os.path.join(KEY_DIR, "attester_public.key")
    with open(pubkey_path) as pubkey_file:
        return bytes.fromhex(pubkey_file.read())
