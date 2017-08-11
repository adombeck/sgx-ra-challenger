import os

#######################################################
# Constants used in the configuration (DO NOT CHANGE) #

# Quote types
QUOTE_UNLINKABLE_SIGNATURE = b"\x00\x00"
QUOTE_LINKABLE_SIGNATURE = b"\x01\x00"

# Key derivation function IDs. Currently the only key derivation function is AES-CMAC.
AES_CMAC_KDF_ID = b"\x01\x00"

#######################################################

# Change this to the SPID Intel assigned to you
SPID = "79DFAE246EF4F7BA7D564C07C3873308"

# Change this to the type you chose during the Intel Attestation Service registration
QUOTE_TYPE = QUOTE_LINKABLE_SIGNATURE

# Currently this is the only curve supported by the Intel SGX SDK
CURVE = "SECP256R1"

# Currently this is the only key derivation function supported by the Intel SGX SDK
KDF_ID = b"\x01\x00"

KEY_DIR = os.path.expanduser("~/.sgx-ra-challenger")
SSL_CERT_PATH = os.path.join(KEY_DIR, "fullchain.pem")
SSL_KEY_PATH = os.path.join(KEY_DIR, "privkey.pem")
IAS_PUBKEY_PATH = os.path.join(KEY_DIR, "RK_PUB.PEM")

# Development Services Environment
IAS_HOST = "test-as.sgx.trustedservices.intel.com"

# Production Environment
# IAS_HOST = "as.sgx.trustedservices.intel.com"

IAS_PORT = 443
