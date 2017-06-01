import os

CURVE = "SECP256R1"

KEY_DIR = os.path.expanduser("~/.sgx-attester")
SSL_CERT_PATH = os.path.join(KEY_DIR, "fullchain.pem")
SSL_KEY_PATH = os.path.join(KEY_DIR, "privkey.pem")

# Development Services Environment
IAS_HOST = "test-as.sgx.trustedservices.intel.com"
# Production Environment
# IAS_HOST = "as.sgx.trustedservices.intel.com"
IAS_PORT = 443

IAS_URL = "https://test-as.sgx.trustedservices.intel.com:443"
