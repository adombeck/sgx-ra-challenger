"""Communication with the Intel Attestation Service
Specification: https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf"""

import logging
import requests
import base64
import os
import hmac
from sgx_ra_challenger.config import IAS_HOST, IAS_PORT, SSL_CERT_PATH, SSL_KEY_PATH, IAS_PUBKEY_PATH
from sgx_ra_challenger.exceptions import QuoteVerificationError
from sgx_ra_challenger import crypto


def retrieve_sigrl(epid_group_id: bytes):
    return bytes()


def get_nonce() -> str:
    return os.urandom(16).hex()


def verify_quote(quote: bytes):
    return


def verify_ias_response_signature(response):
    return


def verify_ias_response_quote(response_body, encoded_quote):
    return
