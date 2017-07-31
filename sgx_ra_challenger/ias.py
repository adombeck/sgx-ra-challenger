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
    url = "https://%s:%s/attestation/sgx/v2/sigrl/%s" % (IAS_HOST, IAS_PORT, epid_group_id.hex())

    response = requests.get(url, cert=(SSL_CERT_PATH, SSL_KEY_PATH))

    if response.status_code != 200:
        response.raise_for_status()

    logging.info("response body: %r", response.content)
    return base64.b64decode(response.content, validate=True)


def get_nonce() -> str:
    return os.urandom(16).hex()


def verify_quote(quote: bytes):
    url = "https://%s:%s/attestation/sgx/v2/report" % (IAS_HOST, IAS_PORT)
    nonce = get_nonce()

    encoded_quote = base64.b64encode(quote).decode()

    body = {
        "isvEnclaveQuote": encoded_quote,
        "nonce": nonce
    }

    response = requests.post(url, json=body, cert=(SSL_CERT_PATH, SSL_KEY_PATH))

    if response.status_code != 201:
        response.raise_for_status()

    body = response.json()
    logging.debug("response headers: %r", response.headers)
    logging.debug("response body: %r", body)

    if body["isvEnclaveQuoteStatus"] != "OK":
        raise QuoteVerificationError("IAS returned quote status %r", body["isvEnclaveQuoteStatus"])

    if not hmac.compare_digest(nonce, body["nonce"]):
        raise QuoteVerificationError("IAS returned incorrect nonce")

    verify_ias_response_signature(response)

    verify_ias_response_quote(body, encoded_quote)

    if not "epidPseudonym" in body:
        return body["id"]
    else:
        return body["id"], body["epidPseudonym"]


def verify_ias_response_signature(response):
    signature = base64.b64decode(response.headers["x-iasreport-signature"])
    with open(IAS_PUBKEY_PATH, 'br') as f:
        pubkey = f.read()
    crypto.verify_ias_signature(signature, pubkey, response.content)


def verify_ias_response_quote(response_body, encoded_quote):
    return hmac.compare_digest(response_body["isvEnclaveQuoteBody"], encoded_quote)
