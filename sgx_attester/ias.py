"""Communication with the Intel Attestation Service
Specification: https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf"""

import logging
import http.client
import ssl
import base64
from sgx_attester.config import IAS_HOST, IAS_PORT, SSL_CERT_PATH, SSL_KEY_PATH
from sgx_attester.exceptions import SigRlRetrievalFailedError

http.client.HTTPConnection.debuglevel = 1


def get_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # XXX: Load only the Intel CA instead of all default certs
    context.load_default_certs()
    context.load_cert_chain(certfile=SSL_CERT_PATH, keyfile=SSL_KEY_PATH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


def connect_to_ias():
    ssl_context = get_ssl_context()
    return http.client.HTTPSConnection(IAS_HOST, port=IAS_PORT, context=ssl_context)


def retrieve_sigrl(epid_group_id: bytes):
    c = connect_to_ias()
    url = "/attestation/sgx/v2/sigrl/%s" % epid_group_id.hex()

    c.request("GET", url)
    r = c.getresponse()
    if r.status != 200:
        raise SigRlRetrievalFailedError("Intel Attestation Service responded with %r %r", r.status, r.reason)

    data = r.read()
    logging.info("Response data: %r", data)
    return base64.b64decode(data, validate=True)


def verify_quote(quote: bytes):
    pass
