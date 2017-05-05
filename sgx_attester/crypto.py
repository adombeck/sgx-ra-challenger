import logging

import hmac
import hashlib
import pyelliptic
import Crypto.Hash.CMAC
import Crypto.Cipher.AES

from sgx_attester import asn1
from sgx_attester.config import CURVE


class MacMismatchError(Exception):
    pass


class HashMismatchError(Exception):
    pass


def generate_ecdh_key_pair():
    # P-256 (aka secp256r1 aka prime256v1) was deprecated by the NSA in 2015 for unknown reasons.
    # See: https://blog.cryptographyengineering.com/2015/10/22/a-riddle-wrapped-in-curve/
    # We should probably use something else, but the Intel SDK functions only support P-256.

    # For testing, we can use these values from the RemoteAttestation sample
    # privkey = bytes.fromhex('0900000009000000090000000900000009000000090000000900000009000000')[::-1]
    # pubkey = b'\x04' + bytes.fromhex('6a83dc84d44c8abb5e42afee8de9f45771fd7366d7faadfaf21714dd5ab99e97')[::-1] + \
    #          bytes.fromhex('79a73872f2b8d6be18917ff7b5d3e5649b1218af39296c241938290bc6ac0c62')[::-1]
    # ecc = pyelliptic.ECC(curve=CURVE, privkey=privkey, pubkey=pubkey)

    ecc = pyelliptic.ECC(curve=CURVE)

    return ecc.get_pubkey()[1:], ecc.get_privkey()


def create_key_signature(private_key: bytes,
                         public_key: bytes,
                         attester_public_key: bytes,
                         enclave_public_key: bytes):

    logging.info("Creating key signature")

    assert len(attester_public_key) == 64
    assert len(enclave_public_key) == 64

    # Reverse public key byte order
    g_b = attester_public_key[:32][::-1] + attester_public_key[32:][::-1]
    g_a = enclave_public_key[:32][::-1] + enclave_public_key[32:][::-1]

    gb_ga = g_b + g_a
    logging.debug("gb_ga: %r | %r\n", g_b.hex(), g_a.hex())

    asn1_signature = pyelliptic.ECC(privkey=private_key, pubkey=b"\x04" + public_key, curve=CURVE).sign(gb_ga)
    signature = asn1.signature_from_asn1(asn1_signature)

    logging.debug("attester_public_key (g_b): %r | %r\n", attester_public_key[:32].hex(), attester_public_key[32:].hex())
    logging.debug("enclave_public_key (g_a): %r | %r\n", enclave_public_key[:32].hex(), enclave_public_key[32:].hex())
    logging.debug("signature: %r | %r\n", signature[:32].hex(), signature[32:].hex())

    assert len(signature) == 64
    assert pyelliptic.ECC(pubkey=b"\x04" + public_key, curve=CURVE).verify(asn1.signature_to_asn1(signature), gb_ga)

    return signature


def derive_key(shared_key, label):
    logging.info("Deriving key %r", label)

    # Reverse shared key byte order (Intel's SGX SDK uses the shared key in little endian byte order...)
    shared_key = shared_key[::-1]

    empty_key = b'\x00' * 16
    cobj1 = Crypto.Hash.CMAC.new(empty_key, ciphermod=Crypto.Cipher.AES)
    cobj1.update(shared_key)
    tmp_key = cobj1.digest()

    derivation_string = b'\x01' + label + b'\x00' + b'\x80\x00'
    cobj2 = Crypto.Hash.CMAC.new(tmp_key, ciphermod=Crypto.Cipher.AES)
    cobj2.update(derivation_string)
    session_mac_key = cobj2.digest()

    return session_mac_key


def derive_shared_key(private_key, own_public_key, other_public_key):
    logging.info("Deriving shared key")
    ecc = pyelliptic.ECC(privkey=private_key, pubkey=b"\x04" + own_public_key, curve=CURVE)
    return ecc.get_ecdh_key(b'\x04' + other_public_key)


def create_msg2_mac(mac_key, attester_public_key, spid, quote_type, kdf_id, signature):
    logging.info("Creating msg2 MAC")

    # Reverse public key byte order
    g_b = attester_public_key[:32][::-1] + attester_public_key[32:][::-1]

    # Reverse signature byte order
    reversed_signature = signature[:32][::-1] + signature[32:][::-1]

    authenticated_bytes = g_b + spid + quote_type + kdf_id + reversed_signature

    logging.info("Authenticated bytes: %r", authenticated_bytes.hex())

    cobj = Crypto.Hash.CMAC.new(mac_key, ciphermod=Crypto.Cipher.AES)
    cobj.update(authenticated_bytes)
    mac = cobj.digest()

    return mac


def create_msg3_mac(mac_key, enclave_public_key, quote, platform_service_security_properties):
    logging.info("Creating msg3 MAC")

    # Reverse public key byte order
    g_a = enclave_public_key[:32][::-1] + enclave_public_key[32:][::-1]

    authenticated_bytes = g_a + platform_service_security_properties + quote

    logging.info("Authenticated bytes: %r", authenticated_bytes.hex())

    cobj = Crypto.Hash.CMAC.new(mac_key, ciphermod=Crypto.Cipher.AES)
    cobj.update(authenticated_bytes)
    mac = cobj.digest()

    return mac


def verify_msg3_mac(mac, session_mac_key, enclave_public_key, quote, platform_service_security_properties):
    new_mac = create_msg3_mac(session_mac_key,
                              enclave_public_key,
                              quote,
                              platform_service_security_properties)
    if not hmac.compare_digest(mac, new_mac):
        raise MacMismatchError("Msg3 MAC %r does not match calculated MAC %r" % (mac, new_mac))


def verify_msg3_report_data(report_data, enclave_public_key, attester_public_key, shared_key):
    vk_key = derive_key(shared_key, label=b"VK")

    # Reverse public key byte order
    g_a = enclave_public_key[:32][::-1] + enclave_public_key[32:][::-1]
    g_b = attester_public_key[:32][::-1] + attester_public_key[32:][::-1]

    m = hashlib.sha256()
    m.update(g_a)
    m.update(g_b)
    m.update(vk_key)
    digest = m.digest()

    new_report_data = digest + b'\x00' * 32

    if not hmac.compare_digest(new_report_data, report_data):
        raise HashMismatchError("Msg3 report data %r does not match calculated report data %r" % (report_data, new_report_data))
