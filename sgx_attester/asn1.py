import logging


def _sig_component_from_asn1(x):
    if len(x) < 32:
        # Add leading zeroes
        x = bytes([0] * (32 - len(x)) + list(x))
    elif len(x) > 32:
        # Remove leading zero
        x = x[1:]

    assert len(x) == 32

    return x


def _sig_component_to_asn1(raw: bytes):

    assert len(raw) == 32

    x = raw

    # Remove leading zeroes
    while x[0] == 0:
        x = x[1:]

    # Add leading zero if first bit is 1
    if x[0] > 0x7f:
        x = bytes([0] + list(x))

    return x


def signature_from_asn1(sig):
    logging.debug("len(sig): %s (%s)", len(sig), sig[1])

    assert sig[0] == 0x30
    assert sig[1] == len(sig) - 2
    assert sig[2] == 0x02

    logging.debug("sig[:4]: %s", [hex(e) for e in sig[:4]])
    len_r = sig[3]

    logging.debug("sig[4:%s]: %s", hex(4 + len_r), [hex(e) for e in sig[4:4 + len_r]])
    r_asn = sig[4:4 + len_r]
    
    logging.debug("sig[%s]: %s", hex(4 + len_r + 1), hex(sig[4 + len_r + 1]))
    len_s = sig[4 + len_r + 1]

    offset_s = 4 + len_r + 2
    logging.debug("sig[%s:%s]: %s", hex(offset_s), hex(offset_s + len_s), [hex(e) for e in sig[offset_s:offset_s + len_s]])
    s_asn = sig[offset_s:offset_s + len_s]

    logging.debug("len(r): %s", len(r_asn))
    logging.debug("len(s): %s", len(s_asn))

    r = _sig_component_from_asn1(r_asn)
    s = _sig_component_from_asn1(s_asn)
    return r + s


def signature_to_asn1(signature: bytes):
    r = _sig_component_to_asn1(signature[:32])
    s = _sig_component_to_asn1(signature[32:])
    return bytes([0x30, 4 + len(r) + len(s), 0x02, len(r)]) + r + bytes([0x02, len(s)]) + s
