# Python SGX Attester

This package enables you to request and perform remote attestation of a remotely running enclave, which uses the Python SGX package for remote attestation.


## Submodules

1. [PyCrypto v2.7a1](https://github.com/dlitz/pycrypto) (Required for AES-CMAC)


## Installation

1. Initialize git submodules: `git submodule update --init`
2. Run the install script: `sudo ./setup.py install`


## Usage
Before you can use the remote attestation, you have to generate a key pair with the `generate_key_pair.py` script found in the `utils/` directory:

    ./generate_key_pair.py

This creates a public and a private key in `$HOME/.sgx-attester/`. You have to provide a copy of the public key to the host running the enclave via a secure channel (it should be stored in `/etc/python-sgx/attester_public.key` on the remote host).

To request attestation from host `192.168.0.2`, run:

    `sgx-attester -c 192.168.0.2 6789`.
