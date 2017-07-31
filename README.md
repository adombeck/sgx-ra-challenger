# Python SGX Remote Attestation Challenger

This package enables you to request and perform remote attestation of a remotely running enclave, which uses the Python SGX package for remote attestation.


## Submodules

1. [PyCrypto v2.7a1](https://github.com/dlitz/pycrypto) (Required for AES-CMAC)


## Installation

1. Initialize git submodules: 

         git submodule update --init

2. Run the install script: 

         sudo ./setup.py install


## Preparation
Before you can use the remote attestation, you have to register a TLS client certificate with Intel SGX Development Services, generate a key pair for authentication to the enclave, and calculate the measurement of the application you want to attest.


### Register Certificate with Intel SGX Development Services

In order verify the quote recieved during remote attestation, you need access to the Intel Attestation Service (IAS). This requires registering a TLS client certificate with Intel. You can request access to the IAS via [this form](https://software.intel.com/formfill/sgx-onboarding).

The `sgx-ra-challenger` needs access to the TLS client certificate, the corresponding private key, and the [IAS public key certificate](https://software.intel.com/sites/default/files/managed/7b/de/RK_PUB.zip). These are expected to be put in `$HOME/.sgx-ra-challenger/(fullchain.pem,privkey.pem,RK_PUB.PEM)`. You can change the paths in `sgx_ra_challenger/config.py`.


### Generate Key Pair

You need to generate a public key pair for authentication of the challenger to the enclave. You can use the `generate_key_pair.py` script in the `utils/` directory:

    ./generate_key_pair.py

This creates a public and a private key in `$HOME/.sgx-ra-challenger/`. You have to provide a copy of the public key to the host running the enclave via a secure channel (it should be stored in `/etc/python-sgx/challenger_public.key` on the remote host).


### Calculate Measurement

You can use the `generate_mrenclave.py` script found in the `utils/` directory to extract the `MRENCLAVE` value from a manifest signature file created with Graphene's `pal-sgx-sign`:

    ./generate_mrenclave.py /var/lib/python-sgx/python3.sig

This extracts the `MRENCLAVE` and writes it to `$HOME/.sgx-ra-challenger/mrenclave`. During attestatnio, this file's content will be compared to the `MRENCLAVE` value in the received quote.


## Usage

To request attestation from host `192.168.0.2`, run:

    sgx-ra-challenger -c 192.168.0.2 6789
