#! /bin/bash

set -e

DIR=$PWD

echo "Installing pycrypto"
cd $DIR/pycrypto
python3.5 ./setup.py install

echo "Installing python-sgx-attester"
cd $DIR
python3.5 ./setup.py install
