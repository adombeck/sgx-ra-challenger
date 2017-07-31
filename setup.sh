#! /bin/bash

set -e

DIR=$PWD

echo "Installing pycrypto"
cd $DIR/pycrypto
sudo python3.5 ./setup.py install

echo "Installing python-sgx-challenger"
cd $DIR
sudo python3.5 ./setup.py install
