#!/bin/sh

PYTHON_VERSION=`python3 -c 'import sys; print("%i" % (sys.hexversion<0x03040000))'`
if [ $PYTHON_VERSION -ne 0 ]; then
    echo "error: you need at least python 3.4 to run this project"    
    exit
fi

rm -rf /usr/lib/python3.*/site-packages/capstone*
rm -rf build

mkdir -p build
cd build

CAPSTONE_VERSION=3.0.4

# Capstone
git clone -b $CAPSTONE_VERSION --depth 1 https://github.com/aquynh/capstone
cd capstone/
./make.sh
sudo ./make.sh install

# Bindings
cd bindings/python
sudo make install3
cd ../../..

# PE
git clone -b master --depth 1 https://github.com/simonzack/pefile-py3k
cd pefile-py3k
sudo python3 setup.py install
cd ..

# ELF
sudo pip3 install pyelftools
