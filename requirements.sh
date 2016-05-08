#!/bin/sh

umask 002

REQ_EXEC="python3 pip3"
for EXEC in ${REQ_EXEC} 
do
    if [ ! -x "$(command -v $EXEC)" ]
    then
        echo "error: unable to find $EXEC, this is required to setup this project"
        exit
    fi
done

PYTHON_VERSION=`python3 -c 'import sys; print("%i" % (sys.hexversion<0x03040000))'`
if [ $PYTHON_VERSION -ne 0 ]; then
    echo "error: you need at least python 3.4 to run this project"    
    exit
fi

python3 -c 'import future' >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    echo "error: unable to find the package 'future' for python3 (required for pefile)"
    exit
fi

# TODO : locate first capstone
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
# https://github.com/erocarrera/pefile
sudo -H pip3 install pefile

# ELF
sudo -H pip3 install pyelftools

# Msgpack
sudo -H pip3 install msgpack-python
