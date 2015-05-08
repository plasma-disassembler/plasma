#!/bin/sh

CS_VERSION=3.0.3-rc1

mkdir -p build
cd build

git clone -b $CS_VERSION --depth 1 https://github.com/aquynh/capstone
cd capstone/
./make.sh
sudo ./make.sh install
cd bindings/python
sudo make install
cd ../../..

git clone -b master --depth 1 https://github.com/simonzack/pefile-py3k
cd pefile-py3k
python setup.py install
cd ..

sudo pip3 install pyelftools
