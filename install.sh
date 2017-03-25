#!/bin/bash

umask 002

if [ "$1" != "--update" ]; then
    if [ $(tput colors) -ne 256 ]; then
        echo -n "warning: your terminal doesn't support 256 colors, continue ? [Y/n] "
        read line
        if [ "$line" == "n" ]; then
            exit
        fi
    fi

    REQ_EXEC="python3 pip3 c++filt"
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

    # Capstone
    pushd . > /dev/null
    mkdir -p build
    cd build
    CAPSTONE_VERSION="3.0.5-rc2"
    if [ -d capstone_$CAPSTONE_VERSION ]; then
        cd capstone_$CAPSTONE_VERSION
        make clean
    else
        git clone -b $CAPSTONE_VERSION --depth 1 https://github.com/aquynh/capstone
        mv capstone capstone_$CAPSTONE_VERSION
        cd capstone_$CAPSTONE_VERSION
    fi
    ./make.sh
    sudo -H ./make.sh install
    popd > /dev/null

    # Waiting that the package pip pefile contains any errors
    cat requirements.txt | grep -v pefile >req
    sudo -H pip3 install -r req 
    rm req
    sudo -H pip3 install future
    git clone --depth 1 https://github.com/erocarrera/pefile
    cd pefile
    python3 setup.py install
    cd ..
fi

python3 setup.py build_ext --inplace

# Or create an alias to run_plasma.py
sudo -H python3 setup.py install
