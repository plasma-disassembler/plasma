#!/bin/bash

red() {
    echo -en "\x1b[;31m$1\x1b[0m"
}

green() {
    echo -en "\x1b[;32m$1\x1b[0m"
}


diff() {
    local name=$1
    local suffix=""
    local more_opt=""

    if [ "$2" != "" ]; then
        local more_opt="-x=$2"
        local suffix="_$2"
    fi

    echo -n "$name$suffix "

    if [ -f "tests/${name}${suffix}.rev" ]; then
        ./reverse.py "tests/${name}.bin" $more_opt --nocolor --nograph >tmp 2>/dev/null
        if [ $? -eq 0 ]; then
            diff -q tmp "tests/${name}${suffix}.rev" >/dev/null
            if [ $? -eq 0 ]; then
                green "[OK]\n"
            else
                red "[FAIL]\n"
            fi
            rm tmp
        else
            red "[EXCEPTION]\n"
        fi
    else
        red "[NOT FOUND]\n"
    fi
}

name=`basename "$1" .rev`
shift

if [ "$1" == "" ]; then
    diff "$name"
else
    while [ "$1" != "" ]; do
        diff "$name" "$1"
        shift
    done
fi



