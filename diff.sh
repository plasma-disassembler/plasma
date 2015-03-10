#!/bin/bash

red() {
    echo -en "\x1b[;31m$1\x1b[0m"
}

green() {
    echo -en "\x1b[;32m$1\x1b[0m"
}

name=`basename "$1" .rev`
echo -n "$name "

if [ -f "tests/${name}.rev" ]; then
    ./reverse.py "tests/${name}.bin" --nocolor --nograph >tmp 2>/dev/null
    if [ $? -eq 0 ]; then
            diff -q tmp "tests/${name}.rev" >/dev/null
            rm tmp
        if [ $? -eq 0 ]; then
            green "[OK]\n"
        else
            red "[FAIL]\n"
        fi
    else
        red "[EXCEPTION]\n"
    fi
else
    red "[NOT FOUND]\n"
fi

