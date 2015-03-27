#!/bin/bash

color() {
    local color="$1"
    if [ "$3" == "" ]; then
        local prefix=""
        local txt="$2"
    else
        local prefix="$2 "
        local txt="$3"
    fi
    echo -en "${prefix}\x1b[;${color}m${txt}\x1b[0m"
}

red() {
    color 31 "$1" "$2"
}

green() {
    color 32 "$1" "$2"
}


__diff() {
    local name=$1
    local suffix=""
    local more_opt=""
    local tmp=tmp$$

    if [ "$2" != "" ]; then
        local more_opt="-x=$2"
        local suffix="_$2"
    fi


    if [ -f "tests/${name}${suffix}.rev" ]; then
        ./reverse.py "tests/${name}.bin" $more_opt --nosectionsname --nocolor >$tmp 2>/dev/null
        if [ $? -eq 0 ]; then
            if [ $verbose -eq 1 ]; then
                diff -b $tmp "tests/${name}${suffix}.rev"
            else
                diff -b $tmp "tests/${name}${suffix}.rev" >/dev/null
            fi

            if [ $? -eq 0 ]; then
                green "$name$suffix" "[OK]\n"
            else
                red "$name$suffix" "[FAIL]\n"
            fi
            rm $tmp
        else
            red "$name$suffix" "[EXCEPTION]\n"
        fi
    else
        red "$name$suffix" "[NOT FOUND]\n"
    fi
}

verbose=0
name=`basename "$1" .rev`
shift

if [ "$1" == "1" ]; then
    verbose=1
    shift
fi

if [ "$1" == "" ]; then
    __diff "$name"
else
    while [ "$1" != "" ]; do
        __diff "$name" "$1"
        shift
    done
fi
