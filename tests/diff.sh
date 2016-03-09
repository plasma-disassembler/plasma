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

OPTIONS="--nosectionsname --nocolor"
VERBOSE=0

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
        ./run_plasma.py "tests/${name}.bin" $more_opt $OPTIONS >$tmp 2>/dev/null
        if [ $? -eq 0 ]; then
            if [ $VERBOSE -eq 1 ]; then
                diff $tmp "tests/${name}${suffix}.rev" 
            else
                diff -q $tmp "tests/${name}${suffix}.rev" >/dev/null
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

name=`basename "$1" .rev`
shift

while true; do
    case "$1" in
        "1")
            VERBOSE=1
            ;;
        -*)
            OPTIONS="$OPTIONS $1"
            ;;
        *)
            break
            ;;
    esac

    shift
done

if [ "$1" == "" ]; then
    __diff "$name"
else
    while [ "$1" != "" ]; do
        __diff "$name" "$1"
        shift
    done
fi
