#!/bin/bash

# 
# Usage :
# ./check.sh [rev|comp]
# 
# rev : generate rev files (erase older !)
# comp : compile c files
#

red() {
    echo -en "\x1b[;31m$1\x1b[0m"
}

green() {
    echo -en "\x1b[;32m$1\x1b[0m"
}

get_time() {
    stat -c %Y "tests/$1"
}

# Compile c files, if .c were modified
if [ "$1" == "comp" ]; then
    ls tests/*.c | while read file; do
        name=`basename "$file" .c`
        time_c=`get_time "${name}.c"`
        if [ ! -f "tests/${name}.bin" ]; then
            time_bin=0
        else
            time_bin=`get_time "${name}.bin"`
        fi
        if [ $time_c -gt $time_bin ]; then
            echo "compiling $name ..."
            gcc "$file" -o "tests/${name}.bin"
        fi
    done
    exit
fi

# Generate reverse files, if .bin were modified
if [ "$1" == "rev" ]; then
    ls tests/*.c | while read file; do
        name=`basename "$file" .c`
        time_bin=`get_time "${name}.bin"`
        if [ ! -f "tests/${name}.rev" ]; then
            time_rev=0
        else
            time_rev=`get_time "${name}.rev"`
        fi
        if [ $time_bin -gt $time_rev ]; then
            echo "reversing $name ..."
            ./reverse.py "tests/${name}.bin" --nocolor --nograph >"tests/${name}.rev"
        fi
    done
    exit
fi

# Diff test
ls tests/*.c | while read file; do
    name=`basename "$file" .c`
    echo -n "$name "
    if [ -f "tests/${name}.rev" ]; then
        ./reverse.py "tests/${name}.bin" --nocolor --nograph >tmp 2>/dev/null
        if [ $? -eq 0 ]; then
            diff -q tmp "tests/${name}.rev" >/dev/null
            if [ $? -eq 0 ]; then
                green "[OK]\n"
            else
                red "[FAIL]\n"
            fi
        else
            red "[EXCEPTION]\n"
        fi
    else
        red "[REV NOT FOUND]\n"
    fi
done

rm tmp
