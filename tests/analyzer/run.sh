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

echo "analyzer tests..."

ls *.bin | while read file; do
    name=`basename $file .bin`

    case "$name" in
        "mips_prefetch")
            opt="--raw mips --rawbe --rawbase 0x400000"
            ;;
        *)
            opt=""
            ;;
    esac

    echo -e "py ${name}.py\n exit" | \
        ../../run_plasma.py -i -na -nc ${name}.bin $opt >tmp 2>/dev/null

    diff -q ${name}.rev tmp >/dev/null
    if [ $? -eq 0 ]; then
        green "$name" "[OK]\n"
    else
        red "$name" "[FAIL]\n"
    fi
done

rm tmp
