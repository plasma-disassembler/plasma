#!/bin/sh

# Regen .rev files (only for the symbol main !)

if [ "$1" == "force" ]; then
  ls tests/*.bin | while read file; do
      name=`basename "$file" .bin`
     ./reverse.py --nograph --nocolor "tests/${name}.bin" >"tests/${name}.rev"
  done
fi

