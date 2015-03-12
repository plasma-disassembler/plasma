#!/bin/sh

# Regen .rev files (only for the symbol main !)

if [ "$1" == "force" ]; then
  ls tests/*.bin | while read file; do
      name=`basename "$file" .bin`
     ./reverse.py --nocolor "tests/${name}.bin" >"tests/${name}.rev"
  done
  mv tests/server.rev tests/server_main.rev
  ./reverse.py tests/server.bin -x=connection_handler -nc >tests/server_connection_handler.rev
else
    echo "Are you sure ?"
    echo "if yes add 'force' in argument"
fi

