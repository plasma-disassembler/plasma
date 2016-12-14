#!/bin/sh

# Regen .rev files (only for the symbol main !)
# otherwise specifial cases at the end

cd ..

if [ "$1" == "force" ]; then
  ls tests/*.bin | while read file; do
      name=`basename "$file" .bin`
     ./run_plasma.py --nocolor "tests/${name}.bin" >"tests/${name}.rev"
  done

  mv tests/server.rev tests/server_main.rev
  ./run_plasma.py tests/server.bin -x=connection_handler -nc >tests/server_connection_handler.rev

  mv tests/pendu.rev tests/pendu__main.rev
  ./run_plasma.py tests/pendu.bin -x=___main -nc >tests/pendu____main.rev
  ./run_plasma.py tests/pendu.bin -x=__imp___cexit -nc >tests/pendu___imp___cexit.rev

else
    echo "Are you sure ?"
    echo "if yes add 'force' in argument"
fi
