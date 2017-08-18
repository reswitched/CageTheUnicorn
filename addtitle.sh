#!/bin/bash

TGT="$1"
SRC="$2"
LOAD="$TGT/load.yaml"

mkdir "$TGT"

echo 'nso:' > "$LOAD"

for fn in "$SRC/"*; do
	if [ -f "$fn" ] && [[ ${fn} != *".npdm" ]]; then
		BARE=$(basename $fn)
		cp "$fn" "$TGT/"
		echo "  - $BARE" >> "$LOAD"
	fi
done

echo 'maps:' >> "$LOAD"
for fn in "$SRC/"*; do
	if [ -f "$fn" ] && [[ ${fn} != *".npdm" ]]; then
		BARE=$(basename $fn)
		echo "  $(tr '[:lower:]' '[:upper:]' <<< ${BARE:0:1})${BARE:1}: [0x7100000000, \"$BARE.map\"]" >> "$LOAD"
	fi
done

cat << EOH > "$TGT/run.py"
import sys
sys.path.append('.')
from ctu import *

#@run#(TRACE_FUNCTION)
@debug(TRACE_MEMCHECK)
def main(ctu):
	ctu.load('$TGT')

	#@ctu.replaceFunction(MainAddress(unknown))
	def memset(ctu, addr, val, size):
		ctu.writemem(addr, chr(val) * size, check=False)

	ctu.call(MainAddress(0x0), _start=True)
EOH
