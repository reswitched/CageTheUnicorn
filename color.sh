#!/bin/bash
echo '#include <idc.idc>' > colorme.idc
echo 'static main(void) {' >> 'colorme.idc'
for x in `cat log.txt | grep 'Block at' | cut -f 4 -d ' ' | sort | uniq | grep '0x'`; do
	echo "SetColor($x, CIC_ITEM, 0x00ff00);" >> colorme.idc;
done
for x in `cat log.txt | sed 's/^.*\[0:\(0x.*\)\].*$/\1/' | grep -v ' ' | cut -f 6 -d ' ' | sort | uniq | grep '0x'`; do
	echo "SetColor($x, CIC_ITEM, 0xff00ff);" >> colorme.idc;
done
echo '}' >> colorme.idc
