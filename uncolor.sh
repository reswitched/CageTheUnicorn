#!/bin/bash

cat colorme.idc | sed 's/0x00ff00)/0xffffff)/g;s/0xff00ff)/0xffffff)/g;' > uncolorme.idc
