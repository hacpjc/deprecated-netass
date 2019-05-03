#!/bin/sh

me="`basename $0`"

#echo "filename: ${me%.*}"
#echo "extension: ${me##*.}"

conf="./${me%.*}.conf"

echo "...Run netass with conf $conf"
./netass -c "$conf"

