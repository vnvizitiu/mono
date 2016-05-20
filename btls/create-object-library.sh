#!/bin/sh

DIR=$1; shift
FILELIST=$1; shift
TARGET=$1; shift

test -f $TARGET && exit 0

rm -f $FILELIST

while [ "$1" != "--" ]; do
	file=$1; shift
	echo "$DIR/$file " >> $FILELIST
done

(cd $DIR && ar cr $TARGET `cat $FILELIST`)

