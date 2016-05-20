#!/bin/sh

DIR=$1; shift
FILELIST=$1; shift
TARGET=$1; shift

rm -f $FILELIST $TARGET

while [ "$1" != "--" ]; do
	file=$1; shift
	echo "$DIR/$file " >> $FILELIST
done

(cd $DIR && ar cr $TARGET `cat $FILELIST`)

