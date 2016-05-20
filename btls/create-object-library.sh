#!/bin/sh

DIR=$1; shift
TARGET=$1; shift

TMPFILE=`mktemp` || exit 1
trap "rm -f $TMPFILE" EXIT

while [ "$1" != "--" ]; do
	file=$1; shift
	echo "$file " >> $TMPFILE
done

rm -f $TARGET
(cd $DIR && ar cr $TARGET `cat $TMPFILE`)


