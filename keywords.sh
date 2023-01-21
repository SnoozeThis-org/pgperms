#!/bin/sh

(
	echo 'package pcac'

	echo 'var keywords = []string{'

	grep ^PG_KEYWORD ../postgres/src/include/parser/kwlist.h | grep ,\ RESERVED_KEYWORD | sed -E 's/^PG_KEYWORD\("(\w+)", \w+, (\w+)_KEYWORD\, (\w+)\)/\1/g' | sed 's/\s.*//g' | sed -e 's/^/"/g' -e 's/$/",/g'

	echo '}'
) | gofmt
