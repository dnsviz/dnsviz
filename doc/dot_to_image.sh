#!/bin/sh

for f in dot/*dot; do
	base=`basename $f .dot`
	dot -Tpng $f > images/$base.png
done
