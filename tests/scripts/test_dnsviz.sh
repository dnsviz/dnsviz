#!/bin/bash

source scripts/vars || exit 1

for zone in unsigned signed-nsec signed-nsec3; do
	if [ "$zone" = "unsigned" ]; then
		zone_file=$ZONE_FILE
	else
		zone_file=$ZONE_FILE.signed
	fi
	output=$ZONE_ORIGIN-$zone.json

	dnsviz probe -A -x $ZONE_ORIGIN:$ZONE_DIR/$zone/$zone_file \
		-N $ZONE_ORIGIN:$ZONE_DIR/$zone/$ZONE_FILE_DELEGATION \
		$ZONE_ORIGIN foo.$ZONE_ORIGIN foo.wildcard.$ZONE_ORIGIN > $output

	dnsviz grok -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION -l warning < $output
	dnsviz print -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION < $output
	dnsviz graph -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION -Thtml < $output > /dev/null
done
