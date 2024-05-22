#!/bin/bash

source scripts/vars || exit 1

RET=0

# options
python3 test_dnsviz_probe_options.py || RET=1
python3 test_dnsviz_graph_options.py || RET=1
python3 test_dnsviz_grok_options.py || RET=1
python3 test_dnsviz_print_options.py || RET=1

# online
python3 test_dnsviz_probe_run_online.py || RET=1

# offline
python3 test_dnsviz_probe_run_offline.py || RET=1
python3 test_dnsviz_graph_run.py || RET=1
python3 test_dnsviz_grok_run.py || RET=1
python3 test_dnsviz_print_run.py || RET=1

for zone in unsigned signed-nsec signed-nsec3; do
	if [ "$zone" = "unsigned" ]; then
		zone_file=$ZONE_FILE
	else
		zone_file=$ZONE_FILE.signed
	fi
	probe_output=`mktemp`
	grok_output=`mktemp`

	dnsviz probe -A -x $ZONE_ORIGIN:$ZONE_DIR/$zone/$zone_file \
		-N $ZONE_ORIGIN:$ZONE_DIR/$zone/$ZONE_FILE_DELEGATION \
		$ZONE_ORIGIN foo.$ZONE_ORIGIN foo.wildcard.$ZONE_ORIGIN > $probe_output || RET=1

	dnsviz grok -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION -l warning < $probe_output > $grok_output || RET=1
	dnsviz print -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION < $probe_output > /dev/null || RET=1
	dnsviz graph -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION -Thtml < $probe_output > /dev/null || RET=1

	[ -z "`cat $grok_output`" ] || RET=1

	rm $probe_output
	rm $grok_output
done

exit $RET
