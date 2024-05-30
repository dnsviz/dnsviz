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

	if ! dnsviz probe -A -x $ZONE_ORIGIN:$ZONE_DIR/$zone/$zone_file \
		-N $ZONE_ORIGIN:$ZONE_DIR/$zone/$ZONE_FILE_DELEGATION \
		$ZONE_ORIGIN foo.$ZONE_ORIGIN foo.wildcard.$ZONE_ORIGIN > $probe_output ; then
		echo 'dnsviz probe failed' 1>&2
		RET=1
		continue
	fi

	if ! dnsviz grok -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION -l warning < $probe_output > $grok_output ; then
		echo 'dnsviz print failed' 1>&2
		RET=1
	fi
	if ! dnsviz print -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION < $probe_output > /dev/null ; then
		echo 'dnsviz grok failed' 1>&2
		RET=1
	fi
	if ! dnsviz graph -t $ZONE_DIR/$zone/$ZONE_FILE_DELEGATION -Thtml < $probe_output > /dev/null ; then
		echo 'dnsviz graph failed' 1>&2
		RET=1
	fi

	if ! [ -z "`cat $grok_output`" ] ; then
		echo 'dnsviz grok output not empty:  ' 1>&2
		cat $grok_output 1>&2
		RET=1
	fi

	rm $probe_output
	rm $grok_output
done

exit $RET
