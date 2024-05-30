#!/bin/bash

source scripts/vars || exit 1

[ -d $KEY_DIR ] || mkdir $KEY_DIR
KSK_RSASHA1=`dnssec-keygen -q -K $KEY_DIR -f KSK -b 2048 -a RSASHA1 $ZONE_ORIGIN`
ZSK_RSASHA1=`dnssec-keygen -q -K $KEY_DIR -b 1024 -a RSASHA1 $ZONE_ORIGIN`
KSK_ECDSA=`dnssec-keygen -q -K $KEY_DIR -f KSK -a ECDSAP256SHA256 $ZONE_ORIGIN`
ZSK_ECDSA=`dnssec-keygen -q -K $KEY_DIR -a ECDSAP256SHA256 $ZONE_ORIGIN`
KSK_RSASHA256=`dnssec-keygen -q -K $KEY_DIR -f KSK -b 2048 -a RSASHA256 $ZONE_ORIGIN`
ZSK_RSASHA256=`dnssec-keygen -q -K $KEY_DIR -b 1024 -a RSASHA256 $ZONE_ORIGIN`

[ -d $ZONE_DIR/signed-nsec ] || mkdir $ZONE_DIR/signed-nsec
cat $ZONE_DIR/unsigned/$ZONE_FILE $KEY_DIR/$KSK_RSASHA256.key $KEY_DIR/$ZSK_RSASHA256.key > $ZONE_DIR/signed-nsec/$ZONE_FILE
dnssec-signzone -K $KEY_DIR -x -k $KSK_RSASHA256 -o $ZONE_ORIGIN $ZONE_DIR/signed-nsec/$ZONE_FILE $ZSK_RSASHA256
cat $ZONE_DIR/unsigned/$ZONE_FILE_DELEGATION dsset-$ZONE_ORIGIN. > $ZONE_DIR/signed-nsec/$ZONE_FILE_DELEGATION
rm dsset-$ZONE_ORIGIN.

[ -d $ZONE_DIR/signed-nsec3 ] || mkdir $ZONE_DIR/signed-nsec3
cat $ZONE_DIR/unsigned/$ZONE_FILE $KEY_DIR/$KSK_RSASHA256.key $KEY_DIR/$ZSK_RSASHA256.key > $ZONE_DIR/signed-nsec3/$ZONE_FILE
dnssec-signzone -K $KEY_DIR -x -k $KSK_RSASHA256 -o $ZONE_ORIGIN -3 - -H 0 $ZONE_DIR/signed-nsec3/$ZONE_FILE $ZSK_RSASHA256
cat $ZONE_DIR/unsigned/$ZONE_FILE_DELEGATION dsset-$ZONE_ORIGIN. > $ZONE_DIR/signed-nsec3/$ZONE_FILE_DELEGATION
rm dsset-$ZONE_ORIGIN.
