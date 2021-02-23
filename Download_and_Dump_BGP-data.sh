#!/bin/bash

# usage: script.sh <year> <month> <day>

# This script takes as an input a date and downloads the BGP-data needed to make a MMing analysis.
# The RIB is dumped using bgpdump whereas the update messages are dumped using mrt2dump.py.
# The data is stored in /home/julian/git/TruePath/Scripts/Python_Scripts/RIPE_ATLAS/Belnet_RIBs_tmp
# inside a folder $YEAR/$MONTH/$DAY.

# CAUTION: Measurements are made in UTC time and dumps in CEST, so that's why we need to download
# the RIB at 0200 and the update messages of the following day.

PATH=/usr/sbin:/usr/bin:/sbin:/bin

PROBING_LOCATION=$1
DATE=$2
IFS=. read YEAR MONTH DAY <<<"${DATE}"

PATH_OF_THE_DAY=$YEAR/$MONTH/$DAY

PATH_TO_TMP_DATA=/home/julian/git/TruePath/Scripts/Python_Scripts/To_Analize_RIPE_ATLAS_probers/Peering_Project/tmp_dumps
PATH_TO_STORED_RIBS=/scratch/delfiore/Peering_Project_RIBs/$PROBING_LOCATION/$PATH_OF_THE_DAY

# ******************************************************************
# ****************** Copying RIBs of interest ***********************
# ******************************************************************

mkdir $PATH_TO_TMP_DATA
echo "Data is being moved to temporal folder..."
cp $PATH_TO_STORED_RIBS/* $PATH_TO_TMP_DATA

echo "Data is being split on a per peer basis..."
python3 Split_RIBs_per_Peer.py $PROBING_LOCATION $YEAR.$MONTH.$DAY

rm -R tmp_dumps
echo "Finished"



