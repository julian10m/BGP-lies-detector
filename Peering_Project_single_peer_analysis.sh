#!/bin/bash

# TO CHANGE. Should create backup of existing folder instead of erasing it.

function CheckIfFolder {
   FOLDER=$1
   if [ ! -d "$FOLDER" ]; then
      echo "Creating folder: $FOLDER/"
      mkdir $FOLDER
   else
      echo "Folder $FOLDER already exists!"
   fi
}

function DeleteResultFolder {
   PATH_TO_FOLDER=$1
   if [ -d $PATH_TO_FOLDER ]; then
       rm -R $PATH_TO_FOLDER
       echo "Erased Folder: $PATH_TO_FOLDER"
fi
}

PROBING_DATA=$1
DATE=$2

IFS=_ read PROBING_LOCATION PEER_ANALYZED <<<"${PROBING_DATA}"
IFS=. read YEAR MONTH DAY <<<"${DATE}"

PATH_TO_STORE_DATA=/home/julian/git/TruePath/Scripts/Python_Scripts/All_Results_Folder/$PEER_ANALYZED

SCAMPER_FILES_PATH=/home/julian/git/TruePath/Scripts/Python_Scripts/To_Analize_RIPE_ATLAS_probers/Peering_Project/Peering_Measurements
SCAMPER_FILE=ScamperOutput.$PEER_ANALYZED.$YEAR$MONTH$DAY.*

INTERMEDIATE_STORING_FOLDER=$PROBING_DATA\_$DATE
PATH_TO_INTERMEDIATE_FOLDER=/home/julian/git/TruePath/Scripts/Python_Scripts/To_Analize_RIPE_ATLAS_probers/Peering_Project/$INTERMEDIATE_STORING_FOLDER

# ******************************************************************
# ******************* Scamper Output Files *************************
# ******************************************************************

echo "Scamper Output: converting from *.warts to *.txt"

if [ ! -f $SCAMPER_FILES_PATH/$PROBING_LOCATION/$SCAMPER_FILE ]; then
    echo "Scamper file missing! (measurements not run that day?)..."
    echo "SKIPPED_DAY: $PROBING_DATA $DATE Scamper_File"
    DeleteResultFolder $PATH_TO_STORE_DATA/$YEAR/$MONTH/$DAY
    exit 1 
fi

mkdir $PATH_TO_INTERMEDIATE_FOLDER

cd $SCAMPER_FILES_PATH/$PROBING_LOCATION/
echo "Input: $SCAMPER_FILE"

/usr/local/bin/sc_analysis_dump $SCAMPER_FILE > $SCAMPER_FILE.tmp
tail -n +100 $SCAMPER_FILE.tmp > $SCAMPER_FILE.tmp2 && mv $SCAMPER_FILE.tmp2 $SCAMPER_FILE.tmp
mv $SCAMPER_FILE.tmp $PATH_TO_INTERMEDIATE_FOLDER/"Scamper_Output.$PEER_ANALYZED.$YEAR$MONTH$DAY.txt"

echo "Finished"

# ******************************************************************
# *********************** Python Script ****************************
# ******************************************************************

echo "Executing Python script"
cd ../../
python3 Peering_Demo_Julian_Approach.py $PROBING_DATA $YEAR.$MONTH.$DAY
ExitStatus=$?
echo "Finished"

if [ $ExitStatus -ne 0 ]; then
   echo "Python Script Failed!"
   rm -R $PATH_TO_INTERMEDIATE_FOLDER/	
   echo "SKIPPED_DAY: $PROBING_DATA $DATE Python_Script"
   DeleteResultFolder $PATH_TO_STORE_DATA/$YEAR/$MONTH/$DAY
   exit 1    
fi

# ******************************************************************
# ************** Creating folder to store Results ******************
# ******************************************************************

echo "Creating directories to store Results..."
echo "**************************************************"

CheckIfFolder $PATH_TO_STORE_DATA
CheckIfFolder $PATH_TO_STORE_DATA/$YEAR
CheckIfFolder $PATH_TO_STORE_DATA/$YEAR/$MONTH

if [ -d "$PATH_TO_STORE_DATA/$YEAR/$MONTH/$DAY" ]; then
	rm -R $PATH_TO_STORE_DATA/$YEAR/$MONTH/$DAY
	echo "Folder $DAY in $PATH_TO_STORE_DATA/$YEAR/$MONTH was found! It will be erased and created again. "
fi

# ******************************************************************
# *********************** Moving Files *****************************
# ******************************************************************

gzip $INTERMEDIATE_STORING_FOLDER/AllResults.bin $INTERMEDIATE_STORING_FOLDER/DetailedAnalysisTvsBGPPaths.txt $INTERMEDIATE_STORING_FOLDER/Traceroutes_$PEER_ANALYZED\_$YEAR$MONTH$DAY.txt
rm $INTERMEDIATE_STORING_FOLDER/Scamper_Output.$PEER_ANALYZED.$YEAR$MONTH$DAY.txt
mv $INTERMEDIATE_STORING_FOLDER/ $PATH_TO_STORE_DATA/$YEAR/$MONTH/$DAY

echo "Finished script"


