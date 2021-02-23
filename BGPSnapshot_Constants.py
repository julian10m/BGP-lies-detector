'''
Created on Apr 4, 2018

@author: julian
'''

#**********************************************************************************************
#********************* CONSTANTS TO READ BGPSNAPSHOT: USED IN RADIX TREE  *********************
#**********************************************************************************************

N_FIELDS_BGP_ENTRY  = 15    # Number of fields in BGP Snapshot Entry

TIMESTAMP_FIELD     = 1     # TimeStamp
TYPE_MESSAGE_FIELD  = 2     # Type of Message 
NEXT_HOP_FIELD      = 3     # Next Hop
PROBING_AS_FIELD    = 4     # AS that provides RIB
PREFIX_FIELD        = 5     # Prefix 
AS_PATH_FIELD       = 6     # ASPath 