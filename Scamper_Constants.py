'''
Created on Apr 4, 2018

@author: julian
'''
import radix

#**********************************************************************************************
#**************************** CONSTANTS TO READ FROM SCAMPER FILE *****************************
#********************************************************************************************** 

SCAMPER_FST_DATA_LINE = 99 

TYPE_CMD_SCAMPER         = 0
SRC_IP_ADD_SCAMPER       = 1
DST_IP_ADD_SCAMPER       = 2
LIST_ID_SCAMPER          = 3
CYCLE_ID_SCAMPER         = 4
TIMESTAMP_SCAMPER        = 5
DEST_REPLIED_SCAMPER     = 6
DEST_RTT_SCAMPER         = 7
REQUEST_TTL_SCAMPER      = 8  
REPLY_TTL_SCAMPER        = 9
HALT_REASON_SCAMPER      = 10
HALT_REASON_DATA_SCAMPER = 11
PATH_COMPLETE_SCAMPER    = 12
FST_HOP_SCAMPER          = 13

IP_FIELD  = 0
RTT_FIELD = 1

MIN_HOPS=3
  
GeneralTimestamp = 666

def Map_IP_to_AS(IP, rtree):
    
    if (IP=='130.79.208.244' or IP=='130.79.208.245' or IP=='130.79.91.253' or IP== '130.79.20.254'):
        return '2259'
    else:
        rnode=rtree.search_best(IP)                
        if (rnode==None):
            #--------------------- print('Warning: NA|%s' % IP, file=WarningLog)
            return 'NA'   
        else:
            return rnode.data["OAS"]
        

def Add_IP_and_RTT_To_DTP(IP, RTT, IPs, RTTs, Scamper_Analysis_File):        
    IPs.append(IP)
    RTTs.append(RTT)
    print (IP, file=Scamper_Analysis_File, end='\t')
    print (RTT, file=Scamper_Analysis_File, end='\n')     
    return IPs, RTTs   

def Find_Exiting_Router_For_DTP(IPs):
    ExitingIP=None
    for IP in IPs:
        if IP=="147.28.0.4" or IP=='165.254.106.17' or IP=="147.28.0.5" or IP=="147.28.0.161":
            ExitingIP=IP
            
    if ExitingIP=="147.28.0.4" or ExitingIP=='165.254.106.17':
        return "r0_Cisco"
    elif ExitingIP=="147.28.0.5" or ExitingIP=="147.28.0.161":
        return "r1_Juniper"           
    else:
        return None

        
        
        
        