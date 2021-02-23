'''
Created on Jan 17, 2018

@author: julian
'''
import sys
from BGPSnapshot_Constants import *
from Scamper_Constants import *
from Pre_Processing import *
from Heuristics import *
import Functions
from pprint import pprint
import json
import csv
import os.path
import pickle
import radix
from collections import Counter
import gzip
from datetime import datetime

#**********************************************************************************************
#***************************** DEFINING INFORMATION TO BE ANALIZED ****************************
#********************************************************************************************** 

usage = "usage: %s <VPx_peer> <2018.month.day> <UpperBound/XorBound/LowerBound> ..." % sys.argv[0]
if len(sys.argv)!=3:
    print("ERROR: Missing Arguments")
    print(usage)
    sys.exit(1)
else:
    PROBING_LOCATION    = sys.argv[1].split("_")[0]
    PEER_ANALYZED       = sys.argv[1].split("_")[1]
    DATE                = sys.argv[2].split(".")

if PROBING_LOCATION!="VP1" and PROBING_LOCATION!="VP2":
    print("ERROR: Unknown VP")
    print(usage)
    sys.exit(1)
    
if PROBING_LOCATION=="VP1":
    if PEER_ANALYZED!="uw01" and PEER_ANALYZED!="isi01" and PEER_ANALYZED!="grnet01":
        print("ERROR: Wrong Peer")
        print(usage)
        sys.exit(1)
    FIRST_AS = {"uw01": "101", "isi01": "226", "grnet01": "5408"}
    AS_LOCATION_VM = "2259"
else:
    if PEER_ANALYZED!="neu01" and PEER_ANALYZED!="clemson01" and PEER_ANALYZED!="utah01":
        print("ERROR: Wrong Peer")
        print(usage)
        sys.exit(1) 
    FIRST_AS = {"neu01": "156", "clemson01": "12148", "utah01": "210"}
    AS_LOCATION_VM = "3130"
    
APPROACHES_OF_ANALYSIS = ["LowerBound",
                          "LowerBoundWI",
                          "LowerBoundWIWI",
                          "OnlyTPA",
                          "OnlySiblings",
                          "XorBound",
                          "XorBoundWI",
                          "UpperBound",
                          "Raw"]

YEAR  = DATE[0]
MONTH = DATE[1]
DAY   = DATE[2]
DATE_PATH = "%s/%s/%s" % (YEAR, MONTH, DAY)

BGP_DATA_PATH_BASE = "/home/julian/git/TruePath/Scripts/Python_Scripts/To_Analize_RIPE_ATLAS_probers/Peering_Project/bgp-data"
CURRENT_BGP_DATA_PATH = os.path.join(BGP_DATA_PATH_BASE, DATE_PATH, PROBING_LOCATION, PEER_ANALYZED) 

if not os.path.isdir(CURRENT_BGP_DATA_PATH):
    print("ERROR: BGP-data not available! in %s" % CURRENT_BGP_DATA_PATH)
    sys.exit(1)
elif len(os.listdir(CURRENT_BGP_DATA_PATH))!=12:
    print("ERROR: some RIB is missing! in %s" % CURRENT_BGP_DATA_PATH)
    sys.exit(1)    

OUTPUT_FOLDER = sys.argv[1] + "_" + sys.argv[2]

if not os.path.isdir(OUTPUT_FOLDER):
    print("ERROR: Folder for results missing! %s" % OUTPUT_FOLDER)
    sys.exit(1)    
    
#----------- RESULTS_FILE = "./Peering_Results/%s/%s%s%s.*" % (YEAR, MONTH, DAY)

#**********************************************************************************************
#************************* VARIABLES USED TO STORE USEFULL DATA *******************************
#********************************************************************************************** 

FinalResults=[]
qTupplesAnalyzed = 0
MMPs = dict.fromkeys(APPROACHES_OF_ANALYSIS, 0)

qNCPforIP = 0
qMPforIP = 0
qPwithASSets = 0
qPASNUnsolved = 0
qIPinASorWrongPeer = 0

#**********************************************************************************************
#************************ Creating All the Needed Mapping Data ******* ************************
#**********************************************************************************************

# Here I create the data that links ASes to Organization's CH. ASes under the same
# ownership share the same CH.
AS2CH = Functions.CreateAS2CHMapping()

print("****************************************************************")
print("Creating Radix Tree for IP-to-AS mapping")

nNewPrefix=0
nRepeatedEntry=0
nDifferentOAS=0

rtree = radix.Radix()
CURRENT_RIB_FILE = os.path.join(CURRENT_BGP_DATA_PATH, PEER_ANALYZED + ".0000.gz")

with gzip.open(CURRENT_RIB_FILE, 'rb') as RIB_File:
    print("RIB is read from: %s" % CURRENT_RIB_FILE)
    
    for line in RIB_File:
        Entry = line.decode()
        [Prefix, ASPath, DontCare] = Entry.split("|")
       
        if Prefix=="0.0.0.0/0" or "bird" in Prefix:
            print("Entry: %s skipped" % Prefix)
            continue
                
        OAS = ASPath.strip().split(" ")[-1]        
        rnode = rtree.search_exact(Prefix)
        if not rnode:
            nNewPrefix+=1                  
            rnode = rtree.add(Prefix)
            if "}" in OAS or Functions.Is_Prohibited_ASn(OAS)[0]:
                rnode.data["OAS"]='NA'   
            else:
                rnode.data["OAS"]= OAS                
        else:
            nRepeatedEntry+=1
            if OAS != rnode.data["OAS"]:
                nDifferentOAS+=1
                rnode.data["OAS"]='NA'

print("nNewPrefix=%s" % nNewPrefix)
print("nRepeatedEntry=%s" % nRepeatedEntry)
print("nDifferentOAS=%s" % nDifferentOAS)

print("Radix Tree for IP-to-AS mapping was created")

#**********************************************************************************************
#******************** Reading the Output of Scamper to Variables ******************************
#********************************************************************************************** 

DstIP_RawDP_Tmstp=[]
qFailedTraceroutes = 0
qFailedIPRule = 0       
 
print("****************************************************************")
print("Reading results from Scamper and mapping from IP-to-AS")
DumpedScamperFile = "Scamper_Output." + PEER_ANALYZED + ".%s%s%s" % (YEAR, MONTH, DAY) + ".txt"
DumpedScamperFile = os.path.join(OUTPUT_FOLDER, DumpedScamperFile)
print("Results read from: %s" % DumpedScamperFile)

with open(OUTPUT_FOLDER + "/Traceroutes_%s_%s%s%s.txt" % (PEER_ANALYZED, YEAR, MONTH, DAY),'w', encoding="utf-8") as Scamper_Analysis_File:
    with open(DumpedScamperFile, "rt", encoding="utf-8") as scamper_file:
        ScamperLineField = list(csv.reader(scamper_file, delimiter='\t'))
    
        Q_TRACEROUTES = len(ScamperLineField)
        for i in range (0,Q_TRACEROUTES):
    
            CurrentTracerouteASPath=[]
            CurrentTracerouteInfo = ScamperLineField[i]
    
            SrcIpAdd        = CurrentTracerouteInfo[SRC_IP_ADD_SCAMPER]
            DstIpAdd        = CurrentTracerouteInfo[DST_IP_ADD_SCAMPER]
            ListId          = CurrentTracerouteInfo[LIST_ID_SCAMPER]
            CycleId         = CurrentTracerouteInfo[CYCLE_ID_SCAMPER]
            Timestamp       = CurrentTracerouteInfo[TIMESTAMP_SCAMPER]
            DestReplied     = CurrentTracerouteInfo[DEST_REPLIED_SCAMPER]
            DestRTT         = CurrentTracerouteInfo[DEST_RTT_SCAMPER]
            RequestTTL      = CurrentTracerouteInfo[REQUEST_TTL_SCAMPER]
            ReplyTTL        = CurrentTracerouteInfo[REPLY_TTL_SCAMPER]
            HaltReason      = CurrentTracerouteInfo[HALT_REASON_SCAMPER]
            HaltReasonData  = CurrentTracerouteInfo[HALT_REASON_DATA_SCAMPER]
            PathComplete    = CurrentTracerouteInfo[PATH_COMPLETE_SCAMPER]
    
            #===========================================================================
            # The first line of the file to record is:
            #        GeneralTimestamp\tTimestamp\tSrcIpAdd\tDstIpAdd\n
            #===========================================================================
    
            print (GeneralTimestamp, file=Scamper_Analysis_File, end='\t')
            print (Timestamp, file=Scamper_Analysis_File, end='\t')
            print (SrcIpAdd, file=Scamper_Analysis_File, end='\t')
            print (DstIpAdd, file=Scamper_Analysis_File, end='\n')
    
            #===========================================================================
            # Then follows a line per hop in the recorded path. There are 2 cases:
            #    1) Actual hop = 'q': All probes weren't answered => Only an "*" is printed to the file
            #    2) One probe was ansered => Only it's IP and RTT are recorded
            #
            # To make the mapping, we rely on the the Radix Tree and check which is the
            # originating AS for each prefix. Like this, we can map every IP seen in a
            # traceroute to an ASN.
            #===========================================================================
    
            LAST_HOP_SCAMPER = len(CurrentTracerouteInfo)
    
            nHops= LAST_HOP_SCAMPER - FST_HOP_SCAMPER
            if nHops==0:
                qFailedTraceroutes +=1
                FinalResults.append([DstIpAdd, "NullTraceroute", Timestamp, None, None, None, None, None, None])
                print ("ERROR: len(Trace)=NULL", file=Scamper_Analysis_File)
                print ("\n***********\n", file=Scamper_Analysis_File)
                continue
    
            IPs=[]
            for j in range (FST_HOP_SCAMPER, LAST_HOP_SCAMPER):
                ActualHop = CurrentTracerouteInfo[j]
    
                if ActualHop == 'q':
                    IPs.append('*')
                    CurrentTracerouteASPath.append('*')
                    print ("*\t*\t*", file=Scamper_Analysis_File, end='\n')
                    continue
    
                else:
                    IP  = ActualHop.split(",")[IP_FIELD]
                    IPs.append(IP)
                    
                    AS = Map_IP_to_AS(IP, rtree)
                    CurrentTracerouteASPath.append(AS)
                    
                    RTT = ActualHop.split(",")[RTT_FIELD]
                    print ("%s\t%s\t%s" % (IP, AS, RTT), file=Scamper_Analysis_File, end='\n')    
    
            if DestReplied=="R":
                IP=DstIpAdd
                IPs.append(IP)
                
                AS = Map_IP_to_AS(IP, rtree)
                CurrentTracerouteASPath.append(AS)
                
                RTT=DestRTT
                print ("%s\t%s\t%s" % (IP, AS, RTT), file=Scamper_Analysis_File, end='\n')
            
            IPRuleFailed = False 
            for Ind in range(0,3):
                if Ind >= len(IPs):
                    break
                elif CurrentTracerouteASPath[Ind] == AS_LOCATION_VM:
                    IPRuleFailed = True
                    break
            if IPRuleFailed:
                qFailedIPRule +=1
                FinalResults.append([DstIpAdd, "FailedIPRule", Timestamp, None, None, None, None, IPs, CurrentTracerouteASPath])
                print ("ERROR: IPRuleFailed", file=Scamper_Analysis_File)
                print ("\n***********\n", file=Scamper_Analysis_File)
                continue
            
            DstIP_RawDP_Tmstp.append([DstIpAdd, CurrentTracerouteASPath, Timestamp, IPs])
            print ("\n***********\n", file=Scamper_Analysis_File)
qSuccessfulTraceroutes = len(DstIP_RawDP_Tmstp)

print("Finished reading results from Scamper and mapping from IP-to-AS")
print("Traceroutes Launched: %s" % Q_TRACEROUTES)
print("Failed Traceroutes: %s" % qFailedTraceroutes)
print("Failed IPRulesDR: %s" % qFailedIPRule)
print("Considered Traceroutes: %s==%s" % (Q_TRACEROUTES - qFailedTraceroutes - qFailedIPRule, qSuccessfulTraceroutes))

if len(DstIP_RawDP_Tmstp) == 0 or qFailedIPRule:
    print("ERROR: Measurements failed (check IP Rules?)")
    sys.exit(1)     

#**********************************************************************************************
#**************** Creating and Loading Updates to Radix Tree **********************************
#**********************************************************************************************  

print("****************************************************************")
print("Creating Radix Tree for Comparisons")

rtree = Functions.Create_Radix_Tree_From_RIBs(CURRENT_BGP_DATA_PATH, DATE)

#**********************************************************************************************
#******************** Comparison of Results ******************************
#********************************************************************************************** 

print("****************************************************************")
print("Comparisons are being held")

ResultsFile = open(OUTPUT_FOLDER + "/DetailedAnalysisTvsBGPPaths.txt",'w', encoding="utf-8") 

for nTupple,DstIPAdd_TracerouteASPath_Timestamp in enumerate(DstIP_RawDP_Tmstp):
    
    DstIP                   = DstIPAdd_TracerouteASPath_Timestamp[0]
    RawTracerouteASPath     = DstIPAdd_TracerouteASPath_Timestamp[1]
    TracerouteTimestamp     = datetime.utcfromtimestamp(int(DstIPAdd_TracerouteASPath_Timestamp[2]))
    RawTraceroute           = DstIPAdd_TracerouteASPath_Timestamp[3]

    rnode, ControlPath= Functions.Peering_Project_DstPrefix_BGPASPath_to_Compare(rtree, DstIP, TracerouteTimestamp)
        
    if(rnode=="qNCPforIP"):
        qNCPforIP+=1
        FinalResults.append([DstIP, "qNCPforIP", TracerouteTimestamp, ControlPath, RawTracerouteASPath, None, None, RawTraceroute, RawTracerouteASPath])
        continue
    elif(rnode=="qMPforIP"):
        qMPforIP+=1
        FinalResults.append([DstIP, "qMPforIP", TracerouteTimestamp, ControlPath, RawTracerouteASPath, None, None, RawTraceroute, RawTracerouteASPath])
        continue

    rnode= rtree.search_exact(rnode.prefix)
    
    if "}" in ControlPath:
        qPwithASSets+=1
        FinalResults.append([DstIP, "ASSet", TracerouteTimestamp, ControlPath, RawTracerouteASPath, None, None, RawTraceroute, RawTracerouteASPath])
        continue
    
    ControlPath = ControlPath.strip().split(' ')
    
    if len(ControlPath)==1 or ControlPath[0]!=FIRST_AS[PEER_ANALYZED]:
        qIPinASorWrongPeer+=1
        FinalResults.append([DstIP, "BadExitOrIPinAS", TracerouteTimestamp, ControlPath, RawTracerouteASPath, None, None, RawTraceroute, RawTracerouteASPath])
        continue
    
    ControlPath, HaspASN = CheckingForpASNsInControlPath(ControlPath)

    if HaspASN:
        qPASNUnsolved+=1
        print("Control Path Includes a pASN! qPASNUnsolved=%s" % str(qPASNUnsolved), file=ResultsFile)
        print("*****************************************************", file=ResultsFile)
        FinalResults.append([DstIP, "pASN", TracerouteTimestamp, ControlPath, RawTracerouteASPath, None, None, RawTraceroute, RawTracerouteASPath])
        continue
    
    qTupplesAnalyzed +=1
    DstPrefix = rnode.prefix    
    print(DstIP, DstPrefix, file=ResultsFile)

    ControlPathBackup = ControlPath[:]
    
    DataPathBackup = RawTracerouteASPath[:]    
    DataPathBackup = RemovingPostOASPath(DataPathBackup, ControlPath, ResultsFile)
    DataPathBackup.insert(0, FIRST_AS[PEER_ANALYZED])
    DataPathBackup.insert(0, FIRST_AS[PEER_ANALYZED])
    
    IsTuppleMMperApproach = {} 
    IsWeirdMMperApproach = {} 
    FinalCPs = {}
    FinalDPs = {}
    for qAA, analysis_approach in enumerate(APPROACHES_OF_ANALYSIS):
        
        ControlPath = ControlPathBackup[:]
        DataPath = DataPathBackup[:]
        
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$", file=ResultsFile)
        print("Analysis Approach: %s" % analysis_approach, file=ResultsFile)
        print("'Starting Point'", file=ResultsFile)
        print("CP = %s" % ControlPath, file=ResultsFile)
        print("DP = %s" % DataPath, file=ResultsFile)     
        print("*****************************************************", file=ResultsFile)    

        #############################################################################
        # Data Preparation: modifications to the IP-to-AS mapping
        #    - LowerBound: Input ---> WeakMappingFull --> CHs(Siblings) ---> Output
        #    - OnlyTPA:    Input -----------> WeakMappingFull -------------> Output
        #    - OnlySiblin: Input ------------> CHs(Siblings) --------------> Output
        #    - XorBund:    Input ---> CHs(Siblings) --> WeakMappingRest ---> Output
        #    - UpperBound: Input ------------------------------------------> Output
        #    - Raw:        Input ------------------------------------------> Output
        #############################################################################         
        print("Data Preparation: Mapping updates on Data Path", file=ResultsFile)  
        
        if analysis_approach in ["LowerBound", "LowerBoundWI", "LowerBoundWIWI"]:
            DataPath = ReplaceWeakMapping(analysis_approach, DataPath, ResultsFile)
            DataPath = Functions.ReplaceASesbyCHs(DataPath, AS2CH, ResultsFile)
        elif analysis_approach == "OnlyTPA":
            DataPath = ReplaceWeakMapping(analysis_approach, DataPath, ResultsFile)
        elif analysis_approach == "OnlySiblings":
            DataPath = Functions.ReplaceASesbyCHs(DataPath, AS2CH, ResultsFile)
        elif analysis_approach == "XorBound" or analysis_approach == "XorBoundWI":
            DataPath = Functions.ReplaceASesbyCHs(DataPath, AS2CH, ResultsFile)
            DataPath = ReplaceWeakMapping(analysis_approach, DataPath, ResultsFile)
        elif analysis_approach == "UpperBound" or analysis_approach == "Raw":
            pass
        else:
            print("ERROR: Unknown Analysis approach: %s" % analysis_approach)
        
        print("*****************************************************", file=ResultsFile)
        #############################################################################   
        # This is included in Data Preparation, but is common to all cases
        #    - Control Path:
        #       1) Apply CHs(Siblings), but ONLY for the analysis_approach that it makes sense
        #       2) Eliminate Prepending
        #    - Data Path:
        #       1) Reduce Path to minimum set (without modifying *s nor NAs)
        #       2) Remove Trailing Wildcards
        #############################################################################
        print("Last Pre-proccesing before comparing paths", file=ResultsFile)    
        
        if analysis_approach in ["LowerBound", "LowerBoundWI", "LowerBoundWIWI", "OnlySiblings", "XorBound", "XorBoundWI"]:
            ControlPath = Functions.ReplaceASesbyCHs(ControlPath, AS2CH, ResultsFile)
        ControlPath = EliminatingPrependingControlPath(ControlPath, ResultsFile)
    
        DataPath = ReduceDataPath(DataPath, ResultsFile)
        DataPath = RemovingTrailingWildcards(DataPath, ResultsFile)
        
        print("*****************************************************", file=ResultsFile)
        ##############################################################################                                                                                              
        # Conservative Transformations: how we solve indeterminations
        #    - LowerBound: Input ---> Missing Hops + Insertion ---> Output
        #    - OnlyTPA:    Input ---> Missing Hops + Insertion ---> Output
        #    - OnlySiblin: Input ---------> Missing Hops ---------> Output
        #    - XorBund:    Input ---------> Missing Hops ---------> Output
        #    - UpperBound: Input ---------> Missing Hops ---------> Output
        #    - Raw:        Input ---------------------------------> Output
        #############################################################################  
        print("Conservative Transformations will be applied!", file=ResultsFile)      

        print("CP = %s" % ControlPath, file=ResultsFile)
        print("DP = %s" % DataPath, file=ResultsFile)    
       
        if analysis_approach == "Raw":
            print("In the Raw case we just eliminate wildcards and shrink the path!", file=ResultsFile)
            DataPath = Functions.EliminateAll_NA_or_Asterisk_TASPath(DataPath)
            DataPath = ReduceDataPath(DataPath, ResultsFile)
  
        Tag = 0
        for AS in DataPath:
            if AS != "*" and AS != "NA" and (AS not in ControlPath):
                Tag = 1
                break
            
        DataPath, ControlPath, ArePathsMismatching, IsWeirdCase = ApplyMissingHopHeuristics(analysis_approach, DataPath, ControlPath, ResultsFile)   
        if ArePathsMismatching:
            if Tag:
                IsWeirdCase = False
                               
        print("######################", file=ResultsFile)
        print("'Result'", file=ResultsFile) 
        print("CP = %s" % ControlPath, file=ResultsFile)
        print("DP = %s" % DataPath, file=ResultsFile) 
        
        if ArePathsMismatching:
            MMPs[analysis_approach]+=1   
            print("Paths disagree: qMMPs[%s]=%s, IsWeirdCase=%s" % (analysis_approach, MMPs[analysis_approach], IsWeirdCase), file=ResultsFile)
        else:
            print("Paths OK", file=ResultsFile)
        print("****************************************", file=ResultsFile)            

        IsTuppleMMperApproach[analysis_approach] = ArePathsMismatching 
        IsWeirdMMperApproach[analysis_approach]  = IsWeirdCase
        FinalCPs[analysis_approach] = ControlPath
        FinalDPs[analysis_approach] = DataPath
    
    FinalResults.append([DstIP,
                         DstPrefix,
                         TracerouteTimestamp,
                         FinalCPs,
                         FinalDPs,
                         IsTuppleMMperApproach,
                         IsWeirdMMperApproach,
                         RawTraceroute,
                         RawTracerouteASPath])

ResultsFile.close()

if not qTupplesAnalyzed:
    print("ERROR: Zero_Analyzed! not because IPRules...")
    sys.exit(1)  

with open(OUTPUT_FOLDER + "/ResultsTraceroutesSummary.txt",'w', encoding="utf-8") as ResultsFile:     
    print("Result Summary", file=ResultsFile)
    
    print("qTraceroutes=%s\n" % Q_TRACEROUTES,
          "qTracesFail=%s\n" % qFailedTraceroutes,
          "qIPRulesFailed=%s\n" % qFailedIPRule,          
          "qSuccessful=%s\n" % qSuccessfulTraceroutes,
          file= ResultsFile)
    
    print("\nDetail Not Considered Cases\n",
          "Unannounced Address Space=%s\n" % qNCPforIP,
          "No prefix present for IP=%s\n" % qMPforIP,
          "Control Path with AS Set=%s\n" % qPwithASSets,
          "Control Path with pASNs=%s\n" % qPASNUnsolved,
          "IP in AS or wrong peer=%s\n" % qIPinASorWrongPeer,
          file=ResultsFile)
    
    print("qTupplesAnalyzed=%s\n" % qTupplesAnalyzed, file=ResultsFile)
    for analysis_approach in APPROACHES_OF_ANALYSIS:
        print("Approach=%s" % analysis_approach,
              "|qMMs=%s" % MMPs[analysis_approach],
              "|MMRatio=%.6f|" % (float(MMPs[analysis_approach])/float(qTupplesAnalyzed)),
              file=ResultsFile)
   
with open(OUTPUT_FOLDER + '/AllResults.bin', 'wb') as f:
    pickle.dump(FinalResults, f)     
    
