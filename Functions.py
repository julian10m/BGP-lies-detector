'''
Created on Jan 17, 2018

@author: julian
'''

from BGPSnapshot_Constants import *
from Scamper_Constants import *

import gzip
import csv
import os.path
import pickle
import radix
from collections import Counter
from datetime import datetime, timedelta

def IsMatching(DataPath, ControlPath):
    if DataPath==ControlPath or Is_PEP(DataPath, ControlPath):
        return True
    else:
        return False

def Is_CEP_or_PEP(DataPath, ControlPath, CEPs, PEPs, ResultsFile, AfterHeuristics):
    ResultToAppend = None
    
    if DataPath==ControlPath:
        CEPs+=1
        if not AfterHeuristics:
            ResultToAppend = "CEP|" 
            print("Complete Match: CEP=%s" % CEPs, file=ResultsFile)
        else:
            ResultToAppend = "CEPH|" 
            print("Complete Match With Heuristics: CEPH=%s" % CEPs, file=ResultsFile)
            
    elif Is_PEP(DataPath, ControlPath):
        PEPs+=1 
        if not AfterHeuristics:
            ResultToAppend = "PEP|"               
            print("Partial Match With Heuristics: PEP=%s" % PEPs, file=ResultsFile)
        else:
            ResultToAppend = "PEPH|"               
            print("Partial Match With Heuristics: PEPH=%s" % PEPs, file=ResultsFile)            
            
    return CEPs, PEPs, ResultToAppend
        

def Is_PEP(DataPath, ControlPath):
    if len(DataPath)<len(ControlPath):
        if DataPath==ControlPath[:len(DataPath)]:
            return True
        else:
            return False
    else:
        return False

#------------------------------------------------------------------------------ 
#------------------------- Checking for Prohibited ASN ------------------------
#------------------------------------------------------------------------------ 
                         
def Is_Prohibited_ASn(ASn):
    ASn_int = int(ASn)
    if Is_Private_ASN(ASn_int):
        return True,'Warning: Private_ASN'
    elif Is_Reserved_ASN(ASn_int):
        return True,'Warning: Reserved_ASN'
    elif Is_Documentation_ASN(ASn_int):
        return True,'Warning: Documentation_ASN'    
    elif Is_Unallocated_ASN(ASn_int):
        return True, 'Warning: Unallocated_ASN'
    else:
        return False, None      
    
def Is_Documentation_ASN(ASn_int):
    if(ASn_int>=64496 and ASn_int<=64511) or (ASn_int>=65536 and ASn_int<=65551):
        return True
    return False

def Is_Reserved_ASN(ASn_int):                        
    if((ASn_int>=65552 and ASn_int<=131071) or ASn_int==0 or ASn_int==65535 or ASn_int==4294967295): 
        return True
    return False
                           
def Is_Private_ASN(ASn_int):             
    if(ASn_int>=64512 and ASn_int<=65534) or (ASn_int>=4200000000 and ASn_int<=4294967294):
        return True
    return False

def Is_Unallocated_ASN(ASn_int):                 
    if(ASn_int>=139578 and ASn_int<=196607) or (ASn_int>=207260 and ASn_int<=262143) or \
      (ASn_int>=268701 and ASn_int<=327679) or (ASn_int>=328704 and ASn_int<=393215) or \
      (ASn_int>=397213 and ASn_int<=4199999999):
        return True
    return False   
 
#------------------------------------------------------------------------------ 
#------------------------- Reducing Path ------------------------
#------------------------------------------------------------------------------ 

def Reduce_ASPath(ASPath):                             
    j=0
    while(j<len(ASPath)-1):
        ActualASN = ASPath[j]
        while (ASPath[j+1]==ActualASN):
                ASPath.pop(j+1)
                if (j==len(ASPath)-1):
                    break
        j+=1
            
    return ASPath

def EliminateAll_NA_or_Asterisk_TASPath(TASPath):                             
    j=0
    while(j<len(TASPath)):
        ActualASN = TASPath[j]
        if ActualASN=='*' or ActualASN=='NA':
            TASPath.pop(j)
            j-=1
        j+=1
    
    return TASPath

#------------------------------------------------------------------------------ 
#-------------------- Checking if Reached Originating ASN ---------------------
#------------------------------------------------------------------------------ 

def Reached_OASN(TracerouteASPath, BGPASPath):
    for ASn in TracerouteASPath:
        if ASn==BGPASPath[-1]:
            IndexOrigin = TracerouteASPath.index(ASn)
            return True, IndexOrigin
    return False, None

#------------------------------------------------------------------------------ 
#-------------------- Checking if There Loops Post-OASN -----------------------
#------------------------------------------------------------------------------ 

def Checking_Loops_Post_OASN(TracerouteASPath, IndexOrigin):
    OASN=TracerouteASPath[IndexOrigin]
    for j in range(IndexOrigin+1, len(TracerouteASPath)):
        ASn=TracerouteASPath[j]
        if(ASn!=OASN and ASn!='*' and ASn!='NA'):
            TracerouteASPath=TracerouteASPath[:IndexOrigin+1]
            return True, TracerouteASPath
    return False, TracerouteASPath


#------------------------------------------------------------------------------ 
#-------------------- Checking if There Are Loops -----------------------
#------------------------------------------------------------------------------ 

def Is_There_Loop(TracerouteASPath, IndexASn):
    ASn=TracerouteASPath[IndexASn]
    for IndexCompASn in range(IndexASn+1,len(TracerouteASPath)):
        CompASn = TracerouteASPath[IndexCompASn]
        if ASn==CompASn:
            for IntermIndex in range(IndexASn+1,IndexCompASn):
                IntermediateASn= TracerouteASPath[IntermIndex]
                if IntermediateASn!='*' and IntermediateASn!='NA':
                    return True, IndexCompASn
            IndexASn=IndexCompASn
    return False, None
                
#------------------------------------------------------------------------------ 
#-------------------- Checking if for AS_SETs -----------------------
#------------------------------------------------------------------------------ 

def Checking_for_AS_sets(ASPath):
    ASSets=[]
    for Index,ASn in enumerate(ASPath):
        if ('{' in ASn) and ('}' in ASn):
            ASSets.append(Index)
    if not ASSets:
        return None
    else:
        return ASSets
    
def Solving_BGPASSet(PreviousASN, ASn, TracerouteASPath):
    ASBlock=ASn.split('{')[1].split('}')[0]             
    ASSet=ASBlock.split(',')
    for ASnInSet in ASSet:
        if(ASnInSet in TracerouteASPath):
            return ASnInSet, 'ASnInSet'
    if (PreviousASN in TracerouteASPath):
        return PreviousASN, 'PreviousASN'
    else:
        return None, 'No Matching'

#**********************************************************************************************
#********************************* Loading Updates to Radix Tree ******************************
#**********************************************************************************************

def Creating_Radix_Tree(CURRENT_RIB_FILE):
    
    rtree = radix.Radix()
    
    with open(CURRENT_RIB_FILE, 'r') as RIB_File:
        for Entry in RIB_File:
            SplittedEntry = Entry.split('|')
            
            if (len(SplittedEntry)!=N_FIELDS_BGP_ENTRY):
                continue

            Prefix = SplittedEntry[PREFIX_FIELD]
            ASPath=SplittedEntry[AS_PATH_FIELD]
            Timestamp=int(SplittedEntry[TIMESTAMP_FIELD])

            rnode = rtree.add(Prefix)
            rnode.data["ASPath"]=[]
            rnode.data["ASPath"].append([ASPath,Timestamp]) 

    return rtree    

#**********************************************************************************************
#********************************* Loading Updates to Radix Tree ******************************
#**********************************************************************************************

def Creating_Radix_Tree_Belnet(rtree, RadixTreeFolderPath):
    qBadEntries=0
        
    with open(RadixTreeFolderPath, 'r') as RIB_File:
        for Entry in RIB_File:
            SplittedEntry = Entry.split('|')
            if (len(SplittedEntry)!=N_FIELDS_BGP_ENTRY):
                qBadEntries+=1
                continue
            
            if SplittedEntry[NEXT_HOP_FIELD]!="193.191.3.85":
                continue
            
            Prefix = SplittedEntry[PREFIX_FIELD]
            ASPath=SplittedEntry[AS_PATH_FIELD]
            Timestamp=int(SplittedEntry[TIMESTAMP_FIELD])

            if Prefix=="0.0.0.0/0":
                continue
            
            rnode = rtree.add(Prefix)
            rnode.data["Results"] = []
            rnode.data["TPaths"] = []     
            rnode.data["ASPath"]=[]
            rnode.data["ASPath"].append([ASPath,Timestamp]) 
            rnode.data["BGPASPath"]=[]
            
    print("\tqBadEntries=%s" % qBadEntries)
    return rtree   

#**********************************************************************************************
#********************************* Loading Updates to Radix Tree ******************************
#**********************************************************************************************

def Loading_Update_Messages_to_Radix_Tree_Belnet(rtree, UpdateMessagesFolderPath):    
    Timestamps=[]
    Timestamps_No_Duplicates=[]
    nDuplicates=0
    nWithdrawlsError=0
    nWithdrawlsOk=0
    nWithdrawlsDuplicated=0
    nNewPrefix=0
    nBackToLife=0    
    
    for data_file in sorted(os.listdir(UpdateMessagesFolderPath)):
        if os.path.isdir(UpdateMessagesFolderPath + "/" + data_file):
            continue
        
        if data_file.split('.')[0]!='updates':
            continue        
    
        with open(UpdateMessagesFolderPath + '/' + data_file, 'r') as Update_File:
            for Entry in Update_File:
                SplittedEntry = Entry.split('|')
                
                if SplittedEntry[NEXT_HOP_FIELD]!="193.191.3.85":
                    continue
                
                Timestamp=int(SplittedEntry[TIMESTAMP_FIELD])
                Timestamps.append(Timestamp)
                
                if SplittedEntry[TYPE_MESSAGE_FIELD]=='W':
                    Prefix = SplittedEntry[PREFIX_FIELD].split('\n')[0]
                    
                    if Prefix=="0.0.0.0/0":
                        continue
                    
                    rnode = rtree.search_exact(Prefix)
                    if not rnode:
                        print('\tWarning UPDATE_MESSAGE_WITHDRWALS_NON_EXISTING_PREFIX', Entry.split('\n')[0], data_file)
                        nWithdrawlsError+=1
                    elif(rnode.data["ASPath"][-1][0]==None):
                        print('\tWarning UPDATE_MESSAGE_DUPLICATED_WITHDRAWL', Entry.split('\n')[0], data_file)
                        nWithdrawlsDuplicated+=1
                    else:
                        Timestamps_No_Duplicates.append(int(SplittedEntry[TIMESTAMP_FIELD]))
                        nWithdrawlsOk+=1
                        rnode.data["ASPath"].append([None,Timestamp])
                else:
                    Prefix = SplittedEntry[PREFIX_FIELD]
                    ASPath=SplittedEntry[AS_PATH_FIELD]
                    rnode = rtree.search_exact(Prefix)
                    
                    if Prefix=="0.0.0.0/0":
                        continue
                    
                    if not rnode:
                        nNewPrefix+=1
                        Timestamps_No_Duplicates.append(int(SplittedEntry[TIMESTAMP_FIELD]))                    
                        rnode = rtree.add(Prefix)
                        rnode.data["Results"] = []
                        rnode.data["TPaths"] = []     
                        rnode.data["ASPath"]=[]
                        rnode.data["ASPath"].append([ASPath,Timestamp])
                        rnode.data["BGPASPath"]=[]
                    else:
                        if rnode.data["ASPath"][-1][0]==ASPath:
                            nDuplicates+=1
                        else:
                            Timestamps_No_Duplicates.append(int(SplittedEntry[TIMESTAMP_FIELD]))
                            if rnode.data["ASPath"][-1][0]==None:
                                nBackToLife+=1
                            rnode.data["ASPath"].append([ASPath,Timestamp])    
           
    print("\tQUpdateMessages=%s\n\tQNonDuplicateMessages=%s" % (len(Timestamps), len(Timestamps_No_Duplicates)))          
    print("\tnWithdrawlsError=%s\n\tnWithdrawlsDuplicates=%s\n\tnWithdrawlsOk=%s" % (nWithdrawlsError, nWithdrawlsDuplicated, nWithdrawlsOk))       
    print("\tnChangeDuplicate=%s\n\tnNewPrefix=%s\n\tBackToLife=%s" %(nDuplicates, nNewPrefix, nBackToLife))    
    return rtree

#**********************************************************************************************
#********************************* Loading Updates to Radix Tree ******************************
#**********************************************************************************************

def Loading_Update_Messages_to_Radix_Tree(rtree, UpdateMessagesFolderPath):    
    
    for data_file in sorted(os.listdir(UpdateMessagesFolderPath)):
        if data_file.split('.')[0]!='updates':
            continue 
        
        update_file = os.path.join(UpdateMessagesFolderPath, data_file)
        with open(update_file, 'r') as Update_File:
            for Entry in Update_File:
                SplittedEntry = Entry.split('|')
                Timestamp=int(SplittedEntry[TIMESTAMP_FIELD])
                
                if SplittedEntry[TYPE_MESSAGE_FIELD]=='W':
                    Prefix = SplittedEntry[PREFIX_FIELD].split('\n')[0]
                    rnode = rtree.search_exact(Prefix)
                    if rnode and rnode.data["ASPath"][-1][0] != None:
                        rnode.data["ASPath"].append([None,Timestamp])
                else:
                    Prefix = SplittedEntry[PREFIX_FIELD]
                    ASPath = SplittedEntry[AS_PATH_FIELD]
                    rnode  = rtree.search_exact(Prefix)
                    
                    if not rnode:
                        rnode = rtree.add(Prefix)
                        rnode.data["ASPath"]=[]
                        rnode.data["ASPath"].append([ASPath,Timestamp])
                    else:
                        if rnode.data["ASPath"][-1][0] != ASPath:
                            rnode.data["ASPath"].append([ASPath,Timestamp])    
    return rtree

#**********************************************************************************************
#********************************* Finding BGPASPath to Compare *******************************
#**********************************************************************************************

def Search_DstPrefix_BGPASPath_to_Compare(rtree, DstIP, TracerouteTimestamp):
   
    BGPASPATH_FIELD=0   
    TIMESTAMP_FIELD=1
    
    rnodes=rtree.search_covering(DstIP)
    
    if not rnodes:
        return "qNCPforIP", None
    
    for rnode in rnodes:
        DeltaTime = TracerouteTimestamp
        rnode_BGPASPaths_Timestamps = rnode.data["ASPath"] 
        BGPASPath=False
        
        for Index in range (0,len(rnode_BGPASPaths_Timestamps)): 
            Actual_BGPASPath_Timestamp = rnode_BGPASPaths_Timestamps[Index]
            ActualDeltaTime = Actual_BGPASPath_Timestamp[TIMESTAMP_FIELD]-TracerouteTimestamp            

            if ActualDeltaTime>0:
                break
            elif(abs(ActualDeltaTime)<=DeltaTime):
                DeltaTime = abs(ActualDeltaTime)
                BGPASPath = Actual_BGPASPath_Timestamp[BGPASPATH_FIELD]
                rnodeFound = rnode
            else:
                print("\tWARNING UPDATES_NOT_IN_CHRONOLOGICAL_ORDER!!!")

        if BGPASPath:   
            return rnodeFound, BGPASPath
        
    return "qMPforIP", None

#**********************************************************************************************
#********************************* SEATLE ******************************
#**********************************************************************************************

def Loading_Update_Messages_to_Radix_Tree_Seatle(rtrees, NextHops, UpdateMessagesFolderPath):    
    
    for data_file in sorted(os.listdir(UpdateMessagesFolderPath)):
        
        if data_file.split('.')[0]!='updates':
            continue 
        
        update_file = os.path.join(UpdateMessagesFolderPath, data_file)
        with open(update_file, 'r') as Update_File:
            for Entry in Update_File:
                SplittedEntry = Entry.split('|')
                
                current_tree = None
                NH_Entry = SplittedEntry[NEXT_HOP_FIELD]
                if NH_Entry == NextHops[0]:
                    current_tree = 0
                elif NH_Entry == NextHops[1]:
                    current_tree = 1
                else:
                    continue
                                
                Timestamp=int(SplittedEntry[TIMESTAMP_FIELD])
                               
                if SplittedEntry[TYPE_MESSAGE_FIELD]=='W':
                    Prefix = SplittedEntry[PREFIX_FIELD].split('\n')[0]
                    rnode = rtrees[current_tree].search_exact(Prefix)
                    if rnode and rnode.data["ASPath"][-1][0] != None:
                        rnode.data["ASPath"].append([None,Timestamp])
                else:
                    Prefix = SplittedEntry[PREFIX_FIELD]
                    ASPath = SplittedEntry[AS_PATH_FIELD]
                    rnode  = rtrees[current_tree].search_exact(Prefix)
                    
                    if not rnode:
                        rnode = rtrees[current_tree].add(Prefix)
                        rnode.data["ASPath"]=[]
                        rnode.data["ASPath"].append([ASPath,Timestamp])
                    else:
                        if rnode.data["ASPath"][-1][0] != ASPath:
                            rnode.data["ASPath"].append([ASPath,Timestamp])    
    return rtrees


#**********************************************************************************************
#********************************* Peering Project: only RIBs *********************************
#**********************************************************************************************

def Create_Radix_Tree_From_RIBs(CURRENT_BGP_DATA_PATH, DATE):
    
    rtree = radix.Radix()
    
    for nfile, filename in enumerate(sorted(os.listdir(CURRENT_BGP_DATA_PATH))):
        print("Treating: %s  (%s/12)" % (filename, 1+nfile))
        Timestamp = DATE[0] + "." + DATE[1] + "."+ DATE[2] + "." + filename.split(".")[1]
        Timestamp = datetime.strptime(Timestamp, '%Y.%m.%d.%H%M')
        current_rib_file = os.path.join(CURRENT_BGP_DATA_PATH, filename)

        with gzip.open(current_rib_file, 'rb') as RIB_File:
            for line in RIB_File:   
                Entry = line.decode()
                [Prefix, ASPath, DontCare] = Entry.split("|")               
                
                if Prefix=="0.0.0.0/0" or "bird" in Prefix:
                    continue
            
                rnode = rtree.search_exact(Prefix)
                if not rnode:
                    rnode = rtree.add(Prefix)
                    rnode.data["ASPath"]=[]
                rnode.data["ASPath"].append([ASPath,Timestamp])
            
    return rtree   
            
def Peering_Project_DstPrefix_BGPASPath_to_Compare(rtree, DstIP, TracerouteTimestamp):
   
    BGPASPATH_FIELD=0   
    TIMESTAMP_FIELD=1
    
    rnodes=rtree.search_covering(DstIP)
    
    if not rnodes:
        return "qNCPforIP", None
    
    for rnode in rnodes:
        DeltaTime = timedelta(hours=24)
        rnode_BGPASPaths_Timestamps = rnode.data["ASPath"] 
        BGPASPath=False
        
        for Index in range (0,len(rnode_BGPASPaths_Timestamps)): 
            Actual_BGPASPath_Timestamp = rnode_BGPASPaths_Timestamps[Index]
            ActualDeltaTime = Actual_BGPASPath_Timestamp[TIMESTAMP_FIELD]-TracerouteTimestamp            

            if ActualDeltaTime > timedelta(0):
                if DeltaTime > timedelta(hours=2):
                    BGPASPath = None
                break
            elif(abs(ActualDeltaTime)<=DeltaTime):
                DeltaTime = abs(ActualDeltaTime)
                BGPASPath = Actual_BGPASPath_Timestamp[BGPASPATH_FIELD]
                rnodeFound = rnode
            else:
                print("\tWARNING UPDATES_NOT_IN_CHRONOLOGICAL_ORDER!!!")

        if BGPASPath:   
            return rnodeFound, BGPASPath
        
    return "qMPforIP", None

# ***********************************************************************
# ***************** Functions handle all Siblings Data ******************
# ***********************************************************************

# This function reads the AS2Org data a dictionary AS2Org that takes an 
# AS as a key, and returns the Org that owns it, and the CH of that Org.

def CreateAS2CHMapping():
    AS2CH = {}
    Orgs = {}
    with open("AS_Relationships/as_2_org.txt", "rt") as f:
        for Line in f:                     
            splittedline = Line.strip().split("|")
            
            if len(splittedline)!=6:
                continue
                       
            ASN = splittedline[0]
            OrgID =splittedline[-3]
    
            if OrgID not in Orgs.keys():
                Orgs[OrgID]= ASN
             
            AS2CH[ASN] = Orgs[OrgID]
             
    return AS2CH


def ReplaceASesbyCHs(ASPath, AS2CH, ResultsFile):    
    print("Ownership: From ASes to CHs", file=ResultsFile)
    for Ind in range(0,len(ASPath)):
        CurrentAS = ASPath[Ind] 
        if CurrentAS in AS2CH.keys():
            ASPath[Ind] = AS2CH[CurrentAS]       
    print(ASPath, file=ResultsFile)
    return ASPath

# ***********************************************************************
# ************ Functions To carry out TPAs' heuristics ******************
# ***********************************************************************   

def FindASIndexInPath(AS, ASPath):
    try:
        Index = ASPath.index(AS)
    except ValueError:
        Index = None
    return Index
   
def ASesInPathandOccurances(RTASPath):
    
    ASesinPath = []
    for ind in range(0,len(RTASPath)):
        CurrentAS = RTASPath[ind]
        if CurrentAS != "*" and CurrentAS != "NA":
            if CurrentAS not in ASesinPath:
                ASesinPath.append(CurrentAS)
                
    CurrentHopsDist = []
    for AS in ASesinPath:
        for ind in range(0,len(RTASPath)):
            if RTASPath[ind]==AS:
                Minind = ind
                break       
        for ind in range(len(RTASPath)-1,-1,-1):
            if RTASPath[ind]==AS:
                Maxind = ind
                break
        to_substract = 0
        for ind in range(Minind+1,Maxind):
            CurrentAS=RTASPath[ind]
            if CurrentAS!=AS and CurrentAS!="*" and CurrentAS!="NA":
                to_substract+=1
        CurrentHopsDist.append(Maxind-Minind+1-to_substract)
        
    return dict(zip(ASesinPath,CurrentHopsDist))
   
def ApplyTPAsWildcardsMaximization(DataPath, ControlPath, DictqHopsPerASInDataPath):
    for IndDP in range(0,len(DataPath)):
        CurrentAS_DP = DataPath[IndDP]
        if CurrentAS_DP != "*" and CurrentAS_DP != "NA" and FindASIndexInPath(CurrentAS_DP, ControlPath)!= None:
            if DictqHopsPerASInDataPath(CurrentAS_DP) == 1:
                DataPath[IndDP] = "*"
            
        
        
        

def ApplyDeletionRuleForTPAs(): 
    RedDataPath = EliminateAll_NA_or_Asterisk_TASPath(DataPath)
    if RedDataPath[-1] not in ControlPath and RedDataPath[-2] in ControlPath:
        if dict_ASes_Occurances[RedDataPath[-1]]<=2:
            del RedDataPath[-1]
    
    Patterns = []
    
    for ind_DP in range(0,len(RedDataPath)-1):
        CurrentAS_DP = RedDataPath[ind_DP]
        indCAS_CP = FindIndexAS(ControlPath, CurrentAS_DP)
        
        if indCAS_CP == None:
            continue
        NextAS_DP = RedDataPath[ind_DP+1]
        NextAS_CP = ControlPath[indCAS_CP+1]
        # We want to know if there is a MM Pattern
        if NextAS_CP!=NextAS_DP:
            # A last checking before assuming it's a MM Pattern...
                                
            # We check if they are siblings...
            if CheckifSiblings(CurrentAS_DP, NextAS_DP, AS2Org) != False:
                qSiblings+=1
                continue

            
            #   CP = A B S1 D E
            #   DP = A B S2 D E
            # If S2 is a sibling of S1, then maybe it's just a mapping problem, so we
            # do not consider this case as a MM Pattern.
            if CheckifSiblings(NextAS_DP, NextAS_CP, AS2Org) != False:
                qSiblings += 1
                continue
            
            # If they are not siblings, then it's a MM Pattern...
            Pattern = CurrentAS_DP + "|" + NextAS_CP + "|-->|" + CurrentAS_DP + "|" + NextAS_DP + "|"
            
            # We check if disagreement happens because of an off-path-AS
            if NextAS_DP not in ControlPath:
                # There is an off-path-AS ...
                
                # We check if the off-path-AS takes the place of another AS
                #   CP = A B C D E
                #   DP = A B X D E
                # A case like this could be caused by TPIPs. Nevertheless, it needs to
                # be checked because if IPs(X)>2, then it is likely that indeed the path
                # really included C in the path.            
                if indCAS_CP+2 < len(ControlPath) and ind_DP+2 < len(RedDataPath):
                    if ControlPath[indCAS_CP+2] == RedDataPath[ind_DP+2] or CheckifSiblings(ControlPath[indCAS_CP+2], RedDataPath[ind_DP+2], AS2Org) != False:
                        if dict_ASes_Occurances[NextAS_DP]<=1:
                            Patterns.append([Pattern, "Replace %s with %s" % (NextAS_DP, NextAS_CP)])   
                            qReplace+=1                               
                            continue                       
            else:
                # NextAS_DP is on-path...
                
                # We check if there is a missing hop in DP
                #   CP = A B C D E
                #   DP = A B D E
                # A case like this could be caused by TPIPs that erased C from the
                # DP, so it's better not to judge this case as MMing. 
                if indCAS_CP+2<len(ControlPath):
                    if ControlPath[indCAS_CP+2]==NextAS_DP or CheckifSiblings(ControlPath[indCAS_CP+2], NextAS_DP, AS2Org) != False:
                        Patterns.append([Pattern, "Include %s between %s and %s" % (NextAS_CP, CurrentAS_DP, NextAS_DP)])
                        qInsert+=1
                        continue
                
            # We check if there is an extra hop in DP (independently of being off-path)
            #   CP = A B D E
            #   DP = A B X D E
            # A case like this could be caused by TPIPs. Nevertheless, it needs to,
            # be checked because of IPs(C)>2, then it is likely that indeed the path
            # really included C in the path
            if ind_DP+2<len(RedDataPath):
                if RedDataPath[ind_DP+2]==NextAS_CP or CheckifSiblings(NextAS_CP, RedDataPath[ind_DP+2], AS2Org) != False:
                    if dict_ASes_Occurances[NextAS_DP]<=1:
                        Patterns.append([Pattern, "Erase %s from DP" % NextAS_DP])
                        qDelete+=1
                        continue    
    
    
    
    
    
    
    
    
    
    
    
    
    
    ##############################################################################  
       
    #-------- print("Checking for ASSets in TracerouteASPath", file=ResultsFile)
#------------------------------------------------------------------------------ 
    #--- ASSetsIndexes = Functions.Checking_for_AS_sets(ReducedTracerouteASPath)
    #----------------------------------------------------- if not ASSetsIndexes:
        #------------------------- print('No sets were found', file=ResultsFile)
    #--------------------------------------------------------------------- else:
        #-------------------------------------------------------- n_T_AS_Sets+=1
        #------------------------------------------- for Index in ASSetsIndexes:
            #-------------------------------- ASn=ReducedTracerouteASPath[Index]
            #--------------------------- ASBlock=ASn.split('{')[1].split('}')[0]
            #------------------------------------------ ASSet=ASBlock.split(',')
            #------------------ print('Found ASSet=%s' % ASn , file=ResultsFile)
            #-------------------------------------------------- if len(ASSet)>1:
                # print('Warning: TRACEROUTE_LONG_AS_Set', ReducedTracerouteASPath, ASn, file=WarningLog)
            #------------------------------------------------------------- else:
                # print('Warning: TRACEROUTE_SHORT_AS_Set', ReducedTracerouteASPath, ASn, file=WarningLog)

         
    #############################################################################
#------------------------------------------------------------------------------ 
    #--------------- print("Checking for ASSets in BGPASPath", file=ResultsFile)
#------------------------------------------------------------------------------ 
    #----------------- ASSetsIndexes = Functions.Checking_for_AS_sets(BGPASPath)
    #----------------------------------------------------- if not ASSetsIndexes:
        #------------------------- print('No sets were found', file=ResultsFile)
    #--------------------------------------------------------------------- else:
        #------------------------------------------------------ n_BGP_AS_Sets+=1
        #-------- print('Warning: AS_SET_BGPASPath', BGPASPath, file=WarningLog)
        #------------------------------------------- for Index in ASSetsIndexes:
            #---------------------------------- PreviousASN = BGPASPath[Index-1]
            #---------------------------------------------- ASn=BGPASPath[Index]
            #------------------ print('Found ASSet=%s' % ASn , file=ResultsFile)
            # MatchingASN, MatchingTag = Functions.Solving_BGPASSet(PreviousASN, ASn, ReducedTracerouteASPath)
            #----------------------------------------------- if not MatchingASN:
                #-------------------------- print(MatchingTag, file=ResultsFile)
                #- print('Warning AS_SET_BGPASPath_NO_MATCHES', file=WarningLog)
            #------------------------------------------------------------- else:
                #-------------------------------- BGPASPath[Index] = MatchingASN
                # print('Matched to %s=%s' %(MatchingTag, MatchingASN), file=ResultsFile)
                    
    ############################################################################  
    
    #---------------------------------------------------------- if TSetsIndixes:
        #--------------- print("#setsT=%s" % len(TSetsIndixes), file=WarningLog)
        #-------------- print("#setsT=%s" % len(TSetsIndixes), file=ResultsFile)
        #----------------------- print(ReducedTracerouteASPath, file=WarningLog)
        #-------------------------------------------- for Index in TSetsIndixes:
            # print("T_SET_ %s" % ReducedTracerouteASPath[Index], file=WarningLog)
            #------------------------- if Index!=len(ReducedTracerouteASPath)-1:
                # print("T_SET_DOES_NOT_PRECLUDE_PATH %s" % ReducedTracerouteASPath[Index], file=WarningLog)
            #------------------------------------------------------------- else:
                # print("T_SET_DOES_PRECLUDE_PATH %s" % ReducedTracerouteASPath[Index], file=WarningLog)
#------------------------------------------------------------------------------ 
    #-------------------------------------------------------- if BGPSetsIndixes:
        #---------- print("#setsBGP=%s" % len(BGPSetsIndixes), file=ResultsFile)
        #----------- print("#setsBGP=%s" % len(BGPSetsIndixes), file=WarningLog)
        #------------------------------------- print(BGPASPath, file=WarningLog)
        #------------------------------------------ for Index in BGPSetsIndixes:
            #---------- print("BGP_SET_ %s" % BGPASPath[Index], file=WarningLog)
            #--------------------------------------- if Index!=len(BGPASPath)-1:
                # print("BGP_SET_DOES_NOT_PRECLUDE_PATH %s" % BGPASPath[Index], file=WarningLog)
            #------------------------------------------------------------- else:
                # print("BGP_SET_DOES_PRECLUDE_PATH %s" % BGPASPath[Index], file=WarningLog)
                
                
    ############################################################################                  

    
                #-------------------------------------------------------- if '{' in ASn:
            #--------------------------- ASBlock=ASn.split('{')[1].split('}')[0]
            #------------------------------------------ ASSet=ASBlock.split(',')
            #---------------------------------------------------- ToEliminate=[]
            #--------------------------- for Index,ASnInSet in enumerate(ASSet):
                # Is_Prohibited,WarningLabel= Functions.Is_Prohibited_ASn(ASnInSet)
                #--------------------------------------------- if Is_Prohibited:
                    #--------------------------------------- Has_ProhibitedASN=1
                    # print('Prohibited ASN Detected inside a set ' + ASnInSet + ' will be eliminated.', file=ResultsFile)
                    #---------- print(WarningLabel + '_IN_SET', file=WarningLog)
                    #--------------------------------- ToEliminate.append(Index)
            #---------------------------------------------- ASSetBackup=ASSet[:]
            #------------------------------- for Index in reversed(ToEliminate):
                #---------------------------------------------- ASSet.pop(Index)
#------------------------------------------------------------------------------ 
            #-------------------------------------------- if ASSetBackup==ASSet:
                #----- print("Warning: SET_NOPROHIBITED_EQUAL", file=WarningLog)
            #------------------------------------------------------------- else:
                #------------------------------------------------- if not ASSet:
                    # print("Warning: SET_PROHIBITED_COMPLETELY_ELIMINATED", file=WarningLog)
                    # print("The set was completely eliminated", file=ResultsFile)
                    #------------------------------------------ BGPASPath.pop(j)
                    #------------------------ print(BGPASPath, file=ResultsFile)
                #--------------------------------------------------------- else:
                    #----------------------------------------- if len(ASSet)==1:
                        # print("Warning: SET_PROHIBITED_REDUCED_AND_MATCHED", file=WarningLog)
                        # print("The set was reduced to one ASn %s" % ASSet[0], file=ResultsFile)
                        #--------------------------------- BGPASPath[j]=ASSet[0]
                        #-------------------- print(BGPASPath, file=ResultsFile)
                    #----------------------------------------------------- else:
                        #-------- print("Warning: SET_REDUCED", file=WarningLog)
                        #----------------------------------------------- Tag='{'
                        #---------------------------- for LeftASN in ASSet[:-1]:
                            #--------------------------- Tag=Tag + LeftASN + ','
                        #--------------------------- Tag = Tag + ASSet[-1] + '}'
                        #-------------------------------------- BGPASPath[j]=Tag
                        # print("The set could only be reduced to %s" % Tag, file=ResultsFile)        
            
            
            
            