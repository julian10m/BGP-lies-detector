'''
Created on Jun 7, 2018

@author: julian
'''
import Functions

#############################################################################



def ASSets_Checking(ControlPath, ResultsFile, WarningLog):
    print("Checking for ASSets in Control-Path", file=ResultsFile)
    
    HasSet=0
    
    j=len(ControlPath)
    while (j):
        ASn = ControlPath[j-1]
        if ('{' in ASn) and ('}' in ASn):
            HasSet=1
            print('AS Set Detected: ' + ASn + '.', end=' ', file=ResultsFile) 
            if j==len(ControlPath):
                print('It finishes the path, so it will be eliminated.', file=ResultsFile)
                del ControlPath[-1]
            else:
                print("It can't be eliminated. We can't analyze this case!.", file=ResultsFile)
                print("", file=ResultsFile) 
                print("Warning: CP_INCLUDE_SETS", file=WarningLog)
                break
        j-=1
    
    if not HasSet:
        print("No ASSets were found", file=ResultsFile)
               
    return ControlPath, j



#############################################################################

# This function takes a DataPath and reduces to a minimum set
# the ASes that appear on it. However, *'s and NA's are kept
# unmodified.
#    
#   Ex.1 
#    CP = A B C D E F 
#    DP = A A B B C D E E F ---> DP = A B C D E F
#
#   Ex.2
#    CP = A B C D E F 
#    DP = A A * * B B * C D E * * E F ---> DP = A * * B * C D E * * E F
#    

def ReduceDataPath(DataPath, ResultsFile):   
    print("Reducing the Data Path", file=ResultsFile)
    j=0
    while(j<len(DataPath)-1):
        ActualASN = DataPath[j]
        if (ActualASN!='*' and ActualASN!='NA'):
            while(DataPath[j+1]==ActualASN):
                    DataPath.pop(j+1)
                    if (j==len(DataPath)-1):
                        break
        j+=1
    print("DP = %s" % DataPath, file=ResultsFile)            
    return DataPath



#############################################################################



def  LoopsDataPath(DataPath, ResultsFile, WarningLog):
    print("Checking for loops in Traceroute AS Path", file=ResultsFile)
    
    Index=0
    Has_loop=0
    while(Index<len(DataPath)-2):
        ASn=DataPath[Index]
        if ASn!='*' and ASn!='NA':
            Is_looped,CuttingIndex=Functions.Is_There_Loop(DataPath, Index)
            if Is_looped:
                Has_loop=1
                DataPath=DataPath[:CuttingIndex]
                print("Loop for ASn=%s between positions %s-%s" %(ASn, Index, CuttingIndex), file=ResultsFile)
        Index+=1
    
    if not Has_loop:
        print('No Loop was found', file=ResultsFile)
    else:
        print("Warning: GENERAL_LOOP", file=WarningLog)
        print('Loops Were Eliminated', file=ResultsFile)
        print(DataPath, file=ResultsFile)

    return DataPath, Has_loop



#############################################################################


 
def RemovingTrailingWildcards(DataPath, ResultsFile):
    print("Checking for ending 'NA' or '*' in Data Path", file=ResultsFile)
    
    found=0
    while(DataPath[-1]=='*' or DataPath[-1]=='NA'):
        found=1
        del DataPath[-1]
    
    if found==1:
        print('Ending NA or * was found and eliminated', file=ResultsFile)
        print(DataPath, file=ResultsFile)
    else:
        print('No Ending NA or * was found', file=ResultsFile)    
        
    return DataPath
    
        

#############################################################################



def CheckingSiblingsControlPath(ControlPath, ResultsFile):
    print("Checking Siblings in BGP AS Path", file=ResultsFile)
    
    found=0
    for Index in range(0, len(ControlPath)):
        ASn = ControlPath[Index]
        if ASn=='20965':
            found =1
            ControlPath[Index]='21320'
    
    if not found:
        print("No Siblings were found", file=ResultsFile)
    else:
        print("Sibling ASN 20965 was replaced to ASN 21320", file=ResultsFile)
        
    return ControlPath 
        
        
        
#############################################################################



def EliminatingPrependingControlPath(ControlPath, ResultsFile):
    print("Eliminating Prepending in Control Path", file=ResultsFile)
    ReducedCP = ControlPath[:]
    ReducedCP = Functions.Reduce_ASPath(ReducedCP)
    if(ReducedCP==ControlPath):
        print('No Prepending was detected', file=ResultsFile)
    else:
        print('Prepending was eliminated', file=ResultsFile)
        print("CP = %s" % ReducedCP, file=ResultsFile)
    
    return ReducedCP  


##############################################################################

def CheckingForpASNsInControlPath(ControlPath):
    
    j=len(ControlPath)
    while j:
        ASn = ControlPath[j-1]
        Is_Prohibited, _= Functions.Is_Prohibited_ASn(ASn)
        if Is_Prohibited:
            if j==len(ControlPath):
                del ControlPath[-1]
            else:
                return ControlPath, True
        j-=1
    
    return ControlPath, False
    
##############################################################################



def RemovingPostOASPath(DataPath, ControlPath, ResultsFile):
    print("Arranging DP for all methods: remove postOAS path", file=ResultsFile)
    ReachedOASN, IndexOrigin = Functions.Reached_OASN(DataPath, ControlPath)
    if not ReachedOASN:
        print("OASN was not reached", file=ResultsFile)
    else:
        if IndexOrigin<len(DataPath)-1:
            DataPath = DataPath[:IndexOrigin+1]
            print('OASN=%s was reached and extra path was cut' % DataPath[IndexOrigin], file=ResultsFile)
        else:
            print('OASN=%s was reached without extra path' % DataPath[IndexOrigin], file=ResultsFile)
        DataPath.append(DataPath[-1])
        
    return DataPath



##############################################################################

def IsMissingHop(ASN):
    if ASN == "*" or ASN == "NA":
        return True
    return False

def ReplaceWeakMapping(ANALYSIS_APPROACH, DataPath, ResultsFile):   
    print("WeekMapping: from IPs(AS)=1 to Wilcards", file=ResultsFile)
    TPAsOcurrances=[]
    j=0
    while(True):
        ActualASN = DataPath[j]
        k = j+1
        while(k<len(DataPath) and DataPath[k]==ActualASN):
            k += 1
        qOcurrances = k - j
        if ActualASN != "*" and ActualASN != "NA":
            if qOcurrances == 1:
                if ANALYSIS_APPROACH in ["LowerBound", "LowerBoundWI", "LowerBoundWIWI", "OnlyTPA"]:
                    DataPath[j] = "*"
                    if ANALYSIS_APPROACH in ["LowerBound", "LowerBoundWI"]:
                        DataPath.insert(j, "*")
                elif ANALYSIS_APPROACH in ["XorBound", "XorBoundWI"]:
                    TPAsOcurrances.append(j)
        if k<len(DataPath):
            j = k
        else:
            break
        
    if ANALYSIS_APPROACH in ["XorBound", "XorBoundWI"]:
        Ind = len(TPAsOcurrances)
        while(Ind):
            Cond1 = (Ind-1) and (TPAsOcurrances[Ind-1]-TPAsOcurrances[Ind-2]==1)
            Cond2 = (Ind<len(TPAsOcurrances)) and (TPAsOcurrances[Ind]-TPAsOcurrances[Ind-1]==1)
            if not(Cond1 or Cond2): 
                j = TPAsOcurrances[Ind-1]
                if not( IsMissingHop(DataPath[j-1]) or (j+1<len(DataPath) and IsMissingHop(DataPath[j+1])) ):
                    DataPath[j] = "*"
                    if ANALYSIS_APPROACH == "XorBound":
                        DataPath.insert(j,"*")
            Ind -= 1
            
    print(DataPath, file=ResultsFile)
    return DataPath


def XorBoundReplaceWeakMapping(ANALYSIS_APPROACH, DataPath, ResultsFile):   
    print("WeekMapping: from IPs(AS)=1 to Wilcards if not surrounding wildcard or additional TPA", file=ResultsFile)
    TPAsOcurrances= [] 
    j=0
    while(True):
        ActualASN = DataPath[j]
        k = j+1
        while(k<len(DataPath) and DataPath[k]==ActualASN):
            k += 1
        qOcurrances = k - j
        if ActualASN != "*" and ActualASN != "NA":
            if qOcurrances == 1:
                TPAsOcurrances.append(j)
        if k<len(DataPath):
            j = k
        else:
            break
    
    Ind = len(TPAsOcurrances)
    while(Ind):
        Cond1 = (Ind-1) and (TPAsOcurrances[Ind-1]-TPAsOcurrances[Ind-2]==1)
        Cond2 = (Ind<len(TPAsOcurrances)) and (TPAsOcurrances[Ind]-TPAsOcurrances[Ind-1]==1)
        if not(Cond1 or Cond2): 
            j = TPAsOcurrances[Ind-1]
            if not(DataPath[j-1] == "*" or (j+1<len(DataPath) and DataPath[j+1]=="*")):
                DataPath[j] = "*"
                DataPath.insert(j,"*")
        Ind -= 1
    print(DataPath, file=ResultsFile)
    return DataPath

def OldXor(ANALYSIS_APPROACH, DataPath, ResultsFile):   
    print("WeekMapping: from IPs(AS)=1 to Wilcards", file=ResultsFile)
    
    j=0
    while(True):
        ActualASN = DataPath[j]
        k = j+1
        while(k<len(DataPath) and DataPath[k]==ActualASN):
            k += 1
        qOcurrances = k - j
        if ActualASN != "*" and ActualASN != "NA":
            if qOcurrances == 1:
                if not(DataPath[j-1] == "*" or (k<len(DataPath) and DataPath[k]=="*")):
                    DataPath[j] = "*"
                    DataPath.insert(j,"*")
        if k<len(DataPath):
            j = k
        else:
            break

    print(DataPath, file=ResultsFile)
    return DataPath
    
###################################################################################

if __name__ == "__main__":
    DataPath = ['a', 'a', 'b', 'c', 'c', '*', "*", 'c', 'c', 'd', 'e', 'f', 'g', 'g' '*', 'f']
    print(DataPath)
    ResultsFile = None
    print("Xor")
    DataPath = OldXor("XorBound", DataPath, ResultsFile)
    #print("LowerBound")
    #DataPath = ReplaceWeakMapping("LowerBound", DataPath, ResultsFile)
    
