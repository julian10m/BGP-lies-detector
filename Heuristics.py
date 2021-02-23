'''
Created on Jun 7, 2018

@author: julian
'''
def MMingHopsHeuristics(DataPath, ControlPath, ResultsFile, WarningLog):
    
    Asterisks_aa_a=0
    nChain_aa_a=0
    Asterisks_ac_b=0
    Asterisks_ab_aorb=0
    nChain_ab=0
        
    j=0
    while (j<len(DataPath)):
        ActualASN = DataPath[j]
        if (ActualASN=='*' or ActualASN=='NA'):
            print('Asterisk or NA Detected in position %s' % str(j), file=ResultsFile) 
            if(j>=len(DataPath)-1):
                print('Asterisk or NA finishes the path, nothing can be decided', file=ResultsFile) 
            else:   # Asterisk found does not conclude the path... 
                print('It does not conclude the path, needs to be checked', file=ResultsFile)
                PreviousASN = DataPath[j-1]    # Doing this I am assuming I never start with an * in the path...
                # FollowingASN = DataPath[j+1]   # Since it does not conclude path, Following ASN exists...
                if(PreviousASN=='*' or PreviousASN=="NA"): # Case there was an * before which could not be resolved...
                    print("There is a chain of * or NA combined that can't be decided", file=ResultsFile)
                    print("Warning: *_SHOULD_NOT_BE_CHECKED", file=WarningLog)
                else: #elif(FollowingASN=='*' or FollowingASN=="NA"): # Case the next one is an * so we try to resolve it...                     
                    found=0
                    for i in range(j+1,len(DataPath)): 
                        if DataPath[i]!='*' and DataPath[i]!='NA':
                            found=1
                            break
                    if not found:
                        j=len(DataPath)                                    
                        print("This chain or single * finishes the path so we skip to the comparison at once", file=ResultsFile)
                    else:  # The chain does not finish the path...
                        if(DataPath[i]==PreviousASN): # case a*a or a**..*a
                            if((i-j)==1):
                                Asterisks_aa_a+=1
                                print("Asterik a*a, *a has been eliminated", file=ResultsFile)  
                            else:
                                nChain_aa_a+=1 
                                print("Chain of Asteriks a**a, **a has been eliminated", file=ResultsFile)  
                            for val in range(j,i+1):
                                DataPath.pop(j) 
                            print(DataPath, file=ResultsFile) 
                            if j<len(DataPath):
                                print("Now ASN=%s in position j=%s will be analyzed next" % (str(DataPath[j]), str(j)) , file=ResultsFile)
                            j-=1    
                        else: # case a*b or a**...*b                                    
                            try:
                                IndexPrev = ControlPath.index(PreviousASN)
                            except ValueError:
                                IndexPrev = None
                                                                        
                            try:  
                                IndexNext = ControlPath.index(DataPath[i])
                            except ValueError:
                                IndexNext = None
                                
                            if(IndexPrev==None):
                                print("Previous ASN does not appear in BGPASPath, paths seem to be different", file=ResultsFile)
                                if(IndexNext==None):
                                    print("Next ASN neither does appear in BGPASPath", file=ResultsFile)
                                else:
                                    print("Next ASN does appear in BGPASPath in position %s" % IndexNext, file=ResultsFile)
                            else:
                                print("Previous ASN appears in BGPASPath in position %s" % IndexPrev, file=ResultsFile)
                                if(IndexNext==None):
                                    print("Next ASN does not appear in BGPASPath, paths seem to be different", file=ResultsFile)
                                else:
                                    print("Next ASN also appears in BGPASPath in position %s" % IndexNext, file=ResultsFile)
                                    nWildCards=i-j
                                    nMiddleASN=IndexNext-IndexPrev-1
                                    print("Wildcards=%s|MiddleASN=%s" %(nWildCards, nMiddleASN), file=ResultsFile)                                                
                                    if(nWildCards==1):
                                        if(nMiddleASN==0):
                                            Asterisks_ab_aorb+=1                        
                                            print('Asterisk a*b_aorb, it will be eliminated', file=ResultsFile)
                                        elif(nMiddleASN==1):
                                            Asterisks_ac_b+=1
                                            print('Asterisk a*c_b, it will be changed to b', file=ResultsFile)                                                        
                                    else:
                                        print("Chain of type a**b detected", file=ResultsFile)
                                        nChain_ab+=1    
                                                                                        
                                    if (nMiddleASN<0):
                                        print("Possible loop, skipping chain", file=ResultsFile)
                                        print("Warning: POSSIBLE_LOOP_nMiddleASN<0", file=WarningLog)
                                    else:
                                        if(nWildCards<nMiddleASN):
                                            print("MissingASN>WildCards, can't be decided", file=ResultsFile)
                                            print("Warning: MissingASN>WildCards", file=WarningLog)
                                        else:
                                            print("|WildCards>=MissingASN|", file=ResultsFile)
                                            while(nWildCards>nMiddleASN):
                                                DataPath.pop(j)
                                                i-=1
                                                nWildCards-=1
                                            for Index in range(nWildCards):
                                                DataPath[j+Index]=ControlPath[IndexPrev+1+Index]
                                            print("Solution reached", file=ResultsFile)  
                                            print(DataPath, file=ResultsFile) 
                            j=i-1
                            print("We skip to asn=%s in position j=%s" % (DataPath[i], i), file=ResultsFile)                                                                            
        j+=1
        
    return DataPath  
        

def ApplyMissingHopHeuristics(ANALYSIS_APPROACH, DataPath, ControlPath, ResultsFile):
    ArePathsMismatching = False
    IsWeirdCase = False    
    j = 0    
    while(True):
        CurrentAS_DP = DataPath[j]
        CurrentAS_CP = ControlPath[j]
        if CurrentAS_DP != CurrentAS_CP:
            if CurrentAS_DP != "*" and CurrentAS_DP != "NA":
                if ANALYSIS_APPROACH != "LowerBound":
                    ArePathsMismatching = True
                    IsWeirdCase = True
                    break
                elif ANALYSIS_APPROACH == "LowerBound":                    
                    if j<len(ControlPath)-1 and CurrentAS_DP == ControlPath[j+1]:
                            DataPath.insert(j, CurrentAS_CP)
                            print("TPA: Missing AS! Inserted ASN=%s in pos=%s" % (DataPath[j], j), file=ResultsFile)
                    else:
                        ArePathsMismatching = True
                        IsWeirdCase = True
                        break
            else:
                PreviousAS_DP = DataPath[j-1]
                k = j
                while(DataPath[k]=="*" or DataPath[k] == "NA"):
                    k+=1
                nWildCards = k-j
                NextAS_DP = DataPath[k]
                if NextAS_DP == PreviousAS_DP:
                    for _ in range(0,nWildCards+1):
                        DataPath.pop(j) 
                    print("Chain of Wildcards of the type %s * %s has been solved" % (NextAS_DP, NextAS_DP), file=ResultsFile)  
                    print("DP = %s" % DataPath, file=ResultsFile) 
                    if j<len(DataPath):
                        print("Now ASN=%s in position j=%s will be analyzed next" % (str(DataPath[j]), str(j)) , file=ResultsFile)
                    j-=1                       
                else:
                    try:  
                        nMiddleASN = ControlPath[j:].index(NextAS_DP)
                    except ValueError:
                        ArePathsMismatching = True
                        IsWeirdCase = True
                        break
                    print("Wildcards=%s|MiddleASN=%s" %(nWildCards, nMiddleASN), file=ResultsFile)                                                
                    if(nWildCards<nMiddleASN):
                        print("MissingASN>WildCards, can't be decided", file=ResultsFile)
                        ArePathsMismatching = True
                        IsWeirdCase = False
                        break
                    else:
                        print("|WildCards>=MissingASN|", file=ResultsFile)
                        while(nWildCards>nMiddleASN):
                            DataPath.pop(j)
                            nWildCards-=1
                        for Index in range(nWildCards):
                            DataPath[j+Index]=ControlPath[j+Index]
                        print("Solution reached", file=ResultsFile)  
                        print("DP = %s" % DataPath, file=ResultsFile) 
                        print("Now ASN=%s in position j=%s" % (DataPath[j], j), file=ResultsFile)
        j+=1
        if j >= len(DataPath) or j>= len(ControlPath):
            break
        
    if not ArePathsMismatching and j >= len(ControlPath) and j<len(DataPath):
        print("DP has additional path when compared to CP!", file=ResultsFile)
        OAS = ControlPath[-1]
        StillMatch = True
        for Ind in range(j,len(DataPath)):
            CurrentAS_DP = DataPath[Ind]
            if CurrentAS_DP != "*" and CurrentAS_DP != "NA" and CurrentAS_DP != OAS:
                StillMatch = False
                break
        if StillMatch:
            DataPath = DataPath[:j]
            print("DP additional path matches, so it has been erased!", file=ResultsFile)
            print("DP = %s" % DataPath, file=ResultsFile)
        else:
            print("DP additional path would make paths mismatch!!", file=ResultsFile)
            IsWeirdCase = True
        
    return DataPath, ControlPath, ArePathsMismatching, IsWeirdCase   