import pandas as pd
import time
from statistics import mean
import concurrent.futures
import pickle
import logging
import os
import glob
import re
from itertools import groupby
import math
import statistics
import random
from scipy.stats import norm
import joblib
from ctypes import *
import numpy as np
from scipy.spatial import distance
from builtins import bytes
import pytricia

class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]
    
lib = cdll.LoadLibrary(
    "./mmdb_reader.so")

def accessGeoIP2data(ip):
    ip = bytes(ip, 'utf-8')
    ip = go_string(c_char_p(ip), len(ip))
    lib.lookup.restype = np.ctypeslib.ndpointer(dtype=float, shape=(2,))
    loc = lib.lookup(ip)
    return loc[0], loc[1]

def euclidean_distance(coords1, coords2):
    return distance.euclidean(coords1, coords2)
 
def get_locations(prefixes):
    locs = set()
    if len(prefixes) > 500:
        prefixes = random.sample(prefixes, 500)
    for prefix in prefixes:
        ip = prefix.split('/')[0]
        x, y = accessGeoIP2data(ip)
        if x == y == 9999.0:
            continue
        loc = (x, y)
        locs.add(loc)
    return list(locs)
  
def compute_pfx_distance(as2prefixes_dict, prefix, asID, d_max):

    asID_prefixes = as2prefixes_dict.get(asID)
    
    if asID_prefixes == None:
        d = 1.0
        return d

    locationsx = get_locations(asID_prefixes)
    locationsy = get_locations([prefix])  # vrpID_prefixes
    
    if len(locationsx) == 0 or len(locationsy) == 0:
        d = None
        return d

    dists = list()
    for x in locationsx:
        dist = euclidean_distance(x, locationsy[0])
        dists.append(dist)

    d = statistics.median(dists)

    # we choose a function: y = (2/pi) * arctan(x) to scale this feature value in the range of [0, 1), and then we define the maximum value is one.
    d = (2/math.pi)*math.atan(d)

    return d
  
def check_as_dependency(asn, vrpasn, as_path, local_hege_dict):
    depen = 0.0
    asn, vrpasn = int(asn), int(vrpasn)
    if local_hege_dict.get((asn, vrpasn)) != None:
        depen = float(local_hege_dict.get((asn, vrpasn)))

    elif local_hege_dict.get((vrpasn, asn)) != None:
        depen = float(local_hege_dict.get((vrpasn, asn)))
    if depen >= 0.5:
        depen = 1.0
    else:
        depen = 0.0
    return depen
  
def check_AS_PC(caida_as_rel_pc, asID, vrpID):
    asID = str(asID)
    vrpID = str(vrpID)
    isPC = False
    c1 = caida_as_rel_pc.get(asID)
    c2 = caida_as_rel_pc.get(vrpID)
    if (c1 is not None and vrpID in c1) or (c2 is not None and asID in c2):
        isPC = True
    return isPC
  
def check_AS_org_v2(caida_as_org, asID, vrpID):
    isSameOrg = False

    orgid1 = caida_as_org.get(asID)
    orgid2 = caida_as_org.get(vrpID)
    if orgid1 != None and orgid2 != None:
        if orgid1 == orgid2:
            isSameOrg = True
            return isSameOrg
    return isSameOrg

def is_covered(prefix, vrp_prefix):
    pyt = None
    if ':' in vrp_prefix:
        pyt = pytricia.PyTricia(128)
    else:
        pyt = pytricia.PyTricia()

    pyt[vrp_prefix] = 'ROA'
    return vrp_prefix == pyt.get_key(prefix)

def check_related_origin(as2prefixes_dict, prefix, asID):
    rela = False
    vrp_prefixes = as2prefixes_dict.get(asID)
    if vrp_prefixes == None:
        return rela
    for vrp_prefix in vrp_prefixes:
        if vrp_prefix == prefix:
            continue
        if is_covered(prefix, vrp_prefix):  # less-specific prefix matching: prefix is a less-specific prefix
            rela = True
            return rela
    return rela

def check_irr(asID, prefix):
    irrValid = False
    matches = []
    cmd = """ whois -h whois.radb.net %s""" % (
        prefix)  # query to RADb database
    try:
        out = os.popen(cmd).read()
        if 'No entries found' in out:
            return irrValid, matches
        matches = re.findall(r'origin:\s+AS(\d+)', out)
        asID = str(asID)
        if asID in matches:
            irrValid = True
    except:
        irrValid = None
        matches = []
    return irrValid, matches

def check_irr_v2(irr_database, asID, prefix):
    score = 0
    if irr_database.get(prefix) != None and irr_database.get(prefix) != 1:
        if str(asID) in irr_database.get(prefix):
            score = score + 1
    else:
        irrValid, matches = check_irr(asID, prefix)
        if irrValid:
            score = score + 1
        if irrValid != None:
            irr_database[prefix] = matches
    return score
  
def compute_statistics_for_benign_conflicts(origin_matching, caida_as_org, caida_as_rel_pc, as2prefixes_dict, date, prefix, asID, vrpID, as_path, local_hege_dict, irr_database):
    score = 0
    score0 = 0
    score1 = 0
    score2 = 0
    score3 = 0
    score4 = 0
    if origin_matching == 1:
        score = 1.0

    score0 = check_irr_v2(irr_database, asID, prefix) * 1.0  # IRR
    if check_related_origin(as2prefixes_dict, prefix, asID):
        score1 = 1.0  # Parent
    if check_AS_org_v2(caida_as_org, asID, vrpID):
        score2 = 1.0  # sameorg
    if check_AS_PC(caida_as_rel_pc, asID, vrpID):
        score3 = 1.0  # PC
    if check_as_dependency(asID, vrpID, as_path, local_hege_dict):
        score4 = 1.0

    return score, score0, score1, score2, score3, score4
  
def feature_extractor():
    basic_path = "./LocalData"

    caida_as_org = {}
    with open(basic_path+'/CAIDA/caida_as_org.p', "rb") as f:
        caida_as_org = pickle.load(f)
    
    caida_as_rel_pc = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pc.p', "rb") as f:
        caida_as_rel_pc = pickle.load(f)

    with open(basic_path+"/IHR/local_hege_dict.p", "rb") as f:
        local_hege_dict = pickle.load(f)

    irr_database = {}
    with open(basic_path+"/IRR/irr_database.p", "rb") as f:
        irr_database = pickle.load(f)

    as2prefixes_dict_path = basic_path + '/ROAs/as2prefixes_dict.p'
    with open(as2prefixes_dict_path, "rb") as f:
        roa_as2prefixes_dict = pickle.load(f)
    with open(basic_path+"/CAIDA/prefixes_to_as.p", "rb") as f:
        extra_as2prefixes_dict = pickle.load(f)
    as2prefixes_dict = deepcopy(roa_as2prefixes_dict)
    for k in extra_as2prefixes_dict:
        if k in as2prefixes_dict:
            continue
        as2prefixes_dict[k] = extra_as2prefixes_dict[k]
    '''
    clf = None
    with open('./dt_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)
    
    scaler = joblib.load('./dt_scaler.gz')
    '''
    
    d_max = euclidean_distance((90, -180), (-90, 180))
    print(d_max, (2/math.pi)*math.atan(d_max))
    '''
    path = './GroundtruthData/202303/hijack_events/'
    files = os.path.join(path, "*.20220131.rov.csv")
    files = glob.glob(files)
    for ifile in files:
    '''
    
    for ty in ['benign_conflict']:  # 'bgp_hijack'
        dataset = defaultdict(list)

        #df = pd.read_csv('./GroundtruthData/Training_Data/'+ty+'.csv', header=None) 
        
        for date, prefix, as_path, asID, vrpIDs in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values):
            
            vrpIDs = str(vrpIDs)
            
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            origin_matching = 0
            for vrpID in vrpIDs.split('+'):
            	if vrpID == str(asID): origin_matching = 1

            asID = int(asID)
           
            OriginMatchs, IRRs, Parents, SameOrgs, PCs, Depens, distances = set(
            ), set(), set(), set(), set(), set(), set()
            lens = set()
            for vrpID in vrpIDs.split('+'):
                vrpID = int(vrpID)

                OriginMatch, IRR, Parent, SameOrg, PC, Depen = compute_statistics_for_benign_conflicts(
                    origin_matching, caida_as_org, caida_as_rel_pc, as2prefixes_dict, date, prefix, asID, vrpID, as_path, local_hege_dict, irr_database)
                OriginMatchs.add(OriginMatch)
                IRRs.add(IRR)
                Parents.add(Parent)
                SameOrgs.add(SameOrg)
                PCs.add(PC)
                Depens.add(Depen)
               

            OriginMatch, IRR, Parent, SameOrg, PC, Depen = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
            if 1.0 in OriginMatchs:
                OriginMatch = 1.0
            if 1.0 in IRRs:
                IRR = 1.0
            if 1.0 in Parents:
                Parent = 1.0
            if 1.0 in SameOrgs:
                SameOrg = 1.0
            if 1.0 in PCs:
                PC = 1.0
            if 1.0 in Depens:
                Depen = 1.0
            
            # if IRR > 0 or Parent > 0:continue  # only for hijacks
            #if origin_matching == 1 or IRR > 0 or Parent > 0:
            #    continue  # only for hijack events
            #ofile2.write(",".join(map(str, [date, prefix, as_path, asID, vrpIDs]))+'\n')
            

            if origin_matching == 1:
                distance = 0.0
            else:
                start = time.monotonic()
                distance = compute_pfx_distance(
                    as2prefixes_dict, prefix, asID, d_max)
                #print(prefix, distance)
                end = time.monotonic()

            if distance == None:
                continue

            '''
            a, b, c, d, e, f = 1, 1, 1.0, 0.2, 0.3, 0.6
            confi_score = a*OriginMatch + b*IRR + c*Parent + d*SameOrg + e*PC + f*Depen
            data = [confi_score, distance]
            X_test = np.array(data).reshape(1, 2)
            X_test = scaler.transform(X_test)
            label = clf.predict(X_test)[0]
            #if label == 2: 
            #	ofile.write(",".join(map(str, [date, prefix, as_path, asID, vrpIDs]))+'\n')
            #1657880312,109.107.140.0/24,None,8100,8888
            
            ofile.write(",".join(map(str, [date, prefix, asID, vrpIDs, label]))+'\n')
            '''


            dataset['time'].append(date)
            dataset['prefix'].append(prefix)
            dataset['asID'].append(asID)
            dataset['OriginMatch'].append(OriginMatch)
            dataset['IRR'].append(IRR)
            dataset['Parent'].append(Parent)
            dataset['SameOrg'].append(SameOrg)
            dataset['PC'].append(PC)  # measure for similarity
            dataset['Depen'].append(Depen)
            dataset['Distance'].append(distance)

        #ofile.close()
        df = pd.DataFrame(dataset)
        df.to_csv('./GroundtruthData/Training_Data/' + ty+'.7f.csv', index=False)
        
        #with open(basic_path+'/IRR/irr_database.p', "wb") as fp:
        #    pickle.dump(dict(irr_database), fp)
            
def main():
    feature_extractor()
   
    


if __name__ == "__main__":
    main()
