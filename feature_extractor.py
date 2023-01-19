import datetime
import requests
import pandas as pd
import time
from datetime import timedelta
from statistics import mean
import concurrent.futures
import pickle
import logging
import os
import glob
import re
import pytricia
from collections import defaultdict
from blist import *
import json
import numpy as np
from scipy.signal import argrelextrema
from multiprocessing import Process, Lock, Manager
import os.path
from itertools import groupby
# import smart_validator
import math
import statistics
import random
from scipy.stats import norm
import logging
from ctypes import *
from builtins import bytes


class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]


bogon_asns_list1 = [0, 23456, 65535, 4294967295]
bogon_asns_list2 = [range(64496, 64511+1), range(65536, 65551+1), range(
    64512, 65534+1), range(4200000000, 4294967294+1), range(65552, 131071+1)]


def is_bogon_asn(asID):
    asID = int(asID)
    if asID in bogon_asns_list1:
        return True
    for asngroup in bogon_asns_list2:
        if asID in asngroup:
            return True
    return False


def getOrgId(caida_as_org, asn):
    OrgId = None
    asn = str(asn)
    for e in caida_as_org:
        if "asn" not in e:
            continue
        if e["asn"] == asn:
            OrgId = e["organizationId"]
    return OrgId


def getCountryCode(caida_as_org, OrgId):
    cc = None
    for e in caida_as_org:
        if "country" not in e:
            continue
        if e["organizationId"] == OrgId:
            cc = e["country"]
    return cc


def check_AS_org(caida_as_org, asID, vrpID):
    isSameOrg = False

    orgid1 = getOrgId(caida_as_org, asID)
    orgid2 = getOrgId(caida_as_org, vrpID)
    if orgid1 != None and orgid2 != None:
        if orgid1 == orgid2:
            isSameOrg = True
            return isSameOrg
    return isSameOrg


def check_AS_org_v2(caida_as_org, asID, vrpID):
    isSameOrg = False

    orgid1 = caida_as_org.get(asID)
    orgid2 = caida_as_org.get(vrpID)
    if orgid1 != None and orgid2 != None:
        if orgid1 == orgid2:
            isSameOrg = True
            return isSameOrg
    return isSameOrg


def check_AS_PC(caida_as_rel_pc, asID, vrpID):
    asID = str(asID)
    vrpID = str(vrpID)
    isPC = False
    c1 = caida_as_rel_pc.get(asID)
    c2 = caida_as_rel_pc.get(vrpID)
    if (c1 is not None and vrpID in c1) or (c2 is not None and asID in c2):
        isPC = True
    return isPC


def as2prefixes(roas):
    as_dict = {}
    for binary_prefix in roas:
        for prefix_addr, prefix_len, max_len, asID in roas[binary_prefix]:
            asID = int(asID)
            if asID not in as_dict:
                as_dict[asID] = list()
            as_dict[asID].append(prefix_addr + '/' + str(prefix_len))
    return as_dict


def is_covered_old(prefix, vrp_prefix):
    pyt = None
    if ':' in vrp_prefix:
        pyt = pytricia.PyTricia(128)
    else:
        pyt = pytricia.PyTricia()

    pyt[vrp_prefix] = 'ROA'
    return vrp_prefix == pyt.get_key(prefix)


def is_covered(ipv4_dict, ipv6_dict, prefix, vrp_prefix):
    if ':' in vrp_prefix:
        if prefix in ipv6_dict.children(vrp_prefix):
            return True
    else:
        if prefix in ipv4_dict.children(vrp_prefix):
            return True


def check_related_origin(as2prefixes_dict, prefix, asID):
    rela = False
    vrp_prefixes = as2prefixes_dict.get(asID)
    if vrp_prefixes == None:
        return rela
    for vrp_prefix in vrp_prefixes:
        if vrp_prefix == prefix:
            continue
        if is_covered_old(prefix, vrp_prefix):  # less-specific prefix matching: prefix is a less-specific prefix, which covers the bgp-announced prefix and mapped to the announcing AS, it may because AS aggregation but not for sure, may be figured out through Email Survey
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


def identify_valley(asn0, asn1, asn2, caida_as_rel_pc, caida_as_rel_pp):
    FOUND = False
    pair1 = None
    pair2 = None
    depth = 0.0
    c = caida_as_rel_pc.get(asn0)
    p = caida_as_rel_pp.get(asn0)
    if (c is not None and asn1 in c):
        pair1 = 'PC'
    if (p is not None and asn1 in p):
        pair1 = 'PP'
    if pair1 == 'PC' or pair1 == 'PP':
        cc = caida_as_rel_pc.get(asn2)
        pp = caida_as_rel_pp.get(asn2)
        if (cc is not None and asn1 in cc):
            pair2 = 'CP'
        if (pp is not None and asn1 in pp):
            pair2 = 'PP'
        if pair2 == 'CP' or pair2 == 'PP':
            FOUND = True

    return FOUND, pair1, pair2


def check_AS_path(caida_as_rel_pp, caida_as_rel_pc, as_path):
    # time overhead is not over 0.01s, which can be negligible
    valleyFree = True
    pair1 = None
    pair2 = None
    # 34800+24961+3356+3257+396998+18779, to make any AS appears no more than once in the AS path
    g = as_path.split('+')
    g.reverse()
    for i in range(1, len(g)-1):
        found, pair1, pair2 = identify_valley(
            g[i-1], g[i], g[i+1], caida_as_rel_pc, caida_as_rel_pp)
        if found:
            valleyFree = False
            leaker = g[i]
            return valleyFree, pair1, pair2, leaker
    return valleyFree, pair1, pair2, None


def check_as_dependency(date, asn, vrpasn, as_path, local_hege_dict):
    # start = time.monotonic()
    if '+' + str(vrpasn) in as_path:
        return True  # vrpasn is the transit network
    if local_hege_dict.get((date, asn, vrpasn)) == 1:
        t = datetime.datetime.fromtimestamp(date, datetime.timezone.utc)
        return True
    if local_hege_dict.get((date, asn, vrpasn)) == None:
        He1 = lookup_local_hegemony(date, asn, vrpasn)
        He2 = lookup_local_hegemony(date, vrpasn, asn)
        local_hege_dict[(date, asn, vrpasn)] = (He1, He2)
    He1 = local_hege_dict.get((date, asn, vrpasn))[0]
    He2 = local_hege_dict.get((date, asn, vrpasn))[1]
    if (He1 is not None and He1 > 0) or (He2 is not None and He2 > 0):
        local_hege_dict[(date, asn, vrpasn)] = 1
        return True
    # end = time.monotonic()
    # elapsed = end-start
    # print('check_as_dependency: ', elapsed)
    return False


def check_as_dependency_v2(asn, vrpasn, as_path, local_hege_dict):
    if '+' + str(vrpasn) in as_path:
        return True  # vrpasn is the transit network
    if (local_hege_dict.get(vrpasn) != None and asn in local_hege_dict[vrpasn]['asns']) or (local_hege_dict.get(asn) != None and vrpasn in local_hege_dict[asn]['asns']):
        return True

    return False


def lookup_local_hegemony(date, originasn, asn):
    # date = date-3600*24
    t = datetime.datetime.fromtimestamp(date, datetime.timezone.utc)
    lte_time = datetime.datetime.strftime(t, '%Y-%m-%dT%H:%M')
    print(lte_time)
    mm = int(lte_time.split('T')[1].split(':')[1])
    mm = int(mm/15) * 15
    if mm == 0:
        mm = '00'
    gte_time = lte_time.split(':')[0] + ':'+str(mm)
    af = 4
    base_url = "https://ihr.iijlab.net/ihr/api/hegemony/?"
    local_api = "originasn=%s&asn=%s&af=%s&timebin=%s&format=json"
    query_url = base_url + local_api % (originasn, asn, af, gte_time)
    try:
        rsp = requests.get(query_url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
        })
        rsp = rsp.json()
        if ('results' in rsp) and (len(rsp['results']) != 0):
            results = rsp['results']
            for res in results:
                he = float(res['hege'])
                return he
        else:

            gte_time = datetime.datetime.strftime(
                t - timedelta(minutes=3*24*60), '%Y-%m-%dT%H:%M')
            updated = '&timebin__gte=%s&timebin__lte=%s&format' % (
                gte_time, lte_time)
            query_url = query_url.split(
                '&timebin')[0] + updated + query_url.split('&format')[1]
            rsp = requests.get(query_url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
            })

            rsp = rsp.json()
            results = rsp['results']
            if len(results) == 0:
                return 0.0
            he = float(results[0]['hege'])
            return he
    except:
        return None
    '''
	hes = list()
	for res in results:
		he = float(res['hege'])
		hes.append(he)
	if len(hes) == 0:
		he = 0.0
		return he
	else:
		he = mean(hes)
		return he
	'''


def globalhe(date, asn):
    He = lookup_local_hegemony(date, 0, asn)
    return date, asn, He


def localhe(date, asn0, asn1):
    He = 0.0
    He = lookup_local_hegemony(date, asn0, asn1)
    return He


def as_hegemony_v2(date, hops):
    Hes = list()

    for hop in hops:
        He = globalhe(date, hop)
        Hes.append(He)
    print(Hes)


def create_globalhe_database(dic, date, hops):
    for hop in hops:
        dic[(date, hop)] = 1


def collect_asns():
    dic = {}
    for ty in ['benign_misconfiguration', 'valid', 'route_leak', 'bgp_hijacks']:
        df = pd.read_csv('./GroundtruthData/FourClasses/'+ty+'.csv')
        for date, as_path in zip(df.iloc[:, 0].values, df.iloc[:, 2].values):
            hops = as_path.split('+')
            create_globalhe_database(dic, date, hops)
        print(ty, len(dic.keys()))
    print(len(dic.keys()))
    with open("global_hege_asns.p", "wb") as fp:
        pickle.dump(dict(dic), fp)


def collect_pfxes():
    dic = defaultdict(list)
    for ty in ['benign_misconfiguration', 'valid', 'route_leak', 'bgp_hijacks']:
        df = pd.read_csv('./GroundtruthData/FourClasses/'+ty+'.csv')
        for prefix in zip(df.iloc[:, 1].values):
            try:
                if dic.get(prefix) != None:
                    continue
                cmd = """ whois -h whois.radb.net %s""" % (
                    prefix)  # query to RADb database
                out = os.popen(cmd).read()
                if 'No entries found' in out:
                    continue
                matches = re.findall(r'origin:\s+AS(\d+)', out)
                if len(matches) == 0:
                    continue
                dic[prefix] = matches
            except:
                continue
    with open("irr_database.p", "wb") as fp:
        pickle.dump(dict(dic), fp)


def validateOrigin(prefix_addr, prefix_len, asID, roa_px_dict, time):
    """
    This implementation is based on RFC 6811; Section 2
    """
    origin_matching = 0  # False
    maxlength_matching = 0  # False

    roas = roa_px_dict[time][0]
    ipv4_dict = roa_px_dict[time][1]
    ipv6_dict = roa_px_dict[time][2]

    entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
    results = []
    if (entry is None):  # unknown to RPKI
        return results

    vrp_prefix_addr, vrp_prefix_len = entry.split('/')
    binary_prefix = ip2binary(vrp_prefix_addr, vrp_prefix_len)
    # an IP Prefix can match multiple ROAs, e.g., in multihoming context
    for vrp_prefix, vrp_prefixlen, vrp_maxlen, vrp_asID in roas[binary_prefix]:
        if(vrp_asID == asID):
            origin_matching = 1
            if prefix_len <= vrp_maxlen:
                maxlength_matching = 1
                results = []
                results.append((origin_matching, maxlength_matching, vrp_asID))
                return results
            else:
                maxlength_matching = 0
        else:
            origin_matching = 0
            if prefix_len <= vrp_maxlen:
                maxlength_matching = 1
            else:
                maxlength_matching = 0
        results.append((origin_matching, maxlength_matching, vrp_asID))
    return results


def ip2binary(prefix_addr, prefix_len):
    if("." in prefix_addr):  # IPv4
        octets = map(lambda v: int(v), prefix_addr.split("."))
        # ['00000011', '00000000', '00000000', '00000000']
        octets = map(lambda v: format(v, "#010b")[2:], octets)

    else:  # IPv6
        octets = map(lambda v: str(v), prefix_addr.split(":"))
        prefix_addrs = prefix_addr.split(":")

        for i in range(8 - len(prefix_addrs)):
            idx = prefix_addrs.index("")
            prefix_addrs.insert(idx, "")

        # 8 groups, each of them has 16 bytes (= four hexadecimal digits)
        prefix_addrs += [""] * (8 - len(prefix_addrs))

        octets = []
        for p in prefix_addrs:
            if(len(p) != 4):  # 4 bytes
                p += (4 - len(p)) * '0'
            octets.append(
                "".join(map(lambda v: format(int(v, 16), "#010b")[6:], p)))

    return "".join(octets)[:int(prefix_len)]


def myParseROA(line):
    if("URI,ASN" in line):
        return None
    _, asn, ip_prefix, maxlen, _, _ = line.rstrip().split(",")
    prefix_addr, prefix_len = ip_prefix.split('/')
    # time = '20220609'
    prefix_len = int(prefix_len)
    if maxlen == '':
        maxlen = prefix_len
    else:
        maxlen = int(float(maxlen))
    asn = asn.split("AS")[1]
    asn = int(asn)
    return (prefix_addr, prefix_len, maxlen, asn)


def myMakeROABinaryPrefixDict(roas_dict):
    roas = {}
    ipv4_dict = pytricia.PyTricia()
    ipv6_dict = pytricia.PyTricia(128)

    for prefix_addr, prefix_len, max_len, asID in roas_dict:
        binary_prefix = ip2binary(prefix_addr, prefix_len)

        if(binary_prefix not in roas):
            roas[binary_prefix] = set()
        roas[binary_prefix].add((prefix_addr, prefix_len, max_len, asID))
        if(":" in prefix_addr):
            ipv6_dict.insert(prefix_addr+'/'+str(prefix_len), 'ROA')
        else:
            ipv4_dict.insert(prefix_addr+'/'+str(prefix_len), 'ROA')

    return roas, ipv4_dict, ipv6_dict


def load_ROAs(roa_path):
    roas_dict = defaultdict(set)
    with open(roa_path) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            roa = myParseROA(line)
            if roa != None:
                prefix_addr, prefix_len = roa[0], roa[1]
                binary_prefix = ip2binary(prefix_addr, prefix_len)
                roas_dict[binary_prefix].add(roa)
    return roas_dict


def load_caida_as_org():
    caida_as_org = None
    with open("/home/zhao/Shujie/Routing_traffic/coding/20220701.as-org2info.jsonl") as f:
        caida_as_org = [json.loads(jline) for jline in f]
    return caida_as_org


def load_caida_as_rel():
    caida_as_rel_pc = {}
    caida_as_rel_pp = {}
    with open("/home/zhao/Shujie/Routing_traffic/coding/20230101.as-rel.txt") as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            if '#' in line:
                continue
            p, c, code = line.split('|')
            code = int(code.strip('\n'))
            if code == -1:
                if p not in caida_as_rel_pc:
                    caida_as_rel_pc[p] = set()
                caida_as_rel_pc[p].add(c)
            if code == 0:
                if p not in caida_as_rel_pp:
                    caida_as_rel_pp[p] = set()
                caida_as_rel_pp[p].add(c)

                if c not in caida_as_rel_pp:
                    caida_as_rel_pp[c] = set()
                caida_as_rel_pp[c].add(p)

    return caida_as_rel_pc, caida_as_rel_pp


def features():
    y, m, d = str(datetime.datetime.fromtimestamp(
        int(date), datetime.timezone.utc)).split(' ')[0].split('-')
    roas_dict_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+y+m+d+'/roas_dict.p'
    roas = {}
    with open(roas_dict_path, "rb") as f:
        roas = pickle.load(f)
    # roas, ipv4_dict, ipv6_dict = myMakeROABinaryPrefixDict(roas_dict)

    asID = int(asID)
    if is_bogon_asn(asID):
        return
    vrpID = int(vrpID)

    prefix_addr, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    maxlen = int(maxlen)

    origin_matching = 0
    maxlength_matching = 0
    if asID == vrpID:
        origin_matching = 1
    if prefix_len <= maxlen:
        maxlength_matching = 1

    confScore = 0
    score1 = 0
    score2 = 0
    score3 = 0
    if origin_matching == 1 and maxlength_matching == 1:
        score1 = score1 + 1
    else:
        if check_AS_org(caida_as_org, asID, vrpID) or check_AS_PC(caida_as_rel_pc, asID, vrpID) or check_related_origin(roas, prefix, asID) or check_as_dependency(date, asID, vrpID, as_path, local_hege_dict):
            score1 = score1 + 1
    if check_irr(asID, prefix):
        score2 = score2 + 1
    valleyFree = check_AS_path(caida_as_rel_pp, caida_as_rel_pc, as_path)
    if not valleyFree:
        score3 = score3 - 1
    confScore = score1 + score2 + score3
    hops = as_path.split('+')
    depth, Hes = compute_hege_depth(date, hops, global_hege_dict)
    dataset['origin_matching'].append(origin_matching)
    dataset['maxlength_matching'].append(maxlength_matching)
    dataset['score1'].append(score1)
    dataset['score2'].append(score2)
    dataset['score3'].append(score3)
    dataset['confidence_score'].append(confScore)
    dataset['hege_depth'].append(depth)
    dataset['Hes'].append(list(Hes))


def check_irr_v2(irr_database, asID, prefix):
    score2 = 0
    if irr_database.get(prefix) != None and irr_database.get(prefix) != 1:
        if str(asID) in irr_database.get(prefix):
            score2 = score2 + 1
    else:
        irrValid, matches = check_irr(asID, prefix)
        if irrValid:
            score2 = score2 + 1
        if irrValid != None:
            irr_database[prefix] = matches
    return score2


def compute_two_scores_v2(rpki_status, caida_as_org, caida_as_rel_pc, as2prefixes_dict, prefix, asID, vrpID, as_path, local_hege_dict):
    score0 = 0
    score1 = 0
    if rpki_status == 1:
        score0 = score0 + 1
        score1 = score1 + 1
    else:
        isSameOrg = check_AS_org(caida_as_org, asID, vrpID)
        if isSameOrg or check_AS_PC(caida_as_rel_pc, asID, vrpID) or check_related_origin(as2prefixes_dict, prefix, asID) or check_as_dependency_v2(asID, vrpID, as_path, local_hege_dict) or check_irr(asID, prefix):
            score1 = score1 + 1
        if isSameCc:
            score0 = score0 + 1
    return score0, score1


def compute_two_scores(rpki_status, caida_as_org, caida_as_rel_pc, as2prefixes_dict, date, prefix, asID, vrpID, as_path, local_hege_dict):
    score0 = 0
    score1 = 0
    if rpki_status == 1:
        score0 = score0 + 1
        score1 = score1 + 1
    else:
        isSameOrg = check_AS_org(caida_as_org, asID, vrpID)
        if isSameOrg or check_AS_PC(caida_as_rel_pc, asID, vrpID) or check_related_origin(as2prefixes_dict, prefix, asID) or check_as_dependency(date, asID, vrpID, as_path, local_hege_dict) or check_irr(asID, prefix):
            score1 = score1 + 1
        if isSameCc:
            score0 = score0 + 1
    return score0, score1


def compute_two_scores_new(origin_matching, caida_as_org, caida_as_rel_pc, as2prefixes_dict, date, prefix, asID, vrpID, as_path, local_hege_dict, irr_database):
    score = 0
    score0 = 0
    score1 = 0
    score2 = 0
    score3 = 0
    score4 = 0
    if origin_matching == 1:
        score = score + 1
    else:

        score0 = check_irr_v2(irr_database, asID, prefix) * 0.4  # IRR
        if check_related_origin(as2prefixes_dict, prefix, asID):
            score1 = 0.4  # Parent
        if check_AS_org_v2(caida_as_org, asID, vrpID):
            score2 = 0.2  # sameorg
            score = score0 + score1 + score2
        elif check_AS_PC(caida_as_rel_pc, asID, vrpID):
            score3 = 0.2  # PC
            score = score0 + score1 + score3
        elif check_as_dependency_v2(asID, vrpID, as_path, local_hege_dict):
            score4 = 0.2  # depen
            score = score0 + score1 + score4
    return score0, score1, score2, score3, score4, score


def compute_score2(asID, prefix):
    score2 = 0
    if check_irr(asID, prefix):
        score2 = score2 + 1
    return score2


def compute_score3(caida_as_rel_pp, caida_as_rel_pc, as_path):
    score3 = 0
    valleyFree, pair1, pair2, leaker = check_AS_path(
        caida_as_rel_pp, caida_as_rel_pc, as_path)
    if not valleyFree:
        score3 = score3 + 0.5
    return score3, pair1, pair2, leaker


def mini_samples():
    f = open('./GroundtruthData/FourClasses/valid.mini.csv', 'w')
    with open('./GroundtruthData/FourClasses/valid.csv') as filehandle:
        filecontents = filehandle.readlines()
        N = len(filecontents)
        print(N)
        # Num of samples: 2000, 5000, 10000, 15000
        rands = random.sample(range(1, N), 500)
        for i, line in enumerate(filecontents):
            if i in rands:
                f.write(line)
    f.close()


def select_random_samples():
    f = open(
        './GroundtruthData/FourClasses/new_features/valid.mini.filtered.5000.4f.csv', 'w')
    f.write('time,prefix,asID,origin_matching,maxlength_matching,' +
            'rpki_status,score1,score2,score3,distance,hege_depth,path_len'+'\n')
    with open('./GroundtruthData/FourClasses/new_features/valid.reduced.filtered.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        N = len(filecontents)
        print(N)
        # Num of samples: 2000, 5000, 10000, 15000
        rands = random.sample(range(1, N), 5000)
        for i, line in enumerate(filecontents):
            if i in rands:
                f.write(line)
    f.close()


def extract_features(ifile, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database):
    dataset = defaultdict(list)
    df = pd.read_csv(ifile, header=None)
    for date, prefix, as_path, asID, vrpID, maxlen in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values, df.iloc[:, 5].values):
        y, m, d = str(datetime.datetime.fromtimestamp(
            int(date), datetime.timezone.utc)).split(' ')[0].split('-')
        # if ty in ['valid', 'benign_misconfiguration']:
        #	y, m, d = '2022', '06', '30'
        as2prefixes_dict = {}
        as2prefixes_dict_path = '/home/zhao/Shujie/Routing_traffic/ROAs/' + \
            y+m+d+'/as2prefixes_dict.p'
        if not os.path.exists(as2prefixes_dict_path):
            continue
        with open(as2prefixes_dict_path, "rb") as f:
            as2prefixes_dict = pickle.load(f)
        # roas, ipv4_dict, ipv6_dict = myMakeROABinaryPrefixDict(roas_dict)

        asID = int(asID)
        if is_bogon_asn(asID):
            continue
        vrpID = int(vrpID)

        prefix_addr, prefix_len = prefix.split('/')
        prefix_len = int(prefix_len)
        maxlen = int(maxlen)

        origin_matching = 0
        maxlength_matching = 0
        if asID == vrpID:
            origin_matching = 1
        if prefix_len <= maxlen:
            maxlength_matching = 1

        rpki_status = 0
        if origin_matching == 1 and maxlength_matching == 1:
            rpki_status = 1

        confScore = 0
        score1 = 0
        score2 = 0
        score3 = 0
        hops = as_path.split('+')
        start = time.monotonic()
        _, score1 = compute_two_scores(rpki_status, caida_as_org, caida_as_rel_pc, as2prefixes_dict,
                                       date, prefix, asID, vrpID, as_path, local_hege_dict)  # score1: isSameCc?

        '''
		if irr_database.get(prefix) != None:
			try:
				if str(asID) in irr_database.get(prefix):
					score2 = score2 + 1
			except:
				print('prefix:', prefix)
		else:
			score2 = compute_score2(asID, prefix)
		'''

        score3 = compute_score3(caida_as_rel_pp, caida_as_rel_pc, as_path)
        maxdepth, Hes = compute_hege_depth(
            date, hops, global_hege_dict, local_hege_dict)
        # if maxdepth == None and Hes == None: continue # default values should be set as zero
        if origin_matching == 1:
            distance = 0.0
        else:
            distance = compute_pfx_distance(as2prefixes_dict, prefix, asID)
        end = time.monotonic()
        elapsed = end-start
        print('time: ', elapsed)
        confScore = score1 + score2 + score3
        dataset['time'].append(date)
        dataset['prefix'].append(prefix)
        dataset['asID'].append(asID)
        dataset['origin_matching'].append(origin_matching)
        dataset['maxlength_matching'].append(maxlength_matching)
        dataset['rpki_status'].append(rpki_status)
        dataset['score1'].append(score1)
        dataset['score2'].append(score2)
        dataset['score3'].append(score3)
        # dataset['confidence_score'].append(confScore)
        dataset['distance'].append(distance)  # measure for similarity
        dataset['hege_depth'].append(maxdepth)
        dataset['Hes'].append(list(Hes))
    df = pd.DataFrame(dataset)
    df.to_csv(ifile+'.4f.csv', index=False)


def feature_extractor_with_futures():
    caida_as_org = load_caida_as_org()
    caida_as_rel_pc, caida_as_rel_pp = load_caida_as_rel()
    global_hege_dict = {}
    local_hege_dict = {}
    with open("global_hege_dict.p", "rb") as f:
        global_hege_dict = pickle.load(f)
    with open("local_hege_dict.p", "rb") as f:
        local_hege_dict = pickle.load(f)
    irr_database = {}
    with open("irr_database.p", "rb") as f:
        irr_database = pickle.load(f)
    print(len(irr_database))
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        file_path = './ValidateData/valid_split_data'
        files = os.path.join(file_path, "*")
        files = glob.glob(files)
        for ifile in files:
            futures.append(executor.submit(extract_features, ifile, caida_as_org, caida_as_rel_pp,
                                           caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database))
        for future in concurrent.futures.as_completed(futures):
            future.result()


def extend_as2prefixes_dict(as2prefixes_dict):
    with open("/home/zhao/Shujie/Routing_traffic/coding/LocalData/CAIDA/prefixes_to_as.p", "rb") as f:
        new_as2prefixes_dict = pickle.load(f)
    for asn in new_as2prefixes_dict:
        if asn in as2prefixes_dict:
            continue
        as2prefixes_dict[asn] = new_as2prefixes_dict[asn]
    return as2prefixes_dict


'''
	file_path = './BGPincidents'
	files = os.path.join(file_path, "bgp_hijacks.*.reduced.csv")
	files = glob.glob(files)
	for ifile in files:
		dataset = defaultdict(list)
		df = pd.read_csv(ifile, header = None)
		ty = ifile.split('/')[-1].split('.')[1]
		print(ty)
	'''


def feature_extractor():
    caida_as_org = {}
    with open("caida_as_org.p", "rb") as f:
        caida_as_org = pickle.load(f)
    caida_as_rel_pc, caida_as_rel_pp = load_caida_as_rel()
    global_hege_dict = {}
    local_hege_dict = {}
    with open("./LocalData/IHR/global_hege_dict.p", "rb") as f:
        global_hege_dict = pickle.load(f)
    
    with open("./LocalData/IHR/local_hege_dict.p", "rb") as f:
        local_hege_dict = pickle.load(f)
    print(len(global_hege_dict))
    irr_database = {}
    with open("irr_database.p", "rb") as f:
        irr_database = pickle.load(f)

    valid_hege_depth = {}
    with open("./valid_hege_depth.p", "rb") as f:
        valid_hege_depth = pickle.load(f)

    benign_misconfiguration_hege_depth = {}
    with open("./benign_misconfiguration_hege_depth.p", "rb") as f:
        benign_misconfiguration_hege_depth = pickle.load(f)

    # for ty in ['route_leak.20211224later']: #'valid.mini', 'route_leak', 'bgp_hijacks', 'benign_misconfiguration.mini'
    for ty in ['route_leak.20190624']:  # 'route_leak', 'bgp_hijacks', route_leak.20190624, route_leak.20210603, route_leak.20210819
        
        dataset = defaultdict(list)
        #df = pd.read_csv('./GroundtruthData/FourClasses/'+ty+'.csv')
        df = pd.read_csv('./BGPincidents/'+ty+'.reduced.csv', header= None)
        # df = pd.read_csv('./ValidateData/'+ty+'.20220715.csv', header=None)
        # 1657901279,103.76.255.0/24,138540+4775+8100,8100,7018,24,Possible BGP hijack
        for date, prefix, as_path, asID, vrpID, maxlen in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values, df.iloc[:, 5].values):
            #valley_depth = hege_depth[(date, asID, prefix)]
            y, m, d = str(datetime.datetime.fromtimestamp(
                int(date), datetime.timezone.utc)).split(' ')[0].split('-')
            # if ty in ['valid', 'benign_misconfiguration']:
            #	y, m, d = '2022', '06', '30'
            as2prefixes_dict = {}
            as2prefixes_dict_path = '/home/zhao/Shujie/Routing_traffic/ROAs/' + \
                y+m+d+'/as2prefixes_dict.p'
            if not os.path.exists(as2prefixes_dict_path):
                print('no as2prefixes dict: ', y, m, d)
                continue
            with open(as2prefixes_dict_path, "rb") as f:
                as2prefixes_dict = pickle.load(f)

            # as2prefixes_dict = extend_as2prefixes_dict(as2prefixes_dict)
            # roas, ipv4_dict, ipv6_dict = myMakeROABinaryPrefixDict(roas_dict)
            
            asID = int(asID)
            if is_bogon_asn(asID):
                continue
            vrpID = int(vrpID)

            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            maxlen = int(maxlen)

            origin_matching = 0
            maxlength_matching = 0
            if asID == vrpID:
                origin_matching = 1
            if prefix_len <= maxlen:
                maxlength_matching = 1

            rpki_status = 0
            if origin_matching == 1 and maxlength_matching == 1:
                rpki_status = 1

            hops = as_path.split('+')
            for hop in hops:
                if is_bogon_asn(hop):
                    continue
            # hops = [x for x in hops if x not in IXP_ASes]
            pathlen = len(hops)
            start = time.monotonic()
            _, _, _, _, _, confi_score = compute_two_scores_new(
                origin_matching, caida_as_org, caida_as_rel_pc, as2prefixes_dict, date, prefix, asID, vrpID, '+'.join(hops), local_hege_dict, irr_database)

            valley_score, pair1, pair2, leaker = compute_score3(
                caida_as_rel_pp, caida_as_rel_pc, as_path)
            # the following two-line code only used for filtering route leak events: filter cases in which no valley exists in the path because we cannot guarantee they are malicious or benign in bgp incidents
            
            # Test for historical incident
            print(leaker)
            if leaker != '396531':
                continue
            
            print(leaker, pair1, pair2)
            valley_depth, Hes = 0.0, []
            if leaker != None:  # we use the average depth instead of absolute depth
            	valley_depth, Hes = compute_hege_depth_v2(date, hops, global_hege_dict)
            	

            path_anomaly = valley_score + valley_depth
            print('path_anomaly: ', path_anomaly)
            if origin_matching == 1:
                distance = 0.0
            else:
                distance = compute_pfx_distance(as2prefixes_dict, prefix, asID)

            end = time.monotonic()
            elapsed = end-start
            # print('time: ', elapsed)

            dataset['time'].append(date)
            dataset['prefix'].append(prefix)
            dataset['asID'].append(asID)
            dataset['origin_matching'].append(origin_matching)
            dataset['maxlength_matching'].append(maxlength_matching)
            dataset['rpki_status'].append(rpki_status)
            dataset['confi_score'].append(confi_score)
            dataset['distance'].append(distance)  # measure for similarity
            dataset['path_anomaly'].append(path_anomaly)

        df = pd.DataFrame(dataset)
        df.to_csv('./BGPincidents/'+ty+'.4f.csv', index=False)
        # df.to_csv('./ValidateData/'+ty+'.20220715.4f.csv', index=False)
        # df.to_csv('./GroundtruthData/FourClasses/new_measurements/' +ty+'.4f.csv', index=False)
    print(len(global_hege_dict))
    with open("global_hege_dict.p", "wb") as fp:
        pickle.dump(dict(global_hege_dict), fp)
    with open("local_hege_dict.p", "wb") as fp:
        pickle.dump(dict(local_hege_dict), fp)


def compute_hege_depth_v2(date, hops, global_hege_dict):
    Hes = list()
    maxdepth = 0.0
    for asn in hops:
        He = 0.0
        asn = int(asn)
        
        if global_hege_dict.get(asn) == None:
            # _, _, He = lookup_local_hegemony_v2(date, '0', asn)
            # print('asn and He: ', asn, He) # check why He is always be zero and just one
            # if He == None: return maxdepth, Hes
            He = 0.0
        else:
            He = global_hege_dict[asn]['heg']
        Hes.append(He)
    # identify the potential anomaly in the path
    Hes = np.array(Hes)
    print('Hes: ', Hes)
    depths = list()
    indices = list()
    locmins = list(argrelextrema(Hes, np.less)[0])
    
    if len(locmins) == 0:
        return maxdepth, Hes
    locmaxs = list(argrelextrema(Hes, np.greater)[0])
    
    locs = sorted(locmins + locmaxs)
    if locs[0] in locmins:
        locs.insert(0, 0)
    if locs[-1] in locmins:
        locs.append(len(Hes)-1)
    locs = sorted(locs)
    for i, loc in enumerate(locs):
        if i == 0:
            continue
        if i == len(locs) - 1:
            continue
        if loc in locmins:
            minv = Hes[loc]
            maxv1 = Hes[locs[i-1]]
            maxv2 = Hes[locs[i+1]]
            avedepth = (((maxv1-minv)/maxv1 + (maxv2-minv)/maxv2)/2) / \
                (locs[i+1]-locs[i-1])  # depth/lengthofvalley
            depths.append(avedepth)
            indices.append(loc)
    if len(depths) > 0:
        maxdepth = max(depths)
        i = depths.index(maxdepth)
        loc = indices[i]
    return maxdepth, Hes


def compute_hege_depth(date, hops, global_hege_dict, local_hege_dict):
    Hes = list()
    maxdepth = 0.0
    for asn in hops:
        He = 0.0
        if global_hege_dict.get((date, asn)) == None:
            _, _, He = globalhe(date, asn)

            if He == None:
                return maxdepth, Hes
            global_hege_dict[(date, asn)] = He
        He = global_hege_dict[(date, asn)]
        Hes.append(He)
    # identify the potential anomaly in the path
    Hes = np.array(Hes)
    depths = list()
    indices = list()
    locmins = list(argrelextrema(Hes, np.less)[0])
    if len(locmins) == 0:
        return maxdepth, Hes
    locmaxs = list(argrelextrema(Hes, np.greater)[0])
    locs = sorted(locmins + locmaxs)
    if locs[0] in locmins:
        locs.insert(0, 0)
    if locs[-1] in locmins:
        locs.insert(-1, len(Hes)-1)
    for i, loc in enumerate(locs):
        if i == 0:
            continue
        if i == len(locs) - 1:
            continue
        if loc in locmins:
            minv = Hes[loc]
            maxv1 = Hes[locs[i-1]]
            maxv2 = Hes[locs[i+1]]
            avedepth = (((maxv1-minv)/maxv1 + (maxv2-minv)/maxv2)/2) / \
                (locs[i+1]-locs[i-1])  # depth/lengthofvalley
            depths.append(avedepth)
            indices.append(loc)
    if len(depths) > 0:
        maxdepth = max(depths)
        i = depths.index(maxdepth)
        loc = indices[i]
    return maxdepth, Hes


def checkglobalhe(date, asn, global_hege_dict):
    if global_hege_dict.get((date, asn)) == None:
        He = lookup_local_hegemony(date, 0, asn)
        print(He)
        return date, asn, He
    return date, asn, global_hege_dict.get((date, asn))


def global_hege_dict():
    # collect_asns()
    global_hege_dict = {}
    with open("global_hege_dict.p", "rb") as f:
        global_hege_dict = pickle.load(f)
    with open("global_hege_asns.p", "rb") as f:
        asn_dict = pickle.load(f)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for t in asn_dict:
                futures.append(executor.submit(
                    checkglobalhe, t[0], t[1], global_hege_dict))
            for future in concurrent.futures.as_completed(futures):
                date, asn, He = future.result()
                global_hege_dict[(date, asn)] = He

    with open("global_hege_dict.p", "wb") as fp:
        pickle.dump(dict(global_hege_dict), fp)


def roas_dict():
    # global_hege_dict()
    
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs'
    files = os.path.join(roa_path, "20171106/roas_dict.p")
    files = glob.glob(files)
    for ifile in files:
        date = re.search(r'\d+', ifile).group(0)
        if os.path.exists(roa_path+'/'+date+'/'+'as2prefixes_dict.p'):
            continue
        print(date)
        roas = {}
        with open(ifile, "rb") as f:
            roas = pickle.load(f)
        as2prefixes_dict = as2prefixes(roas)
        with open(roa_path+'/'+date+'/as2prefixes_dict.p', "wb") as fp:
            pickle.dump(dict(as2prefixes_dict), fp)
    
    '''
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs'
    files = os.path.join(roa_path, "20171106/all.roas.csv")
    files = glob.glob(files)
    for ifile in files:
          date = re.search(r'\d+', ifile).group(0)
          if os.path.exists(roa_path+'/'+date+'/'+'roas_dict.p'):
                continue
          print(date)
          roas_dict = load_ROAs(ifile)
          with open(roa_path+'/'+date+'/roas_dict.p', "wb") as fp:
                pickle.dump(dict(roas_dict), fp)
    '''
    


def global_hege_dict_more():
    global_hege_dict = {}
    mini_list = blist()
    with open("global_hege_dict.p", "rb") as f:
        global_hege_dict = pickle.load(f)
    print(len(global_hege_dict.keys()))
    for date, asn in global_hege_dict:
        if global_hege_dict[(date, asn)] == None:
            mini_list.append((date, asn))
    print(len(mini_list))
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for date, asn in mini_list:
            futures.append(executor.submit(globalhe, date, asn))
        for future in concurrent.futures.as_completed(futures):
            date, asn, He = future.result()
            print(date, asn, He)
            global_hege_dict[(date, asn)] = He
    with open("global_hege_dict.p", "wb") as fp:
        pickle.dump(dict(global_hege_dict), fp)


def under_sampling(ifile):
    f = open(
        './GroundtruthData/FourClasses/valid.split.dat/valid.undersampled.csv', 'w')
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        count = 0
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            asID = fields[3]
            asID = int(asID)
            if is_bogon_asn(asID):
                continue
            f.write(line)
            count = count + 1
            if count == 7300:
                break
    f.close()


def generate_feature_file_v2():
    of = open(
        './GroundtruthData/FourClasses/new_features/bgp_classifier.4f.csv', 'w')
    # valid.undersampled.reduced.filtered
    for ty in ['valid.mini', 'benign_misconfiguration.mini.filtered', 'route_leak', 'bgp_hijacks']:
        f = './GroundtruthData/FourClasses/new_features/'+ty+'.4f.csv'
        with open(f) as filehandle:
            ty = 0
            if 'valid' in f:
                ty = 1
            elif 'benign' in f:
                ty = 1
            elif 'route' in f:
                ty = 2
            elif 'hijacks' in f:
                ty = 2
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                if i == 0:
                    continue
                line = line.strip('\n')
                line = line+','+str(ty)+'\n'
                # line = line + ',' + str(ty) +'\n'
                of.write(line)
    of.close()


def generate_feature_file():
    of = open(
        './GroundtruthData/FourClasses/new_features/bgp_classifier.5000.2f.csv', 'w')
    # valid.undersampled.reduced.filtered
    for ty in ['valid.mini.filtered.5000', 'benign_misconfiguration.reduced.filtered', 'route_leak', 'bgp_hijacks']:
        f = './GroundtruthData/FourClasses/new_features/'+ty+'.4f.csv'
        with open(f) as filehandle:
            ty = 0
            if 'valid' in f:
                ty = 1
            elif 'benign' in f:
                ty = 1
            elif 'route' in f:
                ty = 2
            elif 'hijacks' in f:
                ty = 2
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                if i == 0:
                    continue
                line = line.strip('\n')
                line = line+','+str(ty)+'\n'
                # line = line + ',' + str(ty) +'\n'
                of.write(line)
    of.close()


def combine_csv_files():
    files = os.path.join('./ValidateData/valid_split_data', '*.4f.csv')

    # list of merged files returned
    files = glob.glob(files)

    # joining files with concat and read_csv
    df = pd.concat(map(pd.read_csv, files), ignore_index=True)
    df.to_csv('./ValidateData/valid.4f.csv', index=False)


def process(outfile):
    dic = defaultdict(set)
    with open(outfile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            g = line.split('|')
            ty = g[0]
            timestamp = int(float(g[-2]))
            prefixes = g[1].split(' ')
            for prefix in prefixes:
                prefix_addr, prefix_len = prefix.split('/')
                prefix_len = int(prefix_len)
                peer = g[8].split(' ')[1]
                if ty == '+':
                    as_path = g[2]
                    if "{" in as_path or ":" in as_path:
                        continue
                    # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                    hops = [k for k, g in groupby(as_path.split(" "))]
                    if len(hops) > 1 and hops[0] == peer:
                        asID = int(hops[-1])
                        dic[asID].add(prefix)
    return dic


def compute_q_value(y, m, d, fn, asID):
    infile = '/home/zhao/Shujie/Routing_traffic/bgpdata/'+y+'.'+m+'.'+d+'/'+fn
    outfile = infile.replace('.bz2', '.txt')
    cmd = """ bgpscanner %s > %s """ % (infile, outfile)
    os.system(cmd)
    dic = process(outfile)
    times = list()
    qs = list()
    prefixes = dic[asID]
    print(prefixes)

    '''
	for timestamp, _, _ in dic[prefix]:
		times.append(timestamp)
	times = sorted(times)
	q = 0
	for i in range(len(times)):
		if i == 0:
			delta_time = 0
		else:
			delta_time = times[i] - times[i-1]
		q = 1 + 2**(-(1/300)*delta_time)*q
		qs.append(q)
	'''
    # print(times)
    # print(qs)


def test_q_statistics():
    df = pd.read_csv(
        './GroundtruthData/FourClasses/benign_misconfiguration.csv')
    n = 0
    for date, prefix, as_path, asID, vrpID, maxlen in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values, df.iloc[:, 5].values):
        date = int(date)
        t = str(datetime.datetime.fromtimestamp(date, datetime.timezone.utc))
        # updates.20211231.1615.bz2
        print(t)
        y, m, d = t.split(' ')[0].split('-')
        hh, mm, ss, _ = t.split(' ')[1].split(':')
        mm = int(int(mm)/15) * 15
        if mm == 0:
            mm = '00'
        fn = 'updates.'+y+m+d+'.'+hh+str(mm)+'.bz2'
        print(fn)
        # compute_q_value(y, m, d, fn, asID)
        test_as2prefixes(y, m, d, date, asID)
        n = n+1
        if n == 1:
            break


def accessGeoIP2data(ip):
    ip = bytes(ip, 'utf-8')
    ip = go_string(c_char_p(ip), len(ip))
    lib.lookup.restype = np.ctypeslib.ndpointer(dtype=float, shape=(2,))
    loc = lib.lookup(ip)
    return loc[0], loc[1]

# this method will be modified!!!!


def compute_pfx_distance(as2prefixes_dict, prefix, asID):
    '''
    date = '20220729'
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
    roa_px_dict = smart_validator.load_ROAs(roa_path, date)
    prefix_addr = prefix.split('/')[0]
    prefix_len = int(prefix.split('/')[1])
    results, invalid = smart_validator.validateOrigin(
        prefix_addr, prefix_len, timestamp, None, int(asID), roa_px_dict, date)
    if not invalid:
            print(y+m+d, results)
    '''
    ip = prefix.split('/')[0]
    asID = int(asID)
    vrp_prefixes = as2prefixes_dict.get(asID)  # here !!!!!
    '''
    if vrp_prefixes == None:
        with open("/home/zhao/Shujie/Routing_traffic/coding/LocalData/CAIDA/prefixes_to_as.p", "rb") as f:
            new_as2prefixes_dict = pickle.load(f)
        vrp_prefixes = new_as2prefixes_dict.get(asID)
        if vrp_prefixes == None:
            d = 1.0
            return d
    '''
    
    if vrp_prefixes == None:
    	d = 1.0
    	return d
    
    start = time.monotonic()
    x0, y0 = accessGeoIP2data(ip)

    if x0 == y0 == 9999.0:
        print('No info in GeoIP2: ', ip)
        d = 0.0
        return d
    locs = list()
    if len(vrp_prefixes) > 1000:
        vrp_prefixes = random.sample(vrp_prefixes, 1000)
    for vrp_prefix in vrp_prefixes:
        vrp_ip = vrp_prefix.split('/')[0]
        x, y = accessGeoIP2data(vrp_ip)
        if x == y == 9999.0:
            continue
        loc = (x, y)
        locs.append(loc)
    dists = list()
    for x, y in locs:
        # dist = math.dist((x0, y0), (x, y)) # euclidean distance
        dist = math.sqrt((x0-x)**2 + (y0-y)**2)
        dists.append(dist)
    if len(dists) == 0:
        d = 0.0
        return d
    d = statistics.median(dists)
    # d = min(dists)
    # we choose a function: y = (2/pi) * arctan(x) to scale this feature value in the range of [0, 1), and then we define the maximum value is one.
    d = (2/math.pi)*math.atan(d)

    return d


def revalidateOrigin():
    f = open('./GroundtruthData/FourClasses/benign_misconfiguration.updated.csv', 'w')
    df = pd.read_csv(
        './GroundtruthData/FourClasses/benign_misconfiguration.csv')
    n = 0
    for date, prefix, as_path, asID, vrpID, maxlen in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values, df.iloc[:, 5].values):
        timestamp = date
        date = int(date)
        t = str(datetime.datetime.fromtimestamp(date, datetime.timezone.utc))
        y, m, d = t.split(' ')[0].split('-')
        date = y+m+d
        roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
        roa_px_dict = smart_validator.load_ROAs(roa_path, date)
        asID = int(asID)
        prefix_addr = prefix.split('/')[0]
        prefix_len = int(prefix.split('/')[1])
        results, invalid = smart_validator.validateOrigin(
            prefix_addr, prefix_len, timestamp, as_path, asID, roa_px_dict, date)
        print(results, invalid)
        if not invalid:
            continue
        f.write(
            ','.join(map(str, [date, prefix, as_path, asID, vrpID, maxlen]))+'\n')
    f.close()


def extract_abnormal_cases():
    df = pd.read_csv(
        './GroundtruthData/FourClasses/benign_misconfiguration.4f.csv')
    for date, prefix, asID, v1, v2, v3, v4, v5 in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 5].values, df.iloc[:, 6].values, df.iloc[:, 7].values, df.iloc[:, 8].values, df.iloc[:, 9].values):
        if v1 == v2 == v3 == v4 == v5 == 0:
            # for date, prefix, as_path, asID, vrpID, maxlen in zip(df.iloc[:,0].values, df.iloc[:,1].values, df.iloc[:,2].values, df.iloc[:,3].values, df.iloc[:,4].values, df.iloc[:,5].values):
            timestamp = date
            date = int(date)
            t = str(datetime.datetime.fromtimestamp(
                date, datetime.timezone.utc))
            y, m, d = t.split(' ')[0].split('-')
            # print(prefix, asID)
            as2prefixes_dict = {}
            as2prefixes_dict_path = '/home/zhao/Shujie/Routing_traffic/ROAs/' + \
                y+m+d+'/as2prefixes_dict.p'
            if not os.path.exists(as2prefixes_dict_path):
                continue
            with open(as2prefixes_dict_path, "rb") as f:
                as2prefixes_dict = pickle.load(f)
            compute_pfx_distance(as2prefixes_dict, prefix, asID)


def filter_route_leak():
    depths = []
    paths = []
    f = open('./GroundtruthData/FourClasses/route_leak.filtered.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/route_leak.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            d = float(fields[9])
            # if d == 0.0: continue
            # f.write(line)
            depths.append(d)
            # paths.append(l)
    print(np.percentile(np.array(depths), 5))
    # print(np.percentile(np.array(paths), 55))

    f.close()


def extract_validate_data():
    df = pd.read_csv(
        './GroundtruthData/FourClasses/benign_misconfiguration.mini.csv')
    pfxes = df.iloc[:, 1].values
    targets = [(pfx, str(asID)) for pfx, asID in zip(
        df.iloc[:, 1].values, df.iloc[:, 3].values)]
    # print(targets)
    f = open('./ValidateData/benign_misconfiguration.validate.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/benign_misconfiguration.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            if (fields[1], fields[2]) in targets:
                continue
            f.write(line)
    f.close()


def reformat_irr_database():
    irr_database = {}
    with open("irr_database.p", "rb") as f:
        irr_database = pickle.load(f)
    new_database = {}
    for t in irr_database:
        prefix = t[0]
        new_database[prefix] = irr_database[t]
    with open("irr_database.new.p", "wb") as fp:
        pickle.dump(dict(new_database), fp)


def filter_valid_v2():
    depths = list()
    paths = list()
    networks = {}
    f = open('./GroundtruthData/FourClasses/valid.reduced.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/valid.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            asn = fields[2]
            if asn in networks:
                continue
            networks[asn] = 1
            f.write(line)
    # print(np.percentile(np.array(depths), 99))
    # print(np.percentile(np.array(paths), 99))


def filter_valid():
    depths = list()
    paths = list()
    networks = {}
    f = open(
        './GroundtruthData/FourClasses/new_features/valid.reduced.filtered.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/new_features/valid.reduced.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            asn = fields[2]
            if asn in networks:
                continue
            networks[asn] = 1
            score3 = float(fields[7])
            d = float(fields[9])
            depths.append(d)
            # paths.append(l)
            if score3 > 0 and d > 0.15:
                continue
            f.write(line)
    print(np.percentile(np.array(depths), 99))
    # print(np.percentile(np.array(paths), 99))


def filter_misconfiguration():
    distances = list()
    networks = {}
    f = open('./GroundtruthData/FourClasses/new_features/benign_misconfiguration.reduced.filtered.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/new_features/benign_misconfiguration.reduced.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            asn = fields[2]
            if asn in networks:
                continue
            networks[asn] = 1
            score1 = float(fields[6])
            dis = float(fields[8])
            distances.append(dis)
            if score1 == 0 and dis > 0.713:
                continue  # 0.713
            # if dis > 0.875: continue
            f.write(line)
    print(np.percentile(np.array(distances), 75))


def generate_validate_set():
    targets = {}
    with open('./GroundtruthData/FourClasses/valid.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            time = fields[0]
            prefix = fields[1]
            path = fields[2]
            pathlen = len(path.split('+'))
            asn = fields[3]
            t = (time, prefix, asn)
            targets[t] = pathlen
    f = open('./ValidateData/valid.new.4f.csv', 'w')
    with open('./ValidateData/valid.original.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(',')
            fields = fields[:11]
            # 1655500815,82.160.150.0/24,203261,1,1,1,1,1,0,0.0,0.0,"[1.08603303013129e-06, 0.04898596128762, 0.00013382140265424, 1.66886165136104e-07]"
            time = fields[0]
            prefix = fields[1]
            asn = fields[2]
            t = (time, prefix, asn)
            if t not in targets:
                continue
            pathlen = targets[t]
            d = float(fields[10])
            # if d >= 0.93 and pathlen >= 8: continue
            fields.append(pathlen)
            f.write(','.join(map(str, fields))+'\n')
    f.close()


def undersample_valid_csv():
    targets = {}
    f = open('./GroundtruthData/FourClasses/new_features/valid.reduced.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/new_features/valid.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(',')
            # 1655500815,82.160.150.0/24,203261,1,1,1,1,1,0,0.0,0.0,"[1.08603303013129e-06, 0.04898596128762, 0.00013382140265424, 1.66886165136104e-07]"
            time = fields[0]
            prefix = fields[1]
            asn = fields[2]
            if targets.get(asn) != None:
                continue
            targets[asn] = 1
            f.write(line)
    f.close()


def compute_gaussian_paras(data):
    u = np.mean(data)
    s = np.std(data)
    return u, s


def is_abnormal(u, s, x):
    v = (x-u)/s
    if norm.cdf(v) > 0.95:  # p = 0.05 #orm.cdf(v) < 0.05
        return True
    return False


def calculate_heg_time(date):
    t = datetime.datetime.fromtimestamp(date, datetime.timezone.utc)
    t = datetime.datetime.strftime(t, '%Y-%m-%dT%H:%M')
    mm = int(t.split('T')[1].split(':')[1])
    mm = int(mm/15) * 15
    if mm == 0:
        mm = '00'
    t = t.split(':')[0] + ':'+str(mm)
    return t


def sample_hegemony_values(date, originasn, asn):
    start_time = calculate_heg_time(date-50*15*60)
    end_time = calculate_heg_time(date+1*15*60)
    print(start_time, end_time)
    af = 4
    base_url = "https://ihr.iijlab.net/ihr/api/hegemony/?"
    # &timebin__gte=%s&timebin__lte=%s&format
    local_api = "originasn=%s&asn=%s&af=%s&timebin__gte=%s&timebin__lte=%s&format=json"
    query_url = base_url + \
        local_api % (originasn, asn, af, start_time, end_time)
    # print(query_url)
    rsp = requests.get(query_url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
    }, timeout=60)
    if rsp.status_code != 200:
        return Hes
    rsp = rsp.json()
    x = 0
    Hes = []
    if ('results' in rsp) and (len(rsp['results']) != 0):
        results = rsp['results']
        for res in results:
            if end_time in res['timebin']:
                x = float(res['hege'])
                continue
            he = float(res['hege'])
            Hes.append(he)
    return x, Hes


def fill_miss_values(data):
    # if math.isnan(data[0]): data[0] = data[1]
    s = pd.Series(data)
    s = s.interpolate(method='pad')
    return s


def check_forward_hegemony_value(date, originasn, asn):
    end_time = calculate_heg_time(date+3600*24*2)
    af = 4
    base_url = "https://ihr.iijlab.net/ihr/api/hegemony/?"
    # &timebin__gte=%s&timebin__lte=%s&format
    local_api = "originasn=%s&asn=%s&af=%s&timebin=%s&format=json"
    query_url = base_url + \
        local_api % (originasn, asn, af, end_time)
    x = 0.0
    rsp = None
    try:
        rsp = requests.get(query_url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
        }, timeout=60)
    except:
        return x

    if rsp.status_code != 200:
        return x
    rsp = rsp.json()
    if ('results' in rsp) and (len(rsp['results']) != 0):
        results = rsp['results']
        for res in results:
            if end_time in res['timebin']:
                x = float(res['hege'])
                break
    return x


def one_detection(timestamp, asn):
    x, Hes = sample_hegemony_values(timestamp, '0', asn)
    # print(timestamp, x, Hes)
    u, s = 0.0, 0.0
    abnormal = 'False'
    if len(Hes) == 0:
        abnormal = 'Unverified'
        return abnormal
    else:
        data = Hes[1:]
        if len(data) < 10:
            abnormal = 'Unverified'
            return abnormal
        u, s = compute_gaussian_paras(data)
        if is_abnormal(u, s, x):
            abnormal = 'True'
            # he = check_forward_hegemony_value(timestamp, '0', asn)
            # if not is_abnormal(u, s, he) or he <= 1.05*u:
    return abnormal


def post_analysis():
    file_path = './BGPincidents/original_data'
    files = os.path.join(file_path, "route_leak.20190624.org.csv")  # "*.org.csv"
    files = glob.glob(files)

    for ifile in files:
        print(ifile)
        dataset = defaultdict(list)
        df = pd.read_csv(ifile, header=None)
        ty = ifile.split('/')[-1]
        check = {}
        for start_date, prefix, as_path, asID, leaker in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values):
            # for start_date, leaker in zip(df.iloc[:,0].values, df.iloc[:,1].values):
            date0 = int(start_date)

            if check.get(date0) != None:
                continue
            check[date0] = 1
            # score3, pair1, pair2, leaker = compute_score3(caida_as_rel_pp, caida_as_rel_pc, as_path)
            # if leaker == None: continue
            asn = str(leaker)
            abnormal = one_detection(date0, asn)
            # print(abnormal)
            # refers to the announced time of prefixes
            dataset['date'].append(date0)
            dataset['leaker'].append(leaker)
            dataset['abnormal'].append(abnormal)
        df = pd.DataFrame(dataset)
        df.to_csv('./BGPincidents/post_analysis/'+ty, index=False)


def fix_0401_file():
    df = pd.read_csv(
        './BGPincidents/original_data/bgp_hijacks.20200401.org.csv', header=None)
    df['leaker'] = df.iloc[:, 3].values
    df.to_csv(
        './BGPincidents/original_data/bgp_hijacks.20200401.org.csv', index=False)


def hold_out_set():
    targets = {}
    with open('./GroundtruthData/FourClasses/new_features/benign_misconfiguration.reduced.filtered.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            time = fields[0]
            prefix = fields[1]
            asn = fields[2]
            t = (asn, prefix)
            targets[t] = 1
    print(len(targets))

    f = open('./ValidateData/benign_misconfiguration.4f.csv', 'w')
    with open('./GroundtruthData/FourClasses/new_features/benign_misconfiguration.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            time = fields[0]
            prefix = fields[1]
            asn = fields[2]
            t = (asn, prefix)
            if t in targets:
                continue
            f.write(line)
    f.close()


def extract_route_leaks():
    targets = {}
    f = open('./BGPincidents/route_leak.20200824.refine.csv', 'w')
    with open('./BGPincidents/route_leak.20200824.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            prefix = fields[1]
            d = float(fields[-1].strip('\n'))
            if d > 0.30:
                targets[prefix] = 1
    with open('./BGPincidents/route_leak.20200824.reduced.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(',')
            prefix = fields[1]
            if targets.get(prefix) == None:
                continue
            f.write(line)
    f.close


def filter_simulated_bgp_incidents():
    targets = {}
    f = open('./filter_simulated_benign_conflicts.dat', 'w')
    with open('./bgpsimulator/rank0.asns') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            ip = line.strip('\n')
            targets[ip] = 1
    with open('./GroundtruthData/FourClasses/new_features/benign_misconfiguration.reduced.filtered.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(',')
            ip = fields[2]
            if ip not in targets:
                continue
            f.write(ip+'\n')
    f.close()


def fast_extract_heg_depth():
    depths = defaultdict()
    ty = 'benign_misconfiguration'
    df = pd.read_csv('./GroundtruthData/FourClasses/'+ty+'.4f.csv')
    for date, prefix, asID, hege_depth in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, -1].values):
        hege_depth = float(hege_depth)
        depths[(date, asID, prefix)] = hege_depth

    with open("./"+ty+"_hege_depth.p", "wb") as fp:
        pickle.dump(dict(depths), fp)


def leaker_extract():
    caida_as_org = load_caida_as_org()
    caida_as_rel_pc, caida_as_rel_pp = load_caida_as_rel()
    global_hege_dict = {}
    local_hege_dict = {}
    with open("global_hege_dict.p", "rb") as f:
        global_hege_dict = pickle.load(f)
    with open("local_hege_dict.p", "rb") as f:
        local_hege_dict = pickle.load(f)
    print(len(local_hege_dict))
    irr_database = {}
    with open("irr_database.p", "rb") as f:
        irr_database = pickle.load(f)

    df = pd.read_csv('./ValidateData/route_leak.20220715.csv', header=None)
    ofile = open('./ValidateData/route_leak.20220715.new.csv', 'w')
    for date, prefix, as_path, asID, vrpID, maxlen in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values, df.iloc[:, 5].values):

        asID = int(asID)
        if is_bogon_asn(asID):
            continue
        vrpID = int(vrpID)

        prefix_addr, prefix_len = prefix.split('/')
        prefix_len = int(prefix_len)
        maxlen = int(maxlen)

        origin_matching = 0
        maxlength_matching = 0
        if asID == vrpID:
            origin_matching = 1
        if prefix_len <= maxlen:
            maxlength_matching = 1

        rpki_status = 0
        if origin_matching == 1 and maxlength_matching == 1:
            rpki_status = 1

        confScore = 0
        score1 = 0
        score2 = 0
        score3 = 0
        hops = as_path.split('+')
        hops = [x for x in hops if x not in IXP_ASes]  # No IXP
        pathlen = len(hops)

        score3, pair1, pair2, leaker, bogon = compute_score3(
            caida_as_rel_pp, caida_as_rel_pc, as_path)
        # the following two-line code only used for filtering route leak events
        print(leaker)
        if leaker == None:
            continue

        # filter cases in which no valley exists in the path because we cannot guarantee they are malicious or benign in bgp incidents
        maxdepth, Hes = 0.0, []
        if leaker != None:
            # we use the average depth instead of absolute depth, because the depth will be more large with the path length increasing (the number of ASes will be more in the valley.)
            maxdepth, Hes = compute_hege_depth(
                date, hops, global_hege_dict, local_hege_dict)
        line = ','.join(
            map(str, [date, prefix, as_path, asID, vrpID, maxlen, leaker]))
        ofile.write(line+'\n')

    ofile.close()
    with open("global_hege_dict.p", "wb") as fp:
        pickle.dump(dict(global_hege_dict), fp)
    with open("local_hege_dict.p", "wb") as fp:
        pickle.dump(dict(local_hege_dict), fp)


IXP_ASes = ['1200', '4635', '5507', '6695', '7606', '8714', '9355', '9439', '9560', '9722', '9989', '11670', '15645', '17819',
            '18398', '21371', '24029', '24115', '24990', '35054', '40633', '42476', '43100', '47886', '48850', '50384', '55818', '57463']
IXP_ASes = []

#lib = cdll.LoadLibrary(
#    "/home/zhao/Shujie/Routing_traffic/coding/mmdb_reader.so")

lib = cdll.LoadLibrary("./mmdb_reader.so")


def main():
    # feature_extractor_with_futures()
    # feature_extractor()
    # roas_dict()
    # ifile = './GroundtruthData/FourClasses/valid.csv'
    # under_sampling(ifile)
    # combine_csv_files()
    # test_q_statistics()
    # revalidateOrigin()
    # extract_abnormal_cases()
    # select_random_samples()
    # extract_validate_data()
    # global_hege_dict()
    # filter_route_leak()
    # reformat_irr_database()
    # filter_misconfiguration()
    # filter_valid()
    # generate_feature_file()
    # undersample_valid_csv()
    # generate_validate_set()
    '''
    with open("global_hege_asns.p", "rb") as f:
            global_hege_asns = pickle.load(f)
            print(len(global_hege_asns))
    with open("global_hege_dict.p", "rb") as f:
            global_hege_dict = pickle.load(f)
            print(len(global_hege_dict))
    '''
    # collect_pfxes()
    post_analysis()
    # fix_0401_file()
    # mini_samples()
    # hold_out_set()
    # extract_route_leaks()
    # filter_simulated_bgp_incidents()
    # leaker_extract()
    '''
    start = time.monotonic()
    ip = "81.2.69.142"
    x, y = accessGeoIP2data(ip)
    end3 = time.monotonic()
    print('time: ', end3-start)
    print(x, y)
    '''
    # fast_extract_heg_depth()
    


if __name__ == "__main__":
    main()
