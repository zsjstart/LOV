#!/usr/bin/env python

from collections import defaultdict
from pybgpstream import *
from datetime import *
import ipaddress
import pytricia
import json
from itertools import groupby
import numpy as np
import datetime
import time
from multiprocessing import *
import concurrent.futures
from download_roas import collect_roas
import os
import glob
import warnings
import concurrent.futures
#from download_bgp_raw_data import collect_raw_data
from blist import *
import datetime
import re
import pickle
import pandas as pd
#import feature_extractor

warnings.filterwarnings("ignore")


def myParseROA(line):
    if("URI,ASN" in line):
        return None
    _, asn, ip_prefix, maxlen, _, _ = line.rstrip().split(",")
    prefix_addr, prefix_len = ip_prefix.split('/')
    #time = '20220609'
    prefix_len = int(prefix_len)
    if maxlen == '':
        maxlen = prefix_len
    else:
        maxlen = int(float(maxlen))
    asn = asn.split("AS")[1]
    asn = int(asn)
    return (prefix_addr, prefix_len, maxlen, asn)


def myMakeROABinaryPrefixDict(list_roas):
    roas = {}
    ipv4_dict = pytricia.PyTricia()
    ipv6_dict = pytricia.PyTricia(128)

    for prefix_addr, prefix_len, max_len, asID in list_roas:
        binary_prefix = ip2binary(prefix_addr, prefix_len)

        if(binary_prefix not in roas):
            roas[binary_prefix] = set()
        roas[binary_prefix].add((prefix_addr, prefix_len, max_len, asID))
        if(":" in prefix_addr):
            ipv6_dict.insert(prefix_addr+'/'+str(prefix_len), 'ROA')
        else:
            ipv4_dict.insert(prefix_addr+'/'+str(prefix_len), 'ROA')

    return roas, ipv4_dict, ipv6_dict


def load_ROAs(roa_path, date):
    roa_px_dict = {}
    list_roas = []
    with open(roa_path) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            roa = myParseROA(line)
            if roa != None:
                list_roas.append(roa)
    roas, ipv4_dict, ipv6_dict = myMakeROABinaryPrefixDict(list_roas)
    roa_px_dict[date] = (roas, ipv4_dict, ipv6_dict)
    return roa_px_dict

# update|A|1654732800.000000|ris|rrc00|None|None|7018|12.0.1.63|69.46.83.0/24|12.0.1.63|7018 174 18779 18779|7018:5000 7018:33051|None|None
# update|W|1654732800.000000|ris|rrc00|None|None|34549|80.77.16.114|168.228.114.0/23|None|None|None|None|None


def parseRISandRouteView(line):
    if("INCOMPLETE" in line):
        return None

    c = line.split("|")

    # try:
    #vp      = c[0]
    timestamp = c[2]
    dt = str(datetime.utcfromtimestamp(float(timestamp)))
    y, m, d = dt.split(' ')[0].split("-")
    time = y + m + d
    datetime.strptime(time, "%Y%m%d")

    peer = c[7]
    peerASN = c[8]

    #as_path = c[6].split("{")[0].rstrip()
    as_path = c[11].rstrip()
    if 'None' in as_path:
        return None  # filter Withdraw events

    if "{" in as_path:
        return None
    if ":" in as_path:
        print('as_path: ', as_path)
        return None

    #as_path = map(lambda v: v.split(":")[0], as_path.split(" "))
    as_path = as_path.split(" ")
    origin = int(as_path[-1])
    prefix_addr, prefix_len = c[9].split("/")
    return (peer, peerASN, prefix_addr, int(prefix_len), "+".join(as_path), origin)

    # except:
    #    return None


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


def isCover(prefix_addr, prefix_len, dataset):
    ip_prefix = prefix_addr+'/'+str(prefix_len)
    # get the longest matching prefix for arbitrary prefixes, return None if not exists
    return dataset.get_key(ip_prefix)


def myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict):
    if(":" in prefix_addr):
        return isCover(prefix_addr, prefix_len, ipv6_dict)
    else:
        return isCover(prefix_addr, prefix_len, ipv4_dict)


def validateOrigin(prefix_addr, prefix_len, timestamp, as_path, asID, roa_px_dict, time):
    """
        This implementation is based on RFC 6811; Section 2
    """
    BGP_PFXV_STATE_NOT_FOUND = 0  # Unknown
    BGP_PFXV_STATE_VALID = 1  # Valid
    BGP_PFXV_STATE_INVALID = 2  # Invalid
    results = []
    invalid = None
    if time not in roa_px_dict:
        return results, invalid

    roas = roa_px_dict[time][0]
    ipv4_dict = roa_px_dict[time][1]
    ipv6_dict = roa_px_dict[time][2]

    entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
    result = BGP_PFXV_STATE_NOT_FOUND

    if (entry is None):
        r = " ".join(map(str, [timestamp, prefix_addr,
                               prefix_len, as_path, asID, result, None, None]))
        results.append(r)
        return results, invalid

    vrp_prefix_addr, vrp_prefix_len = entry.split('/')
    binary_prefix = ip2binary(vrp_prefix_addr, vrp_prefix_len)
    # an IP Prefix can match multiple ROAs, e.g., in multihoming context
    for vrp_prefix, vrp_prefixlen, vrp_maxlen, vrp_asID in roas[binary_prefix]:
        covered_prefix = "%s/%s-%s" % (vrp_prefix, vrp_prefixlen, vrp_maxlen)
        if(asID is not None and vrp_asID != 0):
            if(vrp_asID == asID):
                if vrp_maxlen is None:
                    maxlen = vrp_prefixlen
                maxlen = vrp_maxlen
                if prefix_len <= maxlen:
                    result = BGP_PFXV_STATE_VALID
                    r = " ".join(map(str, [
                                 timestamp, prefix_addr, prefix_len, as_path, asID, result, vrp_asID, covered_prefix]))
                    results = []
                    results.append(r)
                    invalid = False
                    return results, invalid
                else:
                    result = BGP_PFXV_STATE_INVALID
                    invalid = True

            else:
                result = BGP_PFXV_STATE_INVALID
                invalid = True
                #print('Hijack: ', [time, prefix_addr, prefix_len, asID, result, vrp_asID, covered_prefix])
            r = " ".join(map(str, [timestamp, prefix_addr, prefix_len,
                                   as_path, asID, result, vrp_asID, covered_prefix]))
            results.append(r)
    return results, invalid


def validateOriginV2(prefix_addr, prefix_len, timestamp, as_path, asID, roa_px_dict, time):
    """
        This implementation is based on RFC 6811; Section 2
    """
    BGP_PFXV_STATE_NOT_FOUND = 0  # Unknown
    BGP_PFXV_STATE_VALID = 1  # Valid
    BGP_PFXV_STATE_INVALID = 2  # Invalid
    results = []
    invalid = None

    roas = roa_px_dict[0]
    ipv4_dict = roa_px_dict[1]
    ipv6_dict = roa_px_dict[2]

    entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
    result = BGP_PFXV_STATE_NOT_FOUND

    if (entry is None):
        r = " ".join(map(str, [timestamp, prefix_addr,
                               prefix_len, as_path, asID, result, None, None]))
        results.append(r)
        return results, invalid

    vrp_prefix_addr, vrp_prefix_len = entry.split('/')
    binary_prefix = ip2binary(vrp_prefix_addr, vrp_prefix_len)
    # an IP Prefix can match multiple ROAs, e.g., in multihoming context
    for vrp_prefix, vrp_prefixlen, vrp_maxlen, vrp_asID in roas[binary_prefix]:
        covered_prefix = "%s/%s-%s" % (vrp_prefix, vrp_prefixlen, vrp_maxlen)
        if(asID is not None and vrp_asID != 0):
            if(vrp_asID == asID):
                if vrp_maxlen is None:
                    maxlen = vrp_prefixlen
                maxlen = vrp_maxlen
                if prefix_len <= maxlen:
                    result = BGP_PFXV_STATE_VALID
                    r = " ".join(map(str, [
                                 timestamp, prefix_addr, prefix_len, as_path, asID, result, vrp_asID, covered_prefix]))
                    results = []
                    results.append(r)
                    invalid = False
                    return results, invalid
                else:
                    result = BGP_PFXV_STATE_INVALID
                    invalid = True

            else:
                result = BGP_PFXV_STATE_INVALID
                invalid = True
                #print('Hijack: ', [time, prefix_addr, prefix_len, asID, result, vrp_asID, covered_prefix])
            r = " ".join(map(str, [timestamp, prefix_addr, prefix_len,
                                   as_path, asID, result, vrp_asID, covered_prefix]))
            results.append(r)
    return results, invalid


def getOrgId(caida_as_org, asn):
    OrgId = None
    asn = str(asn)
    for e in caida_as_org:
        if "asn" not in e:
            continue
        if e["asn"] == asn:
            OrgId = e["organizationId"]
    return OrgId


def check_AS_rela(caida_as_org, caida_as_rel_pc, asID, vrpID):
    isSameOrg = False
    isPC = False
    isCP = False
    orgid1 = getOrgId(caida_as_org, asID)
    orgid2 = getOrgId(caida_as_org, vrpID)

    if orgid1 == orgid2:
        if orgid1 != None and orgid2 != None:
            isSameOrg = True
    else:
        c1 = caida_as_rel_pc.get(asID)
        c2 = caida_as_rel_pc.get(vrpID)
        '''
		if (c1 is not None and vrpID in c1) or (c2 is not None and asID in c2):
			isPC = True
		'''
        if (c1 is not None and vrpID in c1):
            isPC = True
        if (c2 is not None and asID in c2):
            isCP = True

    return isSameOrg, isPC, isCP


def identify_valley(asn0, asn1, asn2, caida_as_rel_pc, caida_as_rel_pp):
    FOUND = False
    c = caida_as_rel_pc.get(asn0)
    p = caida_as_rel_pp.get(asn0)

    if (c is not None and asn1 in c) or (p is not None and asn1 in p):
        if (c is not None and asn1 in c):
            print(asn0, asn1, 'pc')
        if (p is not None and asn1 in p):
            print(asn0, asn1, 'pp')
        cc = caida_as_rel_pc.get(asn2)
        pp = caida_as_rel_pp.get(asn2)
        if (cc is not None and asn1 in cc) or (pp is not None and asn1 in pp):
            if (cc is not None and asn1 in cc):
                print(asn1, asn2, 'cp')
            if (pp is not None and asn1 in pp):
                print(asn1, asn2, 'pp')
            FOUND = True

    return FOUND


def check_AS_path(caida_as_rel_pp, caida_as_rel_pc, as_path):
    valleyFree = True
    # 34800+24961+3356+3257+396998+18779, to make any AS appears no more than once in the AS path
    g = as_path.split('+')
    g.reverse()
    for i in range(1, len(g)-1):
        if identify_valley(g[i-1], g[i], g[i+1], caida_as_rel_pc, caida_as_rel_pp):
            valleyFree = False
            return valleyFree, g[i-1], g[i], g[i+1]

    return valleyFree, None, None, None


def load_historical_data(bgp_asn, time):
    stream = BGPStream(
        # Consider this time interval:
        # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
        from_time="2022-06-09 00:00:00", until_time="2022-06-09 23:59:59",
        collectors=["rrc00"],
        record_type="updates"
    )
    #origin_prefix = defaultdict(set)
    results = set()
    #f = open('./rov.20220609.vrp.invalid.csv','w')
    for rec in stream.records():
        for elem in rec:
            if "prefix" not in elem.fields:
                continue
            pfx = elem.fields["prefix"]
            if "as-path" not in elem.fields:
                continue
            ases = elem.fields["as-path"].split(" ")
            if len(ases) > 0:
                origin = ases[-1]
                if origin == str(bgp_asn):
                    results.add((bgp_asn, pfx, time))
    for result in results:
        print(result)

# here something is wrong.


def is_benign_event(results, caida_as_org, caida_as_rel_pc, roas):
    is_benign = False
    results, misconfig = check_invalid_events(
        results, caida_as_org, caida_as_rel_pc)
    if not misconfig:
        _, rela = check_related_origin(results, roas)
        if rela:
            is_benign = True
    else:
        is_benign = True
    return is_benign


def format_results(ty, results, ofile, check):
    # we just keep a single ROA record in the case of MOAS for each class
    r = results[0]
    fields = r.split(' ')
    start_time = fields[0]
    prefix_addr = fields[1]
    prefix_len = fields[2]
    prefix = prefix_addr + '/'+prefix_len
    as_path = fields[3]
    asID = fields[4]
    vrpID = fields[6]
    covered_prefix = fields[-1].strip('\n')

    maxlen = covered_prefix.split('-')[1]
    # if 'BGP Leak' in ty:
    #    continue
    # if 'Possible BGP hijack' in ty: continue
    s = ','.join([start_time, prefix, as_path, asID, vrpID, maxlen, ty])
    if check.get(s):
        return
    check[s] = True
    ofile.write(s+'\n')


def verify_by_file(ifile, ofile, ty, caida_as_org, caida_as_rel_pc, roa_px_dict, date):
    local_hege_dict = {}
    with open("local_hege_dict.p", "rb") as f:
        local_hege_dict = pickle.load(f)
    print(len(local_hege_dict))
    count = 0
    check = {}

    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(',')
            #1561372207,185.203.63.0/24,2497 701 3356 21459 21459,21459,701
            timestamp = fields[0]  # 2021-12-11 05:54:46
            
            start_date = timestamp
            
            prefix = fields[1]
            print(prefix)
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            as_path = fields[2]
            if "{" in as_path or ":" in as_path:
                continue
            # Get the array of ASns in the AS path and remove repeatedly prepended ASns
            hops = [k for k, g in groupby(as_path.split(" "))]
            asID = int(hops[-1])
            results, invalid = validateOrigin(
                prefix_addr, prefix_len, start_date, '+'.join(hops), asID, roa_px_dict, date)
            #results = check_invalid_events(results, caida_as_org, caida_as_rel_pc)
            if invalid == None:
                continue
            #timestamp, prefix_addr, prefix_len, as_path, asID, result, vrp_asID, covered_prefix
            r = results[0]
            fields = r.split(' ')
            vrpID = int(fields[6])
            
            # filter out events that are RPKI-valid or misconfiguration
            if 'leak' in ty and vrpID != asID:
                continue
            if 'hijack' in ty and not invalid:  # RPKI-valid
                continue
            if 'hijack' in ty and invalid:
                # or my_check_as_dependency(results, local_hege_dict)
                if is_benign_event(results, caida_as_org, caida_as_rel_pc, roa_px_dict[date][0]) or check_irr(asID, prefix) or my_check_as_dependency(results, local_hege_dict):
                    continue
            
            format_results(ty, results, ofile, check)
            # ofile.write(','.join(results)+','+ty+'\n')
            count = count + 1
    print('count: ', ifile, count)
    with open("local_hege_dict.p", "wb") as fp:
        pickle.dump(dict(local_hege_dict), fp)


def check_invalid_events(results, caida_as_org, caida_as_rel_pc):
    new_data = []
    misconfig = False
    for r in results:
        time, prefix_addr, prefix_len, as_path, asID, result, vrpID, covered_prefix = r.split(
            ' ')
        if int(result) == 0:
            return new_data
        # see if both are from the same ISP or their relationship: provider-customer?
        isSameOrg, isPC, isCP = check_AS_rela(
            caida_as_org, caida_as_rel_pc, asID, vrpID)
        if isSameOrg:
            r = r + ' SameOrg'
            misconfig = True
        if isPC:
            r = r + ' PC'
            misconfig = 'True'
        if isCP:
            r = r + ' CP'
            misconfig = 'True'
        if misconfig:
            new_data = []
            new_data.append(r)
            return new_data, misconfig
        new_data.append(r)
    return new_data, misconfig


def process(roas, ipv4_dict, ipv6_dict, outfile):
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
                entry = myGetCovered(
                    prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
                if entry is None:
                    continue
                peer = g[8].split(' ')[1]
                if ty == '+':
                    as_path = g[2]
                    if "{" in as_path or ":" in as_path:
                        continue
                    # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                    hops = [k for k, g in groupby(as_path.split(" "))]
                    if len(hops) > 1 and hops[0] == peer:
                        asID = int(hops[-1])
                        '''
						t = (asID, prefix)
						if t not in dic:
							dic[t] = set()
						dic[t].add((timestamp, 1))
						'''
                        dic[prefix].add(timestamp, asID, 1)

                elif ty == '-':
                    dic[prefix].add(timestamp, asID, 0)
                    '''
					for t in dic:
						if t[1] == prefix: 
							dic[t].add((timestamp, 0))
					'''
    os.remove(outfile)
    return dic


def collect_known_raw_data_old(date, collector, roas, ipv4_dict, ipv6_dict, dic, manager, lock):
    print(date)
    y, m, d = date.split('-')
    dirpath = '/home/zhao/Shujie/Routing_traffic/bgpdata/'+y+'.'+m+'.'+d
    files = os.path.join(dirpath, "*.bz2")
    files = glob.glob(files)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for i, infile in enumerate(files):
            outfile = infile.replace('.bz2', '.txt')
            cmd = """ bgpscanner %s > %s """ % (infile, outfile)
            os.system(cmd)
            # collect_raw_data(year, month, day, collector)
            futures.append(executor.submit(process, roas, ipv4_dict,
                                           ipv6_dict, outfile, dic, manager, lock))
        for future in concurrent.futures.as_completed(futures):
            future.result()


def process_as_link(roas, ipv4_dict, ipv6_dict, date, index, outfile):
    dic = defaultdict(blist)
    with open(outfile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            g = line.split('|')
            ty = g[0]
            timestamp = int(float(g[-2]))
            prefixes = g[1].split(' ')
            for prefix in prefixes:
                # Check if the prefix is known to RPKI
                prefix_addr, prefix_len = prefix.split('/')
                prefix_len = int(prefix_len)
                entry = myGetCovered(
                    prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
                if entry is None:
                    continue

                peer = g[8].split(' ')[1]
                if ty == '+':
                    as_path = g[2]
                    if "{" in as_path or ":" in as_path:
                        continue
                    # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                    hops = [k for k, g in groupby(as_path.split(" "))]
                    if len(hops) > 1 and hops[0] == peer:
                        asID = int(hops[-1])
                        dic[prefix].append(
                            (timestamp, asID, '+'.join(hops), 1))

                elif ty == '-':
                    dic[prefix].append((timestamp, 0, '', 0))
    for prefix in dic:
        dic[prefix] = sorted(set(dic[prefix]))
        for i, tup in enumerate(dic[prefix]):
            if i == 0:
                continue
            if tup[1] == dic[prefix][i-1][1] and tup[2] == dic[prefix][i-1][2] and tup[3] == dic[prefix][i-1][3]:
                dic[prefix].remove(tup)
        dic[prefix] = set(dic[prefix])
    os.remove(outfile)
    return date, index, dic


def collect_known_raw_data_new(roas, ipv4_dict, ipv6_dict, date):
    y, m, d = date.split('-')
    dirpath = '/home/zhao/Shujie/Routing_traffic/bgpdata/'+y+'.'+m+'.'+d
    files = os.path.join(dirpath, "*.bz2")
    files = glob.glob(files)
    dics = blist()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for index, infile in enumerate(files):
            outfile = infile.replace('.bz2', '.txt')
            cmd = """ bgpscanner %s > %s """ % (infile, outfile)
            os.system(cmd)
            # collect_raw_data(year, month, day, collector)
            futures.append(executor.submit(process_as_link, roas,
                                           ipv4_dict, ipv6_dict, date, index, outfile))
        for future in concurrent.futures.as_completed(futures):
            date, index, dic = future.result()
            dics.append(dic)

    basedic = dics[0]
    for dic in dics[1:]:
        mergeDics(basedic, dic)  # this is for process
        #mergePathDics(basedic, dic)
    return basedic


def mergePathDics(dic1, dic2):
    for t in dic1:
        if dic2.get(t) is None:
            continue
        for as_link in dic1[t]:
            if dic2[t].get(as_link) is not None:
                dic1[t][as_link] |= dic2[t][as_link]

    for t in dic2:
        if dic1.get(t) is None:
            dic1[t] = dic2[t]
            continue
        for as_link in dic2[t]:
            if dic1[t].get(as_link) is None:
                dic1[t][as_link] = dic2[t][as_link]

    del dic2


def mergeDics(dic1, dic2):
    for t in dic1:
        if dic2.get(t) is None:
            continue
        dic1[t] |= dic2[t]

    for t in dic2:
        if dic1.get(t) is None:
            dic1[t] = dic2[t]
    del dic2


def create_connection(db_file):
    '''
    Create a database connection to the SQLite database specified by db_file
    @param db_file: database file (str)
    @return: Connection object or None
    '''

    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
        return conn
    except Error as e:
        print(e)
    return None


def creat_sql_database(collector):
    db_file = 'live_database.db'
    con = create_connection(db_file)
    con.isolation_level = None
    cur = con.cursor()
    table_name = re.search(r'route-views(.*)', collector).group(1)
    if table_name[0] == ".":
        table_name = table_name[1:]
    table_name = "_" + table_name
    cur.execute('DROP TABLE IF EXISTS ' + table_name)
    create_table_query = 'CREATE TABLE ' + table_name + \
        '(time INT, peer_asn TEXT, prefix TEXT, origin_asn TEXT, as_path TEXT)'
    cur.execute(create_table_query)
    return con, cur, table_name


def process02(infile, roas, ipv4_dict, ipv6_dict, live_dict, live_path, lock):
    with open(infile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            g = line.split('|')
            timestamp = int(g[-2])
            prefixes = g[1].split(' ')
            for prefix in prefixes:
                prefix_addr, prefix_len = prefix.split('/')
                prefix_len = int(prefix_len)
                entry = myGetCovered(
                    prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
                if entry is None:
                    continue
                peer = g[8].split(' ')[1]
                as_path = g[2]
                if "{" in as_path or ":" in as_path:
                    continue
                # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                hops = [k for k, g in groupby(as_path.split(" "))]
                if len(hops) > 1 and hops[0] == peer:
                    origin_asn = int(hops[-1])
                    t = (origin_asn, prefix)
                    #data_tuple = (timestamp, peer, origin_asn, prefix, as_path)
                    lock.acquire()
                    # live_dict[t] = (timestamp, as_path) # True
                    live_path['+'.join(hops)] = 1
                    lock.release()
                    #cur.execute(insert_element_query, data_tuple)
                    # con.commit()
                    #outfile.write(origin_asn +','+ prefix + '\n')

    cmd = """ bzip2 -z %s""" % (infile)
    os.system(cmd)


def create_live_table(date, roas, ipv4_dict, ipv6_dict, collector):
    #con, cur, table_name = creat_sql_database(collector)
    '''
    t1 = str(datetime.datetime.fromtimestamp(int(date)))
    t2 = str(datetime.datetime.fromtimestamp(int(date)))
    stream = pybgpstream.BGPStream(
            # Consider this time interval:
            # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
            from_time=t1, until_time=t2,
            collectors=[collector],
            record_type="ribs"
    )
    '''
    count = 0
    dirpath = '/home/zhao/Shujie/Routing_traffic/bgpdata/ribsdata.2022.07.15'
    files = os.path.join(dirpath, "*")  # .bz2
    files = glob.glob(files)
    lock = Lock()
    manager = Manager()
    live_dict = manager.dict()  # for lived (AS, prefix) pair
    live_paths = manager.dict()  # for lived AS path
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for i, infile in enumerate(files):
            outfile = infile.replace('.bz2', '')
            cmd = """ bzip2 -d %s""" % (infile)
            out = os.system(cmd)
            futures.append(executor.submit(process02, outfile, roas, ipv4_dict, ipv6_dict,
                                           live_dict, live_paths, lock))  # collect_raw_data(year, month, day, collector)
        for future in concurrent.futures.as_completed(futures):
            future.result()

    # with open("live_data_20220630.p", "wb") as fp:
    #	pickle.dump(dict(live_dict), fp)
    with open("live_paths_20220715.p", "wb") as fp:
        pickle.dump(dict(live_paths), fp)

    '''	
	live_path = live_paths[0]
	for dic in live_paths[1:]:
		mergeDics(live_path, dic)
	with open("live_as_path.p", "wb") as fp:
		pickle.dump(dict(live_path), fp)
	'''

    '''
	for rec in stream.records():
		if rec.status == "valid":
	    		for elem in rec:
	    			timestamp = int(elem.time)
	    			if 'prefix' not in elem.fields:  # Ignore if no prefix already in the element. Move on
	    				continue
	    			prefix = elem.fields['prefix']
	    			prefix_addr, prefix_len = prefix.split('/')
	    			prefix_len = int(prefix_len)
	    			entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
	    			if entry is None: continue
	    			peer = str(elem.peer_asn)
	    			origin_asn = ''
	    			as_path = elem.fields['as-path']
	    			if "{" in as_path or ":" in as_path: continue
	    			# Get the array of ASns in the AS path and remove repeatedly prepended ASns
	    			hops = [k for k, g in groupby(as_path.split(" "))]
	    			if len(hops) > 1 and hops[0] == peer:
	    				origin_asn = hops[-1]
	    			
	    			data_tuple = (timestamp, peer, origin_asn, prefix, as_path)
	    			cur.execute(insert_element_query, data_tuple)
	    			con.commit()
	    			count = count + 1
	print(count)
	   '''


# date, collector, roas, ipv4_dict, ipv6_dict, dic
def collect_known_raw_data(date, collector, roas, ipv4_dict, ipv6_dict, dic, manager, lock):
    t1 = str(datetime.datetime.fromtimestamp(int(date), datetime.timezone.utc))
    t2 = str(datetime.datetime.fromtimestamp(
        int(date)+3600*3-1, datetime.timezone.utc))
    print(t1)
    print(t2)
    stream = pybgpstream.BGPStream(
        # Consider this time interval:
        # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
        from_time=t1, until_time=t2,
        collectors=[collector],
        record_type="updates"
    )

    #f1 = open('./outputs/'+date+'.known.bgp.csv','w')
    for rec in stream.records():
        for elem in rec:
            timestamp = int(elem.time)
            ty = elem.type
            if ty != 'A' and ty != 'W':
                continue
            prefix = elem.fields['prefix']
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
            if entry is None:
                continue
            '''
    			if entry is not None:
    				f1.write(str(elem)+'\n')
    			'''
            peer = str(elem.peer_asn)
            asID = None
            if ty == 'A':
                as_path = elem.fields['as-path']
                if "{" in as_path or ":" in as_path:
                    continue
                # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                hops = [k for k, g in groupby(as_path.split(" "))]
                if len(hops) > 1 and hops[0] == peer:
                    asID = int(hops[-1])
                    t = (asID, prefix)
                    lock.acquire()
                    if t not in dic:
                        dic[t] = manager.list()
                    dic[t].append((timestamp, 1))
                    lock.release()
            else:
                lock.acquire()
                for t in dic.keys():
                    if t[1] == prefix:
                        dic[t].append((timestamp, 0))
                lock.release()


def historical_anomaly_detection(roa_px_dict, date):
    stream = pybgpstream.BGPStream(
        # Consider this time interval:
        # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
        from_time=date+" 00:00:00", until_time=date+" 23:59:59",
        # collectors=["rrc00"],
        record_type="updates"
    )
    y, m, d = date.split('-')
    date = y+m+d
    if date not in roa_px_dict:
        return
    roas = roa_px_dict[date][0]
    ipv4_dict = roa_px_dict[date][1]
    ipv6_dict = roa_px_dict[date][2]
    dic = {}
    #f1 = open('./rov.20211211.rrc00.known.csv','w')
    for rec in stream.records():
        for elem in rec:
            timestamp = elem.time
            ty = elem.type
            if ty != 'A' and ty != 'W':
                continue
            prefix = elem.fields['prefix']
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
            if entry is None:
                continue
            '''
    			if entry is not None:
    				f1.write(str(elem)+'\n')
    			'''
            peer = str(elem.peer_asn)
            if peer not in dic:
                dic[peer] = {}
            asID = None
            if ty == 'A':
                as_path = elem.fields['as-path']
                if "{" in as_path or ":" in as_path:
                    continue
                # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                hops = [k for k, g in groupby(as_path.split(" "))]
                if len(hops) > 1 and hops[0] == peer:
                    asID = int(hops[-1])
                    t = (asID, prefix)
                    if t not in dic[peer]:
                        dic[peer][t] = set()
                    dic[peer][t].add((timestamp, ty))
            else:
                for t in dic[peer]:
                    if t[1] == prefix:
                        dic[peer][t].add((timestamp, ty))
    res = {}
    for peer in dic:
        for t in dic[peer]:
            Pr, Ps = 0.0, 0.0
            # sort according to timestamps
            print(peer, t, sorted(dic[peer][t]))
            sorted_records = list(sorted(dic[peer][t]))
            tys = [v[1] for v in sorted_records]
            if 'W' not in tys:
                end_date = datetime.datetime(int(y), int(
                    m), int(d), 23, 59, 59)  # until_time
                end_date = time.mktime(end_date.timetuple())
                # the first A observed
                if (end_date - sorted_records[0][0]) > 3600*24*7:
                    Pr = 1
                    Ps = 1
            else:
                indices = [i for i, val in enumerate(tys) if val == 'W']
                times = []
                times.append(sorted_records[0][0])  # first 'A'
                times.append(sorted_records[indices[0]][0])  # first 'W'
                for i in range(1, len(indices)):
                    if indices[i] - indices[i-1] > 1:
                        times.append(sorted_records[indices[i-1]+1][0])
                        times.append(sorted_records[indices[i]][0])
                for i in range(0, len(times), 2):
                    Pr = Pr + (times[i+1]-times[i])
                Pr = Pr / 10
                Ps = Pr/(len(times)/2)
            print(peer, t, Pr, Ps)
            if t not in res:
                res[t] = {}
            res[t][peer] = (Pr, Ps)

    for t in res:
        avgPr, avgPs = 0.0, 0.0
        for peer in res[t]:
            avgPr = res[t][peer][0] + avgPr
            avgPs = res[t][peer][1] + avgPs
        avgPr = avgPr/len(res[t])
        avgPs = avgPs/len(res[t])
        print(t, avgPr, avgPs)

    # f1.close()


def collect_short_lived_path(res, dic, date):
    y, m, d = date.split('-')
    end_date = datetime.datetime(int(y), int(m), int(d), 23, 59, 59)
    end_date = calculate_unix_time(end_date)
    #reslist = blist()
    for prefix in dic:
        as_link_dict = defaultdict(blist)
        lolist = blist(sorted(dic[prefix]))
        #if len(lolist) < 10: print(lolist)
        for timestamp, asID, as_path, ty in lolist:

            if ty == 0:
                for as_link in as_link_dict:
                    as_link_dict[as_link].append((timestamp, ty))
            else:
                hops = as_path.split('+')
                for i in range(len(hops)-1):
                    as_link = hops[i]+'-'+hops[i+1]
                    as_link_dict[as_link].append((timestamp, ty))
        for as_link in as_link_dict:
            oldlist = blist(sorted(as_link_dict[as_link]))
            newlist = blist([oldlist[0]])
            for i, tup in enumerate(oldlist):
                if i == 0:
                    continue
                if tup[1] == newlist[-1][1]:
                    continue
                newlist.append(tup)
            #as_link_dict[as_link] = newlist
            tss = [v[0] for v in newlist]
            tys = [v[1] for v in newlist]
            Pr = 0
            if 0 not in tys:
                #Pr = end_date - tss[-1]
                #reslist.append((prefix, as_link, 1))
                continue
            else:
                # reslist.append()

                indices = [i for i, val in enumerate(
                    tys) if val == 0 and i != 0]
                for i in indices:
                    Pr = Pr + (tss[i] - tss[i-1])
                if tys[-1] == 1:
                    #Pr = Pr + (end_date - tss[-1])
                    continue
                if (prefix, as_link) not in res:
                    res[(prefix, as_link)] = Pr
                else:
                    res[(prefix, as_link)] += Pr


def collect_long_lived_events(his_dict):
    res = {}
    for t in his_dict:
        Pr = 0
        lolist = blist([his_dict[t][0]])
        for i, tup in enumerate(his_dict[t][:-1]):
            if i == 0:
                continue
            if tup[1] == lolist[-1][1]:
                continue
            lolist.append(tup)
        tss = [v[0] for v in lolist]
        tys = [v[1] for v in lolist]
        y, m, d = '2022', '06', '30'
        end_date = datetime.datetime(int(y), int(m), int(d), 0, 0, 0)
        end_date = calculate_unix_time(end_date)
        if 0 not in tys:
            Pr = end_date - tss[-1]
        else:
            indices = [i for i, val in enumerate(tys) if val == 0 and i != 0]
            for i in indices:
                Pr = Pr + (tss[i] - tss[i-1])
            if tys[-1] == 1:
                Pr = Pr + (end_date - tss[-1])

        if Pr > 3600*24*7:
            res[t] = Pr

    with open("historical_data_analysis_res.p", "wb") as fp:
        pickle.dump(dict(res), fp)


def validate_long_lived_events_new(res, lived_dict, long_lived_dict, roa_px_dict, roa_time, caida_as_org, caida_as_rel_pc):
    f1 = open('./GroundtruthData/rov.20220630.vrp.valid.csv', 'w')
    f2 = open('./GroundtruthData/rov.20220630.vrp.misconfig.csv', 'w')
    roas = roa_px_dict[roa_time][0]
    for t in res:
        v = lived_dict.get(t)
        if v == None:
            continue  # filter
        timestamp = v[0]
        as_path = v[1]
        if "{" in as_path or ":" in as_path:
            continue
        # Get the array of ASns in the AS path and remove repeatedly prepended ASns
        hops = [k for k, g in groupby(as_path.split(" "))]
        prefix = t[1]
        prefix_addr, prefix_len = prefix.split('/')
        prefix_len = int(prefix_len)


def validate_long_lived_events(res, lived_dict, roa_px_dict, roa_time, caida_as_org, caida_as_rel_pc):
    f1 = open('./GroundtruthData/rov.20220630.vrp.valid.csv', 'w')
    f2 = open('./GroundtruthData/rov.20220630.vrp.misconfig.csv', 'w')
    f3 = open('./GroundtruthData/rov.20220630.vrp.relatedOrigin.csv', 'w')
    f4 = open('./GroundtruthData/rov.20220630.vrp.invalid.res.csv', 'w')
    roas = roa_px_dict[roa_time][0]
    for t in res:
        v = lived_dict.get(t)
        if v == None:
            continue  # filter
        timestamp = v[0]
        as_path = v[1]
        if "{" in as_path or ":" in as_path:
            continue
        # Get the array of ASns in the AS path and remove repeatedly prepended ASns
        hops = [k for k, g in groupby(as_path.split(" "))]
        prefix = t[1]
        prefix_addr, prefix_len = prefix.split('/')
        prefix_len = int(prefix_len)
        asID = t[0]
        results, invalid = validateOrigin(
            prefix_addr, prefix_len, timestamp, '+'.join(hops), asID, roa_px_dict, roa_time)
        if len(results) == 0:
            continue
        if invalid is None:
            continue
        if not invalid:
            f1.write(','.join(results) + '\n')
        else:
            results, misconfig = check_invalid_events(
                results, caida_as_org, caida_as_rel_pc)
            if misconfig:
                f2.write(','.join(results)+'\n')
            else:
                results, rela = check_related_origin(results, roas)
                #check_irr(asID, prefix)
                if rela:
                    f3.write(','.join(results)+'\n')
                else:
                    f4.write(','.join(results)+'\n')
    f1.close()
    f2.close()
    f3.close()
    f4.close()


def as2prefixes(roas):
    as_dict = {}
    for binary_prefix in roas:
        for prefix_addr, prefix_len, max_len, asID in roas[binary_prefix]:
            asID = str(asID)
            if asID not in as_dict:
                as_dict[asID] = list()
            as_dict[asID].append(prefix_addr + '/' + str(prefix_len))
    return as_dict


def is_covered(bgp_prefix, prefix):
    pyt = None
    if ':' in prefix:
        pyt = pytricia.PyTricia(128)
    else:
        pyt = pytricia.PyTricia()

    pyt[prefix] = 'ROA'
    return prefix == pyt.get_key(bgp_prefix)


def check_irr(asID, prefix):
    irrValid = False
    cmd = """ whois -h whois.radb.net %s""" % (prefix)
    out = os.popen(cmd).read()
    if 'No entries found' in out:
        return irrValid
    matches = re.findall(r'origin:\s+AS(\d+)', out)
    asID = str(asID)
    if asID in matches:
        irrValid = True
    return irrValid


def my_check_as_dependency(results, local_hege_dict):
    for r in results:
        time, prefix_addr, prefix_len, as_path, asID, result, vrpID, covered_prefix = r.split(
            ' ')
        time = int(time)
        asID = int(asID)
        vrpID = int(vrpID)
        is_depend = feature_extractor.check_as_dependency_v2(
            time, asID, vrpID, as_path, local_hege_dict)
        if is_depend:
            return True
    return False


def check_related_origin(results, roas):
    new_data = []
    rela = False
    as_dict = as2prefixes(roas)
    for r in results:
        time, prefix_addr, prefix_len, as_path, asID, result, vrpID, covered_prefix = r.split(
            ' ')
        if asID == vrpID:
            continue
        bgp_prefix = prefix_addr + '/' + prefix_len
        prefixes = as_dict.get(asID)
        if prefixes == None:
            continue
        for prefix in prefixes:
            if prefix == bgp_prefix:
                continue
            # prefix is a less-specific prefix, which covers the bgp-announced prefix, check irr infomating matching or not, check the as path (not Done)
            if is_covered(bgp_prefix, prefix):
                rela = True
                new_data = []
                new_data.append(r+' Related Origin')
                return new_data, rela
        new_data.append(r)
    return new_data, rela


'''	
as-path-group bogon-asns {
        /* RFC7607 */
        as-path zero ".* 0 .*";
        /* RFC4893 AS_TRANS */
        as-path as_trans ".* 23456 .*";
        /* RFC5398 and documentation/example ASNs */
        as-path examples1 ".* [64496-64511] .*";
        as-path examples2 ".* [65536-65551] .*";
        /* RFC6996 Private ASNs */
        as-path reserved1 ".* [64512-65534] .*";
        as-path reserved2 ".* [4200000000-4294967294] .*";
        /* RFC7300 Last 16 and 32 bit ASNs */
        as-path last16 ".* 65535 .*";
        as-path last32 ".* 4294967295 .*";
        /* IANA reserved ASNs */
        as-path iana-reserved ".* [65552-131071] .*";
    }
'''
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


def check_country(asn):
    cmd = """ whois -h whois.radb.net %s""" % ('AS'+asn)
    out = os.popen(cmd).read()
    if 'No entries found' in out:
        return None
    matches = re.findall(r'country:\s+([A-Z]+)', out)
    if len(matches) == 0:
        return None
    return matches[0]


def check_as_path(asID, vrpID, live_path):
    asID = int(asID)
    vrpID = int(vrpID)
    if asID in live_path:
        for path in live_path[asID]:
            if str(vrpID) in path:
                return True
    if vrpID in live_path:
        for path in live_path[vrpID]:
            if str(asID) in path:
                return True
    return False


def check_rest_events(live_path):
    f1 = open('./GroundtruthData/rov.20220630.vrp.irr.valid.csv', 'w')
    f2 = open('./GroundtruthData/rov.20220630.vrp.bogon.asns.csv', 'w')
    f3 = open('./GroundtruthData/rov.20220630.vrp.on.path.csv', 'w')
    f4 = open('./GroundtruthData/rov.20220630.vrp.invalid.res.final.csv', 'w')
    with open('./GroundtruthData/rov.20220630.vrp.invalid.res.csv', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            irrValid = False
            bogon = False
            results = line.split(',')
            for r in results:
                fields = r.split(' ')
                prefix_addr = fields[1]
                prefix_len = fields[2]
                asID = fields[4]
                vrpID = fields[6]
                if is_bogon_asn(asID):
                    bogon = True
                    line = line.strip('\n')+' bogon'+'\n'
                    f2.write(line)
                    break
                prefix = prefix_addr+'/'+prefix_len
                cmd = """ whois -h whois.radb.net %s""" % (prefix)
                out = os.popen(cmd).read()
                if 'No entries found' in out:
                    break
                matches = re.findall(r'origin:\s+AS(\d+)', out)
                if asID in matches:
                    irrValid = True
                    line = line.strip('\n')+' irrValid'+'\n'
                    f1.write(line)
                    break
                is_on_path = check_as_path(asID, vrpID, live_path)
                if is_on_path:
                    line = line.strip('\n')+' onPath'+'\n'
                    f3.write(line)
                    break
            if not irrValid and not bogon and not is_on_path:
                line = line.strip('\n')+' invalid'+'\n'
                f4.write(line)
    f1.close()
    f2.close()
    f3.close()
    f4.close()


def check_valid_events(short_lived_path_dict, caida_as_rel_pp, caida_as_rel_pc):
    f1 = open('./GroundtruthData/rov.20220630.vrp.valid.final.csv', 'w')
    f2 = open('./GroundtruthData/rov.20220630.vrp.valid.shortlived.csv', 'w')
    f3 = open('./GroundtruthData/rov.20220630.vrp.valid.nonvalleyfree.csv', 'w')
    with open('./GroundtruthData/rov.20220630.vrp.valid.csv', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            shortlived = False
            time, prefix_addr, prefix_len, as_path, asID, result, vrpID, covered_prefix = line.split(
                ' ')
            if asID != vrpID:
                continue
            prefix = prefix_addr + '/' + prefix_len
            hops = as_path.split('+')

            for i in range(len(hops)-1):
                as_link = hops[i]+'-'+hops[i+1]
                if (prefix, as_link) in short_lived_path_dict:
                    shortlived = True
                    break
            if shortlived:
                f2.write(line)
            else:
                valleyFree, _, _, _ = check_AS_path(
                    caida_as_rel_pp, caida_as_rel_pc, as_path)
                if not valleyFree:
                    f3.write(line)
                else:
                    f1.write(line)
    f1.close()
    f2.close()
    f3.close()


def check_miscon_events(short_lived_path_dict, caida_as_rel_pp, caida_as_rel_pc):
    f1 = open('./GroundtruthData/FourClasses/benign_misconfiguration.final.dat', 'w')
    f2 = open('./GroundtruthData/benign_misconfiguration.shortlived.dat', 'w')
    f3 = open('./GroundtruthData/benign_misconfiguration.nonvalleyfree.dat', 'w')
    with open('./GroundtruthData/FourClasses/benign_misconfiguration.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            shortlived = False
            time, prefix_addr, prefix_len, as_path, asID, result, vrpID, covered_prefix, = line.split(
                ' ')
            if asID != vrpID:
                continue
            prefix = prefix_addr + '/' + prefix_len
            hops = as_path.split('+')

            for i in range(len(hops)-1):
                as_link = hops[i]+'-'+hops[i+1]
                if (prefix, as_link) in short_lived_path_dict:
                    shortlived = True
                    break
            if shortlived:
                f2.write(line)
            else:
                valleyFree, _, _, _ = check_AS_path(
                    caida_as_rel_pp, caida_as_rel_pc, as_path)
                if not valleyFree:
                    f3.write(line)
                else:
                    f1.write(line)
    f1.close()
    f2.close()
    f3.close()


def test_live_stream():
    stream = pybgpstream.BGPStream(
        # accessing ris-live
        project="ris-live",
        # filter to show only stream from rrc00
        filter="collector rrc00",
    )

    for elem in stream:
        print(elem)


def test():
    #dates = [("2021-10-25 09:56", "2021-10-25 10:32", "_212046_"), ("2021-10-13 08:58", "2021-10-13 09:58", "_212046_"), ("2021-09-21 07:40", "2021-09-21 08:54", "_62325_"), ("2021-05-18 09:00", "2021-05-18 14:00", "_48467_"), ("2021-04-16 13:49", "2021-04-16 15:19", "_55410_"), ("2021-02-05 15:50", "2021-02-05 18:55", "_136168_")]
    #("2021-08-19 16:20", "2021-08-19 16:50", "_265038_"), ("2021-07-30 08:33", "2021-07-30 09:13", "_137996_"), ("2021-06-03 10:10", "2021-06-03 12:46", "_199599_")
    dates = [("2019-06-24T10:30", "2019-06-24T12:40", "701_396531_33154")]
    for date in dates:
        # for collector in ['amsix', 'wide', 'chicago']:
        stream = pybgpstream.BGPStream(
            # Consider this time interval:
            # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
            from_time=date[0], until_time=date[1],
            #collectors=["route-views."+collector],
            collectors=["route-views.amsix", "route-views.wide", "route-views.chicago"],
            record_type="updates",
            filter='path '+date[2]
            #filter='prefix more 95.215.3.30/32 and path '+date[2] 
        )
        checked = {}
        d = ''.join(date[0].split(' ')[0].split('-'))
        f0 = open(
            '/home/zhao/Shujie/Routing_traffic/coding/BGPincidents/route.leak.'+d+'.csv', 'w')
        f1 = open(
            '/home/zhao/Shujie/Routing_traffic/coding/BGPincidents/route.leak.'+d+'.dat', 'w')
        for rec in stream.records():
            for elem in rec:
                #"prefix exact 191.102.61.0/26 and prefix exact 130.156.192.0/20 and prefix exact 150.186.96.0/19 and prefix exact 50.202.61.0/24"
                
                if elem.type != 'A':
                    continue
                timestamp = int(elem.time)
                #elem.fields: {'next-hop': '80.77.16.114', 'as-path': '34549 6830 3356 12301', 'communities': {'34549:6830', '6830:23001', '6830:33302', '6830:17000', '34549:100', '6830:17430'}, 'prefix': '91.82.90.0/23'}
                prefix = elem.fields['prefix']
                peer = str(elem.peer_asn)
                as_path = elem.fields['as-path']
                if "{" in as_path or ":" in as_path:
                    continue
                # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                hops = [k for k, g in groupby(as_path.split(" "))]
                if len(hops) == 0:
                    continue
                asID = hops[-1]
                attacker = date[2].split('_')[1]

                if asID == attacker:
                    continue
                t = prefix
                if checked.get(t) != None:
                    continue
                checked[t] = 1
                # unique prefix
                f0.write(
                    ','.join([str(timestamp), prefix, as_path, asID, attacker])+'\n')
                f1.write(str(elem)+'\n')

        f0.close()
        f1.close()


def verify(caida_as_org, caida_as_rel_pc, roa_px_dict, time):
    stream = pybgpstream.BGPStream(
        # Consider this time interval:
        # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
        from_time="2021-12-11 00:00:00", until_time="2021-12-11 00:00:00",
        collectors=["rrc00"],
        record_type="updates"
    )

    f = open('./rov.20211211.rrc00.raw.csv', 'w')
    f1 = open('./rov.20211211.vrp.valid.csv', 'w')
    f2 = open('./rov.20211211.vrp.invalid.csv', 'w')
    f3 = open('./rov.20211211.vrp.misconfig.csv', 'w')
    validated = {}
    for rec in stream.records():
        for elem in rec:
            f.write(str(elem)+'\n')
            if elem.type != 'A':
                continue
            #elem.fields: {'next-hop': '80.77.16.114', 'as-path': '34549 6830 3356 12301', 'communities': {'34549:6830', '6830:23001', '6830:33302', '6830:17000', '34549:100', '6830:17430'}, 'prefix': '91.82.90.0/23'}
            prefix = elem.fields['prefix']
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            # Get the peer ASn
            peer = str(elem.peer_asn)
            as_path = elem.fields['as-path']
            if "{" in as_path or ":" in as_path:
                continue
            # Get the array of ASns in the AS path and remove repeatedly prepended ASns
            hops = [k for k, g in groupby(as_path.split(" "))]
            if len(hops) > 1 and hops[0] == peer:
                asID = int(hops[-1])
                t = (prefix, asID, as_path)
                if t in validated:
                    continue
                results, invalid = validateOrigin(
                    prefix_addr, prefix_len, "+".join(hops), asID, roa_px_dict, time)
                validated[t] = True
                if len(results) == 0:
                    continue
                if invalid is None:
                    continue
                if not invalid:
                    f1.write(str(results) + '\n')
                else:
                    results, misconfig = check_invalid_events(
                        results, caida_as_org, caida_as_rel_pc)
                    if misconfig:
                        f3.write(str(results)+'\n')
                    else:
                        f2.write(str(results)+'\n')

    f1.close()
    f2.close()
    f3.close()
    f.close()


def load_caida_as_org():
    caida_as_org = None
    with open("/home/zhao/Shujie/Routing_traffic/coding/20220701.as-org2info.jsonl") as f:
        caida_as_org = [json.loads(jline) for jline in f]
    return caida_as_org


def load_caida_as_rel():
    caida_as_rel_pc = {}
    caida_as_rel_pp = {}
    with open("/home/zhao/Shujie/Routing_traffic/coding/20220701.as-rel.txt") as filehandle:
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


def calculate_unix_time(date_and_time):
    '''
    Calculate unix time elapsed from a datetime object
    @param: date_and_time (datetime): datetime object
    @return: Seconds elapsed using unix reference (int)
    '''
    return int((date_and_time - datetime.datetime.utcfromtimestamp(0)).total_seconds())


def process_file():
    ofile = open(
        './GroundtruthData/rov.20220630.vrp.invalid.res.updated.csv', 'w')
    with open('./GroundtruthData/rov.20220630.vrp.invalid.res.csv', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            if '+' not in line:
                continue
            ofile.write(line)
    ofile.close()

# Example: 1644754125 192.142.129.0 24 53432+13994+7029+6461+38193+132165+17557+6762+395880+28317 28317 2 64286 192.142.129.0/24-24,BGP Leak: This can be identified as misconfiguration or BGP Leak? We expect to see BGP leak!!!


def format_groundtruth_data(long_lived_path):
    #ifile = './GroundtruthData/rov.20220630.vrp.invalid.(long_lived_prefixes).csv'
    ifile = './BGPincidents/hijack.rov.csv'
    #ofile = open('./GroundtruthData/FourClasses/benign_misconfiguration.csv', 'w')
    ofile = open('./BGPincidents/bgp_hijacks.csv', 'w')
    #ofile = open('./ValidateData/route_leak.csv', 'w')
    check = dict()
    ofile.write('start_time, prefix, as_path, asID, vrpID, maxlen'+'\n')
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            line = line.strip('\n')
            results = line.split(',')
            ty = results[-1]
            # we just keep a single ROA record in the case of MOAS for each class
            r = results[0]
            fields = r.split(' ')
            start_time = fields[0]
            prefix_addr = fields[1]
            prefix_len = fields[2]
            prefix = prefix_addr + '/'+prefix_len
            as_path = fields[3]
            '''
			if long_lived_path.get(as_path) == None:
				print(line)
				continue
			'''
            asID = fields[4]
            vrpID = fields[6]
            covered_prefix = fields[7]
            maxlen = covered_prefix.split('-')[1]
            # if 'BGP Leak' in ty:
            #    continue
            # if 'Possible BGP hijack' in ty: continue
            s = ','.join([start_time, prefix, as_path, asID, vrpID, maxlen])
            if check.get(s):
                continue
            check[s] = True
            ofile.write(s+'\n')
    ofile.close()
# peer_count	start_time	alert_type	base_prefix	base_as	announced_prefix	src_AS	Affected_ASname	example_ASPath


def format_bgpmon_data():
    ifile = './BGPincidents/bgpmon2020-04-01.txt'
    ofile = open('./BGPincidents/route.hijack.20200401.csv', 'w')
    check = dict()
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            line = line.strip('\n')
            fields = line.split('\t')
            date = fields[1]
            # 2020-04-01 19:27:28
            print(fields)
            y, m, d = date.split(' ')[0].split('-')
            hh, mm, ss = date.split(' ')[1].split(':')
            date = datetime.datetime(int(y), int(
                m), int(d), int(hh), int(mm), int(ss))
            timestamp = calculate_unix_time(date)
            prefix = fields[5]
            asID = fields[6]
            as_path = fields[8]
            if check.get(prefix) != None:
                continue
            check[prefix] = 1
            ofile.write(','.join([str(timestamp), prefix, as_path, asID])+'\n')
    ofile.close()


def test00():
    end_date = '2022-06-30'
    y, m, d = end_date.split('-')
    date = y+m+d
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
    roa_px_dict = load_ROAs(roa_path, date)
    if len(roa_px_dict) == 0:
        return
    roas = roa_px_dict[date][0]
    r = ' '.join(map(str, [1655879065, '120.106.128.0', 18,
                           '23673+55329+137557+4809+3462+9916', 9916, 2, 1659, '120.96.0.0/11-11']))
    results = [r]
    print(check_related_origin(results, roas))


def test01():
    live_path = {}
    with open("live_as_path.p", "rb") as f:
        live_path = pickle.load(f)
    check_rest_events(live_path)

    '''
	end_date = '2022-06-30'
	y, m, d = end_date.split('-')
	date = y+m+d
	roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
	roa_px_dict = load_ROAs(roa_path, date)
	if len(roa_px_dict) == 0:
		return
	
	res = {}
	live_dict = {}
	with open("historical_data_analysis_res.p", "rb") as f:
		res = pickle.load(f)
	with open("live_data_20220630.p", "rb") as f:
		live_dict = pickle.load(f)
	caida_as_org = load_caida_as_org()
	caida_as_rel_pc, _ = load_caida_as_rel()
	validate_long_lived_events(res, live_dict, roa_px_dict, date, caida_as_org, caida_as_rel_pc)
	'''


def test02():
    end_date = '2022-06-30'
    y, m, d = end_date.split('-')
    end_date = datetime.datetime(int(y), int(m), int(d), 0, 0, 0)
    end_date = time.mktime(end_date.timetuple())
    date = y+m+d
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
    roa_px_dict = load_ROAs(roa_path, date)
    if len(roa_px_dict) == 0:
        return
    if date not in roa_px_dict:
        return
    roas = roa_px_dict[date][0]
    ipv4_dict = roa_px_dict[date][1]
    ipv6_dict = roa_px_dict[date][2]
    collector = " "  # route-views
    create_live_table(end_date, roas, ipv4_dict, ipv6_dict, collector)


def test03():
    #date = '2022-06-29'
    # collect_known_raw_data_new(date)
    dic1 = {'t1': {'a1': {(1, 2), (2, 3)}, 'a3': {(5, 6)}},
            't3': {'a3': {(5, 6)}}}
    dic2 = {'t2': {'a1': {(2, 3)}}, 't1': {
        'a1': {(1, 2), (2, 3)}, 'a2': {}, 'a3': {(5, 6)}}}
    #mergeDics(dic1, dic2)
    mergePathDics(dic1, dic2)
    print(dic1)


def test04():
    his_dict1 = {}
    his_dict2 = {}
    with open("historical_data.p", "rb") as f1:
        his_dict1 = pickle.load(f1)
        for t in his_dict1:
            his_dict1[t] = set(his_dict1[t])

    with open("historical_data_part1.p", "rb") as f2:
        his_dict2 = pickle.load(f2)
        for t in his_dict2:
            his_dict2[t] = set(his_dict2[t])
    mergeDics(his_dict1, his_dict2)

    for t in his_dict1:
        his_dict1[t] = sorted(his_dict1[t])
    print('Done')
    collect_long_lived_events(his_dict1)


def get_dates(ifile):
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(',')
            start_date = fields[0]
            start_date = start_date.split(' ')[0]
            y, m, d = start_date.split('-')
            date = y+m+d
            print(date)
            ofile = open('./attacks/bgpstream.attacks.'+date+'.dat', 'a')
            ofile.write(line)
            ofile.close()


def test_historical_incidents():
    basic_path = './LocalData'
    caida_as_org = {}
    with open(basic_path+'/CAIDA/caida_as_org.p', "rb") as f:
        caida_as_org = pickle.load(f)
    caida_as_rel_pp = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pp.p', "rb") as f:
        caida_as_rel_pp = pickle.load(f)
    caida_as_rel_pc = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pc.p', "rb") as f:
        caida_as_rel_pc = pickle.load(f)
        
    ifile = "./BGPincidents/route.leak.20190624T10:30.reduced.csv"
    date = re.search(r'\d+', ifile).group(0)
    d = date
    print(d)
    
    
    ofile = open('./BGPincidents/route_leak.'+d+'.reduced.csv', 'w')
    y, m, d = date[0:4], date[4:6], date[6:8]
    collect_roas(y, m, d)
    
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
    roa_px_dict = load_ROAs(roa_path, date)
    print(len(roa_px_dict))
    ty = 'leak'
    verify_by_file(ifile, ofile, ty, caida_as_org,
                   caida_as_rel_pc, roa_px_dict, date)
    ofile.close()
    

def test05extra():
    dirpath = './BGPincidents/'
    files = os.path.join(dirpath, "route.leak.20190624T10:30.csv")
    files = glob.glob(files)

    for ifile in files:
        print(ifile)
        check = {}
        #date = re.search(r'\d+', ifile).group(0)
        s = ifile.split('/')[-1].split('.')[-2]
        print(s)
        path = './BGPincidents/route.leak.20190624T10:30.reduced.csv'
        ofile = open(path, 'w')
        with open(ifile, 'r') as f:
            filecontents = f.readlines()
            for line in filecontents:
                fields = line.split(',')
                prefix = fields[1]
                as_path = fields[2]
                if check.get(prefix) != None:
                    continue
                check[prefix] = 1
                ofile.write(line)
        ofile.close()
        os.remove(ifile)


def test06():
    # load_historical_data(37394)
    #caida_as_org = load_caida_as_org()
    #caida_as_rel_pc, _ = load_caida_as_rel()
    #live_dict = {}
    # with open("live_data_with_path.p", "rb") as f:
    #	live_dict = pickle.load(f)
    end_date = '2022-06-30'
    y, m, d = end_date.split('-')
    date = y+m+d
    roa_path = '/home/zhao/Shujie/Routing_traffic/ROAs/'+date+'/all.roas.csv'
    roa_px_dict = load_ROAs(roa_path, date)
    if len(roa_px_dict) == 0:
        return
    if date not in roa_px_dict:
        return
    roas = roa_px_dict[date][0]
    ipv4_dict = roa_px_dict[date][1]
    ipv6_dict = roa_px_dict[date][2]
    collector = " "  # "route-views.eqix"
    start_date = '2022-06-20'
    y, m, d = start_date.split('-')
    start_date = datetime.datetime(int(y), int(m), int(d), 0, 0, 0)
    start_date = calculate_unix_time(start_date)
    dates = []
    dics = blist()
    for i in range(10):
        date = start_date + 3600*24*i
        t = str(datetime.datetime.fromtimestamp(date, datetime.timezone.utc))
        date = t.split(' ')[0]
        dates.append((i, date))
    for i, date in dates:
        # collect_raw_data(year, month, day, collector)
        dic = collect_known_raw_data_new(roas, ipv4_dict, ipv6_dict, date)
        with open("./outputs/historical_prefix_to_path_"+date+".p", "wb") as fp:
            pickle.dump(dic, fp)

    '''
	his_as_link_dict = dics[0]
	for dic in dics[1:]:
		mergeDics(his_as_link_dict, dic)
	
	for t in his_as_link_dict:
		for as_link in his_as_link_dict[t]:
			sortlist = sorted(his_as_link_dict[t][as_link])
			lolist = blist(sortlist[0])
			for i, tup in enumerate(sortlist):
				if i == 0: continue
				if tup[1] == lolist[-1][1]: continue
				lolist.append(tup)
			his_as_link_dict[t][as_link] = lolist
	print('Done!')
	'''

    '''	
	date = datetime.datetime(int('2022'), int('06'), int('30'), 0, 0, 0)
	timestamp = calculate_unix_time(date)
	live_dict = {}
	with open("live_data.p", "rb") as f:
		live_dict = pickle.load(f)
	print(len(live_dict))
	for t in his_dict:
		his_dict[t] = sorted(his_dict[t])
		if live_dict.get(t) == 1:
			his_dict[t].append((timestamp,1))
		else:
			his_dict[t].append((timestamp,0))
	'''


def test07():
    dirpath = './outputs'
    files = os.path.join(dirpath, "*.p")
    files = glob.glob(files)
    res = {}
    for ifile in files:
        with open(ifile, "rb") as f:
            date = re.search(r'\d+-\d+-\d+', ifile).group(0)
            print(date)
            if date in ['2022-06-20', '2022-06-21', '2022-06-22']:
                continue
            dic = pickle.load(f)
            collect_short_lived_path(res, dic, date)
            dic.clear()

    for k, v in list(res.items()):
        if v > 3600*24*1:
            del res[k]

    with open("./historical_short_lived_path.p", "wb") as fp:
        pickle.dump(res, fp)


def test08():
    caida_as_rel_pc, caida_as_rel_pp = load_caida_as_rel()
    with open("./historical_short_lived_path.p", "rb") as f:
        short_lived_path_dict = pickle.load(f)
        #check_valid_events(short_lived_path_dict, caida_as_rel_pp, caida_as_rel_pc)
        check_miscon_events(short_lived_path_dict,
                            caida_as_rel_pp, caida_as_rel_pc)


def test09():
    filters = ["191.102.61.0/26", "130.156.192.0/20",
               "150.186.96.0/19", "50.202.61.0/24"]
    live_dict = {}
    with open("live_data_20220630.p", "rb") as f:
        live_dict = pickle.load(f)
    for t in live_dict:
        if t[1] in filters:
            print(t, 'true')


def test10():
    lived_path_dict1 = {}
    lived_path_dict2 = {}
    with open("live_paths_20220630.p", "rb") as f:
        lived_path_dict1 = pickle.load(f)
    with open("live_paths_20220715.p", "rb") as f:
        lived_path_dict2 = pickle.load(f)
    long_lived_path = {}
    for path in lived_path_dict1:
        if path in lived_path_dict2:
            long_lived_path[path] = 1
    with open("./long_lived_path.p", "wb") as fp:
        pickle.dump(dict(long_lived_path), fp)


def test11():
    long_lived_path = {}
    with open("./long_lived_path.p", "rb") as f:
        long_lived_path = pickle.load(f)
    format_groundtruth_data(long_lived_path)


def test12():
    ifile = './ValidateData/bgpstream.attacks.20220715.dat'
    caida_as_org = load_caida_as_org()
    caida_as_rel_pc, _ = load_caida_as_rel()
    ofile = open('./ValidateData/bgpstream.attacks.20220715.rov.csv', 'w')
    verify_by_file(ifile, ofile, None, caida_as_org,
                   caida_as_rel_pc, None, None)
    ofile.close()


def test13():
    f1 = open('./ValidateData/bgp_hijacks.20220715.csv', 'w')
    f2 = open('./ValidateData/route_leak.20220715.csv', 'w')
    ifile = './ValidateData/bgpstream.attacks.20220715.rov.csv'
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(',')
            if 'Possible BGP hijack' in fields[-1]:
                #line = fields[0] + ',' + fields[-1]
                f1.write(line)
            elif 'BGP Leak' in fields[-1]:
                f2.write(line)
    f1.close()
    f2.close()


def split_file():
    f1 = open('./BGPincidents/route_leak.20211224later.reduced.csv', 'w')
    f2 = open('./BGPincidents/route_leak.20211224earlier.reduced.csv', 'w')
    ifile = './BGPincidents/route_leak.20211224.reduced.csv'
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(',')
            as_path = fields[2]
            hops = as_path.split('+')
            hops = hops[:-1]
            if '7633' in hops:
                f1.write(line)
            if '132215' in hops:
                f2.write(line)
    f1.close()
    f2.close()


def main():
    # test_live_stream()
    # long_lived_path = {}
    # format_groundtruth_data(None)
    # process_file()
    # test12()
    # test13()
    # test()
    # format_bgpmon_data()
    # test()
    # test05extra()
    # split_file()
    # test05extra()
    test_historical_incidents()


if __name__ == "__main__":
    main()
