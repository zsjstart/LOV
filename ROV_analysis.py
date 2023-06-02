#!/usr/bin/env python
from collections import defaultdict
from pybgpstream import *
from datetime import *
import ipaddress
import pytricia
import json
from itertools import groupby
import numpy as np
import time
import os
import glob
import concurrent.futures
from blist import *
import datetime
import re
import pickle
import pandas as pd

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
    MOAS = set()
    for vrp_prefix, vrp_prefixlen, vrp_maxlen, vrp_asID in roas[binary_prefix]:
        MOAS.add(vrp_asID)

        if(asID is not None and vrp_asID != 0):
            if(vrp_asID == asID):
                maxlen = vrp_maxlen
                if vrp_maxlen is None:
                    maxlen = vrp_prefixlen

                if prefix_len <= maxlen:
                    result = BGP_PFXV_STATE_VALID
                    r = " ".join(map(str, [
                                 timestamp, prefix_addr, prefix_len, as_path, asID, result, vrp_asID]))
                    results = []
                    results.append(r)
                    invalid = False
                    return results, invalid
                else:
                    result = BGP_PFXV_STATE_INVALID
                    '''
                    r = " ".join(map(str, [
                                 timestamp, prefix_addr, prefix_len, as_path, asID, result, vrp_asID]))
                    results = []
                    results.append(r)
                    '''
                    invalid = True  # MaxLength Matches
                    #return results, invalid

            else:
                result = BGP_PFXV_STATE_INVALID
                invalid = True
                #print('Hijack: ', [time, prefix_addr, prefix_len, asID, result, vrp_asID, covered_prefix])
    MOAS = '+'.join(map(str, list(MOAS)))
    r = " ".join(map(str, [timestamp, prefix_addr, prefix_len,
                           as_path, asID, result, MOAS]))
    results.append(r)
    return results, invalid
  
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
  
def isCover(prefix_addr, prefix_len, dataset):
    ip_prefix = prefix_addr+'/'+str(prefix_len)
    # get the longest matching prefix for arbitrary prefixes, return None if not exists
    return dataset.get_key(ip_prefix)


def myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict):
    if(":" in prefix_addr):
        return isCover(prefix_addr, prefix_len, ipv6_dict)
    else:
        return isCover(prefix_addr, prefix_len, ipv4_dict)
      
def process_v2(roas, ipv4_dict, ipv6_dict, infile):
    dic = dict()
    with open(infile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            g = line.split('|')
            ty = g[0]
            timestamp = int(g[-2])
            if ty != '=':
                continue
            prefix = g[1]
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            entry = myGetCovered(prefix_addr, prefix_len, ipv4_dict, ipv6_dict)
            if entry is None:
                continue
            as_path = g[2]
            if "{" in as_path or ":" in as_path:
                continue
            # Get the array of ASns in the AS path and remove repeatedly prepended ASns
            hops = [k for k, g in groupby(as_path.split(" "))]
            if len(hops) > 1:
                asID = int(hops[-1])

                dic[(timestamp, prefix, asID, as_path)] = 1
    return dic
  
def collect_known_raw_data(date, roas, ipv4_dict, ipv6_dict, wf):
    print(date)
    y, m, d = date.split('-')
    dirpath = '/home/zhao/Shujie/Routing_traffic/coding/bgpdata/rib.'+y+'.'+m+'.'+d
    files = os.path.join(dirpath, "*")
    files = glob.glob(files)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i, infile in enumerate(files):
            #outfile = infile.replace('.bz2', '.txt')
            #cmd = """ bgpscanner %s > %s """ % (infile, outfile)
            # os.system(cmd)

            # collect_raw_data(year, month, day, collector)
            futures.append(executor.submit(process_v2, roas, ipv4_dict,
                                           ipv6_dict, infile))
        for future in concurrent.futures.as_completed(futures):
            dic = future.result()
            for k in dic:
                #text = ','.join(map(str, list(sorted(dic[prefix])[0])))
                text = ','.join(map(str, list(k)))
                wf.write(text+'\n')
                
def test_rib_data():
    end_date = '2022-07-15'
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
    wf = open('./bgpdata/results/rib_data_20220615_cover_roas.res', 'w')
    collect_known_raw_data('2022-06-15', roas, ipv4_dict, ipv6_dict, wf)
    wf.close()

def collect_BGPstream_routes():
    #dates = [("2021-10-25 09:56", "2021-10-25 10:32", "_212046_"), ("2021-10-13 08:58", "2021-10-13 09:58", "_212046_"), ("2021-09-21 07:40", "2021-09-21 08:54", "_62325_"), ("2021-05-18 09:00", "2021-05-18 14:00", "_48467_"), ("2021-04-16 13:49", "2021-04-16 15:19", "_55410_"), ("2021-02-05 15:50", "2021-02-05 18:55", "_136168_")]
    #("2021-08-19 16:20", "2021-08-19 16:50", "_265038_"), ("2021-07-30 08:33", "2021-07-30 09:13", "_137996_"), ("2021-06-03 10:10", "2021-06-03 12:46", "_199599_")
    #dates = [("2022-01-31T20:12", "2022-01-31T20:56", "_18978_"), ("2022-05-31T07:28", "2022-05-31T07:53", "_38744_"), ("2022-06-19T10:25", "2022-06-19T11:25", "_38744_"), ("2022-08-10T20:37", "2022-08-10T20:47", "_4775_"), ("2022-11-17T06:00", "2022-11-17T06:06", "_1661_"), ("2022-12-15T05:43", "2022-12-15T05:51", "_1661_"), ("2022-02-09T08:59", "2022-02-09T10:38", "_4436_")]
    dates = [("2022-07-26T21:26", "2022-07-27T23:10", "_12389_")]
    for date in dates:
        # for collector in ['amsix', 'wide', 'chicago']:
        stream = pybgpstream.BGPStream(
            # Consider this time interval:
            # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
            from_time=date[0], until_time=date[1],
            
            collectors=["route-views.amsix","route-views.wide", "route-views.chicago", ],
            #collectors = ['', 'route-views3', 'route-views4', 'route-views5', 'route-views6', 'route-views.amsix', 'route-views.chicago', 'route-views.chile', 'route-views.eqix', 'route-views.flix', 'route-views.gorex', 'route-views.isc', 'route-views.kixp', 'route-views.jinx', 'route-views.linx', 'route-views.napafrica', 'route-views.nwax', 'route-views.phoix', 'route-views.telxatl', 'route-views.wide', 'route-views.sydney', 'route-views.saopaulo', 'route-views2.saopaulo', 'route-views.sg', 'route-views.perth', 'route-views.peru', 'route-views.sfmix', 'route-views.siex', 'route-views.soxrs', 'route-views.mwix', 'route-views.rio', 'route-views.fortaleza', 'route-views.gixa', 'route-views.bdix', 'route-views.bknix', 'route-views.uaeix', 'route-views.ny'],
            #collectors = ['rrc00', 'rrc01', 'rrc02', 'rrc03', 'rrc04', 'rrc05','rrc06','rrc07','rrc08','rrc09','rrc10','rrc11','rrc12','rrc13','rrc14','rrc15','rrc16','rrc17','rrc18','rrc19','rrc20','rrc21', 'rrc22', 'rrc23', 'rrc24', 'rrc25', 'rrc26'],
            record_type="updates",
            filter='path '+date[2]
            #filter='prefix more 95.215.3.30/32 and path '+date[2]
        )
        checked = {}
        d = ''.join(date[0].split(' ')[0].split('-'))
        f0 = open(
            '/home/zhao/Shujie/Routing_traffic/coding/BGPincidents/202303/bgp.hijack.'+d+'.csv', 'w')
        f1 = open(
            '/home/zhao/Shujie/Routing_traffic/coding/BGPincidents/202303/bgp.hijack.'+d+'.dat', 'w')
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

                if asID != attacker:
                    continue
                t = (asID, prefix)
                if checked.get(t) != None:
                    continue
                checked[t] = 1
                # unique prefix
                f0.write(
                    ','.join([str(timestamp), prefix, as_path, asID, attacker])+'\n')
                f1.write(str(elem)+'\n')

        f0.close()
        f1.close()    
