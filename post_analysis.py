import concurrent.futures
from feature_extractor import calculate_heg_time, compute_gaussian_paras, compute_two_scores_new, compute_pfx_distance
import os
import glob
import re
import pickle
import requests
from scipy.stats import norm
import datetime
import math


from matplotlib import pyplot as plt
import numpy as np
import matplotlib as mpl
import matplotlib.dates as md
import pandas as pd
from matplotlib.ticker import ScalarFormatter
from pathlib import Path
from itertools import groupby
from create_local_database import update_at_specific_times, new_load_ROAs, update_roas, download_bgpdata
from smart_validator import validateOriginV2
import time
from test_live_stream import extract_features
from collections import defaultdict
from asrank_download_asn import AsnQuery
import json
import statistics
import ast
import seaborn as sns
import subprocess


#mpl.rcParams["figure.figsize"] = (11, 9)
#mpl.rcParams['figure.dpi'] = 110
#font = {'weight': 'bold',
#        'size': 10}
#plt.rc('font', **font)


def is_abnormal(u, s, x):
    v = (x-u)/s
    if norm.cdf(v) > 0.95:  # p = 0.05 #orm.cdf(v) < 0.05
        return True
    return False


def lookup_local_hegemony_v3(date, originasn, asn):
    start_time = calculate_heg_time(date-50*15*60)
    end_time = calculate_heg_time(date+1*15*60)
    af = 4
    base_url = "https://ihr.iijlab.net/ihr/api/hegemony/?"
    # &timebin__gte=%s&timebin__lte=%s&format
    local_api = "originasn=%s&asn=%s&af=%s&timebin__gte=%s&timebin__lte=%s&format=json"
    query_url = base_url + \
        local_api % (originasn, asn, af, start_time, end_time)
    x = 0.0
    Hes = []
    if query_url in Hes_dict:
        x, Hes = Hes_dict[query_url]
        return x, Hes
    rsp = None
    try:
        rsp = requests.get(query_url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
        }, timeout=60)
    except:
        return x, Hes

    if rsp.status_code != 200:
        return x, Hes
    rsp = rsp.json()
    if ('results' in rsp) and (len(rsp['results']) != 0):
        results = rsp['results']
        for res in results:
            if end_time in res['timebin']:
                x = float(res['hege'])
                continue
            he = float(res['hege'])
            Hes.append(he)
    Hes_dict[query_url] = (x, Hes)
    return x, Hes


def check_forward_hegemony_value(date, originasn, asn, u, s):
    is_burst = False
    for timestamp in range(date+3600*12, date+3600*24+1, 3600*12):  # 1*15*60
        end_time = calculate_heg_time(timestamp)
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
            return is_burst

        if rsp.status_code != 200:
            return is_burst
        rsp = rsp.json()
        if ('results' in rsp) and (len(rsp['results']) != 0):
            results = rsp['results']
            for res in results:
                if end_time in res['timebin']:
                    x = float(res['hege'])
                    break
        if not is_abnormal(u, s, x):

            is_burst = True
            break
    return is_burst


def post_detection_v2(timestamp, asn):
    Hes = []
    abnormal = 'False'

    _, Hes = sample_hegemony_values(timestamp, '0', asn)
    u, s = 0.0, 0.0

    if len(Hes) == 0:
        return abnormal
    else:
        data = Hes[1:]
        if len(data) < 10:
            return abnormal
        u, s = compute_gaussian_paras(data)

        for t in range(timestamp+15*60, timestamp+3*15*60, 15*60):
            x = sample_single_hegemony(t, '0', asn)
            if is_abnormal(u, s, x) and x > 1.01 * u:
                is_burst = check_forward_hegemony_value(t, '0', asn, u, s)
                if is_burst:
                    abnormal = 'True'
                    break
    return abnormal


def post_detection_v3(timestamp, asn):
    Hes = []
    abnormal = 'False'

    x, Hes = lookup_local_hegemony_v3(timestamp, '0', asn)
    u, s = 0.0, 0.0

    if len(Hes) == 0:
        return abnormal
    else:
        data = Hes[1:]
        if len(data) < 10:
            return abnormal
        u, s = compute_gaussian_paras(data)

        if is_abnormal(u, s, x) and x > 1.01 * u:
            is_burst = check_forward_hegemony_value(timestamp, '0', asn, u, s)
            if is_burst:
                abnormal = 'True'

    return abnormal


def post_detection_v4(date, asn):
    Hes = []
    abnormal = 'False'
    y, m, d = date.split('T')[0].split('-')
    hh, mm = date.split('T')[1].split(':')
    timestamp = int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm))))

    for t in range(timestamp, timestamp+3*15*60, 15*60):
        # x = sample_single_hegemony(timestamp, '0', asn)
        x, Hes = sample_hegemony_values(t, '0', asn)
        u, s = 0.0, 0.0
        if len(Hes) == 0:
            return abnormal
        else:
            data = Hes[1:]
            if len(data) < 10:
                return abnormal
            u, s = compute_gaussian_paras(data)

        if is_abnormal(u, s, x) and x > 2*u:
            is_burst = check_forward_hegemony_value(
                timestamp, '0', asn, u, s)
            print('is a burst: ', is_burst)
            if is_burst:
                abnormal = 'True'
                break
    return abnormal


def calculate_unix_time(date_and_time):
    '''
    Calculate unix time elapsed from a datetime object
    @param: date_and_time (datetime): datetime object
    @return: Seconds elapsed using unix reference (int)
    '''
    return int((date_and_time - datetime.datetime.utcfromtimestamp(0)).total_seconds())


def sample_hegemony_values(date, originasn, asn):
    start_time = calculate_heg_time(date-50*15*60)
    end_time = calculate_heg_time(date)
    # print(start_time, end_time)
    af = 4
    base_url = "https://ihr.iijlab.net/ihr/api/hegemony/?"
    # &timebin__gte=%s&timebin__lte=%s&format
    local_api = "originasn=%s&asn=%s&af=%s&timebin__gte=%s&timebin__lte=%s&format=json"
    query_url = base_url + \
        local_api % (originasn, asn, af, start_time, end_time)
    # print(query_url)
    rsp = None
    x = 0
    Hes = []
    try:
        rsp = requests.get(query_url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
        }, timeout=60)
    except:
        return x, Hes
    if rsp.status_code != 200:
        return x, Hes
    rsp = rsp.json()
    if ('results' in rsp) and (len(rsp['results']) != 0):
        results = rsp['results']
        for res in results:
            if end_time in res['timebin']:
                x = float(res['hege'])
                continue
            he = float(res['hege'])
            Hes.append(he)
    return x, Hes


def sample_single_hegemony(timestamp, originasn, asn):
    end_time = calculate_heg_time(timestamp+60*15*1)
    print('Tested time: ', end_time)
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


def one_day_analysis(ty, start_time, end_time, asn):
    f = open('./BGPincidents/post_analysis/plot/'+ty +
             '.'+str(asn)+'.'+start_time, 'w')
    y, m, d = start_time.split('T')[0].split('-')
    hh, mm = start_time.split('T')[1].split(':')
    start_timestamp = calculate_heg_time(int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm)))))
    y, m, d = start_timestamp.split('T')[0].split('-')
    hh, mm = start_timestamp.split('T')[1].split(':')
    start_timestamp = int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm))))

    y, m, d = end_time.split('T')[0].split('-')
    hh, mm = end_time.split('T')[1].split(':')
    end_timestamp = calculate_heg_time(int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm)))))
    y, m, d = end_timestamp.split('T')[0].split('-')
    hh, mm = end_timestamp.split('T')[1].split(':')
    end_timestamp = int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm))))

    for timestamp in range(start_timestamp-3600*10, end_timestamp+3600*10, 60*15):
        #t = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)

        x, Hes = sample_hegemony_values(timestamp, '0', asn)

        u, s = 0.0, 0.0
        abnormal = 'False'
        if len(Hes) == 0:
            continue
        else:
            data = Hes[1:]
            if len(data) < 10:
                continue
            u, s = compute_gaussian_paras(data)
            if is_abnormal(u, s, x) and x > 1.01*u:  # and x > 2*u
                abnormal = 'True'

        # res[timestamp] = (x, abnormal, u, s)
        res = ','.join(map(str, [timestamp, x, abnormal, u, s]))
        # print(res)
        f.write(res+'\n')

    f.close()


def bgp_hijack_post_analysis():
    file_path = './HistoricalDataAnalysis'
    files = os.path.join(
        file_path, "bgp_hijack.*.csv")  # "*.org.csv" #bgp_hijack.20220715.csv
    files = glob.glob(files)
    hijackdict = defaultdict(list)
    asnprefixset = set()
    ofile = open('./HistoricalDataAnalysis/bgp_hijack_incident.csv', 'w')
    f2 = open('./HistoricalDataAnalysis/bgp_hijack_white.csv', 'w')
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                # bgp hijacks,1657872238,64050,23.234.230.94/32,38880 64050,None
                timestamp, attacker, prefix = int(
                    fields[1]), fields[2], fields[3]
                hijackdict[(attacker, prefix)].append(timestamp)

    print('the number of hijacks: ', len(hijackdict))
    for k in hijackdict:
        start_time = sorted(set(hijackdict[k]))[0]
        end_time = sorted(set(hijackdict[k]))[-1]
        t = datetime.datetime.fromtimestamp(
            start_time, datetime.timezone.utc)

        abnormal = post_detection_v2(start_time, k[0])
        if abnormal == 'True':
            ofile.write(','.join(map(str, [t, k[0], k[1]]))+'\n')
        elif end_time - start_time > 3600*24*1:
            f2.write(','.join(map(str, [t, k[0], k[1]]))+'\n')

    ofile.close()
    f2.close()


def bgp_hijack_post_analysis_v2():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    ty = '*_hijack'
    file_path = './HistoricalDataAnalysis/new_measurements/'
    files = os.path.join(
        file_path, ty+".*.csv")  # "*.org.csv" #bgp_hijack.20220715.csv
    files = glob.glob(files)
    '''
    hijackerdict = {}
    with open(file_path+'bgp_hijack.asns.p', "rb") as f:
        hijackerdict = pickle.load(f)
    print(len(hijackerdict))
    '''
    of1 = open(file_path+ty+'_incident.csv', 'w')

    res, dates, numbers = [], [], []
    hijacks = dict()
    minihijacks = dict()
    hijacksatday = defaultdict(set)
    routesatday = defaultdict(set)
    routesdict = {}
    rpki_none, rpki_valid = {}, {}
    rovresults = defaultdict(set)
    confidict = set()
    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]
        date = suffix[4:6]+'/'+suffix[6:8]
        hijackdict = defaultdict(set)
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')

                # bgp hijack,1664721590,59729,213.209.135.0/24,16552 6453 1273 57344 31083 59729,209372,2,0,0+0.0+0+0+0+0,1273
                timestamp, attacker, prefix, as_path, scores = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[-2]
                confi = sum(
                    list(map(float, scores.split('+'))))
                if confi > 0:  # if confi > 0, it could be a benign conflict
                    #print('Confi: ', confi)
                    confidict.add((attacker, prefix))

                hijackdict[(attacker, prefix)].add(
                    (timestamp, as_path, scores))
                hijacksatday[date].add((attacker, prefix))
                routesatday[date].add((prefix, as_path))
                hijacks[(attacker, prefix)] = 1
                routesdict[(attacker, prefix, as_path)] = 1
                '''
                t = str(datetime.datetime.fromtimestamp(
                    timestamp, datetime.timezone.utc))
                time = t.split(' ')[0]
                if (time, attacker) not in hijackerdict:
                    continue
                # here we revalidate attacker-prefixes
                invalid = roa_validation(timestamp, int(
                    attacker), prefix, as_path, roa_px_dict)
                rovresults[attacker].add(invalid)
                minihijacks[(attacker, prefix)] = 1
                '''
        
        for k in hijackdict:
            start_time, as_path, scores = sorted(hijackdict[k])[0]

            t = datetime.datetime.fromtimestamp(
                start_time, datetime.timezone.utc)

            abnormal = post_detection_v3(start_time, k[0])
            if abnormal == 'True':
                of1.write(
                    ','.join(map(str, [t, k[0], k[1], as_path, scores]))+'\n')
        

    print('Hijacks, minihijacks, route objects: ', len(
        hijacks), len(minihijacks), len(routesdict))
    print('Confidence over 0.2: ', len(confidict))
    for attacker in rovresults:
        if False in rovresults[attacker] or None in rovresults[attacker]:
            print(attacker, rovresults[attacker])
    for date in hijacksatday:
        n = len(hijacksatday[date])
        res.append((date, n))
    res = sorted(res)
    for date, n in res:
        dates.append(date)
        numbers.append(n)
    of1.close()
    # print(sum(numbers))
    count = 0
    for date in routesatday:
        count = count + len(routesatday[date])

    return dates, numbers


def whitelist_asbinding_routes():
    file_path = './HistoricalDataAnalysis/*/'
    files = os.path.join(file_path, "asbinding_whitelist.p")
    files = glob.glob(files)
    res = dict()
    for f in files:
        print(f)
        with open(f, "rb") as f:
            asbindingdict = pickle.load(f)
            for k in asbindingdict:
                res[k] = 1
    return res


def collect_invalid_routes():
    file_path = './HistoricalDataAnalysis/new_measurements/'
    files = os.path.join(file_path, "lovres.*.out")
    files = glob.glob(files)
    print(len(files))
    #whiteasbindings = whitelist_asbinding_routes()
    hijackerdict = {}
    leakerdict = {}
    '''
    with open(file_path+'/bgp_hijack.asns.p', "rb") as f:
        hijackerdict = pickle.load(f)
    
    with open(file_path+'/route_leak.asns.p', "rb") as f:
        leakerdict = pickle.load(f)
    print(len(hijackerdict), len(leakerdict))
    '''
    with open('./lov_invalid_route.p', "rb") as f:
        lovinvaliddict = pickle.load(f)
    invalid = dict()
    routesatday = defaultdict(set)
    asdict = defaultdict(set)
    asbindingdict = dict()
    prefixdict = dict()
    underpriordict = dict()

    ofile = open('./all_rpki_invalid_asns.csv', 'w')
    # ofile2 = open(
    #    './HistoricalDataAnalysis/new_measurements/underprioritized_routes.csv', 'w')
    totaldict = {}
    label1dict, label2dict = defaultdict(set), defaultdict(set)
    benignconflicts, conflictasn, conflictprefix, conflictpair = set(), set(), set(), set()
    errors, errorasn, errorprefix, errorpair = set(), set(), set(), set()
    '''
    asbindingdict = {}
    asvalleydict = {}
    with open(file_path+"/asbinding_whitelist.p", "rb") as f:
    	asbindingdict = pickle.load(f)
    with open(file_path+"/asvalley_whitelist.p", "rb") as f:
    	asvalleydict = pickle.load(f)
    '''
    	
    for f in files:
        #suffix = f.split('/')[-1].split('.')[-2]
        #date = suffix[4:6]+'/'+suffix[6:8]
        invalidatday = dict()

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                # 1661932800,270771,181.189.10.0/24,38880 6762 53013 270771,asID,1,0,0+0.0+0+0+0+0,None
                res = line.strip('\n').split(',')
                timestamp = res[0]
                t = str(datetime.datetime.fromtimestamp(
                    int(timestamp), datetime.timezone.utc))
                date = t.split(' ')[0]

                rpki_status = int(res[-3])
                scores = res[-2].split('+')
                origin_matching = scores[0]

                asID = res[1]
                prefix = res[2]
                as_path = res[3]
                label = int(res[-4])
                leaker = res[-1]
                totaldict[(asID, prefix, as_path)] = 1

                if label == 2:
                    label2dict[date].add((prefix, as_path))
                    
                    if (date, asID) in hijackerdict or (date, leaker) in leakerdict:
                        underpriordict[(asID, prefix, as_path)] = 1

                if rpki_status == 1:
                    continue
                # The following is the coding for RPKI-invalid routes!!!!
                routesatday[date].add((asID, prefix, as_path))
                invalid[(prefix, as_path)] = 1
                invalidatday[(asID, prefix, as_path)] = t
                asdict[asID].add(prefix)
                asbindingdict[(asID, prefix)] = 1
                prefixdict[prefix] = 1
                '''
                if (asID, prefix, as_path) in lovinvaliddict:
                    errors.add((prefix, as_path))
                    errorasn.add(asID)
                    errorprefix.add(prefix)
                    errorpair.add((asID, prefix))
                    # continue

                else:

                    if (asID, prefix) in whiteasbindings:
                        label1dict[date].add((prefix, as_path))
                        benignconflicts.add((prefix, as_path))
                        conflictasn.add(asID)
                        conflictprefix.add(prefix)
                        conflictpair.add((asID, prefix))
                    elif label == 1:
                        label1dict[date].add((prefix, as_path))
                        benignconflicts.add((prefix, as_path))
                        conflictasn.add(asID)
                        conflictprefix.add(prefix)
                        conflictpair.add((asID, prefix))
                '''
        # for k in invalidatday:
        #    ofile.write(','.join([invalidatday[k]]+list(k))+'\n')

    print('total number of underprior: ', len(
        underpriordict))
    '''
    geodict = geodistr(asdict)
    print(len(geodict))
    ccres = set()
    for k, v in geodict.items():

        if v != None:
            ccres.add(v)
    print('the number of countries: ', len(ccres))

    res = []
    for k in asdict:
        res.append((len(asdict[k]), k))
    res = sorted(res, reverse=True)

    ranklist = topasrank(res)
    for item in ranklist:
        ofile2.write(','.join(map(str, item))+'\n')
    ofile2.close()
    '''
    # ofile.close()
    # ofile2.close()
    container, dates1, numbers1 = [], [], []
    for date in routesatday:

        n = len(routesatday[date])
        container.append((date, n))
    container = sorted(container)
    for date, n in container:
        dates1.append(date)
        numbers1.append(n)
    
    for i in range(len(dates1)):
    	if i % 4 == 0: continue
    	dates1[i] = ''
    
    
    print('The mean RPKI-invalid routes: ', sum(numbers1)/len(dates1))
    
    '''
    container, dates, numbers = [], [], []
    for date in label2dict:
        n = len(label2dict[date])
        container.append((date, n))
    container = sorted(container)
    for date, n in container:
        dates.append(date)
        numbers.append(n)
    print('DT-invalid numbers: ', dates, numbers)
    print('The mean DT-invalid routes: ', sum(numbers)/len(dates))
    
    
    container, dates, numbers = [], [], []
    for date in label1dict:
        n = len(label1dict[date])
        container.append((date, n))
    container = sorted(container)
    for date, n in container:
        dates.append(date)
        numbers.append(n)
    
    
    
    print('The mean benign conflicts routes: ', sum(numbers)/len(dates))
    # showing statistics in all of invalid announcemnts:
    print('Statistics of conflicts regarding asn, prefix, asprefixpair: ', len(
        benignconflicts), len(conflictasn), len(conflictprefix), len(conflictpair))
    print('Statistics of invalid regarding total number, asn, prefix, asprefixpair: ', len(
        invalid), len(asdict), len(prefixdict), len(asbindingdict))
    print('Statistics of errors regarding total number, asn, prefix, asprefixpair: ', len(
        errors), len(errorasn), len(errorprefix), len(errorpair))
    print("Fraction of ROA misconfigurations: ", len(benignconflicts)/len(invalid), len(conflictasn) /
          len(asdict), len(conflictprefix)/len(prefixdict), len(conflictpair)/len(asbindingdict))
    print("Fraction of errors: ", len(errors)/len(invalid), len(errorasn)/len(asdict),
          len(errorprefix)/len(prefixdict), len(errorpair)/len(asbindingdict))
    '''
    # ofile.close()
    return dates1, numbers1


def process_raw_routes(f, of, roa_px_dict):

    checked = dict()
    with open(f, "r") as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            g = line.split('|')
            timestamp = int(g[-2])
            prefixes = g[1].split(' ')
            for prefix in prefixes:

                as_path = g[2]
                if "{" in as_path or ":" in as_path:
                    continue
                # Get the array of ASns in the AS path and remove repeatedly prepended ASns
                hops = [k for k, g in groupby(as_path.split(" "))]
                if len(hops) == 0:
                    continue
                asID = int(hops[-1])
                invalid = roa_validation(
                    timestamp, asID, prefix, as_path, roa_px_dict)
                checked[(asID, prefix, as_path)] = 1
                if invalid:
                    of.write(
                        ','.join(map(str, [timestamp, asID, prefix, as_path]))+'\n')
    of.write('num:'+str(len(checked))+'\n')


def download_bgp(y, m, d):
    download_path = "http://archive.routeviews.org/route-views.amsix/bgpdata/%s.%s/RIBS/rib.%s%s%s.1200.bz2" % (
        y, m, y, m, d)
    basicpath = "../bgpdata"
    dirpath = os.path.join(basicpath, y+'.'+m+'.'+d)
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)
    else:
        return dirpath
    savepath = dirpath + '/rib.bz2'
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(savepath, "wb") as f:
            f.write(response.content)
    outfile = savepath.replace('.bz2', '.txt')
    cmd = """ bgpscanner %s > %s """ % (savepath, outfile)
    os.system(cmd)
    cmd = """ rm %s""" % (savepath)
    os.system(cmd)

    return dirpath


def collect_invalid_routes_new_measurements():
    for m in [10, 11]:
        if m == 10:
            for d in range(15, 32):
                y, m, d = str(2022), str(m), str(d)
                dirpath = download_bgp(y, m, d)

        elif m == 11:
            for d in range(1, 16):
                if int(d/10) == 0:
                    d = '0'+str(d)
                y, m, d = str(2022), str(m), str(d)
                dirpath = download_bgp(y, m, d)


def measure_invalid_routes(y, m, d, dirpath):
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    update_roas(y, m, d)
    roa_px_dict = new_load_ROAs(roa_path)
    f = dirpath + '/rib.txt'
    of = open(dirpath+'/rib.invalid.res', 'w')
    process_raw_routes(f, of, roa_px_dict)
    cmd = """ rm %s""" % (f)
    os.system(cmd)
    of.close()

    '''
    N = 0
    invdict = dict()
    of = open('./invalid_routes.20221114.res', 'w')
    for f in files:
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):

                if 'num' in line:
                    num = line.split(':')[1].strip('\n')
                    N = N + int(num)
                else:
                    # 1668200657,137130,1.6.219.0/24,5394 9498 21859 9583 137130
                    timestamp, asID, prefix, as_path = line.strip(
                        '\n').split(',')
                    invdict[(asID, prefix, as_path)] = timestamp
    for k in invdict:

        of.write(','.join([invdict[k]]+list(k))+'\n')
    print('total number of all measured routes and invalid: ',
          N, len(invdict))  # 24097787, 98926
    '''


def rpki_invalid_routes_analysis():
    rpki_operators = get_rpki_operators()
    # new_measurements: contain data between 2022-07-15 and 2022-08-31, filter AS8075 if before 2022-10-19
    file_path = './HistoricalDataAnalysis/measure_202209/'
    f = open(file_path + 'rpki_invalid_oper.csv', 'w')
    ifile = file_path + 'rpki_invalid_routes.csv'
    threstimestamp = calculate_heg_time(int(calculate_unix_time(
        datetime.datetime(int('2022'), int('10'), int('19')))))
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.strip('\n').split(',')
            # 2022-09-13 17:59:57+00:00,270771,181.189.10.0/24,6762 53013 270771
            time, asID, prefix, as_path = fields
            date = time.split(' ')[0]
            y, m, d = date.split('-')
            timestamp = calculate_heg_time(
                int(calculate_unix_time(datetime.datetime(int(y), int(m), int(d)))))

            hops = as_path.split(' ')
            rpkis = set()
            for hop in hops:
                if timestamp <= threstimestamp and hop == '8075':
                    continue
                if rpki_operators.get(int(hop)) == 1:
                    rpkis.add(hop)
            if len(rpkis) == 0:
                continue

            f.write(','.join([time, asID, prefix, as_path]) +
                    ','+'+'.join(list(rpkis))+'\n')
    f.close()


def filter_events():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    valdict = defaultdict(set)
    file_path = './HistoricalDataAnalysis/measure_202212/'
    ty = 'route_leak'
    attackerdict = {}
    with open('./HistoricalDataAnalysis/measure_202211'+'/'+ty+'.asns.p', "rb") as f:
        attackerdict = pickle.load(f)
    asndict = {}
    for k in attackerdict:
        asndict[k[1]] = 1

    f = open(file_path + ty+'_statistics.new.csv', 'w')
    ifile = file_path + ty+'_statistics.csv'
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-10-25 09:04:45+00:00,49392,193.108.112.0/24,16552 6453 1273 3216 35598 39238 39238 39238 49392
            line = line.strip('\n')
            timestamp, asID, prefix, as_path = line.split(',')
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            hops = as_path.split(' ')
            origin = hops[-1]
            results, invalid = validateOriginV2(
                prefix_addr, prefix_len, timestamp, "+".join(hops), int(asID), roa_px_dict, None)

            # if invalid == None: continue # only for hijacks

            if invalid == False:
                continue
            if origin == asID:  # only for leaks: leaker is the origin, but prefix is authorized by its provider
                continue
            if asndict.get(asID) != None:
                print(asID)
            vrpIDs = []
            for res in results:  # MOAS
                vrpIDs.append(res.split(' ')[-2])

            f.write(line+','+str(vrpIDs[0])+'\n')

    f.close()

def lov_invalid_post_analysis():
    ty = 'quarantined_*'
    d = 'new_measurements'
    file_path = './HistoricalDataAnalysis/'+d
    files = os.path.join(
        file_path, ty+".202207*.csv")  # "*.org.csv" #bgp_hijack.20220715.csv
    files = glob.glob(files)
    print(len(files))
    
    asbindingdict = {}
    asvalleydict = {}
    with open(file_path+"/asbinding_whitelist.p", "rb") as f:
    	asbindingdict = pickle.load(f)
    with open(file_path+"/asvalley_whitelist.p", "rb") as f:
    	asvalleydict = pickle.load(f)
    	
    
    underprior = verified_post_analysis(d)
    
    
    for f in files:
    
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                # bgp hijack,1657873006,211252,80.76.51.0/24,42541 213035 211252,,2,0,0+0.4+0+0+0+0,None
                timestamp, attacker, prefix, as_path, rpki, scores, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], int(fields[-3]), fields[-2], fields[-1].strip('\n')
                t = str(datetime.datetime.fromtimestamp(
                    timestamp, datetime.timezone.utc))
                date = t.split(' ')[0]
                
                y, m, d = date.split('-')
                date = m+'/'+d
                
                length = prefix.split('/')[1]
                hops = [k for k, g in groupby(as_path.split(" "))]
                
                if asbindingdict.get((str(attacker), prefix)) == 1:
                	continue
                
                if leaker != 'None':
                    
                    as_path = '_'.join(hops)
                    valley = re.search('\d+_'+leaker+'_\d+', as_path).group(0)
                    if asvalleydict.get(valley) == 1:
                    	continue
                underprior[date].add((prefix, as_path))
    dates = []
    numbers = []
    for date in underprior:
    	dates.append(date)
    	numbers.append(len(underprior[date]))
    print('lov_invalid: : ', numbers, dates, sum(numbers)/len(dates))
              
    

def quarantined_asbinding_post_analysis():
    ty = 'quarantined_asbinding'
    file_path = './HistoricalDataAnalysis/measure_202212'
    files = os.path.join(
        file_path, ty+".*.csv")  # "*.org.csv" #bgp_hijack.20220715.csv
    files = glob.glob(files)
    print(len(files))
    hijackerdict = {}
    with open(file_path+'/bgp_hijack.asns.p', "rb") as f:
        hijackerdict = pickle.load(f)
    leakerdict = {}
    with open(file_path+'/route_leak.asns.p', "rb") as f:
        leakerdict = pickle.load(f)
    print(len(hijackerdict), len(leakerdict))

    ofile = open(file_path+'/'+ty+'_whitelist.csv', 'w')
    routesdict = {}
    asbindingdict = defaultdict(set)
    asdict = dict()
    asbinding_whitelist = {}
    bcminidict = {}
    underprior = {}
    filtereddict = {}
    totaldict = {}
    bcroutesminidict = {}
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                # bgp hijack,1657873006,211252,80.76.51.0/24,42541 213035 211252,,2,0,0+0.4+0+0+0+0,None
                timestamp, attacker, prefix, as_path, rpki, scores, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], int(fields[-3]), fields[-2], fields[-1].strip('\n')
                t = str(datetime.datetime.fromtimestamp(
                    timestamp, datetime.timezone.utc))
                date = t.split(' ')[0]
                # some malicious ASes initiated the same routes but not found anomalies with post-analyzer at the other days!!!! Please analyze!!! Take an example to explain
                if hijackerdict.get((date, attacker)) == 1 or leakerdict.get((date, leaker)) == 1:
                    underprior[(attacker, prefix, as_path)] = 1
                    continue
                totaldict[(attacker, prefix, as_path)] = 1

                '''
                # After confirmation, it is a misidentification, caused by the feature value of prefix distance, please modify!! Already done!!
                if (attacker, prefix, as_path) in bcroutesdict:
                    print(date, line)
                    bcroutesminidict[(attacker, prefix, as_path)] = 1
                    # continue
                '''

                length = prefix.split('/')[1]
                if ('.' in prefix and int(length) > 24) or (':' in prefix and int(length) > 48):
                    # remove the length of more than 24, which see more likely to be hijacks.
                    filtereddict[(attacker, prefix, as_path)] = 1
                    continue

                routesdict[(attacker, prefix, as_path)] = 1
                confi_score = sum(list(map(float, scores.split('+'))))
                asbindingdict[(attacker, prefix)].add(
                    (timestamp, confi_score))
                asdict[attacker] = 1
    print('underprioritized {}, quarantined all {} routes objects, {} filtered routes,  the rest {} routes covering {} asbindings in {} Ases: '.format(
        len(underprior), len(totaldict), len(filtereddict), len(routesdict), len(asbindingdict), len(asdict)))

    n1, n2, n3, n4, n5 = 0, 0, 0, 0, 0
    for k in asbindingdict:

        start_time = sorted(asbindingdict[k])[0][0]
        end_time = sorted(asbindingdict[k])[-1][0]
        confi_score = sorted(asbindingdict[k])[-1][1]
        '''
        if k in bcdict:
            bcminidict[k] = 1
        '''
        # if confi_score == 1:
        #    n1 = n1 + 1

        if confi_score >= 0.6:
            n2 = n2 + 1
            asbinding_whitelist[k] = 1
            ofile.write(
                ','.join(map(str, [start_time, k[0], k[1]]))+'\n')
        elif end_time - start_time >= 3600*24*1:
            second_time = sorted(asbindingdict[k])[1][0]
            if second_time - start_time <= 3600*24*30:
                asbinding_whitelist[k] = 1

                n3 = n3 + 1
                ofile.write(
                    ','.join(map(str, [start_time, k[0], k[1]]))+'\n')
            else:
                n5 = n5 + 1
        else:
            n5 = n5 + 1

    ofile.close()
    print('bc, n1, n2, n3, filtered, Other: ',
          len(bcminidict), n1, n2, n3, n4, n5)
    with open(file_path+'/asbinding_whitelist.p', "wb") as fp:
        pickle.dump(dict(asbinding_whitelist), fp)


def quarantined_asvalley_post_analysis():
    ty = 'quarantined_asvalley'
    file_path = './HistoricalDataAnalysis/measure_202212'
    files = os.path.join(
        file_path, ty+".*.csv")  # "*.org.csv" #bgp_hijack.20220715.csv
    files = glob.glob(files)
    print(len(files))
    hijackerdict = {}
    with open(file_path+'/bgp_hijack.asns.p', "rb") as f:
        hijackerdict = pickle.load(f)
    leakerdict = {}
    with open(file_path+'/route_leak.asns.p', "rb") as f:
        leakerdict = pickle.load(f)
    ofile = open(file_path+'/'+ty+'_whitelist.csv', 'w')

    asvalleydict = defaultdict(set)
    asvalley_whitelist = {}
    asdict = {}
    totaldict = {}
    filtereddict = {}
    n = 0
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                # quarantined,1657872031,12654,2001:7fb:fe04::/48,47957 44530 25091 12654,2,1,1+0+0+0+0+0,44530
                timestamp, victim, prefix, as_path, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[-1].strip('\n')
                t = str(datetime.datetime.fromtimestamp(
                    timestamp, datetime.timezone.utc))
                date = t.split(' ')[0]
                if (date, victim) in hijackerdict or (date, leaker) in leakerdict:
                    continue

                hops = [k for k, g in groupby(as_path.split(" "))]
                as_path = '_'.join(hops)
                valley = re.search('\d+_'+leaker+'_\d+', as_path).group(0)
                totaldict[(victim, prefix, as_path)] = 1
                asvalleydict[valley].add(timestamp)
                asdict[leaker] = 1
    print('quarantined {} routes objects, filtered {},  {} valleys in {} Ases: '.format(
        len(totaldict), len(filtereddict), len(asvalleydict), len(asdict)))
    n1, n2 = 0, 0
    for k in asvalleydict:

        if len(asvalleydict[k]) == 1:
            n1 = n1 + 1
        else:
            start_time = sorted(asvalleydict[k])[0]
            second_time = sorted(asvalleydict[k])[1]
            end_time = sorted(asvalleydict[k])[-1]
            if end_time - start_time >= 3600*24*1 and second_time - start_time <= 3600*24*30:
                asvalley_whitelist[k] = 1
                n2 = n2 + 1
                ofile.write(
                    ','.join(map(str, [start_time, k]))+'\n')
            else:
                n1 = n1 + 1
    print('n1, n2: ', n1, n2)
    ofile.close()
    with open(file_path+'/asvalley_whitelist.p', "wb") as fp:
        pickle.dump(dict(asvalley_whitelist), fp)


def route_leak_post_analysis():
    file_path = './HistoricalDataAnalysis'
    ty = 'route_leak'
    files = os.path.join(file_path, ty+".*.csv")  # "*.org.csv"
    files = glob.glob(files)
    leakdict = defaultdict(list)
    hijackdict = defaultdict(list)
    ofile = open('./HistoricalDataAnalysis/'+ty+'_incident.20220811.csv', 'w')
    f2 = open('./HistoricalDataAnalysis/'+ty+'_white.20220811.csv', 'w')
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')

                # bgp hijacks,1657872044,211237,141.11.190.0/24,1103 20562 1273 1299 3356 9121 43260 209737 211237,1273
                timestamp, asID, prefix, as_path, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[5].strip('\n')
                hops = [k for k, g in groupby(as_path.split(" "))]
                as_path = '_'.join(hops)

                valley = re.search('\d+_'+leaker+'_\d+', as_path).group(0)
                leakdict[valley].append(timestamp)
                hijackdict[(asID, prefix)].append(timestamp)
    print('the total number of valleys: ', len(leakdict))
    n = 0
    for k in leakdict:

        start_time = sorted(leakdict[k])[0]
        end_time = sorted(leakdict[k])[-1]
        t = datetime.datetime.fromtimestamp(
            start_time, datetime.timezone.utc)
        if end_time - start_time > 3600*24*1:
            n = n+1
    print(n)

    '''
	leaker = k.split('_')[1]
	abnormal = post_detection_v2(start_time, leaker)
	if abnormal == 'True':
	    ofile.write(','.join(map(str, [t, k, 'route leak']))+'\n')
	elif end_time - start_time > 3600*24*1:
	    f2.write(','.join(map(str, [t, k]))+'\n')
	
	
	if 'extra' in ty:
	for k in hijackdict:
	    start_time = sorted(hijackdict[k])[0]
	    end_time = sorted(hijackdict[k])[-1]
	    t = datetime.datetime.fromtimestamp(
		start_time, datetime.timezone.utc)
	    abnormal = post_detection_v2(start_time, k[0])
	    if abnormal == 'True':
		ofile.write(
		    ','.join(map(str, [t, k[0], k[1], 'bgp hijack']))+'\n')
	    elif end_time - start_time > 3600*24*1:
		f2.write(','.join(map(str, [t, k[0], k[1]]))+'\n')
	'''
    ofile.close()
    f2.close()


def route_leak_post_analysis_v2():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)
    caida_as_rel_pc = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pc.p', "rb") as f:
        caida_as_rel_pc = pickle.load(f)
    file_path = './HistoricalDataAnalysis/new_measurements/'
    ty = '*_leak'
    files = os.path.join(file_path, ty+".*.csv")  # "*.org.csv"
    files = glob.glob(files)
    '''
    leakerdict = {}
    with open(file_path+'route_leak.asns.p', "rb") as f:
        leakerdict = pickle.load(f)
    '''
    ruleout_leaker = {}
    of1 = open(file_path + ty+'_incident.csv', 'w')
    #of2 = open(file_path + ty+'_leakingp2c.csv', 'w')
    bgpdict = set()
    leakerp2c = defaultdict(set)
    leaksp2c = dict()
    res, dates, numbers = [], [], []
    leaksatday = defaultdict(set)
    routesatday = defaultdict(set)
    asdict = {}
    totaldict = {}
    minileaks = {}
    rovresults = defaultdict(set)

    print(len(files))
    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]
        date = suffix[4:6]+'/'+suffix[6:8]
        leakdict = defaultdict(set)

        with open(f) as filehandle:
            filecontents = filehandle.readlines()

            for i, line in enumerate(filecontents):
                fields = line.split(',')

                # bgp hijack,1657873006,211252,80.76.51.0/24,42541 213035 211252,asID,2,0,0+0.4+0+0+0+0,None
                # route leak,1667290557,28126,177.37.208.0/20,211398 48646 49697 196610 51531 6939 24429 28126,28126,2,1,1+0+0+0+0+0,24429
                timestamp, asID, prefix, as_path, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[-1].strip('\n')

                hops = [k for k, g in groupby(as_path.split(" "))]
                as_path_v2 = '_'.join(hops)
                valley = re.search('\d+_'+leaker+'_\d+', as_path_v2).group(0)
                leakdict[valley].add((timestamp, prefix, as_path))
                asdict[(asID, prefix)] = 1
                totaldict[(leaker, prefix)] = 1
                leaksatday[date].add((leaker, prefix))
                routesatday[date].add((prefix, as_path))
                bgpdict.add((prefix, as_path))

                '''
                t = str(datetime.datetime.fromtimestamp(
                    timestamp, datetime.timezone.utc))
                time = t.split(' ')[0]
                if (time, leaker) not in leakerdict:
                    continue
                # here we revalidate attacker-prefixes
                invalid = roa_validation(timestamp, int(
                    leaker), prefix, as_path, roa_px_dict)
                rovresults[leaker].add(invalid)
                minileaks[(leaker, prefix)] = 1
                # using the following code to verify if the leaker AS is a provider of asID
                found = False
                c = caida_as_rel_pc.get(leaker)
                if (c is not None and asID in c):
                    leaksp2c[(leaker, prefix)] = 1
                    found = True
                    of2.write(
                        ','.join(map(str, [timestamp, asID, prefix, as_path, leaker]))+'\n')
                leakerp2c[leaker].add(found)
                '''
        
        for k in leakdict:
            start_time, prefix, as_path = sorted(leakdict[k])[0]

            t = datetime.datetime.fromtimestamp(
                start_time, datetime.timezone.utc)
            leaker = k.split('_')[1]

            abnormal = post_detection_v3(start_time, leaker)
            if abnormal == 'True':
                of1.write(','.join(map(str, [t, k, prefix, as_path]))+'\n')
       

    print('asdict: ', len(asdict))
    print(len(rovresults))
    for attacker in rovresults:
        if False in rovresults[attacker] or True not in rovresults[attacker]:
            print(attacker, rovresults[attacker])
    for date in leaksatday:
        n = len(leaksatday[date])
        res.append((date, n))
    res = sorted(res)
    for date, n in res:
        dates.append(date)
        numbers.append(n)
    print('leaks: ', len(totaldict))
    print('minileaks: ', len(minileaks))
    n = 0
    for leaker in leakerp2c:
        if True in leakerp2c[leaker]:
            n = n + 1
            print(leaker, leakerp2c[leaker])
    print('leaksp2c, n ', len(leaksp2c), n)
    count = 0
    for date in routesatday:
        count = count + len(routesatday[date])
    print('Mean number of LOV-invalid routes: ', count/170, len(routesatday))
    print('Total number of leak routes: ', len(bgpdict))
    of1.close()
    # of2.close()

    return dates, numbers


def verified_post_analysis(d):
    
    file_path = './HistoricalDataAnalysis/'+d+'/'
    ty = '*_leak'
    
    files = os.path.join(file_path, ty+".202207*.csv")  # "*.org.csv"
    files = glob.glob(files)
    routesatday = defaultdict(set)
    routes = dict()
    for f in files:

        suffix = f.split('/')[-1].split('.')[-2]
        date = suffix[4:6]+'/'+suffix[6:8]
        leakdict = defaultdict(set)

        with open(f) as filehandle:
            filecontents = filehandle.readlines()

            for i, line in enumerate(filecontents):
                fields = line.split(',')

                # bgp hijack,1657873006,211252,80.76.51.0/24,42541 213035 211252,asID,2,0,0+0.4+0+0+0+0,None
                # route leak,1667290557,28126,177.37.208.0/20,211398 48646 49697 196610 51531 6939 24429 28126,28126,2,1,1+0+0+0+0+0,24429
                timestamp, asID, prefix, as_path, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[-1].strip('\n')

                routesatday[date].add((prefix, as_path))
                routes[(asID, prefix, as_path)] = 1

    ty = '*_hijack'
    files = os.path.join(file_path, ty+".202207*.csv")  # "*.org.csv"
    files = glob.glob(files)
    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]
        date = suffix[4:6]+'/'+suffix[6:8]
        leakdict = defaultdict(set)

        with open(f) as filehandle:
            filecontents = filehandle.readlines()

            for i, line in enumerate(filecontents):
                fields = line.split(',')

                # bgp hijack,1657873006,211252,80.76.51.0/24,42541 213035 211252,asID,2,0,0+0.4+0+0+0+0,None
                # route leak,1667290557,28126,177.37.208.0/20,211398 48646 49697 196610 51531 6939 24429 28126,28126,2,1,1+0+0+0+0+0,24429
                timestamp, asID, prefix, as_path, leaker = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[-1].strip('\n')

                routesatday[date].add((prefix, as_path))
                routes[(asID, prefix, as_path)] = 1
    count = 0
    print(len(routesatday))
    res, dates, numbers = [], [], []
    for d in routesatday:
        count = count + len(routesatday[d])
        res.append((d, len(routesatday[d])))
    res = sorted(res)
    for date, n in res:
        dates.append(date)
        numbers.append(n)

    print('Total number of verified routes: ', len(routes))
    with open("./lov_invalid_route.p", "wb") as fp:
        pickle.dump(dict(routes), fp)
    print('Mean: ', count/len(routesatday))  
    #return dates, numbers
    return routesatday


def measure_distance():
    file_path = './HistoricalDataAnalysis/'
    files = os.path.join(
        file_path, "benign_conflict.20220814.csv")  # "*.org.csv"
    files = glob.glob(files)
    f0 = open('./HistoricalDataAnalysis/benign_conflict_distance.specific.csv', 'w')
    for f in files:
        checked = dict()
        checked[(34549, '2a07:6fc0:452::/48')] = 1
        date = f.split('/')[-1].split('.')[-2]
        y, m, d = date[0:4], date[4:6], date[6:8]
        roa_px_dict, roa_as2prefixes_dict, as2prefixes_dict, global_hege_dict = update_at_specific_times(
            y, m, d)
        suffix = date

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                line = line.strip('\n')
                fields = line.split(',')
                # benign conflict,1657872032,270771,181.189.10.0/24,6762 53013 270771,1,0,0+0.0+0+0+0+0,None
                timestamp = int(fields[1])
                asID = int(fields[2])
                prefix = fields[3]
                if (asID, prefix) not in checked:
                    continue
                origin_matching = int(fields[-2].split('+')[0])
                if origin_matching == 1:
                    distance = 0.0
                else:
                    distance = compute_pfx_distance(
                        as2prefixes_dict, prefix, asID)
                # checked[(asID, prefix)] = 1
                f0.write(
                    ','.join(map(str, [timestamp, asID, prefix, distance]))+'\n')
    f0.close()


def measure_benign_conflict():
    basic_path = './LocalData'
    caida_as_org = {}
    with open(basic_path+'/CAIDA/caida_as_org.p', "rb") as f:
        caida_as_org = pickle.load(f)
    caida_as_rel_pc = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pc.p', "rb") as f:
        caida_as_rel_pc = pickle.load(f)
    caida_as_rel_pp = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pp.p', "rb") as f:
        caida_as_rel_pp = pickle.load(f)
    irr_database = {}
    with open(basic_path+'/IRR/irr_database.p', "rb") as f:
        irr_database = pickle.load(f)
    local_hege_dict = {}
    with open(basic_path + '/IHR/local_hege_dict.p', "rb") as f:
        local_hege_dict = pickle.load(f)
    clf = None
    with open('./dt_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)

    file_path = './HistoricalDataAnalysis'
    files = os.path.join(
        file_path, "benign_conflict.20220829.csv")  # "*.org.csv"
    files = glob.glob(files)

    for f in files:
        checked = dict()
        date = f.split('/')[-1].split('.')[-2]
        y, m, d = date[0:4], date[4:6], date[6:8]
        roa_px_dict, roa_as2prefixes_dict, as2prefixes_dict, global_hege_dict = update_at_specific_times(
            y, m, d)
        suffix = date
        f0 = open('./HistoricalDataAnalysis/benign_conflict.' +
                  suffix+'.measure.csv', 'w')
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')

                timestamp, asID, prefix, as_path = int(
                    fields[1]), int(fields[2]), fields[3], fields[4]
                if (asID, prefix) in checked:
                    continue
                prefix_addr, prefix_len = prefix.split('/')
                prefix_len = int(prefix_len)

                hops = [k for k, g in groupby(as_path.split(" "))]

                results, invalid = validateOriginV2(
                    prefix_addr, prefix_len, timestamp, "+".join(hops), asID, roa_px_dict, None)
                checked[(asID, prefix)] = 1
                if invalid is None:
                    continue
                if not invalid:
                    continue
                data, scores, vrpID, leaker = extract_features(results, as2prefixes_dict, roa_as2prefixes_dict, caida_as_org,
                                                               caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, timestamp)
                # [rpki_status, confi_score, distance, pathanomalies]
                rpki_status = data[0]
                distance = data[2]
                X_test = np.array(data).reshape(1, 4)
                prop = clf.predict_proba(X_test)[0]

                label = 1
                # we can customize this threshold when deploying in practice.
                if prop[1] > 0.5:
                    label = 2
                if label == 1:
                    f0.write(
                        ','.join(map(str, [timestamp, asID, prefix, leaker, distance] + scores))+'\n')
        f0.close()


def benign_conflict_post_analysis():
    file_path = './HistoricalDataAnalysis/'
    files = os.path.join(
        file_path, "benign_conflict.*.csv")  # "*.org.csv"
    files = glob.glob(files)

    bcdict = defaultdict(list)
    routesdict = set()
    # top10_asns
    # ofile = open(
    #    './HistoricalDataAnalysis/benign_conflict_top10_asns.csv', 'w')
    print(len(files))
    for f in files:
        with open(f) as filehandle:
            filecontents = filehandle.readlines()

            for i, line in enumerate(filecontents):
                line = line.strip('\n')
                fields = line.split(',')

                # 1657872032,270771,181.189.10.0/24,None,0.0,0,0.0,0,0,0.2,0
                timestamp = int(fields[0])
                asID = int(fields[1])
                prefix = fields[2]
                distance = float(fields[4])
                OriginMatching, IRR, Parent, SameOrg, PC, Depen = list(
                    map(float, fields[5:]))

                # confiscore = OriginMatching + IRR + Parent + SameOrg + PC + Depen
                routesdict.add((prefix, as_path))
                bcdict[(asID, prefix)].append(
                    (timestamp, distance, OriginMatching, IRR, Parent, SameOrg, PC, Depen))
    # involving how many ASNs and how many prefixes in which countries, how many Tier-1 or Tier2 providers or CDNs??
    print('bcdict: ', len(bcdict))
    print('Total number of benign-conflict routes: ', len(routesdict))
    '''
    asns = set()
    prefixes = set()
    asndict = defaultdict(set)
    for k in bcdict:
        timestamp, distance, OriginMatching, IRR, Parent, SameOrg, PC, Depen = sorted(
            set(bcdict[k]))[-1]

        text = ''
        if OriginMatching > 0:
            text = text + 'OriginMatching'
        if IRR > 0:
            text = text + 'IRR'
        if Parent > 0:
            text = text + 'Parent'
        if SameOrg > 0:
            text = text + 'SameOrg'
        if PC > 0:
            text = text + 'PC'
        if Depen > 0:
            text = text + 'Depen'

        confiscore = OriginMatching + IRR + Parent + SameOrg + PC + Depen
        # ofile.write(','.join(map(str, list(k)+[text, confiscore]))+'\n')
        # ofile.write(','.join(map(str, list(k)+[distance]))+'\n')
        asID, prefix = k
        asns.add(asID)
        prefixes.add(prefix)
        asndict[asID].add(prefix)
    print('the number of asns: ', len(asns))
    print('the number of prefixes: ', len(prefixes))

    geodict = geodistr(asndict)
    ccres = set()
    for k, v in geodict.items():
        if v != None:
            ccres.add(v)

    print('the number of countries: ', len(ccres))
    '''

    '''
    res = []
    for k in asndict:
        res.append((len(asndict[k]), k))
    res = sorted(res, reverse=True)

    ranklist = topasrank(res)
    for item in ranklist:
        ofile.write(','.join(map(str, item))+'\n')

    ofile.close()
    '''


def characterize_benign_conflict():

    ofile = open(
        './HistoricalDataAnalysis/benign_conflict_categories.extra.csv', 'w')
    with open('./HistoricalDataAnalysis/benign_conflict_results.csv') as filehandle:
        filecontents = filehandle.readlines()
    # res = defaultdict(set)
    res = defaultdict(int)
    asndict = defaultdict(set)
    for i, line in enumerate(filecontents):
        # 44243,185.178.105.0/24,IRRParent,0.8
        line = line.strip('\n')
        fields = line.split(',')
        asID = int(fields[0])
        prefix = fields[1]
        mark = fields[2]
        confiscore = float(fields[-1])
        # res[mark].add((asID, prefix))
        if 'OriginMatching' in mark:
            res['OriginMatching'] = res['OriginMatching'] + 1
        if 'IRR' in mark:
            res['IRR'] = res['IRR'] + 1
        if 'Parent' in mark:
            res['Parent'] = res['Parent'] + 1
        if 'SameOrg' in mark:
            res['SameOrg'] = res['SameOrg'] + 1
        if 'PC' in mark:
            res['PC'] = res['PC'] + 1
        if 'Depen' in mark:
            res['Depen'] = res['Depen'] + 1
        if mark == '':
            res['Other'] = res['Other'] + 1

        asndict[asID].add(prefix)
    for k in res:
        ofile.write(str(k) + ','+str(res[k])+'\n')
    ofile.close()

    tier1_networks = [5511, 2828, 1299, 12956, 3356, 286, 3491, 174,
                      6830, 6453, 3257, 701, 6461, 209, 1239, 2914, 7018, 6762, 3320]

    with open('./HistoricalDataAnalysis/new_measurements/rpki_invalid_routes.asranking.csv') as filehandle:
        filecontents = filehandle.readlines()
    c = 0
    s = 0
    count = 0
    for i, line in enumerate(filecontents):

        line = line.strip('\n')
        # 4765,1,SG,7435
        fields = line.split(',')
        asID = int(fields[0])
        n = int(fields[1])
        count = count + n
        rank = int(fields[3])
        '''
        if asID in tier1_networks:
            print(asID)
            s = s + n
            c = c + 1
        '''

        if rank < 500:
            s = s + n
            c = c + 1

    print(c, s, count)


def benign_conflicts_statistics():
    res, dates, numbers = [], [], []

    file_path = './HistoricalDataAnalysis/new_measurements'
    files = os.path.join(file_path, "benign_conflict.*.csv")  # "*.org.csv"
    files = glob.glob(files)
    unique_bc_dict = {}
    totaldict = {}
    asdict, prefixdict = {}, {}

    print(len(files))
    for f in files:
        date = f.split('/')[-1].split('.')[1]
        bc_dict = dict()
        # benign conflict,1657907383,141460,103.159.254.188/32,38880 58717 134204 141460,vrpID,1,0,1+0+0+0+0+0,None
        suffix = f.split('/')[-1].split('.')[-2]
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                asn, prefix, as_path = fields[2], fields[3], fields[4]

                asdict[asn] = 1
                prefixdict[prefix] = 1
                bc_dict[(asn, prefix, as_path)] = 1
                totaldict[(asn, prefix, as_path)] = 1
                unique_bc_dict[(asn, prefix)] = 1
        n = len(bc_dict)
        res.append((suffix[4:6]+'/'+suffix[6:8], n))
    res = sorted(res)
    for date, n in res:
        dates.append(date)
        numbers.append(n)
    
    # with open(file_path + "/benign_conflict_routes.p", "wb") as fp:
    #    pickle.dump(dict(bc_dict), fp)
    print('Unique benign conflicts and total number: ',
          len(unique_bc_dict), len(totaldict), len(asdict), len(prefixdict))
    return dates, numbers


def total_statistics():

    file_path = './HistoricalDataAnalysis/'
    files = os.path.join(file_path, "benign_conflict.*.csv")  # "*.org.csv"
    files = glob.glob(files)
    rovres = dict()
    n1, n2, n3, n4 = 0, 0, 0, 0
    print(len(files))
    for f in files:

        with open(f, "rb") as fp:
            rovres = pickle.load(fp)
            n1 = n1 + rovres['num_none']
            n2 = n2 + rovres['num_valid']
            n3 = n3 + rovres['num_invalid']
            n4 = n4 + rovres['total_num']
    print(n1, n2, n3, n4)

    '''
    file_path = './HistoricalDataAnalysis/measure_202212/extra'
    files = os.path.join(
        file_path, "measured_routes.*.p")  # "*.org.csv"
    files = glob.glob(files)
    rovres = dict()
    n = 0
    print(len(files))
    for f in files:
    
        with open(f, "rb") as fp:
            rovres = pickle.load(fp)
            for k in rovres:
                print(rovres[k])
                n = n + rovres[k]
        print(n/len(rovres))
    '''


def bgp_measurements():
    ty = "bgp_hijack"
    # ty = "BGPmon"
    # ofile = open(
    #    './HistoricalDataAnalysis/route_leak_statistics.final.new.csv', 'w')
    # with open('./HistoricalDataAnalysis/'+ty+'_overlap.res') as filehandle:
    # with open('./ValidateData/route_leak.20220715.unverified.res') as filehandle:
    with open('./HistoricalDataAnalysis/new_measurements/'+ty+'_statistics.new.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-07-20 09:08:43+00:00,23689
            # 2022-07-25 09:23:10+00:00,60068
            line = line.strip('\n')

            fields = line.split(',')
            timestamp, attacker = fields[0], fields[1]
            date = timestamp.split(' ')[0]
            st = timestamp.split(' ')[1].split(
                ':')[0] + ':' + timestamp.split(' ')[1].split(':')[1]
            et = str(int(timestamp.split(' ')[1].split(':')[
                     0])+1) + ':' + timestamp.split(' ')[1].split(':')[1]
            asn = int(attacker)
            start_time = date + 'T' + st
            end_time = date + 'T' + et

            abnormal = post_detection_v4(start_time, asn)
            if abnormal == 'False':
                continue

            '''
            if abnormal == 'True':
                
                ofile.write(fields[0]+','+fields[1]+'\n')
            else:
                print(abnormal)
            '''
            one_day_analysis(ty, start_time, end_time, asn)
    # ofile.close()


def historical_data_analysis():
    file_path = './HistoricalDataAnalysis'
    files = os.path.join(file_path, "*.txt")  # "*.org.csv"
    files = glob.glob(files)

    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]

        bcdict = dict()
        leakdict = dict()
        hijackdict = dict()
        extraleakdict = dict()
        f0 = open('./HistoricalDataAnalysis/benign_conflict.'+suffix+'.csv', 'w')
        f1 = open('./HistoricalDataAnalysis/route_leak.'+suffix+'.csv', 'w')
        f2 = open('./HistoricalDataAnalysis/bgp_hijack.'+suffix+'.csv', 'w')
        f3 = open('./HistoricalDataAnalysis/route_leak_extra.' +
                  suffix+'.csv', 'w')
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                # benign conflicts,1656662400,28715,2a06:3000:4::/48,208753 39533 6461 12703 12703 12703 28715,1,0,None
                ty, timestamp, asID, prefix, as_path, leaker = fields[0], int(
                    fields[1]), int(fields[2]), fields[3], fields[4], fields[-1].strip('\n')
                if 'benign conflict' in ty:

                    bcdict[(timestamp, asID, prefix)] = [
                        ty, timestamp, asID, prefix, as_path, leaker]
                if 'route leak' in ty:
                    # route leak,1656662400,29447,2a01:e10::/30,208753 212895 211083 24961 12322 29447,2,1,211083,True
                    leaker, verification = fields[-2], fields[-1].strip('\n')
                    if leaker != 'None' and verification == 'True':

                        leakdict[(timestamp, leaker, prefix)] = [ty, timestamp,
                                                                 asID, prefix, as_path, leaker]
                if 'bgp hijacks' in ty:
                    # bgp hijacks,1656662400,5491,2a02:188:1004::/48,208753 41051 39351 12552 31027 5491,2,0,12552,True
                    leaker, verification = fields[-2], fields[-1].strip('\n')

                    if leaker == 'None' and verification == 'True':  # we should verify the leaker apart from the attacker!!!

                        hijackdict[(timestamp, asID, prefix)] = [ty, timestamp,
                                                                 asID, prefix, as_path, leaker]
                if 'bgp hijacks' in ty:
                    # bgp hijacks,1656662400,5491,2a02:188:1004::/48,208753 41051 39351 12552 31027 5491,2,0,12552,True
                    leaker, verification = fields[-2], fields[-1].strip('\n')

                    if leaker != 'None':  # we should verify the leaker apart from the attacker!!!
                        extraleakdict[(timestamp, leaker, prefix)] = [ty, timestamp,
                                                                      asID, prefix, as_path, leaker]
        for k in bcdict:
            f0.write(','.join(map(str, bcdict[k]))+'\n')
        for k in leakdict:
            f1.write(','.join(map(str, leakdict[k]))+'\n')
        for k in hijackdict:
            f2.write(','.join(map(str, hijackdict[k]))+'\n')
        for k in extraleakdict:
            f3.write(','.join(map(str, extraleakdict[k]))+'\n')
        f0.close()
        f1.close()
        f2.close()
        f3.close()


def geodistr(asndict):
    geodict = {}
    basic_path = './LocalData'
    caida_as_cc = {}
    with open(basic_path+'/CAIDA/caida_as_cc.p', "rb") as f:
        caida_as_cc = pickle.load(f)
    for k in asndict:
        if caida_as_cc.get(int(k)) == None:
            cc = None
        else:
            cc = caida_as_cc[int(k)]

        geodict[k] = cc
    return geodict


def topasrank(asnlist):
    ranklist = list()
    for k, v in asnlist:

        query = AsnQuery(int(v))
        rsp = requests.post(
            "https://api.asrank.caida.org/v2/graphql", json={'query': query})

        if rsp.status_code != 200:
            return ranklist

        rsp = rsp.json()

        if 'data' in rsp and 'asn' in rsp['data'] and rsp['data']['asn'] is not None and rsp['data']['asn']['asn'] == str(v):
            r = rsp['data']['asn']['rank']
            cc = rsp['data']['asn']['country']['iso']
            ranklist.append([v, k, cc, r])

    return ranklist


def get_asn_types_dict():
    asn_types_dict = dict()
    with open('./three_types_asns.data') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n')
            asn, ty = line.split(',')
            asn_types_dict[asn] = ty
    print('Number of asns: ', len(asn_types_dict))
    return asn_types_dict


def bgp_attacks_statistics_v2():
    asn_types_dict = get_asn_types_dict()

    ty = 'bgp_hijack'
    attackerdict = defaultdict()
    f = open('./HistoricalDataAnalysis/new_measurements/' +
             ty+'_statistics.final.csv', 'w')
    with open('./HistoricalDataAnalysis/new_measurements/'+ty+'_statistics.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n')
            attacker = line.split(',')[1]
            ty = asn_types_dict.get(attacker)
            f.write(line+','+str(ty)+'\n')
            # attackerdict[attacker] = 1
    f.close()
    '''
    geodict = geodistr(attackerdict)
    print(len(geodict))
    ccres = set()
    for k, v in geodict.items():

        if v != None:
            ccres.add(v)
    print('the number of countries: ', len(ccres))
    '''


def bgp_attacks_statistics():
    basic_path = './LocalData'
    caida_as_rel_pc = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pc.p', "rb") as f:
        caida_as_rel_pc = pickle.load(f)

    events = defaultdict(list)
    check = False

    file_path = './HistoricalDataAnalysis/new_measurements/'
    for ty in ['bgp_hijack', 'route_leak']:
        ofile = open(file_path +
                     ty+'_statistics.csv', 'w')
        ofile2 = open(file_path +
                      ty+'_flapping.csv', 'w')
        ofile3 = open(file_path +
                      ty+'_quarantine.csv', 'w')  # it is not necessary!!! because it has been checked in the previous processing!!!!
        ofile4 = open(file_path +
                      ty+'_incident.filtered.csv', 'w')
        attackerdict = defaultdict()
        totaldict = dict()
        leakerp2c = dict()
        print(file_path+ty+'_incident.csv')
        with open(file_path+ty+'_incident.csv') as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                # 2022-10-14 08:00:30+00:00,20485_48084_48276,31.133.48.0/21,211398 34854 20485 48084 48276 202279

                time = line.split(',')[0]
                date = time.split(' ')[0]
                prefix = line.split(',')[2]
                as_path = line.split(',')[3].strip('\n')
                asID = as_path.split(' ')[-1]

                attacker = None
                valley = None
                if 'hijack' in ty:
                    attacker = line.split(',')[1]

                    confi = sum(
                        list(map(float, line.split(',')[-1].strip('\n').split('+'))))

                    if confi != 0:
                        continue
                    totaldict[(date, attacker)] = 1
                    if check:
                        if check_events(ty, attacker, prefix, ''):
                            ofile4.write(
                                ','.join([time, attacker, prefix, as_path])+'\n')
                elif 'leak' in ty:
                    valley = line.split(',')[1]
                    attacker = line.split(',')[1].split('_')[1]

                    totaldict[(date, attacker)] = 1
                    if check:
                        if check_events(ty, attacker, prefix, valley):
                            ofile4.write(
                                ','.join([time, attacker, prefix, as_path])+'\n')

                if attacker not in attackerdict:
                    attackerdict[attacker] = {
                        'date': set(),
                        'examples': set(),
                    }
                attackerdict[attacker]['date'].add(date)
                attackerdict[attacker]['examples'].add(
                    (time, prefix, as_path, valley))

        print('the number of: ', ty, len(totaldict), len(attackerdict))

        asndict = {}
        attackdict = {}
        frequentdict = {}
        for k, v in attackerdict.items():

            if len(v['date']) > 1:

                for e in v['examples']:
                    if 'leak' in ty:
                        valley = e[-1]

                        frequentdict[valley] = 1
                        prefix = e[1]
                        asID = e[-2].split(' ')[-1]
                        c = caida_as_rel_pc.get(k)

                        if (c is not None and asID in c):
                            leakerp2c[(k, prefix)] = 1
                    elif 'hijack' in ty:
                        prefix = e[1]
                        frequentdict[(k, prefix)] = 1
                ofile2.write(','.join([k]+sorted(v['date']))+'\n')
                continue
            events[(ty, list(v['date'])[0])].append(1)
            time, prefix, as_path, valley = sorted(v['examples'])[0]
            ofile.write(time+','+k+','+prefix+','+as_path+'\n')
            asndict[k] = 1
            attackdict[(list(v['date'])[0], k)] = 1
        with open(file_path+ty+'_frequent_event.whitelist.p', "wb") as fp:
            pickle.dump(dict(frequentdict), fp)
        with open(file_path+ty+'.asns.p', "wb") as fp:
            pickle.dump(dict(attackdict), fp)
        print('Frequent event whitelist: ', len(frequentdict))
        print('leakerp2c: ', len(leakerp2c))
        geodict = geodistr(asndict)
        print(len(geodict))
        ccres = set()
        for k, v in geodict.items():

            if v != None:
                ccres.add(v)
        print('the number of countries: ', len(ccres))

        ofile.close()
        ofile2.close()
        ofile3.close()
        ofile4.close()

    return events


def bgp_attacks_statistics_extra():
    events = defaultdict(list)

    file_path = './HistoricalDataAnalysis/measure_202209/'
    for ty in ['bgp_hijack', 'route_leak']:
        ofile = open(file_path +
                     ty+'_statistics.csv', 'w')

        attackerdict = defaultdict()

        with open(file_path+ty+'_incident.filtered.csv') as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                # 2022-08-11 11:35:52+00:00,59729,176.118.189.0/24,3214 3356 1273 57344 31083 59729,0+0.4+0+0+0+0
                # 2022-07-30 15:30:56+00:00,132876_136975_133524,103.146.66.0/23,3399 9002 132876 136975 133524 139849
                time = line.split(',')[0]
                date = time.split(' ')[0]
                prefix = line.split(',')[2]
                as_path = line.split(',')[3].strip('\n')
                attacker = line.split(',')[1]
                if attacker not in attackerdict:
                    attackerdict[attacker] = {
                        'date': set(),
                        'examples': set(),
                    }
                attackerdict[attacker]['date'].add(date)
                attackerdict[attacker]['examples'].add(
                    (time, prefix, as_path))

        print('the number of: ', ty, len(attackerdict))
        asndict = {}

        for k, v in attackerdict.items():
            if len(v['date']) > 1:
                continue

            time, prefix, as_path = sorted(v['examples'])[0]
            ofile.write(time+','+k+','+prefix+','+as_path+'\n')
            asndict[k] = 1

        geodict = geodistr(asndict)
        print(len(geodict))
        ccres = set()
        for k, v in geodict.items():

            if v != None:
                ccres.add(v)
        print('the number of countries: ', len(ccres))

        ofile.close()

    return events


def roa_validation(timestamp, asID, prefix, as_path, roa_px_dict):
    prefix_addr, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    hops = as_path.split(' ')
    asID = int(asID)
    results, invalid = validateOriginV2(
        prefix_addr, prefix_len, timestamp, "+".join(hops), asID, roa_px_dict, None)
    return invalid


# remove the incidents that have an unknown prefix to ROA or a RPKI-valid AS-prefix binding.


def bgp_incidents_roa_validation():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)
    ty = 'leak'
    file_path = './HistoricalDataAnalysis/measure_202210/'
    f0 = open(file_path +
              ty+'_alltimes_rest.csv', 'w')
    f1 = open(file_path + ty + '_alltimes_rpki_none.csv', 'w')
    f2 = open(file_path + ty + '_alltimes_rpki_valid.csv', 'w')
    ruleout = dict()
    with open(file_path+ty+'_alltimes.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-08-14 10:41:20+00:00,208293_203214_50710,37.237.143.0/24,58511 60051 208293 203214 50710
            line = line.strip('\n')
            timestamp, attacker, prefix, as_path = line.split(',')
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)

            if 'leak' in ty:

                attacker = attacker.split('_')[1]

            hops = as_path.split(' ')
            asID = int(attacker)

            results, invalid = validateOriginV2(
                prefix_addr, prefix_len, timestamp, "+".join(hops), asID, roa_px_dict, None)
            if invalid == None:
                f1.write(line+','+'None'+'\n')
                rpki_none[(attacker, prefix)] = 1
                continue
            vrpIDs = []
            for res in results:  # MOAS
                vrpIDs.append(int(res.split(' ')[-2]))
            if asID in vrpIDs:
                vrpIDs[0] = asID
                f2.write(line+','+'Valid'+'\n')
                # ruleout[attacker] = 1
                continue
            f0.write(line+'\n')
    f0.close()
    f1.close()


def whitelists_statistics():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    attackerdict = dict()
    asprefixdict = defaultdict(int)
    asvalleydict = dict()
    file_path = './HistoricalDataAnalysis/measure_202212'
    with open(file_path+'/asbinding_whitelist.p', "rb") as f:
        asprefixdict = pickle.load(f)
    with open(file_path+'/asvalley_whitelist.p', "rb") as f:
        asvalleydict = pickle.load(f)

    print(len(asprefixdict), len(asvalleydict))

    frequent_asprefix_dict, frequent_asvalley_dict = {}, {}
    with open(file_path+'/bgp_hijack_frequent_event.whitelist.p', "rb") as f:
        fasprefixdict = pickle.load(f)
    with open(file_path+'/route_leak_frequent_event.whitelist.p', "rb") as f:
        fasvalleydict = pickle.load(f)
    for k in fasprefixdict:
        if k in asprefixdict:
            continue
        asprefixdict[k] = 1
    for k in fasvalleydict:
        if k in asvalleydict:
            continue
        asvalleydict[k] = 1

    print(len(asprefixdict), len(asvalleydict))

    # combine with the existing and verified whitelist
    originalasbinding = {}
    # ./LocalData/WhiteList/asbinding_whitelist.p
    with open(file_path+'/asbinding_whitelist_verified.p', "rb") as f:
        originalasbinding = pickle.load(f)

    for k in originalasbinding:
        if k in asprefixdict:
            continue
        asprefixdict[k] = 1
    originalasvalley = {}
    with open(file_path+'/asvalley_whitelist_verified.p', "rb") as f:
        originalasvalley = pickle.load(f)
    for k in originalasvalley:
        if k in asvalleydict:

            continue
        asvalleydict[k] = 1
    print(' After combining: ', len(asprefixdict), len(asvalleydict))
    filtered_asprefixdict = {}
    f, n = 0, 0
    for k in asprefixdict:
        invalid = roa_validation(None, int(k[0]), k[1], '_', roa_px_dict)

        if invalid == False:
            f = f + 1
        elif invalid == None:
            n = n + 1
        if invalid == True:
            filtered_asprefixdict[k] = 1
    asprefixdict = filtered_asprefixdict
    print('After filtering, valid and unknown: ',
          len(asprefixdict), len(asvalleydict), f, n)

    for k in asprefixdict:
        attackerdict[k[0]] = 1
    print('the number of ASes in asprefixdict: %s' % len(attackerdict))

    geodict = geodistr(attackerdict)
    print(len(geodict))
    ccres = set()
    for k, v in geodict.items():

        if v != None:
            ccres.add(v)
    print('the number of countries: ', len(ccres))

    leakerdict = {}
    for k in asvalleydict:
        leaker = k.split('_')[1]
        leakerdict[leaker] = 1
    print('the number of ASes in asvalleydict: %s' % len(leakerdict))
    geodict = geodistr(leakerdict)
    print(len(geodict))
    ccres = set()
    for k, v in geodict.items():

        if v != None:
            ccres.add(v)
    print('the number of countries: ', len(ccres))
    '''
    with open('./LocalData/WhiteList/asbinding_whitelist.p', "wb") as fp:
        pickle.dump(dict(asprefixdict), fp)
    with open('./LocalData/WhiteList/asvalley_whitelist.p', "wb") as fp:
        pickle.dump(dict(asvalleydict), fp)
    '''


def post_analyzer(res, ofs, verified):
    # timestamp, asID, prefix, as_path, vrpID, label, data[0], scores, leaker
    rpki_status = int(res[-3])
    label = int(res[-4])
    leaker = res[-1]
    asn = str(res[1])
    roa_asn = str(res[4])
    date = int(res[0])
    scores = list(map(float, res[-2].split('+')))
    confi_score = sum(scores)
    as_path = res[3]

    if label == 1 and rpki_status == 0:
        ofs[0].write('{},{}\n'.format(
            'benign conflict', ','.join(map(str, res))))

    if label == 2 and rpki_status == 0:
        if verified.get((date, asn)) == None:
            if post_detection_v3(date, asn) == 'False':
                verified[(date, asn)] = False
            else:
                verified[(date, asn)] = True

        if verified.get((date, asn)) == False or confi_score > 0:
            ofs[3].write('{},{}\n'.format(
                'quarantined asbinding', ','.join(map(str, res))))
        else:
            ofs[1].write('{},{}\n'.format(
                'bgp hijack', ','.join(map(str, res))))

        if leaker != 'None':

            if verified.get((date, leaker)) == None:
                if post_detection_v3(date, leaker) == 'False':
                    verified[(date, leaker)] = False
                else:
                    verified[(date, leaker)] = True
            if verified.get((date, leaker)) == False or leaker == roa_asn:
                ofs[4].write('{},{}\n'.format(
                    'quarantined asvalley', ','.join(map(str, res))))
            else:
                ofs[2].write('{},{}\n'.format(
                    'route leak', ','.join(map(str, res))))

    if label == 2 and rpki_status == 1:
        if verified.get((date, leaker)) == None:
            if post_detection_v3(date, leaker) == 'False':
                verified[(date, leaker)] = False
            else:
                verified[(date, leaker)] = True
        if verified.get((date, leaker)) == False or leaker == roa_asn:
            ofs[4].write('{},{}\n'.format(
                'quarantined asvalley', ','.join(map(str, res))))
        else:
            ofs[2].write('{},{}\n'.format(
                'route leak', ','.join(map(str, res))))


def new_historical_data_analysis():
    file_path = './HistoricalDataAnalysis/'
    files = os.path.join(file_path, "*.out")
    files = glob.glob(files)

    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]  # date
        verified = dict()

        f0 = open(file_path + 'benign_conflict.'+suffix+'.csv', 'w')
        f1 = open(file_path + 'bgp_hijack.'+suffix+'.csv', 'w')
        f2 = open(file_path + 'route_leak.'+suffix+'.csv', 'w')
        f3 = open(file_path + 'quarantined_asbinding.' +
                  suffix+'.csv', 'w')
        f4 = open(file_path + 'quarantined_asvalley.' +
                  suffix+'.csv', 'w')
        ofs = [f0, f1, f2, f3, f4]
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                res = line.strip('\n').split(',')
                post_analyzer(res, ofs, verified)

        for of in ofs:
            of.close()


def load_data(ifile):
    x = []
    y = []
    uperrs = []
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(',')
            date = int(fields[0])
            t = datetime.datetime.fromtimestamp(date, datetime.timezone.utc)
            # t = fields[0]
            he = float(fields[1])
            u = float(fields[3])
            s = float(fields[4])
            # print(t)
            x.append(t)
            y.append(he)
            uperrs.append(u + norm.ppf(0.95)*s)

            # lowerrs.append(u - norm.ppf(0.95)*s)
    date = ifile.split('/')[-1].split('.')[-1]
    year, month, day = date.split('T')[0].split('-')
    d = year+month+day
    file_path = './BGPincidents/post_analysis'
    files = os.path.join(file_path, "*.org.csv")  # "*.org.csv"
    files = glob.glob(files)
    res = dict()
    for f in files:
        if d in f:
            df = pd.read_csv(f)
            for date, attacker, abnormal in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values):
                date = datetime.datetime.fromtimestamp(
                    int(date), datetime.timezone.utc)
                res[date] = abnormal
    return x, y, uperrs, res


def plot_vertical_lines(ax, res):
    for t in res:

        if res[t]:

            ax.vlines(t, ymin=0, ymax=1, color='red', linestyle='dashed')
        else:
            ax.vlines(t, ymin=0, ymax=1, color='green', linestyle='dashed')


def plot_jck():
    PLOT_FOLDER = "./BGPincidents/post_analysis/plot"

    file_names = [
        'Hijack.1221.2020-09-29T17:50',
        'Hijack.212046.2021-10-13T08:58',
        'Hijack.212046.2021-10-25T09:56',

        # 'Hijack.12389.2020-04-01T19:28',
        # 'Hijack.55410.2021-04-16T13:49',
        # 'Hijack.48467.2021-05-18T09:00',
        'Leak.396531.2019-06-24T10:30',
        'Leak.9304.2021-01-06T04:21',
        'Leak.199599.2021-06-03T10:10',
        'Leak.265038.2021-08-19T16:20',
        'Leak.42910.2020-08-24T11:21',
        'Leak.132215.2021-12-24T08:22',

        # 'Leak.7633.2021-12-24T16:45',

    ]

    xlimits = [
        (45, -47),
        (11, -14),
        (12, -9),
        # (0, -1),
        # (0, -1),
        (30, -30),
        (5, -38),
        (13, -18),
        (13, -9),
        (10, -23),
        (35, -35),

        # (0, -1),
    ]

    ylimits = [
        (5.5e-3, 5.56e-3),
        (3e-5, 5e-5),
        (2e-5, 9e-5),
        # (0e-3, 5.31e-3),
        # (1e-6, 4e-6),
        (0, 1e-3),
        (0.001, 0.002),
        (0, 9e-4),
        (1e-7, 1.3e-5),
        (2.6e-5, 3.1e-5),
        (0e-5, 8e-5),
        # (0e-5, 3.5e-5),
    ]

    fig, axes = plt.subplots(len(file_names))
    width = 8
    height_factor = 1.5
    fig.set_size_inches(width, len(file_names) * height_factor)

    # Set the default text font size
    plt.rc('font', size=16)
    # Set the axes title font size
    plt.rc('axes', titlesize=10)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=16)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=16)
    # Set the legend font size
    plt.rc('legend', fontsize=18)

    for idx, name in enumerate(file_names):
        ifile = PLOT_FOLDER + '/' + name
        print(ifile)
        x, y, uperrs, res = load_data(ifile)

        ax = axes[idx]

        ax.set_xlim([x[i] for i in xlimits[idx]])
        ax.set_ylim(ylimits[idx])

        ax.tick_params(axis='x', labelrotation=0)

        xfmt = md.DateFormatter('%H:%M')
        ax.xaxis.set_major_formatter(xfmt)
        # ax.xaxis.set_major_locator(md.MinuteLocator(interval=60))
        ax.set_title(name, fontsize = 12, fontweight="bold")
        ax.ticklabel_format(useMathText=True, style="sci",
                            scilimits=(0, 0), axis="y")

        # Do the plotting
        ax.fill_between(x, uperrs, color='lightgrey')

        ymin, ymax = ylimits[idx]

        for t in res:
            linewidth = 1.5
            if res[t]:
                ax.axvline(x=t, ymin=0.02, ymax=.98, color='tomato',
                           linewidth=linewidth, linestyle='solid')
            else:
                ax.axvline(x=t, ymin=0.02, ymax=.98, color='green',
                           linewidth=linewidth, linestyle='solid')

        ax.plot(x, y, '-', linewidth=1, color='black')

    plt.tight_layout()
    #plt.show()
    plt.savefig(
        './BGPincidents/post_analysis/plot/post_analysis_out.pdf', dpi=300)


def plot_distance():
    fig, ax = plt.subplots(1)
    fig.set_size_inches(8, 4)
    # Set the default text font size
    plt.rc('font', size=16)
    # Set the axes title font size
    plt.rc('axes', titlesize=16)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=16)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=16)
    # Set the legend font size
    plt.rc('legend', fontsize=16)
    files = ['valid.reduced.4f.csv',
             'route_leak.4f.csv']

    labels = ['valid', 'route_leak']
    colors = ['#a65628', '#377eb8']
    for n, f in enumerate(files):
        x = []
        with open('./GroundtruthData/FourClasses/new_features/'+f, "r") as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                # 1660896008,58453,2402:4f00:4000::10/124,0.0
                # time,prefix,asID,origin_matching,maxlength_matching,rpki_status,score1,score3,distance,hege_depth
                if i == 0:
                    continue
                line = line.strip('\n')
                fields = line.split(',')
                if float(fields[-3]) == 1.0:
                    print(line)
                    fields[-3] = 0.5
                path_score = float(fields[-3]) + float(fields[-1])

                x.append(float(path_score))

            print('num: ', len(x))
            series = pd.Series(x)
            n, bins, patches = ax.hist(
                series, cumulative=1, histtype='step', bins=10, density=True, color=colors[n], label=labels[n], linewidth=1.5)

    ax.set_xlim(0, 1, 0.5)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel('Path anomalies', fontsize=16)
    ax.set_ylabel('Proportion', fontsize=16)
    plt.legend(loc="lower left")
    plt.grid(linewidth=0.5)
    ax.tick_params(axis='both', which='major', labelsize=16)
    plt.tight_layout()
    # plt.show()
    plt.savefig('./path_anomalies.pdf', dpi=200)


def plot():
    fig, ax = plt.subplots(1)
    fig.set_size_inches(8, 4)
    # Set the default text font size
    plt.rc('font', size=16)
    # Set the axes title font size
    plt.rc('axes', titlesize=16)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=16)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=16)
    # Set the legend font size
    plt.rc('legend', fontsize=16)
    ifile = './HistoricalDataAnalysis/benign_conflict_distance.csv'
    x, y = [], []
    checked = dict()
    with open(ifile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 1660896008,58453,2402:4f00:4000::10/124,0.0
            line = line.strip('\n')
            asID, prefix, distance = line.split(',')
            if (asID, prefix) in checked:
                continue
            x.append(float(distance))
            checked[(asID, prefix)] = distance
        print('num: ', len(x))
        series = pd.Series(x)
        n, bins, patches = ax.hist(
            series, cumulative=1, histtype='step', bins=50, density=True, color='#a65628', label='Distance', linewidth=3)
    ifile = './HistoricalDataAnalysis/benign_conflict_results.csv'
    x, y = [], []
    checked = dict()
    with open(ifile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 1660896008,58453,2402:4f00:4000::10/124,0.0
            line = line.strip('\n')
            confistore = line.split(',')[-1]
            x.append(float(confistore))

        series = pd.Series(x)
        n, bins, patches = ax.hist(
            series, cumulative=1, histtype='step', bins=6, density=True, color='#377eb8', label='Confidence score', linewidth=3)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel('Value', fontsize=16)
    ax.set_ylabel('Proportion', fontsize=16)
    plt.legend(loc="center")
    plt.grid(linewidth=0.5)
    ax.tick_params(axis='both', which='major', labelsize=16)
    plt.tight_layout()
    # plt.show()
    plt.savefig('./benign_conflict_confiscore_distance.pdf', dpi=200)


def compute_fre(fields):
    dates = []
    for item in fields[1:]:  # 2022-07-15

        y, m, d = item.split('-')
        date = datetime.datetime(int(y), int(m), int(d))
        utc_timestamp = calculate_unix_time(date)
        dates.append(utc_timestamp)
    s = []
    for i in range(len(dates)-1):
        d = dates[i+1] - dates[i]

        s.append(d/(3600*24))
    print(fields[0], len(dates))
    f = sum(s) / len(s)
    return f


def plot_occurrence_frequencies():
    fig, ax = plt.subplots(1)
    fig.set_size_inches(8, 4)
    # Set the default text font size
    plt.rc('font', size=16)
    # Set the axes title font size
    plt.rc('axes', titlesize=16)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=16)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=16)
    # Set the legend font size
    plt.rc('legend', fontsize=16)
    ifile = './HistoricalDataAnalysis/new_measurements/flapping.merge.csv'
    x, y = [], []
    checked = dict()
    with open(ifile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 1660896008,58453,2402:4f00:4000::10/124,0.0
            line = line.strip('\n')
            fields = line.split(',')
            fre = compute_fre(fields)
            x.append(fre)

        print('num: ', len(x))
        series = pd.Series(x)
        n, bins, patches = ax.hist(
            series, cumulative=1, histtype='step', bins=50, density=True, color='#a65628', linewidth=3)

    ax.set_ylim(0, 1)
    ax.set_xlim(0, 47)
    plt.xticks(np.arange(1, 47, 4))
    ax.set_xlabel('Occurrence Frequency (Day)', fontsize=16)
    ax.set_ylabel('Proportion', fontsize=16)
    # plt.legend(loc="center")
    plt.grid(linewidth=0.5)
    ax.tick_params(axis='both', which='major', labelsize=16)
    plt.tight_layout()
    # plt.show()
    plt.savefig('./occurrence_frequency.pdf', dpi=200)


def plot_benign_conflicts_numbers():
    fig, ax = plt.subplots(1)
    fig.set_size_inches(15, 7.5)
    # Set the default text font size
    plt.rc('font', size=16)
    # Set the axes title font size
    plt.rc('axes', titlesize=16)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=14)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=14)
    # Set the legend font size
    plt.rc('legend', fontsize=16)

    
    #x1, y1 = collect_invalid_routes()
    #x1, y1 = benign_conflicts_statistics()
    
    #x, y = lov_invalid_analysis()
    #print(x, y)
    x, y = route_leak_post_analysis_v2()
    mean = sum(y)/len(y)
    print(mean)
    ax.axhline(y=mean, linewidth=3, color='black', linestyle='--', label = 'Route leak (mean)')
    plt.plot(x, y, '-', linewidth=3, color='#ffc20a', label='Route leak')
    
    x, y = bgp_hijack_post_analysis_v2()
    mean = sum(y)/len(y)
    print(mean)
    ax.axhline(y=mean, linewidth=3, color='red', linestyle='--', label = 'BGP hijack (mean)')
    
    plt.plot(x, y, '-', linewidth=3, color='#40b0a6', label='BGP hijack')  # label='route leak'
    
    ax.set_xticks(x[::3])
    ax.set_xticklabels(x[::3], rotation=45)

    '''
    x, y = route_leak_post_analysis_v2()
    x, y = bgp_hijack_post_analysis_v2()
    '''
    
    ax.set_ylim(0, 6500)
    # ax.set_xlim(0, 47)
    # plt.xticks(np.arange(1,47,4))
    #ax.tick_params(axis='x', labelrotation=90)
    ax.set_xlabel('Date', fontsize=30)
    ax.set_ylabel('Number(#)', fontsize=30)
    plt.legend(loc="upper left", fontsize = 30)
    # plt.grid(linewidth=0.5)
    ax.tick_params(axis='both', labelsize=30)  # which='major'
    plt.tight_layout()
    #plt.show()
    plt.savefig('./suspected_attacks_numbers.pdf', dpi=300)


def plot02():
    fig, ax = plt.subplots(1)
    fig.set_size_inches(8, 4)
    # Set the default text font size
    plt.rc('font', size=16)
    # Set the axes title font size
    plt.rc('axes', titlesize=16)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=16)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=16)
    ifile = './HistoricalDataAnalysis/benign_conflict_categories.extra.csv'

    # labels, y = ['TooSpecific', 'Depen', 'IRR', 'Parent',
    #             'SameOrg', 'Other'], [17329, 4424, 2129, 2009, 1786, 333]

    labels, y = [], []
    with open(ifile, "r") as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n')
            num = line.split(',')[-1]
            y.append(int(num))
            labels.append(line.split(',')[0])

    print(labels, y)
    ax.set_ylim(0, 20000)
    ax.bar(labels, np.array(y), color='#a65628')
    ax.set_ylabel('Number (#)', fontsize=16)
    ax.tick_params(axis='both', which='major', labelsize=16)
    plt.tight_layout()
    # plt.show()
    plt.savefig('./benign_conflict_classes.pdf', dpi=200)


def plot_events():
    fig, ax = plt.subplots(1)
    fig.set_size_inches(15, 7.5)
    # Set the default text font size
    plt.rc('font', size=30)
    # Set the axes title font size
    plt.rc('axes', titlesize=30)
    # Set the axes labels font size
    plt.rc('axes', labelsize=30)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=30)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=30)
    hijacks, leaks = [], []
    events = bgp_attacks_statistics()
    for e in events:
        date = e[1].split('-')[1] + '/' + e[1].split('-')[2]
        if 'hijack' in e[0]:
            hijacks.append((date, len(events[e])))
        else:
            leaks.append((date, len(events[e])))

    hijacks = sorted(hijacks)
    leaks = sorted(leaks)

    xh, yh = [], {}
    for h in hijacks:
        xh.append(h[0])
        yh[h[0]] = int(h[1])

    xl, yl = [], {}
    for l in leaks:
        xl.append(l[0])
        yl[l[0]] = int(l[1])
    x = sorted(set(xh+xl))
    for date in x:
        if date not in yh:
            yh[date] = 0
        if date not in yl:
            yl[date] = 0

    print([yh[i] for i in x], [yl[i] for i in x])
    width = 0.8
    ax.bar(x, [yh[i] for i in x], width, color='r', label='BGP hijacks')
    ax.bar(x, [yl[i] for i in x], width, bottom=[yh[i]
                                                 for i in x], color='b', label='Route leaks')
    # ax.set_ylim(0, 20000)
    ax.set_xticks(x[::3])
    ax.set_xticklabels(x[::3], rotation=45)
    
    ax.set_ylabel('Number (#)', fontsize=30)
    ax.tick_params(axis='both', which='major', labelsize=30)
    
    plt.tight_layout()
    plt.legend()
    plt.show()
    #plt.savefig('./events_distr.pdf', dpi=200)


def plot_bgp_simulation():
    BasicPath = "./bgpsimulator/"

    folder_names = [
        # 'valid_ann_rov',
        # 'valid_ann_srov',
        # 'benign_conflict_rov',
        # 'benign_conflict_srov',
        'prefix_hijack_rov',
        'prefix_hijack_srov',
        'route_leak_rov',
        'route_leak_srov',
        'hybrid_leak_rov',
        'hybrid_leak_srov',
    ]
    fig, ax = plt.subplots(1)
    fig.set_size_inches(10, 6)
    # Set the default text font size
    plt.rc('font', size=17)
    # Set the axes title font size
    plt.rc('axes', titlesize=16)
    # Set the axes labels font size
    plt.rc('axes', labelsize=16)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=16)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=16)
    '''
	markers = [4, 5, 6, 7]
	lw = [2.5, 2.5, 2.5, 2.5]
	color = ['#377eb8', '#ff7f00', '#f781bf', '#4daf4a']
	'''

    markers = [4, 5, 'p', '8', 6, 7]
    lw = [3, 3, 3, 3, 3, 3]
    color = ['#377eb8', '#ff7f00', '#f781bf',
             '#4daf4a', '#a65628', '#984ea3', '#999999']

    for i, name in enumerate(folder_names):
        print(name)
        with open(BasicPath+name+'/results.json') as f:
            data = json.load(f)

            ty = None
            if "srov" in name:
                name = name.replace(name.split('_')[-1], 'lov')
                ty = "ROVSmartAS"
            else:

                ty = "ROVSimple"
            res = []
            rates = [0, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1]
            for rate in rates:
                res.append(statistics.mean(
                    data["attacker_success_all"]["0"]["BGP Simple ("+ty+" adopting)"][str(rate)]))

            res = [100 for i in res if i >= 99] + [i for i in res if i < 99]
            res = list(100 - np.array(res))
            plt.plot(
                rates, res, marker=markers[i], markersize=14, linewidth=lw[i], color=color[i], label=name)

    plt.legend(loc="center right")
    ax.set_xlabel('Adoption percentage', fontsize=18)
    # Attack success rate, Reachability
    ax.set_ylabel('Reachability (%)', fontsize=18)
    ax.tick_params(axis='both', which='major', labelsize=18)
    plt.show()
    # plt.savefig('./attack_success_rate.pdf', dpi=200)


def plot_detection_delay():
    BasicPath = "./bgpsimulator/"

    folder_names = [
        # 'valid_ann_rov',
        'valid_ann',
        # 'benign_conflict_rov',
        'benign_conflict',
        # 'prefix_hijack_rov',
        'prefix_hijack',
        # 'route_leak_rov',
        'route_leak',
        # 'hybrid_leak_rov',
        'hybrid_leak',
    ]
    fig, ax = plt.subplots(1)
    fig.set_size_inches(10, 6)
    # Set the default text font size
    plt.rc('font', size=18)
    plt.rc('axes', titlesize=18)
    # Set the axes labels font size
    plt.rc('axes', labelsize=18)
    # Set the font size for x tick labels
    plt.rc('xtick', labelsize=18)
    # Set the font size for y tick labels
    plt.rc('ytick', labelsize=18)
    # Set the legend font size
    plt.rc('legend', fontsize=18)
    colors = ['#377eb8', '#ff7f00', '#f781bf',
              '#4daf4a', '#a65628']
    data = []
    names = []
    for i, name in enumerate(folder_names):
        names.append(name)
        print(name)
        x = []
        with open(BasicPath+'detection_delay.'+name+'.res') as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                line = line.strip('\n')
                t = float(line.split(',')[0])
                x.append(t)
        data.append(x)
    bp = plt.boxplot(data, showfliers=False, patch_artist=True,
                     vert=False, showmeans=True, labels=['V', 'BC', 'PH', 'RL', 'HL'])
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor('#999999')
    ax.ticklabel_format(useMathText=True, style="sci",
                        scilimits=(0, 0), axis="x")

    ax.xaxis.get_offset_text().set_fontsize(18)
    ax.set_xlabel('Detection delay (s)', fontsize=18)
    ax.tick_params(axis='both',  labelsize=18)
    # plt.legend(loc="lower left")
    # plt.show()
    plt.savefig('./detection_delay.pdf', dpi=200)


Hes_dict = {}


def test():

    path = './HistoricalDataAnalysis/extra_data'
    files = os.path.join(path, "myres.*.p")
    files = glob.glob(files)
    for ifile in files:
        date = re.search(r'\d+', ifile).group(0)
        print(ifile)
        of = open(path+'/test_histor_stream.myres.' +
                  date+'.txt', 'w')  # add the date
        with open(ifile, "rb") as f:
            myres = pickle.load(f)
            for t in myres:
                # [timestamp, asID, prefix, as_path, label, data[0], leaker]
                date = myres[t][0]
                rpki_status = myres[t][-2]
                label = myres[t][-3]
                if label == 1 and rpki_status == 0:
                    of.write('{},{}\n'.format('benign conflicts',
                                              ','.join(map(str, myres[t]))))
                if label == 2 and rpki_status == 0:
                    asn = str(myres[t][1])
                    of.write('{},{},{}\n'.format('bgp hijacks', ','.join(
                        map(str, myres[t])), post_detection_v2(date, asn)))
                if label == 2 and rpki_status == 1:
                    asn = str(myres[t][-1])
                    if asn == None:  # without an valley detected but high prefix distance or high depth
                        asn = str(myres[t][1])
                    of.write('{},{},{}\n'.format('route leak', ','.join(
                        map(str, myres[t])), post_detection_v2(date, asn)))

        of.close()


def extract_bgpmon_attackers(ifile, ofile):
    attackerdict = dict()
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            line = line.strip('\n')
            fields = line.split(',')
            timestamp = int(fields[0])
            date = str(datetime.datetime.fromtimestamp(
                timestamp, datetime.timezone.utc))

            h = int(date.split(' ')[1].split(':')[0])

            if h < 8 or h > 15:
                continue
            if 'leak' in ifile:
                attacker = fields[-1]
            else:
                attacker = fields[2]
            ofile.write(date+','+attacker+'\n')
            attackerdict[attacker] = 1
    return attackerdict


def compare_with_BGPmon():
    outfile = open('./ValidateData/route_leak.20220715.final.res', 'w')
    ifile = './ValidateData/route_leak.20220715.new.csv'
    attackerdict = extract_bgpmon_attackers(ifile, outfile)

    ofile = open('./HistoricalDataAnalysis/route_leak_cover.csv', 'w')
    with open('./HistoricalDataAnalysis/route_leak_statistics.csv') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            line = line.strip('\n')
            leaker = line.split(',')[-1]

            if leaker in attackerdict:
                print(leaker)
                ofile.write(line+'\n')
    with open('./HistoricalDataAnalysis/route_leak_flapping.csv') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            line = line.strip('\n')
            leaker = line.split(',')[0]

            if leaker in attackerdict:
                print(leaker)
                ofile.write(line+'\n')
    ofile.close()
    outfile.close()


def process_route_leak_extra():
    f1 = open('./HistoricalDataAnalysis/route_leak_incident.new.csv', 'a')
    f2 = open('./HistoricalDataAnalysis/bgp_hijack_incident.new.csv', 'a')
    with open('./HistoricalDataAnalysis/route_leak_extra_incident.new.csv') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            line = line.strip('\n')
            ty = line.split(',')[-1]
            if 'hijack' in ty:
                f2.write(line+'\n')
            else:
                f1.write(line+'\n')
    f1.close()
    f2.close()


def collect_flapping_events():
    checked = set()
    types = ['bgp_hijack', 'route_leak']
    for ty in types:
        with open('./HistoricalDataAnalysis/'+ty+'_flapping.csv') as filehandle:
            filecontents = filehandle.readlines()
            for line in filecontents:
                fields = line.strip('\n').split(',')
                attacker = fields[0]
                checked.add(attacker)
    print(len(checked))


def analyze_error():
    n = 0
    with open('./BGPincidents/bgp_hijacks.20210416.4f.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.strip('\n').split(',')
            print(fields[-2])
            if float(fields[-2]) < 0.11:
                n = n + 1
    print(n)


def add_prefix():
    ty = 'route_leak'
    f = open('./HistoricalDataAnalysis/new_measurements/' +
             ty+'_statistics.final.v2.csv', 'w')
    with open('./HistoricalDataAnalysis/new_measurements/'+ty+'_statistics.final.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-08-11 09:55:24+00:00,13458,108.179.43.0/24,267613 3356 701 13458,612
            f.write("{} {} {}".format("python3", "email_sender.py", line))
    f.close()


def compare_against_spamhaus_DROP():
    ty = 'bgp_hijack'
    targets = set()
    with open('./spamhaus/merge.txt') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            prefix = line.split(';')[0].strip(' ')
            ip, _ = prefix.split('/')
            targets.add(ip)
    targets = list(targets)
    print(targets)
    f = open('./HistoricalDataAnalysis/new_measurements/' +
             ty+'_statistics.spamhaus.csv', 'w')
    with open('./HistoricalDataAnalysis/new_measurements/'+ty+'_statistics.new.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-08-11 09:55:24+00:00,13458,108.179.43.0/24,267613 3356 701 13458,612
            prefix = line.split(',')[2]
            ip, _ = prefix.split('/')
            if ip in targets:
                f.write(line)
    f.close()


def length_more_than_24():
    n = 0
    s = 0
    ty = 'bgp_hijack'
    with open('./HistoricalDataAnalysis/new_measurements/'+ty+'_statistics.new.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-08-11 09:55:24+00:00,13458,108.179.43.0/24,267613 3356 701 13458,612
            prefix = line.split(',')[2]
            ip, length = prefix.split('/')
            if int(length) > 24:
                n = n + 1
            if int(length) == 32:
                s = s + 1
    print(n, s)


def sort_emails_to_victims():
    ty = 'bgp_hijack'
    emailsdict = defaultdict(list)
    f = open('./HistoricalDataAnalysis/new_measurements/' +
             ty+'_oper.emails.sorted.csv', 'w')
    with open('./HistoricalDataAnalysis/new_measurements/'+ty+'_oper.emails.csv') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # python3 email_sender.py '2022-08-11 09:55:24+00:00' '13458' '108.179.43.0/24' '267613 3356 701 13458' '6128' 'abuse@cv.net'
            email = line.split("'")[-2]
            emailsdict[email].append(line)
    for email in emailsdict:
        for line in emailsdict[email]:
            f.write(line)
        f.write('###############################################'+'\n')
    f.close()


def get_rpki_operators():
    df = pd.read_csv('./operators.csv')
    asns = {}
    roas = {}
    total = set()
    for name, ty, details, status, asn, rank in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values, df.iloc[:, 3].values, df.iloc[:, 4].values, df.iloc[:, 5].values):
        total.add(asn)
        details = str(details)
        if details in ['signed + filtering', 'filtering']:
            asns[asn] = 1

        if 'signed' in details:
            roas[asn] = 1
    print(len(asns), len(roas))

    '''
    res = []
    n = 0
    for k in asns:
        res.append((0, k))
    ranklist = topasrank(res)
    for k in ranklist:
    	r = int(k[-1])
    	if r <= 100:
    		n = n +1
    print('number of top 100: ', n)
    '''
    return asns


def check_events(ty, attacker, prefix, valley):
    originalasbinding = {}
    with open('./LocalData/WhiteList/asbinding_whitelist.p', "rb") as f:
        originalasbinding = pickle.load(f)
    originalasvalley = {}
    with open('./LocalData/WhiteList/asvalley_whitelist.p', "rb") as f:
        originalasvalley = pickle.load(f)
    if 'hijack' in ty:
        if (attacker, prefix) in originalasbinding:
            return False
    else:
        if valley in originalasvalley:
            return False
    return True


def check_asbinding_whitelist_test():
    originalasbinding = {}
    with open('./LocalData/WhiteList/asbinding_whitelist.p', "rb") as f:
        originalasbinding = pickle.load(f)
    print('originalasbinding: ', len(originalasbinding))
    asbinding = {}
    with open('./HistoricalDataAnalysis/measure_202209/asbinding_whitelist_verified.p', "rb") as f:
        asbinding = pickle.load(f)
    print('asbinding: ', len(asbinding))


def combine_verified_files():
    res = {}
    ty = 'asbinding'
    with open('./HistoricalDataAnalysis/measure_202212/'+ty+'_whitelist_verified.part1.p', "rb") as f:
        res = pickle.load(f)
    print(len(res))
    with open('./HistoricalDataAnalysis/measure_202212/'+ty+'_whitelist_verified.part2.p', "rb") as f:
        respart = pickle.load(f)
        for k in respart:
            if k in res:
                continue
            res[k] = 1
    print(len(res))
    with open("./HistoricalDataAnalysis/measure_202212/"+ty+"_whitelist_verified.p", "wb") as fp:
        pickle.dump(dict(res), fp)


def compute_email_statistics():
    file_path = './HistoricalDataAnalysis/*/'
    files = os.path.join(file_path, "*_statistics.emails.victim.csv")
    files = glob.glob(files)
    count = 0
    asns = set()
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                email = line.split(' ')[-1].strip('\n')
                asn = line.split(' ')[4]

                if email == '\'\'':
                    continue
                count = count + 1
                asns.add(asn)
                print(asn)
    print(count, len(asns))


