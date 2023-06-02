from create_local_database import new_load_ROAs
from ROV_analysis import validateOriginV2
import os
import glob
import re
import pickle
import requests
from scipy.stats import norm
import datetime
import math
from collections import defaultdict
import numpy as np
from itertools import groupby
import time
import statistics



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
        }, timeout=10)
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

def post_detection_v3(timestamp, asn):
    Hes = []
    abnormal = 'False'

    x, Hes = lookup_local_hegemony_v3(timestamp, '0', asn)
    u, s = 0.0, 0.0

    if x == 0 and len(Hes) <= 45:
        abnormal = 'True'
    if x != 0 and len(Hes) > 5:
        data = Hes[1:]
        u, s = compute_gaussian_paras(data)

        if is_abnormal(u, s, x):
            is_burst = check_forward_hegemony_value(timestamp, '0', asn, u, s)
            if is_burst:
                abnormal = 'True'

    return abnormal


def post_analyzer(date, asn, res, verified, status):
    # timestamp, prefix, asID, vrpIDs, as_path, label, scores
    if verified.get((date, asn)) != None:
        return
    if status.get(asn) != None and status.get(asn)[0]:
        return

    elif status.get(asn) != None and not status.get(asn)[0]:
        if post_detection_v3(date, asn) == 'False':
            status[asn] = (False, res)
        else:
            status[asn] = (True, res)
    else:
        if post_detection_v3(date, asn) == 'False':
            status[asn] = (False, res)
        else:
            status[asn] = (True, res)
    verified[(date, asn)] = 1
    
def post_verification():
    folders = ['measure_202210']
    for folder in folders:
        file_path = './HistoricalDataAnalysis/202303/'+folder+'/'
        files = os.path.join(file_path, "*.out")
        files = glob.glob(files)

        for f in files:
            suffix = f.split('/')[-1].split('.')[-2]  # date

            f0 = open(file_path + 'benign_conflict.'+suffix+'.csv', 'w')
            f1 = open(file_path + 'bgp_hijack.'+suffix+'.csv', 'w')

            f2 = open(file_path + 'hijack_events.' + suffix+'.csv', 'w')
            f3 = open(file_path + 'quarantined_routes.' + suffix+'.csv', 'w')
            verified = {}
            status = {}

            with open(f) as filehandle:
                filecontents = filehandle.readlines()
                for i, line in enumerate(filecontents):
                    res = line.strip('\n').split(',')

                    date = int(res[0])

                    asn = str(res[2])

                    label = int(res[-2])

                    if label == 1:
                        f0.write('{},{}\n'.format(
                            'benign conflict', ','.join(map(str, res))))
                    if label == 2:
                        if is_bogon_asn(int(asn)):

                            continue
                        f1.write('{},{}\n'.format(
                            'bgp hijack', ','.join(map(str, res))))

                        post_analyzer(date, asn, res, verified, status)
            for asn in status:
                if status[asn][0]:
                    f2.write('{},{} \n'.format('hijack event',
                                               ','.join(map(str, status[asn][1]))))
                else:
                    f3.write('{},{} \n'.format('quarantined routes',
                                               ','.join(map(str, status[asn][1]))))
        for f in [f0, f1, f2, f3]:
            f.close()

def roa_validation(timestamp, asID, prefix, as_path, roa_px_dict):
    prefix_addr, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    #hops = as_path.split(' ')
    asID = int(asID)
    results, invalid = validateOriginV2(
        prefix_addr, prefix_len, timestamp, None, asID, roa_px_dict, None)
    return invalid

def benign_conflicts_statistics():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    file_path = './HistoricalDataAnalysis/202303/*/'
    files = os.path.join(file_path, "benign_conflict.*.csv")  # "*.org.csv"
    files = glob.glob(files)

    objectdict = {}
    asdict, prefixdict = {}, {}
    routesatday = defaultdict(set)
  
   
    print(len(files))
   
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.split(',')
                # benign conflict,1664611230,195.253.88.0/23,8561,50611+48519,211398 48646 50629 36236 8561,1,0.0+1.0+1.0+1.0+1.0+0.0
                timestamp = fields[1]
                t = str(datetime.datetime.fromtimestamp(
                    int(timestamp), datetime.timezone.utc))
                date = t.split(' ')[0]

                prefix, asn, vrpasns = fields[2], fields[3], fields[4].split(
                    '+')
                OriginMatch, IRR, Parent, SameOrg, PC, Depen = fields[-1].strip(
                    '\n').split('+')

                asdict[asn] = 1
                prefixdict[prefix] = 1

                routesatday[date].add((asn, prefix))
                objectdict[(asn, prefix)] = 1
               
    # ofile.close()
    print('Unique benign conflicts, asns, prefixes: ',
          len(objectdict), len(asdict), len(prefixdict))
    
    n1, n2 = 0, 0
    for asn, prefix in objectdict:
        invalid = roa_validation(None, int(asn), prefix, None, roa_px_dict)
        if not invalid:
            n1 = n1 + 1
        if invalid == None:
            n2 = n2 + 1
    print('valid and unknown: ', n1, n2)
    
    container, dates, numbers = [], [], []
    print('2022-11-26: ', len(routesatday['2022-11-26']))
    for date in routesatday:
        n = len(routesatday[date])
        container.append((date, n))
    container = sorted(container)
    for date, n in container:
        dates.append(date)
        numbers.append(n)

    return dates, numbers

    if check.get(s):
        return
    check[s] = True
    ofile.write(s+'\n')

def compute_route_fre(dates):
    s = list()
    f = 0.0
    for i in range(len(dates)-1):
        d = dates[i+1] - dates[i]
        s.append(d.days)

    if len(s) > 0:
        f = sum(s) / len(s)
    return f

def quarantined_asbindings_post_analysis():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    ty = 'quarantined_routes'
    file_path = './HistoricalDataAnalysis/202303/*/'
    files = os.path.join(
        file_path, ty+".*.csv")  # "*.org.csv" #bgp_hijack.20220715.csv
    files = glob.glob(files)
    
    res, dates, numbers = [], [], []
    routes = dict()
    routesatday = defaultdict(set)
    objectdict = defaultdict(set)
    asns, prefixes = dict(), dict()
    victims = defaultdict(set)
    attackers = defaultdict(set)
    peers = defaultdict(set)
    days = set()
    print(len(files))
    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]
        date = suffix[0:4] + '-'+suffix[4:6]+'-'+suffix[6:8]
        hijackdict = defaultdict(set)
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            if len(filecontents) == 0:
                routesatday[date] = {}
            for i, line in enumerate(filecontents):
                fields = line.split(',')

                # bgp hijack,1664611301,2001:57a:502::/48,33438,22773,34968 5580 22773 33438,2,0.0+0.0+0.0+0.0+1.0+0.0
                timestamp, prefix, attacker, victs, as_path, scores = int(
                    fields[1]), fields[2], fields[3], fields[4], fields[5], fields[-1].strip('\n')

                found = False
                for vic in victs:
                    if vic in as_path.split(' '):
                        found = True

                if found == True:
                    print(found)
                    continue

                peer_asn = as_path.split(' ')[0]

                t = str(datetime.datetime.fromtimestamp(
                    int(timestamp), datetime.timezone.utc))
                date = t.split(' ')[0]

                # if "10-26" not in date and "10-27" not in date and "10-28" not in date and "10-29" not in date: continue
                # if "11-07" not in date and "11-08" not in date: continue
                # if "11-16" not in date and "11-17" not in date and "11-18" not in date and "11-19" not in date and "11-20" not in date and "11-21" not in date: continue
                # if "11-23" not in date and "11-24" not in date and "11-25" not in date and "11-26" not in date and "11-27" not in date and "11-28" not in date and "11-29" not in date and "11-30" not in date: continue

                if "10-26" not in date and "10-27" not in date and "10-28" not in date and "10-29" not in date and "11-07" not in date and "11-08" not in date and "11-16" not in date and "11-17" not in date and "11-18" not in date and "11-19" not in date and "11-20" not in date and "11-21" not in date and "11-23" not in date and "11-24" not in date and "11-25" not in date and "11-26" not in date and "11-27" not in date and "11-28" not in date and "11-29" not in date and "11-30" not in date:
                    continue

                days.add(date)

                routesatday[date].add((attacker, prefix))
                objectdict[(attacker, prefix)].add(date)
                routes[(attacker, prefix)] = 1
                asns[attacker] = 1
                prefixes[prefix] = 1
                attackers[attacker].add((attacker, prefix))
                victims[victs].add((attacker, prefix))
                peers[peer_asn].add((attacker, prefix))

    whitelist = dict()
    print(len(days))
    #ofile = open('./compute_statistics_for_benign_conflicts_02.csv', 'w')
    print('Total number of quarantined routes: ', len(objectdict))
    for k in objectdict:
        
        asn, prefix = k[0], k[1]
        invalid = roa_validation(None, int(asn), prefix, None, roa_px_dict)
        if not invalid or invalid == None:
            continue

        dates = list()
        for t in sorted(objectdict[k]):
            y, m, d = t.split('-')
            date = datetime.date(int(y), int(m), int(d))
            dates.append(date)
        

        start_date = dates[0]
        whitelisted = False
        while start_date is not None:

            quarantine_days = datetime.timedelta(days=20) # 21 days
            quarantine_date = start_date+quarantine_days

            quarantine_dates = [d for d in dates if d >=
                                start_date and d <= quarantine_date]
            # update start_date
            start_date = min(
                (d for d in dates if d > quarantine_date), default=None)
            if len(quarantine_dates) < 2:
                continue
            last_date = quarantine_dates[-1]
            # here we compute the average frequency of valley occurrence
            
            #end_date = dates[-1]
            #dead_date = datetime.date(2023, 3, 31)
            #and (dead_date - end_date).days <= 30
            if compute_route_fre(quarantine_dates) < 7 and (quarantine_date - last_date).days < 7:
                fre = compute_route_fre(quarantine_dates)
                fres.append(fre)
                whitelist[k] = 1
                whitelisted = True
                
                break
        
            
    print('Number of whitelisted routes at the end of measurement: ', len(whitelist))

    for date in routesatday:
        n = len(routesatday[date])
        res.append((date, n))
    res = sorted(res)
    for date, n in res:
        dates.append(date)
        numbers.append(n)
    res = list()
    for asn in attackers:
        n = len(attackers[asn])
        res.append((n, asn))
    res = sorted(res)
    print('Attackers: ', res[-1])

    res = list()
    for asn in victims:
        n = len(victims[asn])
        res.append((n, asn))
    res = sorted(res)
    print('Victims: ', res[-1])

    res = list()
    for asn in peers:
        n = len(peers[asn])
        res.append((n, asn))
    res = sorted(res)
    print('Peers: ', res[-1])

    print('hijacks, attackers, prefixes, victims: ', len(
        hijacks), len(attackers), len(prefixes), len(victims))
    
    return dates, numbers

def bgp_attacks_statistics():
    events = defaultdict(list)
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    file_path = './HistoricalDataAnalysis/202303/*/'
    files = os.path.join(file_path, "quarantined_routes.*.csv")  # "*.org.csv"
    files = glob.glob(files)
    ofile1 = open(
        './HistoricalDataAnalysis/202303/hijack_events_statistics.212483.csv', 'w')  # "mini" means removing the events that were attributed to AS212483
    ofile2 = open(
        './HistoricalDataAnalysis/202303/hijack_events_flapping.csv', 'w')

    attackerdict = defaultdict()
    totaldict = dict()

    print(len(files))
    for f in files:
        with open(f) as filehandle:
            filecontents = filehandle.readlines()

            for i, line in enumerate(filecontents):
                line = line.strip('\n')
                fields = line.split(',')

                # hijack event,1664611474,2607:f790:fff0::/48,62588,12129,267613 174 2828 12129 62588,2,0.0+0.0+0.0+0.0+1.0+0.0
                timestamp = int(fields[1])
                t = str(datetime.datetime.fromtimestamp(
                    int(timestamp), datetime.timezone.utc))
                date = t.split(' ')[0]

                prefix = fields[2]
                attacker = fields[3]
                victims = fields[4].split('+')
                as_path = fields[5]
                found = False
                for victim in victims:

                    if victim in as_path.split(' '):
                        found = True
                if found == True:
                    continue

                invalid = roa_validation(
                    None, int(attacker), prefix, None, roa_px_dict)
                if not invalid or invalid == None:
                    continue
                if attacker not in attackerdict:
                    attackerdict[attacker] = {
                        'date': set(),
                        'examples': set(),
                    }
                attackerdict[attacker]['date'].add(date)
                attackerdict[attacker]['examples'].add(
                    (str(timestamp), prefix, victims[0], as_path))

    print('the number of captured events: ', len(attackerdict))

    asndict = {}
    attackdict = {}
    frequentdict = {}
    n = 0
    c = 0
    s = 0
    for k, v in attackerdict.items():

        if len(v['date']) > 1:

            # for e in v['examples']:
            #	prefix = e[1]
            #	frequentdict[(k, prefix)] = 1
            frequentdict[k] = 1
            c = c + len(v['date'])
            if k == '395808':
                print('395808: ', len(v['date']))
            ofile2.write(','.join([k]+sorted(v['date']))+'\n')
            for time, prefix, victim, as_path in v['examples']:
                t = str(datetime.datetime.fromtimestamp(
                    int(time), datetime.timezone.utc))
                date = t.split(' ')[0]

                if "2022-11-24" in date or "2022-11-25" in date or "2022-11-26" in date:

                    if as_path.split(' ')[0] == "212483":
                        n = n + 1
            continue
        events[list(v['date'])[0]].append(1)
        c = c + len(v['date'])
        time, prefix, victim, as_path = sorted(v['examples'])[0]
        t = str(datetime.datetime.fromtimestamp(
            int(time), datetime.timezone.utc))
        date = t.split(' ')[0]

        if "10-26" in date or "10-27" in date or "10-28" in date or "10-29" in date or "11-07" in date or "11-08" in date or "11-16" in date or "11-17" in date or "11-18" in date or "11-19" in date or "11-20" in date or "11-21" in date or "11-23" in date or "2022-11-24" in date or "2022-11-25" in date or "2022-11-26" in date or "2022-11-27" in date or "2022-11-28" in date or "2022-11-29" in date or "2022-11-30" in date:
            if as_path.split(' ')[0] == "212483":
                if s < 500:
                    ofile1.write(t+','+k+','+prefix+',' +
                                 as_path+','+victim + '\n')
                s = s + 1
                continue

        #ofile1.write(t+','+k+','+prefix+','+as_path+','+victim + '\n')
        asndict[k] = 1
        attackdict[(list(v['date'])[0], k)] = 1

    print('Frequent events: ', len(frequentdict), c)
    print('Frequent events attributed to AS212483', n)
    with open("./HistoricalDataAnalysis/202303/BGPmon/fre_dict.p", "wb") as fp:
        pickle.dump(dict(frequentdict), fp)

    ofile1.close()
    ofile2.close()

    return events

def hijack_events_statistics():
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)

    file_path = './HistoricalDataAnalysis/202303/measure_*/'
    files = os.path.join(
        file_path, "hijack_events.*.csv")  # "*.org.csv"
    files = glob.glob(files)

    objectdict = {}
    asdict, prefixdict = {}, {}
    events = defaultdict(set)
    routesatday = defaultdict(set)
    #peers = defaultdict(dict)
    peers = {}
    vrpasdict = dict()
    days = set()
    print(len(files))

    for f in files:
        suffix = f.split('/')[-1].split('.')[-2]
        date = suffix[0:4] + '-'+suffix[4:6]+'-'+suffix[6:8]
        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            if len(filecontents) == 0:
                routesatday[date] = {}
            for i, line in enumerate(filecontents):
                fields = line.split(',')

                timestamp = fields[1]
                t = str(datetime.datetime.fromtimestamp(
                    int(timestamp), datetime.timezone.utc))
                date = t.split(' ')[0]
                # if "10-26" not in date and "10-27" not in date and "10-28" not in date and "10-29" not in date: continue
                # if "11-07" not in date and "11-08" not in date: continue
                # if "11-16" not in date and "11-17" not in date and "11-18" not in date and "11-19" not in date and "11-20" not in date and "11-21" not in date: continue

                # if "11-23" not in date and "11-24" not in date and "11-25" not in date and "11-26" not in date and "11-27" not in date and "11-28" not in date and "11-29" not in date and "11-30" not in date: continue

                prefix, asn, victims, as_path = fields[2], fields[3], fields[4].split(
                    '+'), fields[5]

                found = False
                for victim in victims:

                    if victim in as_path.split(' '):
                        found = True
                if found == True:
                    continue

                OriginMatch, IRR, Parent, SameOrg, PC, Depen = fields[-1].strip(
                    '\n').split('+')
                invalid = roa_validation(
                    None, int(asn), prefix, None, roa_px_dict)
                if not invalid or invalid is None:
                    continue
                '''
                if "10-26" in date or "10-27" in date or "10-28" in date or "10-29" in date:
                    peer_asn = as_path.split(' ')[0]
                    peers.setdefault(peer_asn, {})[asn] = 1
                    days.add(date)
                elif "11-07" in date or "11-08" in date:
                    peer_asn = as_path.split(' ')[0]
                    peers.setdefault(peer_asn, {})[asn] = 1
                    days.add(date)
                elif "11-16" in date or "11-17" in date or "11-18" in date or "11-19" in date or "11-20" in date or "11-21" in date:
                    peer_asn = as_path.split(' ')[0]
                    peers.setdefault(peer_asn, {})[asn] = 1
                    days.add(date)
                elif "11-23" in date or "11-24" in date or "11-25" in date or "11-26" in date or "11-27" in date or "11-28" in date or "11-29" in date or "11-30" in date:
                    peer_asn = as_path.split(' ')[0]
                    peers.setdefault(peer_asn, {})[asn]= 1
                    days.add(date)
                '''

                asdict[asn] = 1
                prefixdict[prefix] = 1
                peer_asn = as_path.split(' ')[0]

                peers.setdefault(peer_asn, {}).setdefault(date, set()).add(asn)
                routesatday[date].add((asn, prefix))
                # if (asn, prefix) in objectdict: continue
                objectdict[(asn, prefix)] = 1
                events[date].add(asn)
                #ofile.write(','.join([asn, prefix, OriginMatch, IRR, Parent, SameOrg, PC, Depen])+'\n')

    # ofile.close()

    print('Unique confirmed hijacks, asns, prefixes ',
          len(objectdict), len(asdict), len(prefixdict))

    container, dates, numbers = [], [], []
    print('2022-11-26: ', len(routesatday['2022-11-26']))
    for date in routesatday:
        n = len(routesatday[date])
        container.append((date, n))
    container = sorted(container)
    for date, n in container:
        dates.append(date)
        numbers.append(n)
    print(len(dates))
    s = 0
    for date in peers['212483']:
        print(date, len(peers['212483'][date]))
        s = s + len(peers['212483'][date])
    print('Peer 212483: ', s)

    #print('Peer 212483: ', len(peers['212483']))
    c = 0
    for date in events:

        c = c + len(events[date])
    print('Events: ', c)
    with open('./HistoricalDataAnalysis/202303/hijack_events.p', "wb") as fp:
        pickle.dump(dict(events), fp)
    return dates, numbers

def test_bgpmon_events(ty, start_time, end_time, asn):
    report_time = start_time

    y, m, d = report_time.split('T')[0].split('-')
    hh, mm = report_time.split('T')[1].split(':')

    report_timestamp = int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm))))

    start_timestamp = calculate_heg_time(int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm)))))
    y, m, d = start_timestamp.split('T')[0].split('-')
    hh, mm = start_timestamp.split('T')[1].split(':')
    start_timestamp = int(calculate_unix_time(
        datetime.datetime(int(y), int(m), int(d), int(hh), int(mm))))

    for timestamp in range(start_timestamp-5*3600, start_timestamp+5*3600, 60*15):
        t = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)

        x, Hes = sample_hegemony_values(timestamp, '0', asn)

        u, s = 0.0, 0.0
        abnormal = 'False'
        if x == 0 and len(Hes) <= 45:  # we set 45 when the total number of samples is 50
            abnormal = 'True'
        if x != 0 and len(Hes) > 5:
            data = Hes[1:]
            u, s = compute_gaussian_paras(data)

            if is_abnormal(u, s, x):
                abnormal = 'True'
                '''
                is_burst = check_forward_hegemony_value(timestamp, '0', asn, u, s)
               
                if is_burst:
                    abnormal = 'True'
                '''
        if abnormal == 'True':
            delay = (timestamp - report_timestamp)/3600
            if x == 0:
                delay = 0
            #t = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            print(t, x, delay)
            return delay

    return None

def bgpmon_measurements():
   
    ty = "BGPmon"
    with open('./HistoricalDataAnalysis/'+ty+'_overlap.res') as filehandle:
    # with open('./ValidateData/route_leak.20220715.unverified.res') as filehandle:
    # with open('./HistoricalDataAnalysis/202303/'+ty+'/bgp_hijacks.remaining.csv') as filehandle:
    
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            # 2022-07-20 09:08:43+00:00,23689
            # 2022-07-25 09:23:10+00:00,60068
            line = line.strip('\n')
            # 2022-10-27 08:34:34+00:00,100.20.30.0/24,8612+174+3320+4809+15399+37027+37063,37063
            fields = line.split(',')
            timestamp, attacker = fields[0], fields[-1]
            date = timestamp.split(' ')[0]
            st = timestamp.split(' ')[1].split(
                ':')[0] + ':' + timestamp.split(' ')[1].split(':')[1]
            et = str(int(timestamp.split(' ')[1].split(':')[
                     0])+1) + ':' + timestamp.split(' ')[1].split(':')[1]

            asn = int(attacker)
            start_time = date + 'T' + st
            end_time = date + 'T' + et

            delay = test_bgpmon_events(
                ty, start_time, end_time, asn)  # test_bgpmon_events
            if delay == None:
                continue
            ofile.write(line+','+str(int(delay))+'\n')
    ofile.close()
    
def main():
    post_verification()
    # benign_conflicts_statistics()
    # quarantined_asbindings_post_analysis()
    # bgp_attacks_statistics()
    # hijack_events_statistics()
    # bgpmon_measurements()



if __name__ == "__main__":
    main()
