#!/usr/bin/env python
# import shutup
import pybgpstream
from itertools import groupby
from smart_validator import validateOriginV2, myParseROA, myMakeROABinaryPrefixDict, calculate_unix_time
from datetime import timezone
import datetime
import pickle
# from feature_extractor import is_bogon_asn, compute_two_scores_v2, compute_score3, compute_pfx_distance, compute_hege_depth_v2, identify_valley
import time
import os
import re
import numpy as np
from feature_extractor import *
from create_local_database import update_at_specific_times
import logging
import warnings
from copy import deepcopy
from post_analysis import post_detection_v3

warnings.filterwarnings("ignore")


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
        return irrValid, matches
    return irrValid, matches


def load_ROAs(roa_path):
    roa_px_dict = {}
    list_roas = []
    with open(roa_path) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            roa = myParseROA(line)
            if roa != None:
                list_roas.append(roa)
    roas, ipv4_dict, ipv6_dict = myMakeROABinaryPrefixDict(list_roas)
    roa_px_dict = (roas, ipv4_dict, ipv6_dict)
    return roa_px_dict


def extract_features(results, as2prefixes_dict, roa_as2prefixes_dict, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, timestamp):
    _, prefix_addr, prefix_len, as_path, asID, res, _, covered_prefix = results[0].split(
        ' ')
    asID = int(asID)
    vrpIDs = []
    for res in results:  # MOAS
        vrpIDs.append(int(res.split(' ')[-2]))
    prefix = prefix_addr+'/'+str(prefix_len)
    prefix_len = int(prefix_len)
    maxlen = covered_prefix.split('-')[-1]
    maxlen = int(maxlen)

    origin_matching = 0
    maxlength_matching = 0
    if asID in vrpIDs:
        origin_matching = 1
    if prefix_len <= maxlen:
        maxlength_matching = 1

    rpki_status = 0
    if origin_matching == 1 and maxlength_matching == 1:
        rpki_status = 1

    confi_score = 0
    score0 = 0
    score1 = 0
    score2 = 0
    score3 = 0
    score4 = 0
    hops = as_path.split('+')
    start = time.monotonic()

    scores = []
    for vrpID in vrpIDs:
        score0, score1, score2, score3, score4, confi_score = compute_two_scores_new(
            origin_matching, caida_as_org, caida_as_rel_pc, roa_as2prefixes_dict, timestamp, prefix, asID, vrpID, '+'.join(hops), local_hege_dict, irr_database)
        scores.append((score0, score1, score2, score3, score4, confi_score))
    confi_scores = []
    for s in scores:
        confi_scores.append(s[-1])
    maximum = max(confi_scores)
    for s in scores:
        if s[-1] == maximum:
            score0, score1, score2, score3, score4, confi_score = s[0], s[1], s[2], s[3], s[4], s[5]

    path_score, pair1, pair2, leaker = compute_score3(
        caida_as_rel_pp, caida_as_rel_pc, as_path)
    valleydepth, Hes = 0.0, []
    if leaker != None:
        valleydepth, Hes = compute_hege_depth_v2(
            timestamp, hops, global_hege_dict)
    if origin_matching == 1:
        distance = 0.0
    else:
        distance = compute_pfx_distance(as2prefixes_dict, prefix, asID)
    path_anomaly = path_score+valleydepth
    return [rpki_status, confi_score, distance, path_anomaly], [origin_matching, score0, score1, score2, score3, score4], vrpIDs, leaker


def is_bogon_path(hops):
    for hop in hops:
        if is_bogon_asn(hop):
            return True


def test_historical_stream(start_date, roa_px_dict, as2prefixes_dict, roa_as2prefixes_dict, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, asbinding_whitelist, asvalley_whitelist, clf):
    # for start_date in ['2022-08-20', '2022-08-21', '2022-08-22', '2022-08-23', '2022-08-24', '2022-08-25', '2022-08-26']:
    y, m, d = start_date.split(' ')[0].split('-')
    hh, mm, ss = start_date.split(' ')[1].split(':')
    date = datetime.datetime(int(y), int(m), int(d), int(hh), int(mm), int(ss))
    utc_timestamp = calculate_unix_time(date)
    start_timestamp = utc_timestamp
    asbinding, asvalley = {}, {}
    measured_routes = {}
    while utc_timestamp < start_timestamp + 3600*24*16:
        
        y, m, d = start_date.split(' ')[0].split('-')
        #!!!!!!!!need to be uncommented
        #roa_px_dict, roa_as2prefixes_dict, as2prefixes_dict, global_hege_dict = update_at_specific_times(y, m, d)
        end_date = str(datetime.datetime.fromtimestamp(
            utc_timestamp + 3600*10, timezone.utc))  # 12 hours

        stream = pybgpstream.BGPStream(
            # Consider this time interval:
            # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
            from_time=start_date, until_time=end_date,
            # "route-views.wide", "route-views.chicago"
            collectors=["route-views.amsix"],
            record_type="updates"
        )
        validated = {}
        
        n1, n2, n3, n4 = 0, 0, 0, 0
        # bogon_asns = {}
        # myres = {}

        lovres = open("./HistoricalDataAnalysis/lovres."+y+m+d+".out", 'w')
        now = datetime.datetime.now()
        start_time = calculate_unix_time(now)
        end_time = start_time
        for elem in stream:
            if end_time > start_time + 3600*4:
                break
            if elem.type != 'A':
                continue
            timestamp = int(elem.time)
            # print(utc_time.timestamp(), timestamp)
            # elem.fields: {'next-hop': '80.77.16.114', 'as-path': '34549 6830 3356 12301', 'communities': {'34549:6830', '6830:23001', '6830:33302', '6830:17000', '34549:100', '6830:17430'}, 'prefix': '91.82.90.0/23'}
            prefix = elem.fields['prefix']
            prefix_addr, prefix_len = prefix.split('/')
            prefix_len = int(prefix_len)
            peer = str(elem.peer_asn)

            as_path = elem.fields['as-path']
            if "{" in as_path or ":" in as_path:
                continue
            # Get the array of ASns in the AS path and remove repeatedly prepended ASns
            hops = [k for k, g in groupby(as_path.split(" "))]

            # peer is at the second in the AS path
            if len(hops) > 1 and hops[0] == peer:
                asID = int(hops[-1])
                # ignore the ASes of routerview collectors and peer
                t = (asID, prefix, as_path)
                if is_bogon_asn(asID) or is_bogon_path(hops):
                    # record bogon asn
                    # bogon_asns[t] = 1
                    continue  # block!!!
                # if t in validated:
                #    continue
                validated[t] = 1
                
                results, invalid = validateOriginV2(
                    prefix_addr, prefix_len, timestamp, "+".join(hops), asID, roa_px_dict, None)
                

                if invalid == None:
                    n1 = n1 + 1
                elif invalid == False:
                    n2 = n2 + 1
                elif invalid == True:
                    n3 = n3 + 1

                if invalid is None:
                    continue  # unknown to RPKI, no need to process

                data, scores, vrpIDs, leaker = extract_features(results, as2prefixes_dict, roa_as2prefixes_dict, caida_as_org,
                                                                caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, timestamp)

                origin_matching = scores[0]
                scores = '+'.join(map(str, scores))
                if asbinding_whitelist.get((str(asID), prefix)) == 1:
                    asbinding[(str(asID), prefix)] = 1
                valley, rvalley = None, None
                if leaker != None:
                    ind = hops.index(leaker)
                    valleylist = [hops[ind-1], hops[ind], hops[ind+1]]
                    valley = '_'.join(valleylist)
                    valleylist.reverse()
                    rvalley = '_'.join(valleylist)
                    if asvalley_whitelist.get(valley) == 1:
                        asvalley[valley] = 1
                    elif asvalley_whitelist.get(rvalley) == 1:
                        asvalley[rvalley] = 1

                X_test = np.array(data).reshape(1, 4)
                prop = clf.predict_proba(X_test)[0]
                # print(data, scores, prop)
                # label = np.argmax(prop) + 1
                label = 1
                # we can customize this threshold when deploying in practice.
                if prop[1] > 0.5:
                    label = 2
                if label == 1 and data[0] == 1:
                    continue  # Not save valid annoucements
                if label == 2:

                    if leaker == None and (origin_matching == 1 or asbinding_whitelist.get((str(asID), prefix)) == 1):
                        continue
                    if leaker != None:

                        if (asvalley_whitelist.get(valley) == 1 or asvalley_whitelist.get(rvalley) == 1 or str(leaker) in vrpIDs) and (origin_matching == 1 or asbinding_whitelist.get((str(asID), prefix)) == 1):
                            continue

                res = [timestamp, asID, prefix, as_path, vrpIDs[0],
                       label, data[0], scores, leaker]

                # post_analyzer(res, lovres, verified)
                lovres.write(','.join(map(str, res))+'\n')
                now = datetime.datetime.now()
                end_time = calculate_unix_time(now)
                
        measured_routes[y+m+d] = len(validated)
        
        
        n4 = n1 + n2 + n3
        msres = {}
        msres['num_none'] = n1
        msres['num_valid'] = n2
        msres['num_invalid'] = n3
        msres['total_num'] = n4

        # with open("./HistoricalDataAnalysis/bogon_asns."+y+m+d+".p", "wb") as fp:
        #    pickle.dump(dict(bogon_asns), fp)
        with open("./HistoricalDataAnalysis/msres."+y+m+d+".p", "wb") as fp:
            pickle.dump(dict(msres), fp)
        
        
        lovres.close()
        utc_timestamp = utc_timestamp + 3600*24
        start_date = str(datetime.datetime.fromtimestamp(
            utc_timestamp, timezone.utc))
        
    with open("./HistoricalDataAnalysis/asbinding_whitelist_verified.part2.p", "wb") as fp:
        pickle.dump(dict(asbinding), fp)
    with open("./HistoricalDataAnalysis/asvalley_whitelist_verified.part2.p", "wb") as fp:
        pickle.dump(dict(asvalley), fp)
    with open("./HistoricalDataAnalysis/measured_routes."+y+m+d+".p", "wb") as fp:
            pickle.dump(dict(measured_routes), fp)


def test_live_stream(start_date, roa_px_dict, as2prefixes_dict, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, clf):
    stream = pybgpstream.BGPStream(
        # accessing routeview-stream
        project="routeviews-stream",
        # filter to show only stream from amsix bmp stream
        filter="router wide, router amsix, router chicago",
    )
    # validated = {}
    bogon_asns = {}
    rovres = {}
    myres = {}
    num_validate = 0
    num_classifi = 0
    for elem in stream:
        dt = datetime.datetime.now(timezone.utc)
        utc_time = dt.replace(tzinfo=timezone.utc)
        if utc_time.timestamp() > start_date + 300:
            break
        if elem.type != 'A':
            continue
        timestamp = int(elem.time)
        # print(utc_time.timestamp(), timestamp)
        # elem.fields: {'next-hop': '80.77.16.114', 'as-path': '34549 6830 3356 12301', 'communities': {'34549:6830', '6830:23001', '6830:33302', '6830:17000', '34549:100', '6830:17430'}, 'prefix': '91.82.90.0/23'}
        prefix = elem.fields['prefix']
        prefix_addr, prefix_len = prefix.split('/')
        prefix_len = int(prefix_len)
        peer = str(elem.peer_asn)

        as_path = elem.fields['as-path']
        if "{" in as_path or ":" in as_path:
            continue
        # Get the array of ASns in the AS path and remove repeatedly prepended ASns
        hops = [k for k, g in groupby(as_path.split(" "))]
        hops = hops[1:]
        pathlen = len(hops)
        # peer is at the second in the AS path
        if len(hops) > 1 and hops[0] == peer:
            asID = int(hops[-1])
            # ignore the ASes of routerview collectors and peer
            t = (asID, prefix, '+'.join(hops[1:]))
            if is_bogon_asn(asID):
                # record bogon asn
                bogon_asns[t] = 1
                continue  # block!!!
            # if t in validated: continue
            results, invalid = validateOriginV2(
                prefix_addr, prefix_len, timestamp, "+".join(hops), asID, roa_px_dict, None)
            # validated[t] = True
            num_validate = num_validate + 1
            if invalid is None:
                continue  # unknown to RPKI, pass
            rovres[t] = invalid
            result = results[0]
            data, leaker = extract_features(result, as2prefixes_dict, caida_as_org, caida_as_rel_pp,
                                            caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, timestamp)
            num_classifi = num_classifi + 1
            X_test = np.array(data).reshape(1, 5)
            prop = clf.predict_proba(X_test)[0]
            label = np.argmax(prop) + 1
            # y_pred = list(clf.predict_proba(X_test)[0])
            # label = y_pred.index(max(y_pred)) + 1
            myres[t] = [timestamp, asID, prefix,
                        as_path, label, data[0], leaker]
    print('Total number of validations: ', num_validate)
    print('Total number of classifications: ', num_classifi)
    with open("./bogon_asns.p", "wb") as fp:
        pickle.dump(dict(bogon_asns), fp)
    with open("./rovres.p", "wb") as fp:
        pickle.dump(dict(rovres), fp)
    with open("./myres.p", "wb") as fp:
        pickle.dump(dict(myres), fp)


def check_AS_path(caida_as_rel_pp, caida_as_rel_pc, as_path, local_hege_dict):
    # time overhead is not over 0.01s, which can be negligible
    valleyFree = True
    # 34800+24961+3356+3257+396998+18779, to make any AS appears no more than once in the AS path
    g = as_path.split('+')
    g.reverse()
    for i in range(1, len(g)-1):
        if identify_valley(g[i-1], g[i], g[i+1], caida_as_rel_pc, caida_as_rel_pp):
            valleyFree = False
            print(g[i+1], g[i], g[i-1])
            asn2 = int(g[i])
            asn3 = int(g[i-1])
            if (local_hege_dict.get(asn3) != None and asn2 in local_hege_dict[asn3]['asns']):
                print('True')
            return valleyFree

    return valleyFree


def test_abnormal(roa_px_dict, as2prefixes_dict, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database):
    line = "1656153511,103.158.87.0/24,3130+6939+132602+10075+141404,141404,141404,24"
    # 198589, '37.77.48.0/24', '6447 6830 1299 6663 210021 211181 34929 208293 198589'
    fields = line.split(',')
    prefix = fields[1]
    prefix_addr, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    timestamp = int(fields[0])
    asID = int(fields[3])
    check_AS_path(caida_as_rel_pp, caida_as_rel_pc,
                  fields[2], local_hege_dict)  # not feasible
    # results, invalid = validateOriginV2(prefix_addr, prefix_len, timestamp, fields[2], asID, roa_px_dict, None)
    # result = results[0]
    # data = extract_features(result, as2prefixes_dict, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, timestamp)


logging.basicConfig(level=logging.INFO, filename='./test_live_stream.log')


def main():
    # roa_px_dict, as2prefixes_dict, roa_as2prefixes_dict
    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = load_ROAs(roa_path)
    roa_as2prefixes_dict = {}
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
    caida_as_org = {}
    with open(basic_path+'/CAIDA/caida_as_org.p', "rb") as f:
        caida_as_org = pickle.load(f)
    caida_as_rel_pp = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pp.p', "rb") as f:
        caida_as_rel_pp = pickle.load(f)
    caida_as_rel_pc = {}
    with open(basic_path+'/CAIDA/caida_as_rel_pc.p', "rb") as f:
        caida_as_rel_pc = pickle.load(f)

    global_hege_dict = {}
    local_hege_dict = {}
    # with open(basic_path + '/IHR/global_hege_dict.p', "rb") as f:
    #    global_hege_dict = pickle.load(f)
    # with open(basic_path + '/IHR/local_hege_dict.p', "rb") as f:
    #    local_hege_dict = pickle.load(f)

    irr_database = {}
    with open(basic_path+'/IRR/irr_database.p', "rb") as f:
        irr_database = pickle.load(f)

    asbinding_whitelist, asvalley_whitelist = {}, {}
    with open(basic_path+'/WhiteList/asbinding_whitelist.p', "rb") as f:
        asbinding_whitelist = pickle.load(f)
    with open(basic_path+'/WhiteList/asvalley_whitelist.p', "rb") as f:
        asvalley_whitelist = pickle.load(f)

    clf = None
    with open('./dt_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)
    dt = datetime.datetime.now(timezone.utc)
    utc_time = dt.replace(tzinfo=timezone.utc)
    start_date = utc_time.timestamp()
    # test_live_stream(start_date, roa_px_dict, as2prefixes_dict, caida_as_org, caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, clf)
    start_date = '2022-12-16 08:00:00'
    test_historical_stream(start_date, roa_px_dict, as2prefixes_dict, roa_as2prefixes_dict, caida_as_org,
                           caida_as_rel_pp, caida_as_rel_pc, local_hege_dict, global_hege_dict, irr_database, asbinding_whitelist, asvalley_whitelist, clf)
    with open(basic_path+'/IRR/irr_database.p', "wb") as fp:
        pickle.dump(dict(irr_database), fp)


if __name__ == "__main__":
    main()
    # historical_data_analysis()
