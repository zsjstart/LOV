from download_roas import collect_roas
from datetime import timezone
import datetime
import requests
import os
import pickle
import json
import shutil
import pandas as pd
from collections import defaultdict
from feature_extractor import load_ROAs, as2prefixes
import geoip2.database
import geoip2.errors
import ipaddress
import time
import convert_mmdb_to_csv
from smart_validator import myParseROA, myMakeROABinaryPrefixDict, calculate_unix_time

from copy import deepcopy


def new_load_ROAs(roa_path):
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


def calculate_unix_time(date_and_time):
    '''
    Calculate unix time elapsed from a datetime object
    @param: date_and_time (datetime): datetime object
    @return: Seconds elapsed using unix reference (int)
    '''
    return int((date_and_time - datetime.datetime.utcfromtimestamp(0)).total_seconds())


def update_roas(y, m, d):
    output = collect_roas(y, m, d)
    save_path = "./LocalData/ROAs/"
    cmd = """ cp %s %s """ % (output, save_path+"all.roas.csv")
    out = os.system(cmd)
    roas_dict = load_ROAs(save_path+"all.roas.csv")
    with open(save_path+'roas_dict.p', "wb") as fp:
        pickle.dump(dict(roas_dict), fp)
    as2prefixes_dict = as2prefixes(roas_dict)
    with open(save_path+'as2prefixes_dict.p', "wb") as fp:
        pickle.dump(dict(as2prefixes_dict), fp)
    output = output.replace('/all.roas.csv', '')
    shutil.rmtree(output)


def load_caida_as_org(ifile):
    caida_as_org_dict = {}
    caida_as_cc_dict = {}
    with open(ifile) as f:  # "/home/zhao/Shujie/Routing_traffic/coding/20220701.as-org2info.jsonl"
        caida_as_org = [json.loads(jline) for jline in f]
    org2cc = dict()
    for e in caida_as_org:
        if "country" not in e:
            continue
        OrgId = e["organizationId"]
        cc = e["country"]
        org2cc[OrgId] = cc

    for e in caida_as_org:
        if "asn" not in e:
            continue
        asn = int(e["asn"])
        OrgId = e["organizationId"]
        cc = org2cc[OrgId]
        caida_as_org_dict[asn] = OrgId
        caida_as_cc_dict[asn] = cc
    os.remove(ifile)
    return caida_as_org_dict, caida_as_cc_dict


def load_caida_as_rel(ifile):
    caida_as_rel_pc = {}
    caida_as_rel_cp = defaultdict(set)
    caida_as_rel_pp = {}
    IXP_ASes = []
    with open(ifile) as filehandle:  # "/home/zhao/Shujie/Routing_traffic/coding/20220701.as-rel.txt"
        filecontents = filehandle.readlines()
        for line in filecontents:
            if 'IXP ASes' in line:
                IXP_ASes = line.split(':')[1].strip(' ').strip('\n').split(' ')
                # print(IXP_ASes)
            if '#' in line:
                continue
            p, c, code = line.split('|')
            code = int(code.strip('\n'))
            if code == -1:
                if p not in caida_as_rel_pc:
                    caida_as_rel_pc[p] = set()
                caida_as_rel_pc[p].add(c)
                caida_as_rel_cp[c].add(p)
            if code == 0:
                if p not in caida_as_rel_pp:
                    caida_as_rel_pp[p] = set()
                caida_as_rel_pp[p].add(c)

                if c not in caida_as_rel_pp:
                    caida_as_rel_pp[c] = set()
                caida_as_rel_pp[c].add(p)
    os.remove(ifile)
    return caida_as_rel_pc, caida_as_rel_cp, caida_as_rel_pp, IXP_ASes


def load_prefixes_to_as(ifile):
    prefixes_to_as = {}
    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            ip, length, asn = line.split('\t')
            ip = ip.strip('\t')
            length = length.strip('\t')
            asn = asn.strip('\t').strip('\n')
            #print(ip, length, asn)
            if ',' in asn:
                continue
            asns = asn.split('_')
            for asn in asns:
                asn = int(asn)
                if asn not in prefixes_to_as:
                    prefixes_to_as[asn] = set()
                prefixes_to_as[asn].add(ip + '/'+length)
    os.remove(ifile)
    return prefixes_to_as


def download_as_org(y, m, d):
    download_path = "https://publicdata.caida.org/datasets/as-organizations/" + \
        y+m+d+".as-org2info.jsonl.gz"
    # 20220701.as-org2info.jsonl.gz
    save_path = "./LocalData/CAIDA/as-org2info.jsonl.gz"
    output = "./LocalData/CAIDA/as-org2info.jsonl"
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)
    cmd = """ gzip -dc %s > %s""" % (save_path, output)
    out = os.system(cmd)
    caida_as_org, caida_as_cc = load_caida_as_org(output)
    with open("./LocalData/CAIDA/caida_as_org.p", "wb") as fp:
        pickle.dump(caida_as_org, fp)
    with open("./LocalData/CAIDA/caida_as_cc.p", "wb") as fp:
        pickle.dump(caida_as_cc, fp)


def download_as_rel(y, m, d):
    download_path = "https://publicdata.caida.org/datasets/as-relationships/serial-1/" + \
        y+m+d+".as-rel.txt.bz2"
    save_path = "./LocalData/CAIDA/as-rel.txt.bz2"
    output = "./LocalData/CAIDA/as-rel.txt"
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)
    cmd = """ bzip2 -dc %s > %s""" % (save_path, output)
    out = os.system(cmd)
    caida_as_rel_pc, caida_as_rel_cp, caida_as_rel_pp, IXP_ASes = load_caida_as_rel(
        output)
    with open("./LocalData/CAIDA/caida_as_rel_pc.p", "wb") as fp:
        pickle.dump(dict(caida_as_rel_pc), fp)
    with open("./LocalData/CAIDA/caida_as_rel_cp.p", "wb") as fp:
        pickle.dump(dict(caida_as_rel_cp), fp)
    with open("./LocalData/CAIDA/caida_as_rel_pp.p", "wb") as fp:
        pickle.dump(dict(caida_as_rel_pp), fp)
    with open("./LocalData/CAIDA/IXP_ASes.p", "wb") as fp:
        pickle.dump(IXP_ASes, fp)


def download_prefixes_to_as(y, m, d):
    # https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/2022/09/ routeviews-rv2-20220904-1200.pfx2as.gz
    download_path = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/" + \
        y+"/"+m+"/"+"routeviews-rv2-"+y+m+d+"-1600.pfx2as.gz"
    save_path = "./LocalData/CAIDA/routeviews-rv2.pfx2as.gz"
    output = "./LocalData/CAIDA/routeviews-rv2.pfx2as"
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)

    cmd = """ gzip -dc %s > %s""" % (save_path, output)
    out = os.system(cmd)
    prefixes_to_as = load_prefixes_to_as(output)
    with open("./LocalData/CAIDA/prefixes_to_as.p", "wb") as fp:
        pickle.dump(prefixes_to_as, fp)

def download_russia_blocked_domain_list():
    download_path = "https://reestr.rublacklist.net/api/v3/dpi/"
    save_path = "/home/zhao/Shujie/coding/Datasets/online_analysis/russia_blocked_dpi.dat"
    
    response = requests.get(download_path)
    res = {}
    if response.status_code == 200:
        with open(save_path, "w") as f:
            
            for k in response.json():
                domains = k['domains']
                for domain in domains:
                	res[domain] = 1
                	f.write(domain+'\n')
    print(len(res))


def update_CAIDA(y, m, d):
    download_as_org(y, m, d)
    download_as_rel(y, m, d)


def update_P2A(y, m, d):
    download_prefixes_to_as(y, m, d)


def update_GeoIP(y, m, d):
    mylicensekey = "ZIZ2JEjyp1OuBqGg"
    # https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz
    download_path = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz" % (
        mylicensekey)
    # tar -xvzf GeoLite2-City_20220805.tar.gz */GeoLite2-City.mmdb > ./GeoLite2-City.mmdb
    save_path = "./LocalData/GeoIP/temporary/GeoLite2-City.tar.gz"
    output = "./LocalData/GeoIP/temporary"
    ofile = "GeoLite2-City.mmdb"
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)

    cmd = """ tar -xf %s --directory %s """ % (
        save_path, output)  # GeoLite2-City.mmdb
    out = os.system(cmd)
    cmd = """ cp %s %s """ % (output+'/*/'+ofile, "./LocalData/GeoIP/"+ofile)
    out = os.system(cmd)
    if os.path.exists(output) and os.path.isdir(output):
        shutil.rmtree(output)
    os.mkdir(output)


def load_ihr_global(today, ifile):
    global_hege_dict = {}
    # with open('./LocalData/IHR/global_hege_dict.p', "rb") as f:
    #	global_hege_dict = pickle.load(f)

    df = pd.read_csv(ifile)
    # 2022-08-05 23:45:00+00,0,58110,1.10334833368854e-09
    for timebin, asn, heg in zip(df.iloc[:, 0].values, df.iloc[:, 2].values, df.iloc[:, 3].values):
        y, m, d = timebin.split(' ')[0].split('-')
        hh, mm, ss = timebin.split(' ')[1].split(':')
        ss = ss.split('+')[0]
        date = datetime.datetime(int(y), int(
            m), int(d), int(hh), int(mm), int(ss))
        date = int(calculate_unix_time(date))
        if asn not in global_hege_dict:
            global_hege_dict[asn] = {
                'date': 0,
                'heg': 0.0
            }
        global_hege_dict[asn]['date'] = date
        global_hege_dict[asn]['heg'] = heg
    for asn in list(global_hege_dict):
        date = global_hege_dict[asn]['date']
        if today - date > 3600*24*10:
            del global_hege_dict[asn]
    os.remove(ifile)
    return global_hege_dict


def load_ihr_local(today, ifile):
    local_hege_dict = {}
    with open('./LocalData/IHR/local_hege_dict.p', "rb") as f:
        local_hege_dict = pickle.load(f)
    df = pd.read_csv(ifile)
    for timebin, originasn, asn in zip(df.iloc[:, 0].values, df.iloc[:, 1].values, df.iloc[:, 2].values):
        y, m, d = timebin.split(' ')[0].split('-')
        hh, mm, ss = timebin.split(' ')[1].split(':')
        ss = ss.split('+')[0]
        date = datetime.datetime(int(y), int(
            m), int(d), int(hh), int(mm), int(ss))
        date = int(calculate_unix_time(date))
        if originasn not in local_hege_dict:
            local_hege_dict[originasn] = {
                'asns': set(),
                'date': 0
            }
        local_hege_dict[originasn]['asns'].add(asn)
        local_hege_dict[originasn]['date'] = date

    for asn in list(local_hege_dict):
        date = local_hege_dict[asn]['date']
        if today - date > 3600*24*10:
            del local_hege_dict[asn]
    os.remove(ifile)
    return local_hege_dict


def update_IHR_global(y, m, d):
    # https://ihr-archive.iijlab.net/ihr/hegemony/ipv4/global/2022/08/04/ihr_hegemony_ipv4_global_2022-08-04.csv.lz4
    download_path = "https://ihr-archive.iijlab.net/ihr/hegemony/ipv4/global/%s/%s/%s/ihr_hegemony_ipv4_global_%s-%s-%s.csv.lz4" % (
        y, m, d, y, m, d)
    # lz4 -dc ihr_hegemony_ipv4_global_2022-08-04.csv.lz4 > ihr_hegemony_global.csv
    save_path = "./LocalData/IHR/ihr_hegemony_global.csv.lz4"
    output = "./LocalData/IHR/ihr_hegemony_global.csv"
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)
    cmd = """ lz4 -dc %s > %s """ % (save_path, output)
    out = os.system(cmd)
    os.remove(save_path)
    today = datetime.datetime(int(y), int(m), int(d),
                              int(00), int(00), int(00))
    today = int(calculate_unix_time(today))
    global_hege_dict = load_ihr_global(today, output)
    with open("./LocalData/IHR/global_hege_dict.p", "wb") as fp:
        pickle.dump(dict(global_hege_dict), fp)


def update_IHR_local(y, m, d):
    # https://ihr-archive.iijlab.net/ihr/hegemony/ipv4/local/2022/08/04/ihr_hegemony_ipv4_local_2022-08-04.csv.lz4
    download_path = "https://ihr-archive.iijlab.net/ihr/hegemony/ipv4/local/%s/%s/%s/ihr_hegemony_ipv4_local_%s-%s-%s.csv.lz4" % (
        y, m, d, y, m, d)
    # lz4 -dc ihr_hegemony_ipv4_global_2022-08-04.csv.lz4 > ihr_hegemony_global.csv
    save_path = "./LocalData/IHR/ihr_hegemony_local.csv.lz4"
    output = "./LocalData/IHR/ihr_hegemony_local.csv"
    response = requests.get(download_path)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)
    cmd = """ lz4 --rm -dc %s > %s """ % (save_path, output)
    out = os.system(cmd)
    today = datetime.datetime(int(y), int(m), int(d),
                              int(00), int(00), int(00))
    today = int(calculate_unix_time(today))
    local_hege_dict = load_ihr_local(today, output)
    with open("./LocalData/IHR/local_hege_dict.p", "wb") as fp:
        pickle.dump(dict(local_hege_dict), fp)


def process(y, m, d):

    download_path = "http://archive.routeviews.org/route-views.amsix/bgpdata/%s.%s/RIBS/rib.%s%s%s.1200.bz2" % (
        y, m, y, m, d)
    basicpath = "../bgpdata"
    dirpath = os.path.join(basicpath, y+'.'+m+'.'+d)
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)
    else:
        return
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


def download_bgpdata():
    for m in [10, 11]:
        if m == 10:
            for d in range(15, 32):
                y, m, d = str(2022), str(m), str(d)
                process(y, m, d)
        elif m == 11:
            for d in range(1, 16):
                if int(d/10) == 0:
                    d = '0'+str(d)
                y, m, d = str(2022), str(m), str(d)
                process(y, m, d)
    


# range,continent_code,continent,country_code,country,city,region,region_code,latitude,longitude,location_accuracy_radius


def update_at_specific_times(y, m, d):
    update_roas(y, m, d)
    update_IHR_global(y, m, d)

    basic_path = './LocalData'
    roa_path = basic_path + '/ROAs/all.roas.csv'
    roa_px_dict = new_load_ROAs(roa_path)
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
    global_hege_dict = {}
    with open(basic_path + '/IHR/global_hege_dict.p', "rb") as f:
        global_hege_dict = pickle.load(f)
    return roa_px_dict, roa_as2prefixes_dict, as2prefixes_dict, global_hege_dict


def main():
    dt = datetime.datetime.now(timezone.utc)
    utc_time = dt.replace(tzinfo=timezone.utc)
    t = str(datetime.datetime.fromtimestamp(
        utc_time.timestamp(), timezone.utc))
    date = t.split(' ')[0]
    y, m, d = date.split('-')
    y, m, d = '2022', '12', '31'
    #update_roas(y, m, d)
    utc_timestamp = utc_time.timestamp() - 3600 * 24
    t = str(datetime.datetime.fromtimestamp(utc_timestamp, timezone.utc))
    date = t.split(' ')[0]
    y, m, d = date.split('-')
    m = '12'
    d = '01'
    #update_CAIDA(y, m, d)
    #update_GeoIP(y, m, d)
    utc_timestamp = utc_time.timestamp() - 3600 * 24 * 2
    t = str(datetime.datetime.fromtimestamp(utc_timestamp, timezone.utc))
    date = t.split(' ')[0]
    y, m, d = date.split('-')
    y = '2021'
    m = '06'
    d = '03'
    update_IHR_global(y, m, d)
    #update_IHR_local(y, m, d)
    m = '12'
    d = '09'
    #update_P2A(y, m, d)
    #download_bgpdata()
    #download_russia_blocked_domain_list()


if __name__ == "__main__":
    main()
