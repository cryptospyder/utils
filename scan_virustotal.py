#!/usr/bin/env python

import json
import time
from datetime import datetime, timedelta
import urllib
import urllib2
import re
import sys
import cPickle as pickle
import os.path
import shutil
import csv


###########################################################################
# CONSTANTS
###########################################################################

API_KEYS = ["apikey_goes_here"]

DUMP_FILE = "vt_cache.dump"

# Number of days a result on VT is considered 'fresh', if the report is older than DAYS_VALID, we will submit to have it scanned
DAYS_VALID = 30

# Debug Mode
DEBUG = False

# Print out results with positive hits greater than this threshold
BADDNESS_THRESHOLD = 5

RATE = 4 # Max number of requests per minute (4 for public API, 3000 for private)
DELAY = 60/RATE # Make sure we run less than RATE per minute
GROUP_SIZE = 250
SCAN_GROUP_SIZE = GROUP_SIZE/10
TRY_AGAIN_TIMEOUT = 60
MAX_TRIES = 1
TOTAL_MAX = 20

###########################################################################
# URLS
###########################################################################
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2/"
VIRUSTOTAL_URL_REPORT_URL = VIRUSTOTAL_BASE_URL + "url/report"
VIRUSTOTAL_URL_SCAN_URL = VIRUSTOTAL_BASE_URL + "url/scan"
VIRUSTOTAL_IP_REPORT_URL = VIRUSTOTAL_BASE_URL + "ip-address/report"
VIRUSTOTAL_HASH_SCAN_URL = VIRUSTOTAL_BASE_URL + "file/report"
BLOCKED_MSG = "VirusTotal doesn't seem to be responding. We might have gotten blocked... :("

###########################################################################
# GLOBALS
###########################################################################
tries = 0
total_tries = 0 # never reset this
queries = 0
resources = 0
api_index = 8



###########################################################################
# UTILITY FUNCTIONS
###########################################################################

def removeNonAscii(s):
  if not isinstance(s, unicode):
    return s
  return "".join([i if ord(i)<128 else "!~!" for i in s])

def getIPs(line):
  return re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line, re.IGNORECASE)

def getDomains(line):
  return re.findall(r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?)', line, re.IGNORECASE)

def getHashes(line):
    return re.findall("[A-F0-9]{32}|[A-F0-9]{40}|[A-F0-9]{64}", line, re.IGNORECASE) # get the first MD5 or SHA1 hash (hex coded string)


def extractFromFile(f):
  data = f.read()
  return extractFromList(re.split("\r|\n", data))

def extractFromList(l):
  domains = []
  ips = []
  hashes = []
  for line in l:
      line = removeNonAscii(line)
      domains.extend(getDomains(line))
      ips.extend(getIPs(line))
      hashes.extend(getHashes(line))

  return domains, ips, hashes


def extractAll():
  domains = set()
  ips = set()
  hashes = set()
  total = 0

  if len(sys.argv) < 2:
    print "You must give at least one file name to scan after scan.py"
    sys.exit(1)

  files = sys.argv[1:]
  print "Extracting IOCs from {0} files".format(len(files))

  for filename in files: # Get all the files passed in
    with open(filename) as input_file:
      found_domains, found_ips, found_hashes = extractFromFile(input_file)

    if len(found_domains) == 0 and len(found_ips) == 0 and len(found_hashes) == 0:
      print "ERROR: No IOCs found to scan for file: '{0}'.".format(filename)
      continue
    else:
      total += len(found_domains)
      total += len(found_ips)
      total += len(found_hashes)
      domains.update(found_domains)
      ips.update(found_ips)
      hashes.update(found_hashes)

  if DEBUG:
    print domains
    print ips
    print hashes
  unique = sum([len(domains), len(ips), len(hashes)])
  if unique < total:
      print "Compressed {0} total IOCs to {1}.".format(total, unique)
  return sorted(domains), sorted(ips), sorted(hashes)



###########################################################################
# VT QUERY FUNCTIONS
###########################################################################

def get_api_key():
    return API_KEYS[api_index % len(API_KEYS)]

def query_vt(url, to_scan=[], sep=",", options={}):
    global queries
    global resources
    global tries
    if total_tries > TOTAL_MAX:
        return dict([(scanned, None) for scanned in to_scan])
      
    
    queries += 1
    resources += len(to_scan)

    scores = {}
    try:
        parameters = {"apikey": get_api_key()}
        parameters["resource"] = sep.join(to_scan)
        parameters.update(options)
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json_res = response.read()

        if json_res:
            result_list = json.loads(json_res)
            # We just get 1 result, surround with []
            if isinstance(result_list, dict):
                result_list = [result_list]

            if DEBUG:
                print result_list

            for result in result_list:
                scanned = result.get("resource", None)
                if scanned:
                    scores[scanned] = result.get("positives", None)
        else:
            print "VT is not responding to us! :("
            time.sleep(TRY_AGAIN_TIMEOUT)
            global tries
            global total_tries
            tries += 1
            total_tries += 1
            if tries > MAX_TRIES:
                tries = 0
                global api_index
                api_index += 1
    except Exception, err:
        print "Error:", err
    return dict([(scanned, scores.get(scanned, None)) for scanned in to_scan])


def query_vt_file_hashes(file_hashes):
    return query_vt(VIRUSTOTAL_HASH_SCAN_URL, file_hashes)

def query_vt_urls(urls):
    return query_vt(VIRUSTOTAL_URL_REPORT_URL, urls, "\n", {"scan": "1"})

###########################################################################
# SCORE LOGIC
###########################################################################

def get_scores(to_score, f, cache={}):
    scores = {}
    to_scan = []
    for key in to_score:
        if key in cache:
            scores[key] = cache[key]
        else:
            to_scan.append(key)

    if len(to_scan) > GROUP_SIZE:
        print "Scanning the first {0} IOCs...".format(GROUP_SIZE)
    else:
        print "Scanning {0} IOCs...".format(len(to_scan))


    for i in xrange(0, len(to_scan), GROUP_SIZE):
        to_query = to_scan[i:min(i+GROUP_SIZE, len(to_scan))]
        results = f(to_query)
        scores.update(results)
        for scanned,score in results.iteritems():
            if score != None:
                cache[scanned] = score

        num_todo = min(GROUP_SIZE, max(0, len(to_scan)-(i+GROUP_SIZE)))
        if num_todo > 0 and total_tries < TOTAL_MAX:
            time.sleep(DELAY)
            print "Scaning the next {0} IOCs...".format(num_todo)

    return scores


def scan_domains(domains, cache={}):
    return get_scores(domains, query_vt_urls, cache)

def scan_ips(ips, cache={}):
    # TODO add IP specific logic
    return {}

def scan_hashes(hashes, cache={}):
    return get_scores(hashes, query_vt_file_hashes, cache)








###########################################################################
# MAIN
###########################################################################

if __name__ == "__main__":
    # save the start time
    run_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

    domains, ips, hashes = extractAll()

    if os.path.isfile(DUMP_FILE):
        shutil.copyfile(DUMP_FILE, DUMP_FILE + ".bak")
        cache = pickle.load(open(DUMP_FILE, 'rb'))
    else:
        cache = {}

    try:
        scored_domains = scan_domains(domains + ips, cache)
    except:
        print "Failed to get VT scores for domains"
        scored_domains = {}

    try:
        scored_ips = scan_ips(ips, cache)
    except:
        print "Failed to get VT scores for IPs"
        scored_ips = {}
    try:
        scored_hashes = scan_hashes(hashes, cache)
    except:
        print "Failed to get VT scores for hashes"
        scored_hashes = {}

    # TODO output the scored results
    filename = "VT_results_{0}.csv".format(run_time)
    print "Saving scores to {0}".format(filename)

    output = scored_domains.items() + scored_ips.items() + scored_hashes.items()
    
    with open(filename, "wb") as f:
        f.write("Scanned,Score\n")
        for scanned, score in output:
            f.write("{0},{1}\n".format(scanned, score))


    print "Made a total of {0} queries to VT for {1} resources.".format(queries, resources)

    if DEBUG:
        print "SCORES:"
        print output
        print "CACHE:"
        print cache

    pickle.dump(cache, open(DUMP_FILE, 'wb'))
    print "VT Responses cached"
