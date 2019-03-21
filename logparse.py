#!/bin/env python

import re, time, random, sys, getopt, json, copy, socket

from select import select
from dateutil import parser
from datetime import datetime

import Device


def makeDate(datestring):
    d = datetime.utcnow()

    try:
        d = parser.parse(datestring)
    except ValueError:
        if verbose > 0:
            print "makeDate: %s is not a valid datetime" % datestring

    return str(d.strftime("%Y-%m-%dT%H:%M:%S.%f"))

def resolveHostname(ip):
    try:
        (host, null, null) = socket.gethostbyaddr(ip)
    except socket.herror:
        host = ip
    return host

def generateDicts(sock):
    skip = 0
    skipcount = 0

    # Compile regex patterns for iteration on each component of the message
    pats = {}

    pristrings = [r'^<(?P<pri>\d{1,3})>(\d*:?)?']
    pats['pri'] = []
    for i in pristrings:
        pats['pri'].append(re.compile(i + r'(?P<space>\s?)\S+'))

    # Date/time
    datestrings = [r'(?P<date>[A-Za-z]+ [ \d]?\d \d\d:\d\d:\d\d( [A-Z]{3}:)?)',
                   r'(?P<date>\d{4} [A-Za-z]+ [ \d]?\d \d\d:\d\d:\d\d( [A-Z]{3}:)?)',
                   r'(?P<date>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)']
    pats['date'] = []
    for i in datestrings:
        pats['date'].append(re.compile(i + r'(?P<space>\s+)\S+'))

    # Host/IP
    hoststrings = [r'(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                   r'(?P<host>[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.[a-z]+[0-9]?))',
                   r'(?P<host>[a-z0-9_-]+)']
    pats['host'] = []
    for i in hoststrings:
        pats['host'].append(re.compile(i + r'(?P<space>\s+)\S+', re.IGNORECASE))

    # Rest of line
    pats['text'] = [re.compile(r'(?P<text>.*)(?P<space>\s*)$')]

    currentDict = {}

    a10 = Device.A10('logs')
    arista = Device.Arista('logs')
    brocade = Device.Brocade('logs')
    f5 = Device.F5('logs')
    force10 = Device.Force10('logs')
    juniper = Device.Juniper('logs')
    linux = Device.Linux('logs')

    while True:
        inready, outready, excready = select([sock], [], [])

        for s in inready:
            # We can safely init the dict here because multiline messages are
            # still contained within single datagrams
            currentDict = {}

            line, (src_ip, port) = s.recvfrom(8192)
            # Strip any leading junk
            if line[0] == '\0':
                line = line.lstrip('\r\n\0 ')

            for pname in ['pri', 'date', 'host', 'text']:
                for p in pats[pname]:
                    matched = p.match(line)

                    if matched:
                        if pname == 'pri':
                            currentDict['severity'] = str(int(matched.group('pri')) & 7)
                            currentDict['facility'] = str(int(matched.group('pri')) >> 3)

                        currentDict[pname] = matched.group(pname)

                        # Trim the line up to the ending space from the last match
                        line = line[matched.end('space'):]

                        # We matched this element so no need to keep looping on it
                        break

                # None of the patterns matched for this field
                if pname not in currentDict:
                    print "Did not match for %s: %s" % (pname, line)

            # Chop off any remaining crap
            line = line.rstrip()

            # Finished parsing but did not consume the whole line (should never happen)
            if len(line) > 0:
                print "still some line left: [%s]" % line

            # Did not match anything at all?
            if currentDict == {}:
                print "matched nothing: [%s]" % line
                continue

            elif currentDict['text'].find('last message repeated') == 0 or currentDict['text'].find('RT_FLOW') == 0:
                skip = 1
                break

            else:
                skip = 0
                vendor = None
                currentDict['fromhost'] = resolveHostname(src_ip)
                currentDict['fromhost-ip'] = src_ip
                if 'host' not in currentDict:
                    currentDict['host'] = currentDict['fromhost'].lower()
                else:
                    currentDict['host'] = currentDict['host'].lower()

                try:
                    if currentDict['host'].find('v-') == 0:
                        vendor = linux

                    elif currentDict['host'].find('bar') == 0 or currentDict['host'].find('bcr') == 0 or currentDict['host'].find('scr') == 0 or currentDict['host'].find('sff') == 0 or currentDict['host'].find('mfw') == 0 or currentDict['host'].find('re') == 0 or currentDict['host'].find('bmr') == 0  or currentDict['host'].find('fw') == 0:
                        vendor = juniper

                    elif currentDict['host'].find('ma') == 0 or currentDict['host'].find('trr') == 0 or currentDict['host'].find('spr') == 0 or currentDict['host'].find('ssr') == 0 or currentDict['host'].find('ser') == 0:
                        vendor = arista

                    elif currentDict['host'].find('slb') == 0 or currentDict['host'].find('mlb') == 0 or currentDict['host'].find('glb') == 0 or currentDict['host'].find('vpr') == 0:
                        vendor = a10

                    elif currentDict['host'].find('lb') == 0:
                        vendor = f5

                    elif currentDict['host'].find('r1') == 0 or currentDict['host'].find('r2') == 0 or currentDict['host'].find('sw') == 0:
                        vendor = brocade

                    elif currentDict['host'].find('10.1') == 0:
                        vendor = force10

                    if vendor:
                        if vendor.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match %s message for host %s: %s" % (vendor.vendor, currentDict['host'], currentDict['text'])

                    else:
                        print "Did not match host pattern for host: %s  message: %s" % (currentDict['host'], currentDict['text'])


                except KeyError:
                    print "Field not found:", currentDict

                    skip = 1
                    skipcount += 1

                if skip == 0:
                    yield(currentDict)


opts, args = getopt.getopt(sys.argv[1:], "jvr")

matches = {}
messages = []
verbose = 0
use_json = 0
rsyslog_json = 0
minute = datetime.utcnow().strftime("%M")

# define mandatory fields here
baseDict = {
    "host": 'UNKNOWN',
    "facility": 'UNKNOWN',
    "severity": 'debug',
    "key": 'UNKNOWN',
    "message": 'UNKNOWN'
}

severityMap = {
    "0": "emerg",
    "1": "alert",
    "2": "crit",
    "3": "err",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "debug"
}

facilityMap = {
    "0": "kernel",
    "1": "user",
    "2": "mail",
    "3": "system",
    "4": "auth",
    "5": "syslog",
    "6": "lpd",
    "7": "news",
    "8": "uucp",
    "9": "time",
    "10": "auth",
    "11": "ftp",
    "12": "ntp",
    "13": "logaudit",
    "14": "logalert",
    "15": "clock",
    "16": "local0",
    "17": "local1",
    "18": "local2",
    "19": "local3",
    "20": "local4",
    "21": "local5",
    "22": "local6",
    "23": "local7"
}

for o, a in opts:
    if o == '-v':
        verbose = 1
    if o == '-j':
        use_json = 1
    if o == '-r':
        rsyslog_json = 1

syslogTuple = ('', 514)
syslogSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
syslogSocket.bind(syslogTuple)

for msgDict in generateDicts(syslogSocket):
    #print "log: %s" % msgDict
    messages.append(msgDict)

    if use_json > 0:
        jsonDict = copy.deepcopy(baseDict)
        if 'date' not in msgDict:
            jsonDict['@timestamp'] = makeDate('now')
        else:
            jsonDict['@timestamp'] = makeDate(msgDict['date'].rstrip(':'))

        jsonDict['host'] = msgDict['host']
        jsonDict['message'] = msgDict['text']
        if 'severity' in msgDict:
            jsonDict['severity'] = severityMap[msgDict['severity']]
            jsonDict['facility'] = facilityMap[msgDict['facility']]

        if 'msg_type' in msgDict:
            jsonDict['msg_type'] = msgDict['msg_type']
        else:
            jsonDict['msg_type'] = msgDict['text'].partition(' ')[0].partition('[')[0]

        if 'id' in msgDict:
            jsonDict['instance'] = msgDict['id'] + '_' + jsonDict['host']
            if 'key_fields' in msgDict:
                for f in msgDict['key_fields']:
                    jsonDict['instance'] += '_' + msgDict[f]
            jsonDict['key'] = jsonDict['instance'] + '_state:' + str(msgDict['state'])
        else:
            jsonDict['key'] = jsonDict['host'] + '_' + msgDict['text']

        print json.dumps(jsonDict)

    if verbose > 0:
        print msgDict

    if int(datetime.utcnow().strftime("%M")) != minute:
        minute = int(datetime.now().strftime("%M"))
        if verbose > 0:
            print "%28s Messages parsed: %d" % (str(datetime.utcnow()), len(messages))


