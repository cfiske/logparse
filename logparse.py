#!/bin/env python

import re, time, random, sys, getopt, json, copy, socket

from select import select
from dateutil import parser
from datetime import datetime
from eprint import eprint

import Device


def makeDate(datestring):
    d = datetime.utcnow()

    try:
        d = parser.parse(datestring)
    except ValueError:
        if verbose > 0:
            eprint("makeDate: %s is not a valid datetime" % datestring)

    return str(d.strftime("%Y-%m-%dT%H:%M:%S.%f"))

def resolveHostname(ip):
    try:
        (host, null, null) = socket.gethostbyaddr(ip)
    except socket.herror:
        host = ip
    return host

def generateDicts(sock):
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

    skip = 0
    skipcount = 0
    sminute = datetime.utcnow().strftime("%M")
    readcount = 0
    yieldcount = 0

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
    pats['message'] = [re.compile(r'(?P<message>.*)(?P<space>\s*)$')]

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
            readcount += 1

            # We can safely init the dict here because multiline messages are
            # still contained within single datagrams
            currentDict = {}

            line, (src_ip, port) = s.recvfrom(8192)

            # Pristine copy of what we received
            currentDict['raw_message'] = line

            # Strip any leading junk
            if line[0] == '\0':
                line = line.lstrip('\r\n\0 ')

            for pname in ['pri', 'date', 'host', 'message']:
                for p in pats[pname]:
                    matched = p.match(line)

                    if matched:
                        if pname == 'pri':
                            currentDict['severity_int'] = str(int(matched.group('pri')) & 7)
                            currentDict['facility_int'] = str(int(matched.group('pri')) >> 3 & 23)
                            currentDict['severity_label'] = severityMap[currentDict['severity_int']]
                            currentDict['facility_label'] = facilityMap[currentDict['facility_int']]

                        currentDict[pname] = matched.group(pname)

                        # Trim the line up to the ending space from the last match
                        line = line[matched.end('space'):]

                        # We matched this element so no need to keep looping on it
                        break

                # None of the patterns matched for this field
                if pname not in currentDict:
                    eprint("Did not match for %s: %s" % (pname, line))

            # Chop off any remaining crap
            line = line.rstrip()

            # Finished parsing but did not consume the whole line (should never happen)
            if len(line) > 0:
                eprint("still some line left: [%s]" % line)

            # Did not match anything at all?
            if currentDict == {}:
                eprint("matched nothing: [%s]" % line)
                continue

            elif currentDict['message'].find('last message repeated') == 0:
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
                    if currentDict['host'].find('v-') >= 0 and currentDict['host'].find('-net') >= 7:
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
                        currentDict['vendor'] = vendor.vendor
                        if not vendor.matchLogPattern(currentDict):
                            eprint("Did not match %s message for host %s: %s" % (vendor.vendor, currentDict['host'], currentDict['message']))
                            # Flag as unmatched message
                            currentDict['state'] = 5

                    else:
                        eprint("Did not match host pattern for host: %s  message: %s" % (currentDict['host'], currentDict['message']))


                except KeyError:
                    eprint("Field not found:", currentDict)

                    skip = 1
                    skipcount += 1

                if skip == 0:
                    yield(currentDict)
                    yieldcount += 1

                if int(datetime.utcnow().strftime("%M")) != sminute:
                    sminute = int(datetime.now().strftime("%M"))
                    eprint("%28s Messages read: %d yielded: %d skipped: %d" % (str(datetime.utcnow()), readcount, yieldcount, skipcount))

opts, args = getopt.getopt(sys.argv[1:], "l:t:p:v")

matches = {}
messages = []
verbose = 0
listen_port = 514
target_host = 'localhost'
target_port = 5150
minute = datetime.utcnow().strftime("%M")

for o, a in opts:
    if o == '-v':
        verbose = 1
    if o == '-t':
        target_host = a
    if o == '-p':
        target_port = int(a)
    if o == '-l':
        listen_port = int(a)

listenTuple = ('', listen_port)
listenSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listenSocket.bind(listenTuple)

sendTuple = (target_host, target_port)
sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sendSocket.connect(sendTuple)

eprint("Listening on port %d" % (listen_port))
eprint("Sending to %s port %d" % (target_host, target_port))

for msgDict in generateDicts(listenSocket):
    if 'date' not in msgDict:
        msgDict['date'] = makeDate('now')
    else:
        msgDict['date'] = makeDate(msgDict['date'].rstrip(':'))

    if 'msg_type' not in msgDict:
        msgDict['msg_type'] = msgDict['message'].partition(' ')[0].partition('[')[0]

    if 'id' in msgDict:
        msgDict['instance'] = msgDict['id'] + '_' + msgDict['host']
        if 'key_fields' in msgDict:
            for f in msgDict['key_fields']:
                msgDict['instance'] += '_' + msgDict[f]
            msgDict.pop('key_fields', None)
        msgDict['key'] = msgDict['instance'] + '_state:' + str(msgDict['state'])
    else:
        msgDict['key'] = msgDict['host'] + '_' + msgDict['message']

    try:
        sendSocket.send(json.dumps(msgDict) + '\n')
    except socket.error:
        time.sleep(1)
        sendSocket.connect(sendTuple)
        sendSocket.send(json.dumps(msgDict) + '\n')

    if verbose > 0:
        eprint(msgDict)

    if int(datetime.utcnow().strftime("%M")) != minute:
        minute = int(datetime.now().strftime("%M"))
        if verbose > 0:
            eprint("%28s Messages parsed: %d" % (str(datetime.utcnow()), len(messages)))


