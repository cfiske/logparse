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


def generateDicts(sock):
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
            line, src_ip = s.recvfrom(8192)

            # This -may- be a dangerous assumption, but anything starting with
            # a space is typically a continuation of the previous line
            if line[0].isspace():
                if currentDict:
                    currentDict["text"] += ' ' + line.lstrip()
                    continue

            # XXX - May or may not need this for direct rsyslog but some logfiles
            #       have occasional lines prefixed with a bunch of nulls
            if line[0] == '\0':
                # XXX - This is probably terrible code, but may be faster than regex?
                line = line[(line.find(' ') - 3):]

            for pname in ['pri', 'date', 'host', 'text']:
                for p in pats[pname]:
                    matched = p.match(line)

                    if matched:
                        # If we got a priority tag (which is the beginning
                        # of a new log message) and still have a populated
                        # object, dump it and reset the object
                        if pname == 'pri':
                            if currentDict:
                                yield(currentDict)
                                currentDict = {}

                            else:
                                currentDict['severity'] = int(matched.group('pri')) & 7
                                currentDict['facility'] = int(matched.group('pri')) >> 3

                        if pname == 'date':
                            currentDict['date'] = makeDate(matched.group('date').rstrip(':'))

                        if pname == 'host':
                            currentDict[pname] = matched.group(pname).lower()
                        else:
                            currentDict[pname] = matched.group(pname)

                        line = line[matched.end('space'):]

                        # We matched this element so no need to keep looping on it
                        break

                if pname not in currentDict:
                    print "Did not match for %s: %s" % (pname, line)

            # Chop off any remaining crap
            line = line.rstrip()

            if len(line) > 0:
                print "still some line left: [%s]" % line

            if currentDict == {}:
                print "matched nothing: [%s]" % line

            elif currentDict['text'].find('last message repeated') == 0:
                continue

            else:
                skip = 0

                try:
                    if currentDict['host'].find('v-') == 0:
                        if linux.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match Linux message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    elif currentDict['host'].find('bar') == 0 or currentDict['host'].find('bcr') == 0 or currentDict['host'].find('scr') == 0 or currentDict['host'].find('sff') == 0 or currentDict['host'].find('mfw') == 0 or currentDict['host'].find('re') == 0 or currentDict['host'].find('bmr') == 0  or currentDict['host'].find('fw') == 0:
                        if juniper.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match Juniper message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    elif currentDict['host'].find('ma') == 0 or currentDict['host'].find('trr') == 0 or currentDict['host'].find('spr') == 0 or currentDict['host'].find('ssr') == 0 or currentDict['host'].find('ser') == 0:
                        if arista.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match Arista message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    elif currentDict['host'].find('slb') == 0 or currentDict['host'].find('mlb') == 0 or currentDict['host'].find('glb') == 0 or currentDict['host'].find('vpr') == 0:
                        if a10.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match A10 message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    elif currentDict['host'].find('lb') == 0:
                        if f5.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match F5 message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    elif currentDict['host'].find('r1') == 0 or currentDict['host'].find('r2') == 0 or currentDict['host'].find('sw') == 0:
                        if brocade.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match Brocade message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    elif currentDict['host'].find('10.1') == 0:
                        if force10.matchLogPattern(currentDict):
                            if currentDict['state'] == 0:
                                skip = 1
                                skipcount += 1
                        else:
                            print "Did not match Force10 message for host %s: %s" % (currentDict['host'], currentDict['text'])

                    else:
                        print "Did not match host pattern for host: %s  message: %s" % (currentDict['host'], currentDict['text'])

                except KeyError:
                    print "Field not found:", currentDict

                    skip = 1
                    skipcount += 1

                if skip == 0:
                    yield(currentDict)
                    currentDict = {}


opts, args = getopt.getopt(sys.argv[1:], "jv")

matches = {}
messages = []
verbose = 0
use_json = 0
minute = datetime.utcnow().strftime("%M")

# define mandatory fields here
baseDict = {
    "host": 'UNKNOWN',
    "facility": 'UNKNOWN',
    "severity": 'debug',
    "msg_type": 'UNKNOWN',
    "message": 'UNKNOWN'
}


for o, a in opts:
    if o == '-v':
        verbose = 1
    if o == '-j':
        use_json = 1

syslogTuple = ('', 514)
syslogSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
syslogSocket.bind(syslogTuple)

for msgDict in generateDicts(syslogSocket):
    if msgDict['text'].find('RT_FLOW') != -1:
        continue

    #print "log: %s" % msgDict
    messages.append(msgDict)

    if use_json > 0:
        jsonDict = copy.deepcopy(baseDict)
        if 'date' not in currentDict:
            jsonDict['@timestamp'] = makeDate('now')
        else:
            jsonDict['@timestamp'] = currentDict['date']

        jsonDict['host'] = currentDict['host'].lower()
        jsonDict['message'] = currentDict['text']
        jsonDict['msg_type'] = currentDict['id']

        # mmjsonparse in rsyslog won't parse JSON correctly without
        # the '@cee:@cee:' prefix
        print "@cee:@cee:" + json.dumps(jsonDict)
    else:
        if verbose > 0:
            print currentDict

    if int(datetime.utcnow().strftime("%M")) != minute:
        minute = int(datetime.now().strftime("%M"))
        if verbose > 0:
            print "%28s Messages parsed: %d" % (str(datetime.utcnow()), len(messages))


