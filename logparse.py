#!/usr/bin/env python

import re, time, random, sys, getopt, json, copy

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

opts, args = getopt.getopt(sys.argv[1:], "ajv")

matches = {}
verbose = 0
use_json = 0
addtag = 0
skipcount = 0
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
    if o == '-a':
        addtag = 1
    if o == '-j':
        use_json = 1

with open("/dev/stdin") as f:

    # Compile regex patterns for iteration on each component of the message
    pats = {}

    pats['pri'] = [re.compile(r'^<(?P<pri>\d{1,3})>(?P<space>\s?)\w+')]

    # Date/time
    datestrings = [r'\w+ [ \d]?\d \d\d:\d\d:\d\d [A-Z]{3}:', r'\w+ [ \d]?\d \d\d:\d\d:\d\d']
    pats['date'] = []
    for i in datestrings:
        pats['date'].append(re.compile(r'(?P<date>' + i + r')(?P<space>\s+)\S+'))

    # Host/IP
    hoststrings = [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.[a-z]+[0-9]?)', r'[a-z0-9_-]+']
    pats['host'] = []
    for i in hoststrings:
        pats['host'].append(re.compile(r'(?P<host>' + i + r')(?P<space>\s+)\S+'))

    # Rest of line
    pats['text'] = [re.compile(r'(?P<text>\S.*)(?P<space>\s*)$')]

    currentDict = {}
    jsonDict = copy.deepcopy(baseDict)

    messages = []

    juniper = Device.Juniper('logs')
    linux = Device.Linux('logs')

    for line in f:
        line.rstrip()

        # This -may- be a dangerous assumption, but anything starting with
        # a space is typically a continuation of the previous line
        if line[0].isspace():
            if currentDict:
                currentDict["text"] += ' ' + line.lstrip()
                continue

        if addtag == 1:
            line = '<' + str(random.randint(9, 191)) + '>' + line

        rawline = line

        for pname in ['pri', 'date', 'host', 'text']:
            for p in pats[pname]:
                matched = p.match(line)

                if matched:
                    # If we got a priority tag (which is the beginning
                    # of a new log message) and still have a populated
                    # object, dump it and reset the object
                    if pname == 'pri':
                        if currentDict:
                            if verbose > 0:
                                print currentDict

                            messages.append(currentDict)
                            currentDict = {}

                        else:
                            currentDict['severity'] = int(matched.group('pri')) & 7
                            currentDict['facility'] = int(matched.group('pri')) >> 3

                    if pname == 'date':
                        currentDict['date'] = makeDate(matched.group('date').rstrip(':'))

                    currentDict[pname] = matched.group(pname)

                    line = line[matched.end('space'):]

                    # We matched this element so no need to keep looping on it
                    break

        if len(line) > 0:
            print "still some line left: %s" % line

        if currentDict == {}:
            print "matched nothing: %s" % line

        elif currentDict['text'].find('last message repeated') == 0:
            continue

        else:
            skip = 0

            if currentDict['host'].find('v-') == 0:
                if linux.matchLogPattern(currentDict):
                    if currentDict['state'] == 0:
                        skip = 1
                        skipcount += 1
            elif juniper.matchLogPattern(currentDict):
                if currentDict['state'] == 0:
                    skip = 1
                    skipcount += 1
            else:
                if verbose > 0:
                    print "Did not match Juniper message: %s" % (currentDict['text'])

            if skip == 0:
                if use_json > 0:
                    if 'date' not in currentDict:
                        jsonDict['@timestamp'] = makeDate('now')
                    else:
                        jsonDict['@timestamp'] = currentDict['date']

                    jsonDict['host'] = currentDict['host']
                    jsonDict['message'] = currentDict['text']
                    jsonDict['msg_type'] = currentDict['id']

                    # mmjsonparse in rsyslog won't parse JSON correctly without
                    # the '@cee:@cee:' prefix
                    print "@cee:@cee:" + json.dumps(jsonDict)
                else:
                    if verbose > 0:
                        print currentDict

                currentDict = {}

        if int(datetime.utcnow().strftime("%M")) != minute:
            minute = int(datetime.now().strftime("%M"))
            if verbose > 0:
                print "%28s Messages parsed: %d  Skipped: %d" % (str(datetime.utcnow()), len(messages), skipcount)


if verbose > 0:
    print "done"


for message in messages:
    if 'host' in matches and message['host'] in matches['host']:
        matches['host'][message['host']] += 1
    else:
        if 'host' not in matches:
            matches['host'] = {}

        matches['host'][message['host']] = 1

if verbose > 0:
    for h in matches['host'].keys():
        print "%s: %d" % (h, matches['host'][h])

    print "Skipped: %d" % (skipcount)

