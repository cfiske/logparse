#!/usr/bin/env python

import re, time, random, sys, getopt

from dateutil import parser
from datetime import datetime

import Device


def validDate(datestring):
    try:
        parser.parse(datestring)
        return True
    except ValueError:
        print "%s is not a valid datetime" % datestring
        return False

opts, args = getopt.getopt(sys.argv[1:], "av")

matches = {}
verbose = 0
addtag = 0
skipcount = 0
minute = datetime.now().strftime("%M")

for o, a in opts:
    if o == '-v':
        verbose = 1
    if o == '-a':
        addtag = 1

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

    messages = []

    juniper = Device.Juniper('logs')

    for line in f:
        line.rstrip()

        # This -may- be a dangerous assumption, but anything starting with
        # a space is typically a continuation of the previous line
        if line[0].isspace():
            if currentDict:
                currentDict["text"] += ' ' + line.lstrip()
                continue

        if addtag == 1:
            line = '<' + str(random.randint(0, 191)) + '>' + line

        rawline = line

        for pname in ['pri', 'date', 'host', 'text']:
            #print "checking %s" % pname
            for p in pats[pname]:
                matched = p.match(line)

                if matched:
                    # If we got a priority tag (which is the beginning
                    # of a new log message) and still have a populated
                    # object, dump it and reset the object
                    if pname == 'pri':
                        currentDict['severity'] = int(matched.group('pri')) & 7
                        currentDict['facility'] = int(matched.group('pri')) >> 3
                        if currentDict:
                            if verbose > 0:
                                print currentDict

                            messages.append(currentDict)
                            currentDict = {}

                    if pname == 'date':
                        if not validDate(matched.group('date').rstrip(':')):
                            currentDict['date'] = time.strftime("%b %d %H:%M:%S", time.gmtime())

                    currentDict[pname] = matched.group(pname)

                    line = line[matched.end('space'):]

                    # We matched this element so no need to keep looping on it
                    break

        if len(line) > 0:
            print "still some line left: %s" % line

        if currentDict == {}:
            print "matched nothing: %s" % line
        else:
            skip = 0
            if juniper.matchLogPattern(currentDict):
                if currentDict['state'] == 0:
                    skip = 1
                    skipcount += 1
#            else:
#                print "Did not match Juniper message: %s" % (currentDict['text'])

            if skip == 0:
                messages.append(currentDict)
                currentDict = {}

        if int(datetime.now().strftime("%M")) != minute:
            minute = int(datetime.now().strftime("%M"))
            print "%28s Messages parsed: %d  Skipped: %d" % (str(datetime.now()), len(messages), skipcount)


print "done"


for message in messages:
    if 'host' in matches and message['host'] in matches['host']:
        matches['host'][message['host']] += 1
    else:
        if 'host' not in matches:
            matches['host'] = {}

        matches['host'][message['host']] = 1

for h in matches['host'].keys():
    print "%s: %d" % (h, matches['host'][h])

print "Skipped: %d" % (skipcount)

