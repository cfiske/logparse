#!/usr/bin/env python

import re, time, random, sys, getopt
from dateutil import parser
from datetime import datetime


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
bigcount = 0
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

    for line in f:
        bigcount += 1
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

        skip = 0
        for pname in ['pri', 'date', 'host', 'text']:
            gotmatch = 0
            #print "checking %s" % pname
            for p in pats[pname]:
                if gotmatch > 0:
                    continue
                matched = p.match(line)
                if matched:
                    gotmatch = 1

                    # If we got a priority tag (which is the beginning
                    # of a new log message) and still have a populated
                    # object, dump it and reset the object
                    if pname == 'pri' and currentDict:
                        if verbose > 0:
                            print currentDict

                        currentDict = {}

                    if pname == 'date':
                        if not validDate(matched.group('date').rstrip(':')):
                            currentDict['date'] = time.strftime("%b %d %H:%M:%S", time.gmtime())

                    if pname == 'host':
                        if 'host' in matches and matched.group(pname) in matches['host']:
                            matches['host'][matched.group(pname)] += 1
                        else:
                            if 'host' not in matches:
                                matches['host'] = {}

                            print "new host: %s" % matched.group(pname)
                            matches['host'][matched.group(pname)] = 1

                        if matched.group(pname).startswith('v-webapp'):
                            #print "skipping %s" % matched.group('host')
                            skip = 1
                            currentDict = {}
                            break

                    if pname == 'pri':
                        currentDict['severity'] = int(matched.group('pri')) & 7
                        currentDict['facility'] = int(matched.group('pri')) >> 3

                    currentDict[pname] = matched.group(pname)

                    line = line[matched.end('space'):]

                    #currentDict = {"tag": matched.group('pri'), "date": matched.group('date'), "host": matched.group('host'), "text": matched.group('text'), "severity": logsev, "facility": logfac}
                #else:
                #    print "did not match %s: %s" % (pname, line)
            else:
                continue
            break

        if skip == 0:
            if len(line) > 0:
                print "still some line left: %s" % line

            if currentDict == {}:
                print "matched nothing: %s" % line
                if currentDict:
                    print currentDict
                    currentDict = {}

        if int(datetime.now().strftime("%M")) != minute:
            minute = int(datetime.now().strftime("%M"))
            print "%28s Message count: %d" % (str(datetime.now()), bigcount)


print "done"

for h in matches['host'].keys():
    print "%s: %d" % (h, matches['host'][h])

