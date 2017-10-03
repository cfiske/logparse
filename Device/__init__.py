import re

class Device(object):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Generic'
        self.logPatterns = {}

    def getName(self):
        return self.name

    def getVendor(self):
        return self.vendor

    def matchLogPattern(self, message):
        for p in self.logPatterns:
            matched = p.match(message['text'])

            if matched:
                pattern = self.logPatterns[p]
                if pattern['state'] == 0:
                    # Return instantly on ignored messages
                    #print "discarding - matched pattern id %s with text: %s" % (pattern['id'], message['text'])
                    message['state'] = 0
                    return 1

                #print "matched pattern id %s with text: %s" % (pattern['id'], message['text'])
                for k in pattern:
                    message[k] = pattern[k]

                # Matched, so stop
                return 1

        #print "warning: no pattern matched for text: %s" % (message['text'])

        return 0

    def getLogPatterns(self):
        return self.logPatterns

    # Log patterns for parser matching
    # - msg_id = Unique-per-class message identifier tag
    # - msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
    #               'ignore' means the message will be discarded unprocessed
    # - msg_ttl = For stateless messages, indicates message is only valid
    #             for msg_ttl seconds
    # - msg_keys = List of message tokens which make up the instance key
    #
    # If 'pattern' is a list, multiple patterns can be matched with the same
    # criteria (if 2 different messages are equivalent in meaning)
    #
    # The unique message key will be comprised of:
    # [(vendor + msg_id), msg_state, msg_keys]
    def addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):

        # Compiled patterns list
        cpatterns = []

        if isinstance(pattern, list) and len(pattern) > 0:
            for p in pattern:
                cpatterns.append(re.compile(p))
        elif isinstance(pattern, str) and len(pattern) > 0:
            cpatterns.append(re.compile(pattern))
        else:
            print "error: pattern must not be empty or blank. skipping"
            return 0

        if isinstance(msg_id, (str, int)):
            msg_id = self.vendor + '-' + str(msg_id)
        else:
            print "error: msg_id must be type str or int. skipping: %s" % (pattern)
            return 0

        if not isinstance(msg_state, int):
            print "warning: msg_state must be type int. defaulting to stateless: %s" % (pattern)
            msg_state = 3

        if not isinstance(msg_ttl, int):
            print "warning: msg_ttl must be type int. defaulting to 0: %s" % (pattern)
            msg_ttl = 0

        if not isinstance(msg_keys, list):
            print "warning: msg_keys must be type list. defaulting to empty: %s" % (pattern)
            msg_keys = []

        pattern_dict = {}
        pattern_dict['id'] = msg_id
        pattern_dict['state'] = msg_state
        pattern_dict['ttl'] = msg_ttl
        pattern_dict['keys'] = msg_keys

        for cp in cpatterns:
            if cp in self.logPatterns:
                print "warning: duplicate pattern. skipping: (%s) %s" % (self.logPatterns[cp]['id'], pattern)
            else:
                self.logPatterns[cp] = pattern_dict

        return 1


class A10(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'A10'
        self.logPatterns = {}


class Arista(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Arista'
        self.logPatterns = {}


class Brocade(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Brocade'
        self.logPatterns = {}


class Cisco(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Cisco'
        self.logPatterns = {}


class F5(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'F5'
        self.logPatterns = {}


class Force10(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Force10'
        self.logPatterns = {}


class Linux(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Linux'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^stats-loader-production: \[[^\]+]\] ERROR -- : Error while calculating rate: ', 1, 0, 0, ['peer_ip'])


class Juniper(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Juniper'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^/kernel: (?P<msg_type>tcp_auth_ok): Packet from (?P<peer_ip>\d+\.\d+\.\d+\.\d+):\d{1,5} unexpectedly has MD5 digest', 1, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^/kernel: .*vks.*', 2, 0, 0, [])
        self.addLogPattern(r'^mgd\[\d{1,5}\]: UI_CHILD_START: .* \'(?P<process>.+\'', 3, 0, 600, ['process'])
        self.addLogPattern(r'^mgd\[\d{1,5}\]: UI_CHILD_STATUS: .* \'(?P<process>.+\', .*', 4, 0, 600, ['process'])


