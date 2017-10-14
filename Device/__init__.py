import re

class Device(object):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
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

                if self.verbose is True:
                    print "matched pattern id %s with text: %s" % (pattern['id'], message['text'])

                for k in pattern:
                    message[k] = pattern[k]

                # Matched, so stop
                return 1

        print "warning: no pattern matched for host [%s] text: %s" % (message['host'], message['text'])

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

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'A10'
        self.logPatterns = {}


class Arista(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Arista'
        self.logPatterns = {}


class Brocade(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Brocade'
        self.logPatterns = {}


class Cisco(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Cisco'
        self.logPatterns = {}


class F5(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'F5'
        self.logPatterns = {}


class Force10(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Force10'
        self.logPatterns = {}


class Linux(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Linux'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^stats-loader-production: E, \[.+\] ERROR -- : Error while calculating rate: ', 1000, 0, 0, [])


class Juniper(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Juniper'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^/kernel: (?P<msg_type>tcp_auth_ok): Packet from (?P<peer_ip>(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)):\d{1,5} (unexpectedly has|missing) MD5 digest', 1000, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>jsr_jsm_update_hold_timeo): bucket created for bgp timeout', 1001, 3, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ex92xx_fib_cnt) \d+', 1002, 3, 600, [])
        self.addLogPattern(r'^/kernel: hw.chassis.startup_time update to \d+', 1003, 0, 600, [])
        self.addLogPattern(r'^/kernel: .*vks.*', 1004, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_ARP_ADDR_CHANGE): arp info overwritten for (?P<instance>\S+) from ', 1005, 0, 600, ['instance'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>MTU) for (?P<instance>\S+) (reduced|increased) ', 1006, 0, 600, ['instance'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>iff_handle_ifa_delete): deletion of address on ', 1007, 0, 600, ['instance'])
        self.addLogPattern(r'^/kernel: : port status changed', 1008, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_LACP_INTF_STATE_CHANGE): lacp_update_state_userspace: cifd (?P<port>\S+) - (?P<state>(CD|DETACHED|ATTACHED)) state - .+', 1009, 3, 0, ['port','state'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ae_bundlestate_ifd_change): bundle (?P<port>\S+): bundle IFD minimum bandwidth or minimum links not met, .+', 1010, 3, 0, ['port'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ae_linkstate_ifd_change): MDOWN received for interface (?P<port>\S+), member of (?P<instance>\S+)', 1011, 2, 0, ['port','instance'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ae_linkstate_ifd_change): MUP received for interface (?P<port>\S+), member of (?P<instance>\S+)', 1012, 1, 0, ['port','instance'])
        self.addLogPattern(r'^/kernel: Percentage memory available\(\d+\)less than threshold\(\d+\s?%\)', 1013, 3, 0, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>jsr_prl_recv_ack_msg)\(\): received PRL ACK message on non-active socket', 1014, 3, 600, [])
        self.addLogPattern(r'^/kernel:  Filter idx: \d+ ifl index \d+ Interface  ?(?P<port>\S+)', 1015, 3, 600, ['port'])
        self.addLogPattern(r'^/kernel:  Packet in FW : [0-9a-f]+', 1016, 3, 600, ['port'])

        self.addLogPattern(r'^master failed to clean up hw entry', 1100, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: waiting for lock, Process', 1101, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: lock acquired by ', 1102, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: Failed to get mapping from kernel blob ', 1103, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: dfwlib_pm_sem_release: PID<\d+> released the lock', 1104, 0, 600, [])

        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_START): .* \'(?P<process>.+)\'', 3000, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_STATUS): .* \'(?P<process>.+)\', .*', 3001, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CMDLINE_READ_LINE): User \'(?P<user>.+)\', command \'(?P<command>[^\']+)', 3002, 3, 600, ['user','command'])
        self.addLogPattern(r'^sshd: (?P<msg_type>SSHD_LOGIN_FAILED): Login failed for user \'(?P<user>\S+)\' from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: error: PAM: authentication error for (?P<user>\S+) from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Failed password for (?P<user>\S+) from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_AUTH_EVENT): Authenticated user \'(?P<user>\S+)\' at ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Accepted \S+ for (?P<user>\S+) from ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOGIN_EVENT): User \'(?P<user>[^\']+)\' login, class ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOGOUT_EVENT): User \'(?P<user>[^\']+)\' logout', 3006, 1, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_JUNOSCRIPT_CMD): User \'(?P<user>[^\']+)\' used JUNOScript client to run command \'(?P<command>[^\']+)', 3006, 3, 600, ['user','command'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_NETCONF_CMD): User \'(?P<user>[^\']+)\' used NETCONF client to run command \'(?P<command>[^\']+)', 3007, 3, 600, ['user','command'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_DBASE_LOGIN_EVENT): User \'(?P<user>[^\']+)\' entering configuration mode', 3008, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_DBASE_LOGOUT_EVENT): User \'(?P<user>[^\']+)\' exiting configuration mode', 3009, 1, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT): User \'(?P<user>[^\']+)\' requested \'commit\' operation', 3010, 2, 0, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT_PROGRESS): Commit operation in progress: ', 3011, 3, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT_COMPLETED): commit complete', 3012, 1, 0, [])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_STATUS): Cleanup child \'(?P<process>[^\']+)\', PID \d+', 3013, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>UI_CLI_IDLE_TIMEOUT): Idle timeout for user \'(?P<user>[^\']+)\' exceeded and session terminated', 3014, 0, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CFG_AUDIT_OTHER): User \'(?P<user>[^\']+)\' (activate|deactivate)', 3015, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Received disconnect from ', 3058, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Connection closed by ', 3058, 0, 600, [])
        self.addLogPattern(r'^inetd\[\d{1,5}\]: (?P<process>\S+)\[\d{1,5}\]: exited, status \d+', 3058, 0, 600, ['process'])
        self.addLogPattern(r'^/usr/sbin/(?P<msg_type>cron)\[\d{1,5}\]: \((?P<user>\S+)\) CMD \(\s*(?P<process>\S.*)\)', 3059, 0, 600, ['user','process'])
        self.addLogPattern(r'^ifinfo: pif_get_ifd IFD \S+', 3060, 0, 600, [])
        self.addLogPattern(r'^gkmd: Exit at main \d+', 3061, 0, 600, [])
        self.addLogPattern(r'^autoconfd: shmlog: unable to create argtype:', 3062, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: (?P<msg_type>tac_send_authen): unexpected EOF ', 3063, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: subsystem request for netconf by user (?P<user>.+)', 3064, 0, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: subsystem request for netconf failed, subsystem not found', 3065, 0, 600, [])

        self.addLogPattern(r'^jddosd\[\d{1,5}\]: (?P<msg_type>DDOS_PROTOCOL_VIOLATION_SET): Protocol (?P<protocol>.+) is violated at (?P<instance>fpc \d+) for \d+ times', 3067, 2, 0, ['protocol','instance'])
        self.addLogPattern(r'^jddosd\[\d{1,5}\]: (?P<msg_type>DDOS_PROTOCOL_VIOLATION_CLEAR): Protocol (?P<protocol>.+) has returned to normal. Violated at (?P<instance>fpc \d+) for \d+ times', 3068, 1, 0, ['protocol','instance'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFDD_TRAP_SHOP_STATE)_DOWN: local discriminator: \d+, new state: down, interface: (?P<port>\S+), peer addr: (?P<peer_ip>\S+)', 3069, 2, 0, ['port','peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFDD_TRAP_SHOP_STATE)_UP: local discriminator: \d+, new state: up, interface: (?P<port>\S+), peer addr: (?P<peer_ip>\S+)', 3070, 1, 0, ['port','peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFD Session) (?P<peer_ip>\S+) \(IFL \d+\) state Up -> \S+ LD/RD\(\d+/\d+\) Up time:', 3071, 2, 0, ['peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFD Session) (?P<peer_ip>\S+) \(IFL \d+\) state \S+ -> Up LD/RD\(\d+/\d+\)', 3072, 1, 0, ['peer_ip'])
        self.addLogPattern(r'^dcd\[\d{1,5}\]: (?P<msg_type>parse_mix_rate_parent_ae) : ifd (?P<instance>\S+) no configured link-speed', 3073, 1, 0, ['instance'])
        self.addLogPattern(r'^/usr/sbin/sampled\[\d{1,5}\]: (?P<process>sampled_read_config): trace_file is 0x[0-9a-f]+, parse_only is \d', 3074, 1, 0, ['process'])
        self.addLogPattern(r'ffp\[\d{1,5}\]: \"dynamic-profiles\": No change to profiles', 3075, 1, 0, [])
        self.addLogPattern(r'^/usr/sbin/sampled\[\d{1,5}\]: (?P<process>sighup_event): trace_file is 0x[0-9a-f]+', 3076, 1, 0, ['process'])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: kernel time sync enabled \d+', 3080, 1, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: kernel time sync status \d+', 3080, 1, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: ntpd \d+\.\d+\.\d+', 3081, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: precision = \d+\.\d+ usec', 3082, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: Listening on interface \S+', 3083, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: frequency initialized \d+\.\d+ PPM', 3084, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: synchronized to (?P<peer_ip>\S+), stratum=\d', 3085, 3, 600, ['peer_ip'])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: kernel time sync disabled \d+', 3086, 2, 600, [])

        self.addLogPattern(r'^pfed: (?P<msg_type>PFED_NOTIF_GLOBAL_STAT_UNKNOWN): Unknown global notification stat:', 3090, 0, 600, [])
        self.addLogPattern(r'^pfed: downward spike received from pfe for ', 3091, 0, 600, [])

        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_TRAP_QUEUED): Adding trap to (?P<instance>\S+) to destination queue', 3100, 0, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_SEND_FAILURE): trap_io_send_trap_now: send to \((?P<instance>\S+)\) failure:', 3101, 3, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_TRAP_QUEUE_MAX_ATTEMPTS): trap_dq_send_traps: after \d+ attempts, deleting \d+ traps queued to (?P<instance>\S+)', 3102, 3, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_AUTH_FAILURE): nsa_log_community: unauthorized SNMP community from (?P<instance>\S+)', 3103, 3, 0, ['instance'])
        self.addLogPattern(r'^mib2d\[\d{1,5}\]: (?P<msg_type>SNMP_TRAP_LINK_UP): ifIndex (?P<ifindex>\d+), ifAdminStatus \S+, ifOperStatus up\(1\), ifName (?P<port>\S+)', 3104, 1, 0, ['ifindex','port'])
        self.addLogPattern(r'^mib2d\[\d{1,5}\]: (?P<msg_type>SNMP_TRAP_LINK_DOWN): ifIndex (?P<ifindex>\d+), ifAdminStatus \S+, ifOperStatus down\(2\), ifName (?P<port>\S+)', 3105, 2, 0, ['ifindex','port'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>LIBJSNMP_NS_LOG_WARNING): WARNING: AgentX session, \S+, noticed request timeout', 3106, 3, 0, [])

        self.addLogPattern(r'^(?P<msg_type>jl2tpd): jl2tpd: main: \*\*\* jl2tpd running \*\*\*', 3200, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): jl2tpd: main: L2tp config check instantiation', 3201, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): L2TP running with debug events enabled', 3202, 0, 600, ['process'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<process>lldp_server_reinit)\(\) reinit server', 3203, 0, 600, ['process'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<process>L2CPD): SNMP Filter Interface configuration success', 3203, 0, 600, ['process'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: INFRA var init done so returning', 3204, 0, 600, [])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<process>l2cpd) disabling pnac module', 3205, 0, 600, [])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: INFRA init done so returning', 3206, 0, 600, [])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: task_reconfigure reinitializing done', 3207, 0, 600, ['process'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<msg_type>LLDP_NEIGHBOR_DOWN): A neighbor of interface (?P<port>\S+) has gone down\.', 3208, 2, 600, ['port'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<msg_type>LLDP_NEIGHBOR_UP): A neighbor has come up for interface (?P<port>\S+)\.', 3209, 1, 600, ['port'])
        self.addLogPattern(r'^chassisd\[\d{1,5}\]: (?P<process>CHASSISD_BLOWERS_SPEED)_FULL: Fans and impellers being set to full speed', 3210, 2, 600, [])
        self.addLogPattern(r'^chassisd\[\d{1,5}\]: (?P<process>CHASSISD_BLOWERS_SPEED)(_MEDIUM)?: Fans and impellers (are now running at normal|being set to intermediate) speed', 3211, 1, 600, [])
        self.addLogPattern(r'^chassisd\[\d{1,5}\]: (?P<process>fpc_pic_process_pic_power_off_config):\d+ :No FPC in slot (?P<instance>\d+), skipping', 3212, 3, 600, [])
        self.addLogPattern(r'^chassisd\[\d{1,5}\]: (?P<process>CHASSISD_PARSE_COMPLETE): Using new configuration', 3213, 3, 600, [])
        self.addLogPattern(r'^\S+: invoke-commands: Executed \S+, output to \S+ in text format', 3214, 0, 600, [])
        self.addLogPattern(r'^\S+: transfer-file: Transferred \S+', 3215, 0, 600, [])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_BANDWIDTH_CHANGE): MPLS path\s+\(lsp (?P<instance>\S+)\) bandwidth changed, path bandwidth \d+ bps', 4000, 0, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_DOWN): MPLS path\s+down on LSP (?P<instance>\S+)', 4001, 2, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_UP): MPLS path\s+up on LSP (?P<instance>\S+) path bandwidth \d+ bps', 4002, 1, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_BANDWIDTH_CHANGE): MPLS LSP (?P<instance>\S+) bandwidth changed, lsp bandwidth \d+ bps', 4100, 0, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_DOWN): MPLS LSP (?P<instance>\S+) down on (?P<path>\S+)', 4101, 2, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_UP): MPLS LSP (?P<instance>\S+) up on (?P<path>\S+) Route ', 4102, 1, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_CHANGE): MPLS LSP (?P<instance>\S+) change on (?P<path>\S+) Route ', 4103, 3, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RSVP_INCORRECT_FLOWSPEC): Bandwidth in PATH Tspec greater than RESV flowspec for Session: (?P<instance>.+\) Proto \d+) Sender: ', 4104, 3, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_LDP_NBRDOWN): LDP neighbor (?P<instance>\S+) \((?P<port>\S+)\) is down', 4105, 2, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_LDP_NBRUP): LDP neighbor (?P<instance>\S+) \((?P<port>\S+)\) is up', 4106, 1, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_OSPF_NBRDOWN): OSPF neighbor (?P<instance>\S+) \(realm ospf-v2 (?P<port>\S+) area \d+\.\d+\.\d+\.\d+\) state changed from \S+ to Down', 4107, 2, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_OSPF_NBRUP): OSPF neighbor (?P<instance>\S+) \(realm ospf-v2 (?P<port>\S+) area \d+\.\d+\.\d+\.\d+\) state changed from \S+ to (Full|2Way)', 4108, 1, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RSVP_NBRDOWN): RSVP neighbor (?P<instance>\S+) down on interface (?P<port>\S+) nbr-type \S+', 4109, 2, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RSVP_NBRUP): RSVP neighbor (?P<instance>\S+) up on interface (?P<port>\S+) nbr-type \S+', 4110, 1, 0, ['instance','port'])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_listen_accept): Connection attempt from unconfigured neighbor: (?P<peer_ip>\S+)\+\d{1,5}', 4200, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_[a-z0-9_]+)(:\d+)?: NOTIFICATION sent to (?P<peer_ip>\S+)\+\d{1,5} \(proto\): code \d+ \(', 4201, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_[a-z0-9_]+)(:\d+)?: NOTIFICATION sent to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): code \d+ \(', 4201, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_UNUSABLE_NEXTHOP): bgp_nexthop_sanity: peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) next hop ', 4202, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_nexthop_sanity): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) next hop ', 4202, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_standby_socket_read_internal):\d+: NOTIFICATION received from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_read_v4_message):\d+: NOTIFICATION received from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv_open): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): received NOTIFICATION code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): peer (?P<peer_ip>\S+)\+\d{1,5} \(proto\): .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): read from peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) failed: .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_listen_accept): Connection received from (?P<peer_ip>\S+), .+', 4205, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_pp_recv): dropping (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\), connection collision', 4206, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_pp_recv): rejecting connection from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\), peer in state ', 4206, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>trace_(on|rotate)): (tracing|rotating)', 4207, 0, 0, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_WRITE_WOULD_BLOCK): bgp_send: sending \d+ bytes to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) blocked', 4208, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_WRITE_FAILED): bgp_send: sending \d+ bytes to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) failed', 4209, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_BGP_NEIGHBOR_STATE_CHANGED): BGP peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) changed state from Established to (?P<peer_state>\S+)', 4210, 2, 0, ['peer_ip','peer_asn', 'peer_state'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_BGP_NEIGHBOR_STATE_CHANGED): BGP peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) changed state from \S+ to (?P<peer_state>Established)', 4211, 1, 0, ['peer_ip','peer_asn', 'peer_state'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_RESET_PENDING_CONNECTION): (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): reseting pending active connection', 4212, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_PREFIX_THRESH_EXCEEDED): (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): Configured maximum prefix-limit threshold\(\d+\) exceeded', 4213, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>task_process_events): no write/connect method for BGP_\d+_(?P<peer_asn>\d+)\.(?P<peer_ip>(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+))\+\d+ socket', 4214, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^(rpd|l2cpd)\[\d{1,5}\]: (?P<msg_type>JTASK_TASK_REINIT): Reinitializing', 4215, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>L2CKT) acquiring mastership for primary', 4216, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>L2VPN) acquiring mastership for primary', 4217, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>task_reconfigure) reinitializing done', 4218, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: EVENT <?(Bandwidth)? ?(?P<msg_type>UpDown)>? (?P<port>\S+) index \d+( (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)/\d+ -> zero-len)? <Up( Broadcast)?( Multicast)?( Localup)?>', 4219, 2, 0, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: EVENT <?(Bandwidth)? ?(?P<msg_type>UpDown)>? (?P<port>\S+) index \d+( (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)/\d+ -> zero-len)? <(Broadcast)?( Multicast)?( Localup)?>', 4220, 1, 0, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: EVENT <?(?P<msg_type>Bandwidth)?>? (?P<port>\S+) index \d+( (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)/\d+ -> zero-len)? <(Up )?(Broadcast)?( Multicast)?( Localup)?>', 4221, 3, 0, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: \*STP Change\*, notify to other modules', 4222, 0, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: STP handler: Stp index=\d+, op=\S+, state=(Disc|Forw)arding', 4223, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: IF: Skipped marking address (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+) on ifl (?P<port>\S+) as UP', 4224, 3, 600, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>KRT Ifstate): Received IP(v4|v6)? address (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+) on ifl (?P<port>\S+)\.', 4224, 3, 600, ['port'])

        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP laser) bias current low  alarm set', 4300, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP laser) bias current low  alarm cleared', 4301, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\)\(\d+\)): (?P<msg_type>SFP\+) unplugged', 4302, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\)\(\d+\)): (?P<msg_type>SFP\+) plugged in', 4303, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP (output|receive) power) low  (warning|alarm) set', 4304, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP (output|receive) power) low  (warning|alarm) cleared', 4305, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP syslog throttling): disabling syslogs for ', 4306, 2, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP syslog throttling): enabling syslogs for ', 4307, 1, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP voltage (high|low)) ? alarm set', 4308, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP voltage (high|low)) ? alarm cleared', 4309, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Detected Ethernet MAC Local Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4310, 2, 0, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Cleared Ethernet MAC Local Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4311, 1, 0, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Detected Ethernet MAC Remote Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4312, 2, 0, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Cleared Ethernet MAC Remote Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4313, 1, 0, ['instance','port'])

        self.addLogPattern(r'^(?P<instance>fpc\d+) Next-hop resolution requests from interface (?P<port>\d+) throttled ', 4400, 1, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>pic_xmchip_wanio_dfe_tuning_op):(?P<port>\S+) - (En|Dis)able DFE (adaptive )?tuning ', 4401, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_phy_dfe_tuning_state): ?(?P<port>\S+) - DFE coarse/fine tuning completes', 4402, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>PFE_FW_SYSLOG_IP6)_(GEN|ICMP|TCP_UDP): FW: (?P<port>\S+)\s+D \S+ SA \S+', 4403, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>CMT): fpc \d+ hsl type \d+', 4404, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_plat_dfe_coarse_tuning)_(start|stop): CMIC\(\d+/\d+\) (start|stop) DFE (adaptive )?tuning for (?P<port>\S+)', 4405, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_vsc8248_ready_for_dfe): CMIC\(\d+/\d+\)\(\d\) - VSC8248 EDC FW unexpectedly in state \d+', 4406, 3, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) SYSLOG: \d+ messages? lost, message queue overflowed', 4407, 3, 600, [])


