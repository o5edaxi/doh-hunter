import json
import socket
import time
import sys
import configparser
import base64
import ipaddress
import random
import string
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
from threading import Thread
from io import BytesIO

from parsezeeklogs import ParseZeekLogs
import pycurl

config = configparser.ConfigParser()
try:
    # Get variables from the configuration file
    config.read('config.txt')
    general = config['General']
    run_mode_1 = config['Run Mode 1']
    run_mode_2 = config['Run Mode 2']
    run_mode_3 = config['Run Mode 3']
    logging_cfg = config['Logging']

    log_level_info = {'DEBUG': logging.DEBUG,
                      'INFO': logging.INFO,
                      'WARNING': logging.WARNING,
                      'ERROR': logging.ERROR,
                      'CRITICAL': logging.CRITICAL,
                      }
    log_level_from_config = logging_cfg.get('LOG_LEVEL')
    log_level = log_level_info.get(log_level_from_config, log_level_from_config)
    logging.basicConfig(level=log_level, format='%(asctime)s [%(levelname)s] %(message)s')
    RUN_MODE = int(general.get('RUN_MODE'))
    CHECKS_TIMEOUT = int(general.get('CHECKS_TIMEOUT'))
    TAG_LIFETIME = int(general.get('TAG_LIFETIME'))
    CACHE_AGEOUT = int(general.get('CACHE_AGEOUT'))
    REFERENCE_DOMAIN = general.get('REFERENCE_DOMAIN')
    ZEEK_LOG_PATH = general.get('ZEEK_LOG_PATH')
    MAX_THREADS = int(general.get('MAX_THREADS'))
    MAX_KEYS = int(general.get('MAX_KEYS'))
    FAIL_OPEN = general.getboolean('FAIL_OPEN')
    IPV4_INCLUDE = general.get('IPV4_INCLUDE')
    IPV4_EXCLUDE = general.get('IPV4_EXCLUDE')
    IPV6_INCLUDE = general.get('IPV6_INCLUDE')
    IPV6_EXCLUDE = general.get('IPV6_EXCLUDE')
    MAX_API = int(run_mode_1.get('MAX_API'))
    FW_TAG = run_mode_1.get('FW_TAG')
    FW_IP = run_mode_1.get('FW_IP')
    API_KEY = run_mode_1.get('API_KEY')
    FW_TIMEOUT = int(run_mode_1.get('FW_TIMEOUT'))
    CHECK_FW_CERT = run_mode_1.getboolean('CHECK_FW_CERT')
    HTTP_PORT = int(run_mode_2.get('HTTP_PORT'))
    FILE_PATH = run_mode_3.get('FILE_PATH')

except Exception as e:
    logging.critical('Error reading config file "config.txt": %s', e)
    sys.exit(1)

cacheDict = {}
dohlist = []
dohtext = ""
lastcleaned = 0
lastcleanededl = 0
discovered = 0
textrevision = 0
prevdiscovered = 0
taggingrate = 0
prevts = time.time()
uptime_1 = time.time()


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(dohtext.encode())


def run_server():
    httpd = HTTPServer(('', HTTP_PORT), SimpleHTTPRequestHandler)
    logging.warning('Starting server on port %d', HTTP_PORT)
    httpd.serve_forever()


def filterip(IP):
    try:
        address = ipaddress.ip_address(IP)
    except ValueError:
        logging.error('%s is not a valid IPv4/IPv6 address, skipping', IP)
        return 0
    if type(address) is ipaddress.IPv4Address:
        for incmember in v4inclfilter:
            logging.debug('%s must be in %s', address, incmember)
            if address in incmember:
                logging.debug('%s matches filters', IP)
                for excmember in v4exclfilter:
                    logging.debug('%s must NOT be in %s', address, excmember)
                    if address in excmember:
                        logging.debug('%s does not match filters, skipping', IP)
                        return 0
                    else:
                        logging.debug('%s matches filters', IP)
                return 1
        logging.debug('%s does not match filters, skipping', IP)
        return 0
    elif type(address) is ipaddress.IPv6Address:
        for incmember in v6inclfilter:
            logging.debug('%s must be in %s', address, incmember)
            if address in incmember:
                logging.debug('%s matches filters', IP)
                for excmember in v6exclfilter:
                    logging.debug('%s must NOT be in %s', address, excmember)
                    if address in excmember:
                        logging.debug('%s does not match filters, skipping', IP)
                        return 0
                    else:
                        logging.debug('%s matches filters', IP)
                return 1
        logging.debug('%s does not match filters, skipping', IP)
        return 0
    else:
        logging.error('%s is not a valid IPv4/IPv6 address, skipping', IP)
        return 0


def curl_debug(debug_type, debug_msg):
    logging.debug('debug(%d): %s', debug_type, debug_msg)


def check_ip(IP, sni, query, query64, transactionid):
    logging.debug('%s Attempting wire format query for IP %s using SNI %s', transactionid, IP, sni)
    buffer = BytesIO()
    c = pycurl.Curl()
    c.setopt(pycurl.RESOLVE, ["{}:443:{}".format(sni, IP)])
    c.setopt(pycurl.URL, 'https://{}/dns-query?dns={}'.format(sni, query64))
    c.setopt(pycurl.HTTPHEADER, ["accept: application/dns-message"])
    c.setopt(pycurl.SSL_VERIFYPEER, 0)
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    c.setopt(pycurl.TIMEOUT, CHECKS_TIMEOUT)
    c.setopt(pycurl.WRITEDATA, buffer)
    if logging.DEBUG >= logging.root.level:
        c.setopt(pycurl.VERBOSE, 1)
        c.setopt(pycurl.DEBUGFUNCTION, curl_debug)
    try:
        c.perform()
    except pycurl.error:
        logging.info('%s cURL had issues or timed out while checking IP %s with SNI %s using '
                     'wire format', transactionid, IP, sni)
        return 0
    if c.getinfo(pycurl.HTTP_CODE) != 200:
        logging.info('%s HTTP status unsuccessful for IP %s with SNI %s using wire format, '
                     'HTTP_CODE %d', transactionid, IP, sni, c.getinfo(pycurl.HTTP_CODE))
    body = buffer.getvalue()
    logging.info('%s Received response from IP %s using SNI %s and wire format', transactionid, IP,
                 sni)
    logging.debug('%s Response body: %s', transactionid, body)
    if len(body) < 1000 and len(body) > 10:
        if body[-4] == oct1 and body[-3] == oct2 and body[-2] == oct3 and body[-1] == oct4:
            logging.warning('%s Found a wire format DoH server at IP %s with SNI %s', transactionid,
                            IP, sni)
            return 1
        else:
            logging.debug('%s No match for wire format response, last 4 bytes are %s %s %s %s, '
                          'expected %s %s %s %s', transactionid, body[-4], body[-3], body[-2],
                          body[-1], oct1, oct2, oct3, oct4)
    else:
        logging.debug('%s Attempting JSON query for IP %s using SNI %s', transactionid, IP, sni)
        buffer = BytesIO()
        c.setopt(pycurl.URL, 'https://{}/dns-query?name={}&type=A'.format(sni, query))
        c.setopt(pycurl.HTTPHEADER, ["accept: application/dns-json"])
        c.setopt(pycurl.WRITEDATA, buffer)
        try:
            c.perform()
        except pycurl.error:
            logging.info('%s cURL had issues or timed out while contacting IP %s with SNI %s '
                         'using JSON', transactionid, IP, sni)
            return 0
        logging.info('%s HTTP status unsuccessful for IP %s with SNI %s using JSON, HTTP_CODE %d',
                     transactionid, IP, sni, c.getinfo(pycurl.HTTP_CODE))
        c.close()
        body = buffer.getvalue()
        logging.info('%s Received response from IP %s using SNI %s and JSON', transactionid, IP,
                     sni)
        logging.debug('%s Response body: %s', transactionid, body)
        if len(body) < 1000 and len(body) > 10 and exampleip in str(body):
            logging.warning('%s Found a JSON DoH server at IP %s with SNI %s', transactionid, IP,
                            sni)
            return 1
        else:
            logging.info('%s Tried both methods and did not detect for IP %s using SNI %s',
                         transactionid, IP, sni)
            return 0


def check_cache(IP, sni):
    try:
        for lists in cacheDict[IP]:
            if sni == lists[0]:
                return 1
        logging.debug('IP %s with SNI %s not found in cache', IP, sni)
        return 0
    except KeyError:
        logging.debug('IP %s not found in cache for any SNI', IP)
        return 0


def write_cache(IP, sni, transactionid):
    if len(cacheDict) > MAX_KEYS:
        logging.critical('%s Cache full, cannot cache IP %s', transactionid, IP)
        return 0
    try:
        cacheDict[IP].append([sni, time.time()])
    except KeyError:
        logging.debug('%s Key %s not present, adding it', transactionid, IP)
        cacheDict[IP] = [[sni, time.time()]]


def age_out_cache():
    ts = time.time()
    keystorm = []
    subvaltorm = []
    for IP, sni_list in cacheDict.items():
        for sublist in sni_list:
            logging.debug('Cache entry %s %s age is %s seconds', IP, sublist[0], ts - sublist[1])
            if ts - sublist[1] > CACHE_AGEOUT:
                subvaltorm.append([IP, sublist])
    for sublist in subvaltorm:
        logging.debug('removing %s from entry %s in cache', sublist[1], sublist[0])
        cacheDict[sublist[0]].remove(sublist[1])
    for IP, sni_list in cacheDict.items():
        if not sni_list:
            keystorm += [IP]
    for IP in keystorm:
        logging.debug('removing key %s from cache', IP)
        del cacheDict[IP]


def tag_ip(IP, timeout, tag, fw_ip, api_key, transactionid):
    global taggingrate
    global MAX_API
    if taggingrate > MAX_API:
        logging.error('%s Tagging rate is over the configured limit ( %d vs %d ). Retrying tag '
                      'in 2 seconds', transactionid, taggingrate, MAX_API)
        time.sleep(2 + random.random())
        if taggingrate > MAX_API:
            logging.critical('%s Not tagging IP %s on firewall, tagging rate is %d which is above '
                             'the configured max %d', transactionid, IP, taggingrate, MAX_API)
            return 0
    xml = ('<uid-message><type>update</type><payload><register><entry ip="{}" persistent="0"><tag>'
           '<member timeout="{}">{}</member></tag></entry></register></payload>'
           '</uid-message>'.format(IP, timeout, tag))
    buffer = BytesIO()
    c = pycurl.Curl()
    try:
        if type(ipaddress.ip_address(IP)) is ipaddress.IPv4Address:
            c.setopt(pycurl.URL, 'https://{}/api/?type=user-id&key={}'.format(fw_ip, api_key))
        else:
            # IPv6
            c.setopt(pycurl.URL, 'https://[{}]/api/?type=user-id&key={}'.format(fw_ip, api_key))
    except ValueError:
        # FQDN
        c.setopt(pycurl.URL, 'https://{}/api/?type=user-id&key={}'.format(fw_ip, api_key))
    c.setopt(pycurl.POSTFIELDS, "cmd={}".format(xml))
    c.setopt(pycurl.SSL_VERIFYPEER, CHECK_FW_CERT)
    c.setopt(pycurl.SSL_VERIFYHOST, CHECK_FW_CERT)
    c.setopt(pycurl.TIMEOUT, FW_TIMEOUT)
    c.setopt(pycurl.WRITEDATA, buffer)
    if logging.DEBUG >= logging.root.level:
        c.setopt(pycurl.VERBOSE, 1)
        c.setopt(pycurl.DEBUGFUNCTION, curl_debug)
    try:
        c.perform()
    except pycurl.error:
        logging.error('%s cURL had issues or timed out while trying to contact the firewall'
                      ' at %s to tag IP %s', transactionid, fw_ip, IP)
        return 0
    body = buffer.getvalue()
    logging.info('%s Received response from firewall at %s tagging IP %s', transactionid, fw_ip, IP)
    logging.debug('%s Response body: %s', transactionid, body)
    if c.getinfo(pycurl.HTTP_CODE) == 200:
        return 1
    else:
        logging.critical('%s Tagging IP %s on firewall %s failed with HTTP code %s', transactionid,
                         IP, fw_ip, c.getinfo(pycurl.RESPONSE_CODE))
        return 0


def thread_func(ip, sni, reference_domain, ref_domain_base64, tag_lifetime, fw_tag, fw_ip, api_key):
    global discovered
    global dohlist
    found = 0
    transactionid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    if check_ip(ip, sni, reference_domain, ref_domain_base64, transactionid):
        logging.warning('%s Found DoH server at %s with SNI %s', transactionid, ip, sni)
        discovered += 1
        if RUN_MODE == 1:
            # Notify firewall
            if tag_ip(ip, tag_lifetime, fw_tag, fw_ip, api_key, transactionid):
                logging.warning('%s Successfully tagged IP %s on firewall %s with tag %s',
                                transactionid, ip, fw_ip, fw_tag)
            else:
                logging.critical('%s Failed to tag IP %s on firewall %s', transactionid, ip, fw_ip)
        else:
            for sublist in dohlist:
                if ip == sublist[0]:
                    # Update timestamp
                    sublist[1] = time.time()
                    found = 1
                    break
            if not found:
                dohlist.append([ip, time.time()])
            if RUN_MODE == 2:
                logging.warning('%s Updating dynamic list with IP %s on next refresh',
                                transactionid, ip)
            if RUN_MODE == 3:
                logging.warning('%s Updating file list with IP %s on next refresh', transactionid,
                                ip)
    if check_cache(ip, sni):
        logging.debug('IP %s with SNI %s found in cache after rechecking', ip, sni)
    else:
        logging.debug('%s Adding IP %s with SNI %s to cache', transactionid, ip, sni)
        write_cache(ip, sni, transactionid)


def text_refresh():
    global textrevision
    global dohtext
    dohtext = ""
    dohtext += "#REVISION {}\n".format(textrevision)
    dohtext += "#TOTAL DoH FOUND: {}\n".format(len(dohlist))
    dohtext += "#TOTAL IPs IN CACHE: {}\n".format(len(cacheDict))
    dohtext += "#RUNNING TIME: {} SECONDS\n\n".format(time.time() - uptime_1)
    for lists in dohlist:
        dohtext += lists[0]
        dohtext += "\n"
    textrevision += 1


def age_out_list():
    global dohlist
    listtorm = []
    for lists in dohlist:
        if time.time() - lists[1] > TAG_LIFETIME and TAG_LIFETIME > 0:
            listtorm += [lists]
    for lists in listtorm:
        dohlist.remove(lists)


def tag_rate_checker():
    global taggingrate
    global discovered
    global prevdiscovered
    global prevts
    while True:
        time.sleep(1)
        taggingrate = (discovered - prevdiscovered) / (time.time() - prevts)
        prevdiscovered = discovered
        prevts = time.time()
        logging.debug('Script is sending %s tags per second to the firewall', taggingrate)


logging.warning('Make sure you edit config.txt with your preferred settings.')
logging.warning('Run mode is %d', RUN_MODE)
time.sleep(5)
if TAG_LIFETIME > 2592000 or TAG_LIFETIME < 0:
    logging.critical('The maximum value for TAG_LIFETIME is 2592000 and the minimum is '
                     '0 (unlimited). Please configure a compatible value and run the script again.')
    sys.exit(1)
if RUN_MODE not in (1, 2, 3):
    logging.critical('RUN_MODE must be either 1, 2 or 3.')
    sys.exit(1)
if RUN_MODE == 1 and (API_KEY == "" or FW_IP == ""):
    logging.critical('Please configure a valid firewall IP and API key.')
    sys.exit(1)
if not os.path.isfile(ZEEK_LOG_PATH):
    logging.critical('File %s not found', ZEEK_LOG_PATH)
    sys.exit(1)

# Check filters

v4inclfilter = []
if IPV4_INCLUDE == "":
    IPV4_INCLUDE = "0.0.0.0/0"
for member in IPV4_INCLUDE.split(','):
    try:
        addr = ipaddress.ip_network(member)
        if type(addr) is ipaddress.IPv4Network and addr != "":
            v4inclfilter += [ipaddress.ip_network(member)]
        else:
            logging.critical('Invalid IPv4 include filter provided, %s. Exiting', member)
            sys.exit(1)
    except SystemExit:
        sys.exit(1)
    except ValueError:
        logging.critical('Invalid IPv4 include filter provided, %s. Exiting', member)
        sys.exit(1)

v4exclfilter = []
if IPV4_EXCLUDE != "":
    for member in IPV4_EXCLUDE.split(','):
        try:
            addr = ipaddress.ip_network(member)
            if type(addr) is ipaddress.IPv4Network and addr != "":
                v4exclfilter += [ipaddress.ip_network(member)]
            else:
                logging.critical('Invalid IPv4 exclude filter provided, %s. Exiting', member)
                sys.exit(1)
        except SystemExit:
            sys.exit(1)
        except ValueError:
            logging.critical('Invalid IPv4 exclude filter provided, %s. Exiting', member)
            sys.exit(1)

v6inclfilter = []
if IPV6_INCLUDE == "":
    IPV6_INCLUDE = "::/0"
for member in IPV6_INCLUDE.split(','):
    try:
        addr = ipaddress.ip_network(member)
        if type(addr) is ipaddress.IPv6Network and addr != "":
            v6inclfilter += [ipaddress.ip_network(member)]
        else:
            logging.critical('Invalid IPv6 include filter provided, %s. Exiting', member)
            sys.exit(1)
    except SystemExit:
        sys.exit(1)
    except ValueError:
        logging.critical('Invalid IPv6 include filter provided, %s. Exiting', member)
        sys.exit(1)

v6exclfilter = []
if IPV6_EXCLUDE != "":
    for member in IPV6_EXCLUDE.split(','):
        try:
            addr = ipaddress.ip_network(member)
            if type(addr) is ipaddress.IPv6Network and addr != "":
                v6exclfilter += [ipaddress.ip_network(member)]
            else:
                logging.critical('Invalid IPv6 exclude filter provided, %s. Exiting', member)
                sys.exit(1)
        except SystemExit:
            sys.exit(1)
        except ValueError:
            logging.critical('Invalid IPv6 exclude filter provided, %s. Exiting', member)
            sys.exit(1)

# Start HTTP server

if RUN_MODE == 2:
    thread = Thread(target=run_server, args=())
    thread.daemon = True
    thread.start()

# Domain name to wire format

labels = b""
for part in REFERENCE_DOMAIN.split('.'):
    label = part.encode('ascii')
    length = len(label).to_bytes(1, 'big')
    labels += (length + label)
reference_domain_hex = labels.hex()
hex_string = "abcd01000001000000000000{}0000010001".format(reference_domain_hex)
hex_bytes = bytes.fromhex(hex_string)
reference_domain_base64 = base64.urlsafe_b64encode(hex_bytes).decode("utf-8")
reference_domain_base64 = reference_domain_base64.replace("=", "")

if RUN_MODE == 1:
    thread = Thread(target=tag_rate_checker, args=())
    thread.start()

logging.warning('Entering scan loop')

while True:
    logging.info('Commencing scan')
    threadlist = []
    toremove = []
    for t in threadlist:
        if not t.is_alive():
            toremove += [t]
    for t in toremove:
        threadlist.remove(t)
    logging.info('Current active threads is %d', len(threadlist))
    # Resolve example.com for comparison
    logging.warning('Attempting to resolve reference domain %s', REFERENCE_DOMAIN)
    retries = 0
    success = False
    while not success:
        try:
            exampleip = [str(i[4][0]) for i in socket.getaddrinfo(REFERENCE_DOMAIN, 80)]
            success = True
        except Exception as e:
            retries += 1
            if retries > 10:
                logging.critical('Failed to resolve reference domain %s, exiting...',
                                 REFERENCE_DOMAIN)
                sys.exit(1)
            logging.error('Failed to resolve reference domain %s because of %s, retrying...',
                          REFERENCE_DOMAIN, e)
            time.sleep(10)

    exampleip = exampleip[0]
    exampleip_split = exampleip.split(".", 3)

    oct1 = int(exampleip_split[0])
    oct2 = int(exampleip_split[1])
    oct3 = int(exampleip_split[2])
    oct4 = int(exampleip_split[3])

    logging.warning('Domain %s resolves to %s', REFERENCE_DOMAIN, exampleip)

    timerolled = time.time()
    while not os.path.isfile(ZEEK_LOG_PATH):
        if time.time() - timerolled > 4000:
            logging.critical('Log file at %s not present for over 1 hour. Exiting script.',
                             ZEEK_LOG_PATH)
            sys.exit(1)
        logging.warning('Log file at %s currently does not exist, probably rolled by Zeek. Checking'
                        ' again in 10 seconds...', ZEEK_LOG_PATH)
        time.sleep(10)

    # Parse ssl.log

    logging.warning('Parsing file %s', ZEEK_LOG_PATH)
    for log_record in ParseZeekLogs(ZEEK_LOG_PATH, output_format="json", safe_headers=False,
                                    fields=["id.resp_h", "id.resp_p", "server_name", "resumed",
                                            "established"]):
        if log_record is not None:
            log_record_json = json.loads(log_record)
            logging.debug('Parsing log record %s', log_record_json)
            if not filterip(log_record_json["id.resp_h"]):
                continue
            # Look for fully established HTTPS connections
            logging.debug('Destination port is %s and established value is %s',
                          log_record_json["id.resp_p"], log_record_json["established"])
            if log_record_json["id.resp_p"] == 443 and log_record_json["established"] is True:
                logging.debug('Log record compatible, scanning it')
                # Don't send SNI if not available, check IP and cache it
                if log_record_json["server_name"] == "-" or log_record_json["server_name"] == "":
                    logging.info('Log record %s has no SNI information, using raw IP instead',
                                 log_record_json["id.resp_h"])
                    if not check_cache(log_record_json["id.resp_h"], log_record_json["id.resp_h"]):
                        if len(cacheDict) > MAX_KEYS and FAIL_OPEN is True:
                            logging.error('FAIL_OPEN is set to True and cache is full, not scanning'
                                          ' IP %s with SNI %s', log_record_json["id.resp_h"],
                                          log_record_json["id.resp_h"])
                            continue
                        logging.info('IP %s with SNI %s not in cache, checking it',
                                     log_record_json["id.resp_h"], log_record_json["id.resp_h"])
                        thread = Thread(target=thread_func, args=(log_record_json["id.resp_h"],
                                        log_record_json["id.resp_h"], REFERENCE_DOMAIN,
                                        reference_domain_base64, TAG_LIFETIME, FW_TAG, FW_IP,
                                        API_KEY))
                        thread.start()
                        threadlist.append(thread)
                    else:
                        logging.debug('IP %s with SNI %s is already in cache, scan aborted',
                                      log_record_json["id.resp_h"], log_record_json["id.resp_h"])
                else:
                    # Check IP and cache it
                    if not check_cache(log_record_json["id.resp_h"],
                                       log_record_json["server_name"]):
                        if len(cacheDict) > MAX_KEYS and FAIL_OPEN is True:
                            logging.error('FAIL_OPEN is set to True and cache is full, not scanning'
                                          ' IP %s with SNI %s', log_record_json["id.resp_h"],
                                          log_record_json["server_name"])
                            continue
                        logging.info('IP %s with SNI %s not in cache, checking it',
                                     log_record_json["id.resp_h"], log_record_json["server_name"])
                        thread = Thread(target=thread_func, args=(log_record_json["id.resp_h"],
                                        log_record_json["server_name"], REFERENCE_DOMAIN,
                                        reference_domain_base64, TAG_LIFETIME, FW_TAG, FW_IP,
                                        API_KEY))
                        thread.start()
                        threadlist.append(thread)
                    else:
                        logging.debug('IP %s with SNI %s is already in cache, scan aborted',
                                      log_record_json["id.resp_h"], log_record_json["server_name"])

            while len(threadlist) > MAX_THREADS:
                logging.debug('MAX_THREADS value reached, waiting')
                toremove = []
                for t in threadlist:
                    if not t.is_alive():
                        toremove += [t]
                for t in toremove:
                    threadlist.remove(t)
            logging.info('Current active threads is %d', len(threadlist))

    logging.warning('Waiting 60 seconds before cache clean')
    time.sleep(60)

    # Age out cache and list

    logging.warning('Cleaning stale cache entries')
    age_out_cache()

    if RUN_MODE in (2, 3):
        logging.warning('Cleaning stale list entries')
        age_out_list()
        # Refresh EDL text string
        logging.warning('Refreshing external lists')
        text_refresh()
        # Write to file
        if RUN_MODE == 3:
            with open(FILE_PATH, "w") as text_file:
                print(dohtext, file=text_file)

    logging.warning('Current entries in cache: %s unique IPs, maximum limit is %s', len(cacheDict),
                    MAX_KEYS)
    logging.warning('Total DoH servers discovered: %d', len(dohlist))

    logging.warning('Waiting 60 seconds before next scan')
    time.sleep(60)
