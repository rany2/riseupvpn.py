#!/usr/bin/env python3

import io
import os
import re
import sys
import grp
import json
import atexit
import socket
import argparse
import requests
import tempfile
import subprocess
import distutils.spawn

# Quit with error if called as a module
if __name__ != "__main__": sys.exit(1)

# Parse options
parser = argparse.ArgumentParser(description="RiseupVPN Python Edition")
group = parser.add_mutually_exclusive_group()
group.add_argument('-b', '--blacklist', help='blacklists country (delimited by space)')
group.add_argument('-w', '--whitelist', help='whitelists country (delimited by space)')
parser.add_argument('-g', '--gateway', help='which gateway to use (delimited by space) (default use GeoIP, if GeoIP unavailable uses json order of eip)')
parser.add_argument('-l', '--list-gateway', help='lists gateways available', action='store_true')
parser.add_argument('-G', '--geoip-url', help='sets geoip-url (to unset, use none) (default https://api.black.riseup.net:9001/json)', default='https://api.black.riseup.net:9001/json')
parser.add_argument('-a', '--provider-url', help='sets provider url (default https://black.riseup.net/provider.json)', default="https://black.riseup.net/provider.json")
parser.add_argument('-R', '--dont-drop', help="don\'t drop OpenVPN to nobody user", action='store_true')
args = parser.parse_args()

# Check for dependencies
unsatisfied_dependency = False
def which(x):
    result = distutils.spawn.find_executable(x)
    if result is not None:
        return result
    return False
for program in ['openvpn','resolvconf']:
    if not which(program):
        print ("Error: %s is required for this script. Please install it!" % program, file=sys.stderr)
        unsatisfied_dependency = True
if unsatisfied_dependency: sys.exit(1)

# Handle cleanup
def cleanup(sysexit=False):
    # Delete temporary files
    if "ca_file" in globals() and ca_file.name is not None: os.unlink(ca_file.name)
    if "public_key" in globals() and public_key.name is not None: os.unlink(public_key.name)
    if "private_key" in globals() and private_key.name is not None: os.unlink(private_key.name)

    # If tundev is set we remove resolvconf entry
    if "tundev" in globals(): subprocess.Popen(["resolvconf", "-d", tundev], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # If OpenVPN was started
    if "openvpn" in globals():
        openvpn.terminate()
        try:
            openvpn.wait(timeout=1)
        except subprocess.TimeoutExpired:
            openvpn.kill()

    if sysexit:
        atexit.unregister(cleanup)
        sys.exit()
atexit.register(cleanup)

# Get API certificate for RiseupVPN
r = requests.get(args.provider_url)
provider = json.loads(r.content)
cacertURL = provider['ca_cert_uri']
apiVersion = provider['api_version']
apiUrl = provider['api_uri'] + '/' + apiVersion
r = requests.get(cacertURL)
ca_file = tempfile.NamedTemporaryFile(delete=False)
ca_file.write(r.content)
ca_file.close()
print ("Info: retrieved API certificate", file=sys.stderr)

# Get proper group for nobody
# https://0xacab.org/leap/bitmask-vpn/-/blob/main/helpers/bitmask-root#L62
def get_no_group_name():
    try:
        grp.getgrnam('nobody')
        return 'nobody'
    except KeyError:
        try:
            grp.getgrnam('nogroup')
            return 'nogroup'
        except KeyError:
            return None

# Make sure IP address is valid
# https://0xacab.org/leap/bitmask-vpn/-/blob/main/helpers/bitmask-root#L208
def is_valid_address(value):
    try:
        socket.inet_aton(value)
        return True
    except Exception:
        return False

# Get list of gateways to be used (based on GeoIP, eip order, or specified by user)
if args.gateway is not None:
    gateways = args.gateway.split(" ")
elif args.geoip_url != "none":
    r = requests.get(args.geoip_url, verify=ca_file.name)
    gateways = json.loads(r.content)['gateways']
    print ("Info: retrieved gateway list based on GeoIP preference", file=sys.stderr)
else:
    gateways = ['none']

# Grab EIP Service JSON
r = requests.get(apiUrl + "/config/eip-service.json", verify=ca_file.name)
eip_service = json.loads(r.content)
print ("Info: retrieved EIP Service JSON", file=sys.stderr)
if args.list_gateway:
    if apiVersion == "3":
        gw_list = []
        for x in eip_service['gateways']:
            for y in x['capabilities']['transport']:
                if y['type'] != "openvpn": continue
                try:
                    gw_list += [ "%s %s %s" % (eip_service['locations'][x['location']]['country_code'], x['location'], x['host']) ]
                except: # if the eip-service.json doesn't have locations (calyx)
                    gw_list += [ "%s" % (x['host']) ]
        for x in sorted(gw_list): print (x)
    else:
        print ("Error: apiVersion %s is not supported for --list-gateway" % apiVersion, file=sys.stderr)
    sys.exit()

# Make OpenVPN cmdline
ovpn_config = []
for x in eip_service['openvpn_configuration']:
    if eip_service['openvpn_configuration'][x] == True:
        ovpn_config += [ '--' + x ]
    else:
        ovpn_config += [ '--' + x ] + eip_service['openvpn_configuration'][x].split(" ")

# Blacklist/Whitelist detection function
def blacklist_check(x, y):
    if (args.blacklist or args.whitelist) is not None:
        country = eip_service['locations'][x['location']]['country_code'].lower()
        if args.blacklist is not None:
            for y in args.blacklist.split(" "):
                if y.lower() == country: return False
        if args.whitelist is not None:
            for y in args.whitelist.split(" "):
                if y.lower() != country: return False
    return True

# Append OpenVPN configuration for remote
def append_ovpn_remote_config(x, ports, proto):
    global ovpn_config
    ovpn_config += [ '--remote', x['ip_address'], ports, proto ]

# Prepare final OpenVPN configuration
for gateway in gateways:
    for x in eip_service['gateways']:
        if x['host'] == gateway or gateway == "none":
            if apiVersion == "3":
                for y in x['capabilities']['transport']:
                    if y['type'] != "openvpn": continue
                    for z in range(len(y['ports'])):
                        ports = y['ports'][z]
                        proto = y['protocols'][z]
                        if blacklist_check(x, y): append_ovpn_remote_config(x, ports, proto)
            else: # apiVersion 1 support
                for y in range(len(x['capabilities']['ports'])):
                    if x['capabilities']['transport'][y] != "openvpn": continue
                    ports = x['capabilities']['ports'][y]
                    proto = x['capabilities']['protocols'][y]
                    if blacklist_check(x, y): append_ovpn_remote_config(x, ports, proto)

# Verify if server isn't doing something malicious and finalize OpenVPN configuration
# Source for verify: https://0xacab.org/leap/bitmask-vpn/-/blob/main/helpers/bitmask-root#L140
ALLOWED_FLAGS = {
    "--remote": ["IP", "NUMBER", "PROTO"],
    "--tls-cipher": ["CIPHER"],
    "--cipher": ["CIPHER"],
    "--auth": ["CIPHER"],
    "--keepalive": ["NUMBER", "NUMBER"],
    "--tun-ipv6": [],
    "--block-ipv6": [] # If https://0xacab.org/leap/container-platform/lilypad/-/issues/39 gets approved.
}
PARAM_FORMATS = {
    "NUMBER": lambda s: re.match("^\d+$", s),
    "PROTO": lambda s: re.match("^(tcp|udp|tcp4|udp4)$", s),
    "IP": lambda s: is_valid_address(s),
    "CIPHER": lambda s: re.match("^[A-Z0-9-]+$", s)
}
ovpn_config_new = []
notice_shown = []
fail_after_parse = False
for x in ovpn_config:
    if x.startswith("--"):
        y = x # current option
        a = 0
    if y in ALLOWED_FLAGS.keys():
        if x == y:
            ovpn_config_new.append(x)
        else:
            try:
                match = PARAM_FORMATS[ALLOWED_FLAGS[y][a]](x)
            except:
                match = False
            if match:
                ovpn_config_new.append(x)
            else:
                fail_after_parse = True
                print ("Error: forbidden param option %s on %s param %s!" % (x, a, y), file=sys.stderr)
            a += 1
    else:
        fail_after_parse = True
        if y not in notice_shown:
            print ("Error: forbidden param %s!" % (y), file=sys.stderr)
            notice_shown.append(y)
if fail_after_parse:
    print ("Error: for your own safety, the script will now abort!", file=sys.stderr)
    sys.exit(1)
else:
    ovpn_config = ovpn_config_new
    del ovpn_config_new
print ("Info: completed final OVPN configuartion", file=sys.stderr)

# Get OVPN certificates and private keys
r = requests.get(apiUrl + "/cert", verify=ca_file.name)
private_key = tempfile.NamedTemporaryFile(delete=False)
public_key = tempfile.NamedTemporaryFile(delete=False)
private_line = False
public_line = False
for line in r.text.split('\n'):
    if line.startswith("-----BEGIN RSA PRIVATE KEY-----") or private_line:
        private_line = True
        private_key.write(line.encode() + b'\n')
        if line.startswith("-----END RSA PRIVATE KEY-----"):
            private_line = False
            private_key.close()
    elif line.startswith("-----BEGIN CERTIFICATE-----") or public_line:
        public_line = True
        public_key.write(line.encode() + b'\n')
        if line.startswith("-----END CERTIFICATE-----"):
            public_line = False
            public_key.close()
print ("Info: retrived client public and private keys", file=sys.stderr)

ovpn_config += [
    "--nobind",
    "--client",
    "--dev", "tun",
    "--tls-client",
    "--remote-cert-tls", "server",
    "--script-security", "0",
    "--persist-key",
    "--persist-local-ip",
    "--ca", ca_file.name,
    "--key", private_key.name,
    "--cert", public_key.name,
    "--verb", "3", # needed to get current device name
    "--block-ipv6" # to workaround broken git, ssh, etc.
]
if not args.dont_drop:
    ovpn_config += [ "--user", "nobody" ]
    no_group = get_no_group_name()
    if no_group is not None: ovpn_config += [ '--group', no_group ]

print ("Info: OVPN Starting…", file=sys.stderr)
openvpn = subprocess.Popen(["openvpn"] + ovpn_config, stdout=subprocess.PIPE)
ovpn_terminate = False
print ("Info: OVPN Started!", file=sys.stderr)
print ("Info: OVPN Connecting…", file=sys.stderr)
for line in io.TextIOWrapper(openvpn.stdout, encoding="utf-8"):
    line = line.rstrip('\n')
    if "tundev" not in globals() or tundev is None:
        try:
            tundev = re.findall("TUN/TAP device ([\S]*) opened", line)[0]
            resolvconf = subprocess.Popen(["resolvconf", "-x", "-a", tundev], stdout=subprocess.DEVNULL, stdin=subprocess.PIPE)
            resolvconf.communicate(input=b'nameserver 10.41.0.1\nnameserver 10.42.0.1\n')
        except:
            pass
    if len(re.findall(" Initialization Sequence Completed$", line)) > 0:
        print ("Info: OVPN Connected!", file=sys.stderr)
    elif len(re.findall(", restarting$", line)) > 0:
        if args.dont_drop:
            print ("Info: OVPN Reconnecting…", file=sys.stderr)
        else:
            ovpn_terminate = True
    if ovpn_terminate:
        # We need to terminate if we are dont_drop, this because when we become nobody
        # we could no longer add gateway to route and start having issues
        print ("Info: OVPN Terminated!", file=sys.stderr)
        cleanup(True) # True = sys.exit()
openvpn.wait()
