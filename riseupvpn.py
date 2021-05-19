#!/usr/bin/env python3

import io
import os
import re
import sys
import json
import signal
import argparse
import requests
import tempfile
import subprocess

# Quit with error if called as a module
if __name__ != "__main__": sys.exit(1)

# Options
parser = argparse.ArgumentParser(description="RiseupVPN Python Edition")
group = parser.add_mutually_exclusive_group()
group.add_argument('-b', '--blacklist', help='blacklists country (delimited by space)')
group.add_argument('-w', '--whitelist', help='whitelists country (delimited by space)')
parser.add_argument('-g', '--gateway', help='which gateway to use (delimited by space) (default use GeoIP, if GeoIP unavailable uses json order of eip)')
parser.add_argument('-l', '--list-gateway', help='lists gateways available', action='store_true')
parser.add_argument('-G', '--geoip-url', help='sets geoip-url (to unset, use none) (default https://api.black.riseup.net:9001/json)', default='https://api.black.riseup.net:9001/json')
parser.add_argument('-a', '--provider-url', help='sets provider url (default https://black.riseup.net/provider.json)', default="https://black.riseup.net/provider.json")
args = parser.parse_args()

# Handle signal/cleanup
def terminator(signo, stack_frame, auto=True):
    # Delete temporary files
    os.unlink(ca_file.name)
    os.unlink(public_key.name)
    os.unlink(private_key.name)

    # If tundev is set we remove resolvconf entry
    if tundev is not None: subprocess.Popen(["resolvconf", "-d", tundev], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Exit everything if executed by signal
    if auto: sys.exit()

# Make temporary files, set needed variables, and capture signals
ca_file = tempfile.NamedTemporaryFile(delete=False)
private_key = tempfile.NamedTemporaryFile(delete=False)
public_key = tempfile.NamedTemporaryFile(delete=False)
tundev = None
signal.signal(signal.SIGINT, terminator)
signal.signal(signal.SIGTERM, terminator)

# Get API certificate for RiseupVPN
r = requests.get(args.provider_url)
provider = json.loads(r.content)
cacertURL = provider['ca_cert_uri']
apiUrl = provider['api_uri'] + '/' + provider['api_version']
apiVersion = provider['api_version']
r = requests.get(cacertURL)
ca_file.write(r.content)
ca_file.close()

# Get proper group for nobody
# https://0xacab.org/leap/bitmask-vpn/-/blob/main/helpers/bitmask-root#L62
def get_no_group_name():
    import grp
    try:
        grp.getgrnam('nobody')
        return 'nobody'
    except KeyError:
        try:
            grp.getgrnam('nogroup')
            return 'nogroup'
        except KeyError:
            return None

# Get list of gateways to be used (based on GeoIP, eip order, or specified by user)
if args.gateway is not None:
	gateways = args.gateway.split(" ")
elif args.geoip_url != "none":
	r = requests.get(args.geoip_url, verify=ca_file.name)
	gateways = json.loads(r.content)['gateways']
else:
	gateways = ['none']

# Grab EIP Service JSON
r = requests.get(apiUrl + "/config/eip-service.json", verify=ca_file.name)
eip_service = json.loads(r.content)
if args.list_gateway:
    gw_list = []
    for x in eip_service['gateways']:
        for y in x['capabilities']['transport']:
            if y['type'] != "openvpn": break
            gw_list += [ "%s %s %s" % (eip_service['locations'][x['location']]['country_code'], x['location'], x['host']) ]
    for x in sorted(gw_list): print(x)
    terminator(0, 0)

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
        country = eip_service['locations'][x['location']]['country_code']
        if args.blacklist is not None:
            for y in args.blacklist.split(" "):
                if y == country:
                    return False
                else:
                    return True
        if args.whitelist is not None:
            for y in args.whitelist.split(" "):
                if y != country:
                    return False
                else:
                    return True
    else:
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


# Get OVPN certificates and private keys
r = requests.get(apiUrl + "/cert", verify=ca_file.name)
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

# Finalize OpenVPN configuration
ovpn_config += [
    "--nobind",
    "--client",
    "--dev", "tun",
    "--tls-client",
    "--remote-cert-tls", "server",
#    "--management-signal",
    "--script-security", "0",
    "--user", "nobody",
    "--persist-key",
    "--persist-local-ip",
    "--ca", ca_file.name,
    "--key", private_key.name,
    "--cert", public_key.name,
    "--verb", "3", # needed to get current device name
    "--block-ipv6" # to workaround broken git, ssh, etc.
]
no_group = get_no_group_name()
if no_group is not None: ovpn_config += [ '--group', no_group ]

openvpn = subprocess.Popen(["openvpn"] + ovpn_config, stdout=subprocess.PIPE)
for line in io.TextIOWrapper(openvpn.stdout, encoding="utf-8"):
    line = line.rstrip('\n')
    try:
        tundev = re.findall("TUN/TAP device ([\S]*) opened", line)[0]
    except:
        pass
    if tundev != None:
        resolvconf = subprocess.Popen(["resolvconf", "-x", "-a", tundev], stdout=subprocess.DEVNULL, stdin=subprocess.PIPE)
        resolvconf.communicate(input=b'nameserver 10.41.0.1\nnameserver 10.42.0.1\n')
