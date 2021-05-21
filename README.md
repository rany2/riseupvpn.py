# Requirements

* resolvconf
* openvpn

# How to run?

`sudo ./riseupvpn.py`

# Help page

`./riseupvpn.py -h`

# Notes

To use over some proxy for initial connection, use ALL_PROXY as the requests module actually has support for it.
So you will be able to get access to API that will then allow you to connect to the VPN.
(OpenVPN connection won't be over the proxy)  

To use with Calyx, run with "--geoip-url none" and "--provider-url https://calyx.net/provider.json"  

It is recommended to use openresolv over systemd-resolvconf and systemd-resolved. This is because,
due to the way systemd-resolved functions you will be vulnerable to DNS leaks for the length of the
reconnection process. This won't happen with openresolv. For information on how to setup resolvconf
for NetworkManager see: https://wiki.archlinux.org/title/NetworkManager#Use_openresolv
