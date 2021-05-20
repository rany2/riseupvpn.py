#!/usr/bin/env bash

# Example usage:
# ./firewall.sh up
# ./firewall.sh down
# ./firewall.sh up 1000
needed=3
if [ $# -lt $needed ]
then
	cat <<-EOF
	$0 up|down uid fw_interface (optional: extra permitted IPs)

	Example usage:
	 $0 up 1000 tun1 192.168.0.0/24 [200::/7]
	 $0 down 1000 tunriseupvpn
	 $0 up 1000 tunriseupvpn
	EOF
	exit 0
fi
action=$1
uid=$2
interface=$3
shift 3

for x in '' 6
do
	if [ "$action" == "down" ]
	then
		sudo ip${x}tables -D OUTPUT -j RiseupVPN
		sudo ip${x}tables -F RiseupVPN
		sudo ip${x}tables --delete-chain RiseupVPN
	else
		sudo ip${x}tables -N RiseupVPN
		sudo ip${x}tables -I RiseupVPN ! -o lo+ -m owner --uid-owner $uid -j REJECT
		sudo ip${x}tables -I RiseupVPN -o $interface -m owner --uid-owner $uid -j ACCEPT
		if [ "$x" == "6" ]
		then
			for address in "$@"
			do
				if [[ "$address" =~ ^\[ ]]
				then
					address=$(sed -e 's/^\[//g' -e 's/\]$//g' <<<"$address")
					sudo ip${x}tables -I RiseupVPN -d "$address" -j ACCEPT
				fi
			done
		else
			for address in "$@"
			do
				if ! [[ "$address" =~ ^\[ ]]
				then
					sudo ip${x}tables -I RiseupVPN -d "$address" -j ACCEPT
				fi
			done
		fi
		sudo ip${x}tables -I OUTPUT -j RiseupVPN
	fi
done
