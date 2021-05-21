#!/usr/bin/env bash
[ "$1" == "down" ] && needed=2 || needed=3
if [ $# -lt $needed ]
then
	cat <<-EOF
	$0 up|down uid fw_interface (optional: extra permitted IPs)

	Example usage:
	 $0 up 1000 tun1 192.168.0.0/24 [200::/7]
	 $0 down 1000
	 $0 up 1000 riseupvpn
	EOF
	exit 0
fi
action=$1
uid=$2
interface=$3
chain=RVPN$uid
shift 3

for x in '' 6
do
	if [ "$action" == "down" ]
	then
		sudo ip${x}tables -D OUTPUT -j $chain
		sudo ip${x}tables -F $chain
		sudo ip${x}tables --delete-chain $chain
	else
		sudo ip${x}tables -N $chain
		sudo ip${x}tables -I $chain ! -o lo+ -m owner --uid-owner $uid -j REJECT
		sudo ip${x}tables -I $chain -o $interface -m owner --uid-owner $uid -j ACCEPT
		if [ "$x" == "6" ]
		then
			for address in "$@"
			do
				if [[ "$address" =~ ^\[ ]]
				then
					address=$(sed -e 's/^\[//g' -e 's/\]$//g' <<<"$address")
					sudo ip${x}tables -I $chain -d "$address" -m owner --uid-owner $uid -j ACCEPT
				fi
			done
		else
			for address in "$@"
			do
				if ! [[ "$address" =~ ^\[ ]]
				then
					sudo ip${x}tables -I $chain -d "$address" -m owner --uid-owner $uid -j ACCEPT
				fi
			done
		fi
		sudo ip${x}tables -I OUTPUT -j $chain
	fi
done
