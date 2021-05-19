#!/usr/bin/env bash
( echo 'Average Latency (ms)|Country|Server Address'
for x in $(./riseupvpn.py -l 2>/dev/null | awk '{print $1"+"$NF}')
do
echo "$(ping -c4 -i0.2 "$(cut -d+ -f2 <<<"$x")" |tail -1 |cut -d/ -f5|sed -e 's/^$/-1/g')|$(cut -d+ -f1 <<<"$x")|$(cut -d+ -f2<<<"$x")" &
done | sort -n ) | column -s '|' -t
