#!/bin/bash
INTERFACE=$(ip route get 8.8.8.8 | awk '/dev/ {print $5; exit}')
tc qdisc del dev $INTERFACE root 2>/dev/null
tc qdisc del dev $INTERFACE ingress 2>/dev/null
ip link set dev $INTERFACE mtu 1500 2>/dev/null
echo 1000 > /sys/class/net/$INTERFACE/tx_queue_len 2>/dev/null

if tc qdisc add dev $INTERFACE root handle 1: cake bandwidth 1000mbit rtt 20ms 2>/dev/null && \
   tc qdisc add dev $INTERFACE parent 1: handle 10: netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null; then
    echo "$(date): CAKE+Netem optimization complete" >> /var/log/tc_smart.log
elif tc qdisc add dev $INTERFACE root handle 1: fq_codel limit 10240 flows 1024 target 5ms interval 100ms 2>/dev/null && \
     tc qdisc add dev $INTERFACE parent 1: handle 10: netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null; then
    echo "$(date): FQ_CoDel+Netem optimization complete" >> /var/log/tc_smart.log
elif tc qdisc add dev $INTERFACE root handle 1: htb default 11 2>/dev/null && \
     tc class add dev $INTERFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc class add dev $INTERFACE parent 1:1 classid 1:11 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc qdisc add dev $INTERFACE parent 1:11 handle 10: netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null; then
    echo "$(date): HTB+Netem optimization complete" >> /var/log/tc_smart.log
elif tc qdisc add dev $INTERFACE root handle 1: pfifo_fast 2>/dev/null && \
     tc qdisc add dev $INTERFACE parent 1: handle 10: netem delay 1ms loss 0.005% 2>/dev/null; then
    echo "$(date): Basic PFIFO+Netem optimization complete" >> /var/log/tc_smart.log
else
    tc qdisc add dev $INTERFACE root netem delay 1ms loss 0.005% 2>/dev/null
    echo "$(date): Fallback Netem optimization complete" >> /var/log/tc_smart.log
fi
