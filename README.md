pcap flow generation utility

generate ranodmized pcap data based on netflow topology. e.g. this generates X number of unique 5 tupple IPv4 TCP/UDP flows. 

Primary usage for load testing capture and analytics systems


```
PCAP Flow Packet Generator : FMADIO 10G 40G 100G Packet Capture : http://www.fmad.io
pcap_genflow

Options:
-v                 : verbose output

--pktcnt   <total packts>        : total number of packets to output
--flowcnt  <total flows>         : total number of flows
--pktsize  <packet size>         : size of each packet
--pktslice <packet slice amount> : packet slicing amount (default 0)
--bps      <bits output rate>    : output generation rate (e.g. 1e9 = 1Gbps)

```
