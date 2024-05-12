# LINFO2347 Project Network Attacks 2023-2024

### Names: Dave Pikop, Anton Romanova 

## Project Overview

## Table of Contents
- [Project Overview](#project-overview)
- [Basic enterprise network protection](#Basic-enterprise-network-protection)
- [Network Attacks](#network-attacks)
- [Network Protection](#network-protection)
- [Launch topology attacks and protection](#Launch-topology-attacks-and-protection)

## Basic network protection
In the new version of the network, we have implemented a basic firewall using nftables. 
The configuration script is located in the `topo-default.sh` file."

To run the new configuration, execute the following command:

```sudo -E python3 ~/LINFO2347/topo-default.py```

### Test the Firewall

Our `nftables` firewall configuration was tested using the `pingall` command, yielding the following results:

```text
dns -> X X X X X X X X
ftp -> X X X X X X X X
http -> X X X X X X X X
internet -> dns ftp http ntp r1 r2 X X
ntp -> X X X X X X X X
r1 -> X X X internet X r2 ws2 ws3
r2 -> X X X internet X r1 X X
ws2 -> dns ftp http internet ntp r1 r2 ws3
ws3 -> dns ftp http internet ntp r1 r2 ws2
*** Results: 61% dropped (28/72 received)
```

## SSH/FTP Brute force

### attack

We performed a basic ssh bruteforce with `paramiko` and a 10k password 
list to which we added "mininet" on line 50 to avoid waiting too long

to run the attack from the internet, run
`internet python /home/mininet/LINFO2347/attacks/01_ssh_bruteforce.py`

The attack is performed in parallel with 7 threads. 

### mitigation

To mitigate brute-force attack we can simply rate-limit new connections
to 5 new connections per minute. If a client goes over this limit,
his ip address will be added to a blacklist for two minutes

```nftables
table inet dmz {
     # set of temporarily blocked ip
     set blocklist {
         type ipv4_addr
         timeout 2m      # expire ban after 2 minute
         size 65536
     }

     chain inbound {
         type filter hook input priority 0; policy accept;

         # Check if the source IP is in the blocklist
         ip saddr @blocklist drop

         # Rate limit incoming connections to SSH and FTP
         tcp dport { 22, 21 } ct state new counter packets 1 jump check_rate
     }

     chain check_rate {
         # General rate limit chain for specified ports
         ct state new limit rate over 5/minute burst 5 packets add @blocklist { ip saddr timeout 2m } drop
     }

     chain outbound {
         type filter hook output priority 0; policy drop;
         # Allow responses to established or related sessions
         ip daddr { 10.1.0.2, 10.1.0.3, 10.2.0.2 } ct state established,related accept
     }
 }
```

## Network scan

### attack

To perform a network scan, we will send SYN packets to all ports (let's say in a range from 1 to 1000

