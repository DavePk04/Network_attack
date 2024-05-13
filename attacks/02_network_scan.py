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

