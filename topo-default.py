"""
Custom topology for the LINFO2347 - Computer System Security course.

Mimics a small enterprise network, with 2 workstations in a trusted LAN,
and service-providing servers in a DMZ LAN.

Adapted from https://stackoverflow.com/questions/46595423/mininet-how-to-create-a-topology-with-two-routers-and-their-respective-hosts

Updates: this version includes a basic firewall setup using nftables.
Updated by: Dave Pikop, Anton Romanova
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.examples.linuxrouter import LinuxRouter
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from pathlib import Path
import argparse
import time


class TopoSecu(Topo):

    def build(self):

        # Add 2 routers in two different subnets
        r1 = self.addHost('r1', cls=LinuxRouter, ip=None)  # Workstation LAN router
        r2 = self.addHost('r2', cls=LinuxRouter, ip=None)  # Internet router

        # Add 2 switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add router-switch links in the same subnet
        self.addLink(s1, r1, intfName2='r1-eth0', params2={'ip': '10.1.0.1/24'})
        self.addLink(s2, r1, intfName2='r1-eth12', params2={'ip': '10.12.0.1/24'})
        self.addLink(s2, r2, intfName2='r2-eth12', params2={'ip': '10.12.0.2/24'})

        # Add outside host
        internet = self.addHost(name='internet', ip='10.2.0.2/24', defaultRoute='via 10.2.0.1')
        self.addLink(internet, r2, intfName2='r2-eth0', params2={'ip': '10.2.0.1/24'})

        # Adding hosts specifying the default route
        ws2 = self.addHost(name='ws2', ip='10.1.0.2/24', defaultRoute='via 10.1.0.1')
        ws3 = self.addHost(name='ws3', ip='10.1.0.3/24', defaultRoute='via 10.1.0.1')
        httpServer = self.addHost(name='http', ip='10.12.0.10/24', defaultRoute='via 10.12.0.2')
        dnsServer = self.addHost(name='dns', ip='10.12.0.20/24', defaultRoute='via 10.12.0.2')
        ntpServer = self.addHost(name='ntp', ip='10.12.0.30/24', defaultRoute='via 10.12.0.2')
        ftpServer = self.addHost(name='ftp', ip='10.12.0.40/24', defaultRoute='via 10.12.0.2')

        # Add host-switch links
        self.addLink(ws2, s1)
        self.addLink(ws3, s1)
        self.addLink(httpServer, s2)
        self.addLink(dnsServer, s2)
        self.addLink(ntpServer, s2)
        self.addLink(ftpServer, s2)


topos = {
    "secu": ( lambda: TopoSecu() )
}


def add_routes(net):
    ### STATIC ROUTES ###
    info(net['r1'].cmd("ip route add 10.2.0.0/24 via 10.12.0.2 dev r1-eth12"))
    info(net['r2'].cmd("ip route add 10.1.0.0/24 via 10.12.0.1 dev r2-eth12"))


def start_services(net: Mininet) -> None:
    """
    Start services on servers.
    :param net: Mininet network
    """
    # Apache2 HTTP server
    info(net['http'].cmd("/usr/sbin/apache2ctl -DFOREGROUND &"))
    # dnsmasq DNS server
    info(net['dns'].cmd("/usr/sbin/dnsmasq -k &"))
    # NTP server
    info(net['ntp'].cmd("/usr/sbin/ntpd -d &"))
    # FTP server
    info(net['ftp'].cmd("/usr/sbin/vsftpd &"))

    # SSH server on all servers
    cmd = "/usr/sbin/sshd -D &"
    for host in ['http', 'ntp', 'ftp']:
        info(net[host].cmd(cmd))


def stop_services(net: Mininet) -> None:
    """
    Stop services on servers.
    :param net: Mininet network
    """
    # Apache2 HTTP server
    info(net['http'].cmd("killall apache2"))
    # dnsmasq DNS server
    info(net['dns'].cmd("killall dnsmasq"))
    # OpenNTPd NTP server
    info(net['ntp'].cmd("killall ntpd"))
    # FTP server
    info(net['ftp'].cmd("killall vsftpd"))


def run(fw: str):
    topo = TopoSecu()
    net = Mininet(topo=topo)

    add_routes(net)
    setup_firewall(net, fw)
    stop_services(net)
    time.sleep(1)
    start_services(net)

    net.start()
    CLI(net)
    stop_services(net)
    net.stop()


def ping_all(fw: str):
    topo = TopoSecu()
    net = Mininet(topo=topo)

    add_routes(net)
    setup_firewall(net, fw)
    stop_services(net)
    time.sleep(1)
    start_services(net)

    net.start()
    net.pingAll()
    stop_services(net)
    net.stop()


def setup_firewall(net: Mininet, fw: str) -> None:
    """
    Set up firewall from fw directory with nftables.
    :param net: Mininet network
    """
    fw_dir = Path(f"~/LINFO2347/firewalls/").expanduser().resolve() / fw
    if not fw_dir.exists():
        raise FileNotFoundError(f"Firewall configuration directory {fw_dir} does not exist.")


    dmz_firewall = fw_dir / "dmz.conf"
    r1_firewall = fw_dir / "r1.conf"
    r2_firewall = fw_dir / "r2.conf"
    ws2_firewall = fw_dir / "ws2.conf"
    ws3_firewall = fw_dir / "ws3.conf"

    # check if the firewall configuration files exist
    for file, host in [
            (dmz_firewall, 'http'),
            (dmz_firewall, 'dns'),
            (dmz_firewall, 'ntp'),
            (dmz_firewall, 'ftp'),
            (r1_firewall, 'r1'),
            (r2_firewall, 'r2'),
            (ws2_firewall, 'ws2'),
            (ws3_firewall, 'ws3')
    ]:
        if not file.exists():
            continue
        print(f"Applying firewall rules for {host} from {file}")
        # net[host].cmd(f"nft -f {file}")
        # print the command stdout and stderr
        print(net[host].cmd(f"nft -f {file}"))


if __name__ == '__main__':

    # Command-line arguments
    parser = argparse.ArgumentParser(
        prog="topo.py",
        description="Mininet topology for the network attacks project of the course LINFO2347."
    )
    # Optional flag -p
    parser.add_argument("-p", "--pingall", action="store_true", help="Perform pingall test")
    # optional --fw flag (defaults to `default`)
    parser.add_argument("--fw", help="Firewall configuration to use", default="default")
    # Parse arguments
    args = parser.parse_args()

    setLogLevel('info')

    if args.pingall:
        # Deploy topology, run pingall test, then exit
        ping_all(args.fw)
    else:
        # Deploy topology, open CLI
        run(args.fw)

