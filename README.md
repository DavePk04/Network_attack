# LINFO2347 Project Network Attacks 2023-2024

### Names: Dave Pikop, Anton Romanova 

## Project Overview

## Table of Contents
- [Project Overview](#project-overview)
- [Basic enterprise network protection](#Basic-enterprise-network-protection)
- [Network Attacks](#network-attacks)
- [Network Protection](#network-protection)
- [Launch topology attacks and protection](#Launch-topology-attacks-and-protection)

## Basic enterprise network protection
In the new version of the network, we have implemented a firewall using the nftables
tool. The configuration script is located in the `topo-basic-protection.sh` file."

To run the new configuration, execute the following command:

```sudo -E python3 ~/LINFO2347/topo-basic-protection.sh```

## Test the Firewall

Our `nftables` firewall configuration was tested using the `pingall` command, yielding the following results:

- DMZ servers (`dns`, `ftp`, `http`, `ntp`): Could not ping any hosts, aligning with the policy to prevent DMZ servers from initiating connections.
- Internet host: Only able to ping routers (`r1`, `r2`), not other hosts, indicating proper restrictions are in place against direct access to the internal network.
- Routers (`r1`, `r2`): Can ping each other and workstations (`ws2`, `ws3`), as expected for routers.
- Workstations (`ws2`, `ws3`): Can ping each other and routers, confirming that workstation communication is unrestricted within the internal network.

Overall, 77% packet loss indicates that the firewall is effectively blocking undesired traffic. The test results mostly align with our network policies, though further review is required for the `internet` host's inability to ping DMZ servers, which should be allowed.


[//]: # (We tested the network firewall rules. Here are the results:)

[//]: # ()
[//]: # (1. `ws2 ping ws3`: Ping worked. Workstations can talk to each other.)

[//]: # (2. `ws2 ping http`: Ping worked. DMZ servers can only respond to incoming connections.)

[//]: # (3. `http ping ws2`: Ping blocked. DMZ servers cannot send any ping or initiate any connection.)

[//]: # (4. `internet ping dns`: Ping worked. Internet can talk to DMZ servers.)

[//]: # (5. `internet ping ws2`: Ping blocked. Correct, internet should not talk to workstations.)