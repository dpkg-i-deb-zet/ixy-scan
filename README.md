# ixy-scan
Claims to be the fastest IPv4 Scanner known so far. 10Gbit/s or 14.88Mpps possible! (single core performance)

# Overview
Please read all the instructions regarding ixy here: https://github.com/emmericp/ixy
After you got the example code running (ixy-pktgen can send packets), you can add the ixy-scan.c file to the makefile, and compile it.

# Structure
ixy-scan does three things:
- ARP answering, so that the Router is aware of the ip-address of the machine running ixy-scan.
- Sending SYN packets, configurable at compile time.
- Receiving ACK packets, and prints their ip-address to stdout.

# Happy scanning!
