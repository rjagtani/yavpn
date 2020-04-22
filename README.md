# YAVPN
A Client-Server VPN program and TCP proxy, writen in Python3. 

## Install
You should run the `server.py` and `client.py` on different machines.

### Virtual Machines
For a simple local test, You can run on the **Ubuntu-16.04** Virtual Machine locally. 
- VM Image: You can use the **Seed Lab Ubuntu-16.04 Image**, link: https://seedsecuritylabs.org/lab_env.html. The official user manual: https://seedsecuritylabs.org/Labs_16.04/Documents/SEEDVM_VirtualBoxManual.pdf
- Network Setting: Each VM needs a fixed and unique IP address. You can the VM in **Oracle VM VirtualBox** with the *Network Bridge* Network Setting. 

### Requirements
The VPN program runs on Python3.5+, you can choose to use the *virtual python environment* in the `venv` directory, or install 
the packets in the `requirements.txt` on your local Python3 environment

### Run on Local Python3 Env
- install packets by pip3. `pip3 install -r requirements.txt`
- change directory to the project root
- run VPN Server: `sudo python3 server.py`
- run VPN Client: `sudo python3 client.py <server's IP> 2003`
    - if you want to get the Server's IP, run this command `ifconfig`

### Run on Virtual Python3 Env
- switch to root user: `sudo -i`
- change directory to the project root
- activate the virtual env: `source ./venv/bin/activate`
- run VPN Server: `python3 server.py`
- run VPN Client: `python3 client.py <server's IP> 2003`
    - if you want to get the Server's IP, run this command `ifconfig`


## Test

### Simple Ping Test

You can apply a simple ping test to check if the program runs properly. 

1. Finish the installation above, have Client and Server running
2. Check Client machine's network interfaces and routing table
    1. run command: `ifconfig`, and there should be a network interface named `tun0`
    2. run command: `route`, and the default gateway should be `10.0.0.1` thourgh `tun0` device

3. on client machine `ping 10.0.0.1 -c 4` which is the Server's Virtual Private IP 
    you should receive ping replies from the server

4. on client machine `ping 8.8.8.8 -c 4` which is the google DNS Server's IP
    you should also receive ping replies from the server

### Packet Sniff Test

You can run the WireShark to sniff the traffic of `tun0` on Client, and sniff the traffic of the true `ethernet` device on Server. 
And then browse some websites on the Client machine.

- You should see that all the IPV4 packets are routed to the Server through **VPN Tunnel** -- `tun0` device. 
- And those packets are forwarded to the App Server by the VPN Server (src IP spoofed to the VPN Server's IP)
- The returned packets are then forwarded to the VPN Client (dst IP spoofed to the VPN Client's IP)
- The proxy only supports `TCP`, `UDP`, and `ICMP` protocols. 


## Useful Tools

### Route table
- **route**
    - `route -n`: show all the route rules without name resolution
    - `route add/del -host/-net <IP> gw <IP> dev <network device name>`: add and delete route rules.
    - [route tutorial](https://www.computerhope.com/unix/route.htm)

- **pyroute2**
    - python module to interact with Linux Routing
    - `IPRoute()` has methods to get routing information and modify routing table
    - [IPRoute doc](https://docs.pyroute2.org/iproute.html)

### Socket
- **socket**
    - use python built-in socket module
    - [socket tutorial](https://realpython.com/python-sockets/)

### Packet
- **tshark**
    - packet sniffing and analysis

- **scapy**
    - process raw IP packet
