# YAVPN
A point-to-point VPN Client-Server program, writen in Python3. 

## Run VPN
You should run the server and client on different machines.
You may create two VMs with Network Bridge mode so that both of them has static IP
### Server
- command `sudo python3 server.py`

### Client
- command `sudo python3 client.py <server's IP> 2003`
- 2003 is the port that server is listening on

## Simple Test
You can apply a simple test to check if the program runs properly. 
- on client machine `ping 10.0.0.1 -c 4` which is the server machine
- you should receive ping replies from the server

- on client machine `ping 8.8.8.8 -c 4` which is the google DNS server
- you should receive ping replies from the server

Also, you can check your route table that all your traffic sends through the TUN device

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
