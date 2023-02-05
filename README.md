# YAVPN
A Client-Server VPN program writen in Python3. 

## Install
You should run the server.py and client.py on two different Virtual Machines.

### Virtual Machines 
For a simple local test, You can run on the Ubuntu-16.04 Virtual Machine locally. 
- VM Image: You can get Ubuntu 16.04.7 LTS Image using the following link: https://releases.ubuntu.com/16.04/.
- Setting up Virtual Box: You can use the following documentation to set up your VM to ensure proper connectivity: https://seedsecuritylabs.org/Labs_16.04/Documents/SEEDVM_VirtualBoxManual.pdf
- VM Image: The official user manual: https://seedsecuritylabs.org/Labs_16.04/Documents/SEEDVM_VirtualBoxManual.pdf
- Network Setting: Each VM needs a fixed and unique IP address. You can the VM in Oracle VM VirtualBox with the *Network Bridge* Network Setting. 
- (Edit, document says something else) Before running the program, it's crucial to properly configure the network adapter. Please follow these steps: 
  - Attach the network adapter to a bridged adapter. 
  - Set the Promiscuous mode to "Allow VMs".
 

### Requirements
The VPN software operates with Python3.5. You have the option to either utilize the virtual Python environment located in the venv folder or install the necessary packages listed in requirements.txt to your local Python3 setup.

### Run on Virtual Python3 Env
- Switch to root user: sudo -i
- Change directory to the project root
- Activate the virtual env: source ./venv/bin/activate
- Run VPN Server: python3 server.py
- Run VPN Client: python3 client.py <server's IP> 2003
    - If you want to get the Server's IP, run this command ifconfig

### Adjusting Configuration Variables :
- To select the preferred encryption algorithm, simply modify the PREFERENCE variable located in the config.py file. Depending on your specific needs, choose the encryption algorithm that best suits your requirements. Select 1 for Fernet and 2 for RC4



## Useful Tools

### Route table
- route
    - route -n: show all the route rules without name resolution
    - route add/del -host/-net <IP> gw <IP> dev <network device name>: add and delete route rules.
    - [route tutorial](https://www.computerhope.com/unix/route.htm)

- pyroute2
    - python module to interact with Linux Routing
    - IPRoute() has methods to get routing information and modify routing table
    - [IPRoute doc](https://docs.pyroute2.org/iproute.html)

### Socket
- socket
    - use python built-in socket module
    - [socket tutorial](https://realpython.com/python-sockets/)

### Packet
- tshark
    - packet sniffing and analysis

- scapy
    - process raw IP packet