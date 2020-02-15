## Yet Another VPN

### Background
Nowadays, public users on the internet start to pay more attention to their online privacy and security. 
However, surfing the web on an unsecured Wi-Fi network means you could be exposing your private information 
and browsing habits. The virtual private network (VPN) solves the problem for them. It provides secure and 
encrypted connections to a remote server even in an unsecured network. What’s more, using VPN can let you 
communicate with the outside freely even in a restricted or censored network environment. Therefore, our 
project would implement a VPN server to proxy the client HTTP requests, to encrypt and secure the client 
information. 

### Proposal
The basic method of implementing a VPN is to create an encrypted tunnel between the client and the VPN 
server. The tunnel is built on a virtual network card of the client host, where the client program would 
act as a proxy of all the HTTP requests. It first encapsulates the HTTP request with a tunnel protocol, 
and then sends the packet to the VPN server through the normal protocol stack. 

After receiving the packet through the normal protocol stack, the server decapsulates the tunnel protocol 
and obtains the original HTTP request. Then the server resends the request using its own IP. The server and 
client perform the same reverse process to send it back. 

As for the tunnel protocol, we would choose from ICMP, IP in IP, L2TP, and PPTP protocols, which present 
good performance in the existing VPNs. 

#### Related works

There are many other open source ongoing VPN projects, such as [StrongSwan](https://github.com/strongswan/strongswan), [SoftEtherVPN](https://github.com/SoftEtherVPN/SoftEtherVPN) and [OpenVPN](https://github.com/OpenVPN/openvpn), that we may refer to. 
StrongSwan is one of the most classic VPN project basd on IPsev protocol. 
But as IPS always tends to block IPsec protocol, people start build VPN based on more commonly used protocols. 
For example, OpenVPN runs on TCP or UDP protocol instead of IPsec. 
It uses OPENSSL to encrypt all the data and the authenication process. 
It offers three ways to authenticate each other: pre-shared secret keys, certificates and username/password.
Further on, SoftEtherVPN offers more ways to build up a VPN. 
It can set up a VPN based on Ethernet over HTTPS, L2TP over IPsec, PPP over HTTPS and IP over TCP/UDP (OpenVPN Protocol).
There are also many ditributed VPN projects using peer-to-peer technology, such as [badVPN](https://github.com/shadowsocks/badvpn), in which the data sent between clients do not need go through the center server. 
There are also decentralized VPN projects, such as [radvpn](https://github.com/mehrdadrad/radvpn), who dose not need a central point.


### Hypotheses
VPN server and VPN client program. The user connects to the VPN server through the tunnel created by the 
client program. Then the user can hide its IP information and connect to the public internet with the VPN 
server’s IP exposed to the public. The overhead given by the tunnel encryption and decryption would result 
in transfer delay and even worse slow down the packets transfer speed. Because the tunnel encryption and 
decryption process would be the bottleneck of the transfer. 

One plausible alternative is Physically Private Networking (PPN). PPN is more secure than VPN but it is 
expensive and has many physical restrictions.

### Implementation Design

#### Using `tun` or `tap`
- tun: can only read/write IP packets
- tap: support link layer packets

Because we are implementing a simple VPN we don't need to process link layer packets. For simplicity we will 
use `tun`.
#### TCP or UDP
We have basically 4 types of packet : `tcp in tcp`, `tcp in udp`, `udp in udp`, `udp in tcp`, we need to decide
whether to use `tcp` or `udp` to encapsulate our workload.

If using `tcp`, let's consider `tcp in tcp`. If packet loss happen, tcp will resend the packet. Because our VPN should
not be responsible for resend packet, the actual user and host should be responsible for the resend, which will cause 
a tcp resend storm. Our VPN is not designed to handle such massive workload. For `udp in tcp`, because you don't need
to guarantee sequence and packet loss, it's unnecessary to use `udp in tcp`.

If using `udp`, the `tcp in udp` would be simple, even packet loss happens, the tcp resend would happen again, but from
VPN's view it's just managing `udp` packets, so the workload would be lighter. As for `udp in udp`, because anyway you
don't want guaranteed delivery and sequence or congestion control at all, it's completely ok.

We will use `udp` to encapsulate our workloads, it could be `tcp` or  `udp`, depends on what application we want to 
support. First we will implement `tcp` because we can utilize the existing `tcp` resend and sequence and no extra work
is needed at VPN. `udp` is harder because if any side disconnects, they both won't know. Thus we need a heartbeat 
mechanism to keep the connection. This will be discussed later and as an extension point.


#### Language: Python + C, Platform: Linux

Python is shipped with useful networking-related libraries and is simpler to implement a server compared with C. C 
will introduce a lot of wheel building work and we never had any experience of using C to implement a server. Although 
for VPN, those compiled language is more appropriate in terms of performance and robustness. However we will utilize 
some python tools to integrate with Linux native C library. 

We will only implement Linux VPN, and will not do anything about Windows.



#### Client
Client will be a python application that :
- intercept packets to `eth0` and redirect to `tun`
- read packet from `tun` and encapsulate using `udp`
- create a udp connection with server, send the encapsulated packet to server

#### Server
Server will be a python server that :
- listen on certain ports for new client connection
- receive packets from client, unpack it to retrieve raw packet
- processing the raw packets, forward the packet to somewhere in the internet
- get response from Internet
- encapsulate the packet then send back to client
(TODO) need to ask more about VPN from professor

#### Latency
Because each tunnel will open a file descriptor in the file system for each connection, our python must be multi-threaded.
Along with the encapsulation process, the processing speed might not be able to process so many packets. So as an extension
point, we might use a message queue to store packed request.

#### Heartbeat 
The heartbeat can be implemented as : after server established a tunnel connection with a client, it sends a heartbeat packet
every X second, and the client should respond within Y seconds. If client Y failed to respond, server creates a disconnection 
message to client(which might not arrive) then hang up. The client can simply timeout when no server packets are received
per Z seconds. We have to tune X,Y,Z value so that : not too short to cut healthy connection, or create heartbeat storm.
 
#### Security
This will be an extension point. Because our encapsulated packet are not encrypted, it could be sniffed on the Internet.
To solve this problem, we can use a simple public key mechanism like:
1. Use HTTPS to pass .pem data. 
2. (Optional) use D-H algorithm to negotiate token (but this is too complex, we are very likey not able to get here)
3. Either use token or .pem data to encrypt/decrypt our inner workload




### Experiments

#### Packet Loss Test
There are a lot of packet loss testing tool, we can download one of them and :
1. test the packet loss without VPN
2. test the packet loss with VPN

We will try both tcp and udp.
#### Client/Server disconnect
We will shut down client/server with a force quit. Then we will observe
how fast the server/client will react to the disconnection


#### Max client connection per server
We will launch X client with Y data rate, and test the average performance until
we find the threshold where performance decrease rapidly.

#### Speed/Latency
(TODO)


### Timeline
TODO (We will decide on this together probably on Friday after class)

Feb 15 ~ 23 Reading Break : 
- Set up lab environment
- Implement a Simple Server for only receiving connections

Feb 23 ~ Mar 1
- Implement Client with tunnel set up.

Mar 1 ~ Mar 10
- Implement Server forwarding and response 

Mar 10 ~ Mar 19
- End to End test, bug fixes, 

Mar 20
- Milestone Presentation

Mar 21 ~ 28
- Extension Point: Heartbeat 

Mar 28 ~ Apr 7
- Extension Point: Encryption

Apr 8
Final Project Demo

