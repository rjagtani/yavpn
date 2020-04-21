## Motivation

Our project implements a Client-Server VPN program written in Python.

The motivation of this project is that the public network is not secure. The conversation over public network is exposed to all other users. Therefore, we build a virtual private network to enhance secure and private communication, even though they are in different local networks. 
Besides, we can use the VPN Server as a proxy to hide the client from the public network. 

## Description
The figure concludes the general idea of the project. 
The communication between Client and Server is encrypted through the VPN Tunnel.
All machines are inside the Virtual Private IP Range (10.0.0.0/24). They communicate with each other using that Virtual Private IP
The VPN Server works as a Transport Layer proxy between Clients and Application Servers

## Demo
Here is a quick demo running on two Virtual Machines

## Conclusion

In conclusion, we have achieved these functionalities listed below. But we do have some future works to work on. 
Such as Imporve VPN Server concurrent performance. Add more approaches to encrypt the VPN Tunnel. Also, supporting more protocols in our proxy would be fancy. 

In the end, there are the contacts of all contributors to this project. Thanks for watching 




## Demo

On the left is our VPN Server machine with its IP listed here. The client machine is on the right with another static IP. And we can see its current default gateway in the routing table. 

Now, we start the VPN Server and Client program on each machine respectively. After the connection established, we can see that the new TUN network interface is created on both machines. And the default gateway of the client machine is changed to 10.0.0.1, which is the Virtual Private IP of the Server.

To test the connection between Server and Client, the client tries to ping server by using their Virtual Private IP and vice versa. Both ping requests should succeed and they did. 

As for the proxy functionality, we can apply a more advanced test by sniffing the packets using wireshark to test their behaviors. To keep the result clear, we only focus on the HTTP packets with IPV4. Now we just browse some websites and see the results. 
The results shows that every packet sent out from Client first goes to the VPN Server and the Server spoofed the src IP and forward to the Application Server. The returned packet from the Application server is then forwarded back to the Client. Therefore, from the aspect of a Client Application, it communicates with the App server by using its Virtual Private IP.  


