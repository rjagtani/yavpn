## TUN device
- The TUN would add four bytes `\x00\x00\x08\x00` to the front of an IP packet, everytime you read from the TUN device. 
    - These four bytes acts as an identity of an ethernet frame
- When you write an IP packet to the TUN device, you should also add four bytes `\x00\x00\x08\x00` to the front of that IP packet.

## Disable TCP Reset Packet
`sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`

## Raw Socket
- `socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)`
- sniff all the packets that satisfy the filtering requirements (For example, filtering on the Protocol type)
- `socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)` let the raw socket include IP header
- raw socket directly sends the IP packet. It does not process the Transport layer
