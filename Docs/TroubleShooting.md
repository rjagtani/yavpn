## TUN device
- The TUN would add four bytes `\x00\x00\x08\x00` to the front of an IP packet, everytime you read from the TUN device. 
    - These four bytes acts as an identity of an ethernet frame
- When you write an IP packet to the TUN device, you should also add four bytes `\x00\x00\x08\x00` to the front of that IP packet.