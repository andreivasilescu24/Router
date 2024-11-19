### Longest Prefix Match

For finding the longest prefix match, I used the Trie tree implementation. In the beginning of the `main()` function, I read the entries from the routing table into a vector. Then, I constructed the Trie tree: for each entry in the routing table, based on a bit of 0 or 1 in the prefix address, I moved to the left or right child in the tree, creating the respective node if necessary. Both the prefix and the mask are shifted by one bit during each iteration in the while loop, which continues until the mask's 1 bits are exhausted. Once the loop ends, the entire routing entry is stored in the value field of the node where the traversal stops. Therefore, a routing entry will be found in a node at a depth equal to the length of the entry's mask.

I also implemented a function that traverses the Trie tree to find the longest matching prefix. This function checks if the bit in the target IP address is 0 or 1 and traverses the tree accordingly (to the left or right child). At each node, it checks if a value is present, as this may be a potential match. However, the traversal does not stop at the first node with a NULL value because we are searching for the longest prefix. Thus, we continue as deep as possible into the tree, and the last node along the path containing a value is the correct match (it has the longest mask).

In the loop where packets are continuously received, after a packet is received, it will first be checked whether it is an IPV4 or ARP packet. If it is neither, it will be discarded.

---

### **IPV4 Case**

If an IPV4 packet is received, the checksum is recalculated and compared with the checksum in the packet. If the checksums do not match, the packet is discarded, as it indicates packet corruption. If the checksums match, the program continues. It will check if the destination IP of the packet matches the router's IP. In this case, it will check if it is an ICMP Echo (Ping) Request. If so, it will send back an ICMP Echo Reply to the source, modifying the ICMP header to reflect the new type (Reply).

If the destination IP is not the router's IP, it means the packet must be routed further. The TTL (Time-to-Live) field will be decremented by 1, and if TTL is less than or equal to 1, an ICMP "Time Exceeded" message will be sent back to the source. The headers for Ethernet, IPV4, and ICMP will be created separately, and then they will be linked in memory using `memcpy` to form a continuous memory block. After this, the ICMP message is sent, and the program waits for a new packet.

If the TTL is still valid, the longest prefix match is searched for in the Trie tree using the method described above, to find the appropriate destination for routing the packet. If no match is found, an ICMP "Destination Unreachable" message will be sent to the source, following the same procedure as for the "Time Exceeded" message, except the ICMP type will differ. The program will then wait for the next packet.

If a match is found in the Trie tree, the checksum is updated after decreasing the TTL, and the next hop's IP address is looked up in the dynamic ARP table. If the next hop’s IP is found in the ARP table, the destination MAC address will be updated with the MAC address from the table, and the source MAC will be updated using the `get_interface_mac` function for the interface found in the Trie entry. If the next hop’s IP address is not found in the ARP table, an Ethernet header and an ARP header will be created, linked together in memory, and the ARP request will be sent. Additionally, the IP and MAC of the next hop will be added to the dynamic ARP table, with the MAC still unknown. The destination MAC in the Ethernet header will be set to the broadcast address `FF:FF:FF:FF:FF:FF`, and the source MAC will be the interface's MAC from the entry found in the Trie. The ARP request is then sent.

---

### **ARP Case**

There are two cases: receiving an ARP Reply or an ARP Request, determined by the value of the "op" field (1 for Request, 2 for Reply).

- **ARP Reply:**  
  If an ARP Reply is received, it corresponds to a previous ARP Request sent by the router. The source MAC address from the ARP Reply will be used to update the destination MAC address for a previously queued packet whose destination MAC was unknown. The program will then search for the longest matching prefix for the destination IP address in the Trie, and once the match is found, the interface will be determined. The ARP table entry for the unknown IP will be updated with the received MAC address for future lookups. Finally, the packet is sent on the correct interface with the updated destination MAC.

- **ARP Request:**  
  If an ARP Request is received, the router will reply with an ARP Reply. The Ethernet and ARP headers will be created and linked together in memory, containing the correct IP and MAC addresses. The source MAC address in the ARP Reply will be the MAC address of the interface corresponding to the IP address from which the Request was received. The "op" field will be set to 2 (Reply), and the Reply will be sent on the correct interface.
