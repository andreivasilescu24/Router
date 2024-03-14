#include "queue.h"
#include "lib.h"
#include "list.h"
#include "queue.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

// TRIE IMPLEMENTATION
typedef struct TrieNode {
    struct TrieNode* node_left; // copilul stang
    struct TrieNode* node_right; // copilul drept
    struct route_table_entry* value; // valoarea nodului reprezntata de o intrare din tabela de rutare
}Node;

Node* create_node() {
    Node* new_node = (Node*)malloc(sizeof(Node));
    new_node->value = malloc(sizeof(struct route_table_entry));
    
    new_node->node_left = NULL;
    new_node->node_right = NULL;
    new_node->value = NULL;

    return new_node;
}

// functia care parcurge arborele Trie si gaseste longest prefix match-ul
struct route_table_entry* longest_prefix_match(uint32_t my_ip, Node* root) {
	uint32_t my_mask = 1;
	Node* actual_node = root;

	uint32_t search_ip = my_ip;
	struct route_table_entry* found_address = NULL;

	while(actual_node) {
		if(actual_node->value) {
			uint32_t possible_prefix = my_ip & actual_node->value->mask;
			if(possible_prefix == actual_node->value->prefix) {
				found_address = actual_node->value;
			}
		}

		uint32_t actual_bit_ip = search_ip & my_mask;
		search_ip = search_ip >> 1;

		if(actual_bit_ip == 1) {
			actual_node = actual_node->node_right;
		} else {
			actual_node = actual_node->node_left;
		}
			
	}

	return found_address;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	
	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry* route_table = malloc(100000 * sizeof(struct route_table_entry));
	int size_route_table = read_rtable(argv[1], route_table);

	// construiesc arborele
	Node* root = create_node();
	uint32_t my_mask = 1;

	for(int index = 0; index < size_route_table; index++) {
		uint32_t actual_prefix = route_table[index].prefix;
		uint32_t actual_mask = route_table[index].mask;

		Node* actual_node = root;
		while(actual_mask & my_mask) {
			uint32_t actual_bit_ip = actual_prefix & my_mask;
			actual_prefix = actual_prefix >> 1;
			actual_mask = actual_mask >> 1;

			if(actual_bit_ip == 1) {
				if(actual_node->node_right == NULL) {
					actual_node->node_right = create_node();
				}
				
				actual_node = actual_node->node_right;
				
			} else {
				if(actual_node->node_left == NULL) {
					actual_node->node_left = create_node();
				}
				
				actual_node = actual_node->node_left;
			}
			
		}
		actual_node->value = &route_table[index];
	}

	list arp_table_list = NULL;
	list aux_arp_table_list;

	queue waiting_arp_queue = queue_create();

	// adresa MAC de broadcast
	uint8_t broadcast_mac[6];
	for(int i = 0; i < 6; i++) {
		broadcast_mac[i] = 0xFF;
	}

	// adresa MAC plina de zero-uri
	uint8_t target_zeros_mac[6];
	for(int i = 0; i < 6; i++) {
		target_zeros_mac[i] = 0x00;
	}


	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// IP
		if(ntohs(eth_hdr->ether_type) == 0x0800) {
			uint8_t *interface_mac = malloc(sizeof(uint8_t) * 6);
			get_interface_mac(interface, interface_mac);
			
			struct iphdr *aux_ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));

			// checksum ok
			uint16_t ex_checksum = ntohs(aux_ip_hdr->check);
			aux_ip_hdr->check = 0;
			uint16_t actual_checksum = checksum((uint16_t*)aux_ip_hdr, sizeof(struct iphdr));
			aux_ip_hdr->check = actual_checksum;
			
			// arunc
			if(actual_checksum != ex_checksum) {
				continue;
			}
			
			char* ip_stored_char = get_interface_ip(interface);

			if(aux_ip_hdr->daddr == inet_addr(ip_stored_char)) {
				struct icmphdr* icmp_hdr_request = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				// RECEIVE ECHO (PING) REQUEST
				if(icmp_hdr_request->type == 8 && icmp_hdr_request->code == 0) {
					icmp_hdr_request->type = 0;
					icmp_hdr_request->checksum = 0;
					icmp_hdr_request->checksum = htons(checksum((uint16_t*)icmp_hdr_request, sizeof(struct icmphdr)));

					uint32_t aux_ip_addr = aux_ip_hdr->daddr;
					aux_ip_hdr->daddr = aux_ip_hdr->saddr;
					aux_ip_hdr->saddr = aux_ip_addr;

					aux_ip_hdr->ttl -= 1;

					uint8_t* aux_mac_addr = malloc(6 * sizeof(uint8_t));
					memcpy(aux_mac_addr, eth_hdr->ether_dhost, 6);
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, aux_mac_addr, 6);

					// SEND ECHO (PING) REPLY
					send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				}
				continue;

			} else {
				// scad ttl
				aux_ip_hdr->ttl -= 1;
				if(aux_ip_hdr->ttl <= 1) {
					// TIME EXCEEDED 
					// ETHER HEADER				
					struct ether_header* new_ether_header = malloc(sizeof(struct ether_header));

					uint8_t* mac_interface_to_send = malloc(6 * sizeof(uint8_t));
					get_interface_mac(interface, mac_interface_to_send);

					memcpy(new_ether_header->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(new_ether_header->ether_shost, mac_interface_to_send, 6);
					new_ether_header->ether_type = eth_hdr->ether_type;

					// IP HEADER
					struct iphdr* new_ip_hdr = malloc(sizeof(struct iphdr));
					new_ip_hdr->tos = 0;
					new_ip_hdr->ihl = 5;
					new_ip_hdr->version = 4;
					new_ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
					new_ip_hdr->id = htons(0x01);
					new_ip_hdr->frag_off = 0;
					new_ip_hdr->ttl = 255;
					new_ip_hdr->protocol = 1;
					new_ip_hdr->saddr = inet_addr(get_interface_ip(interface));
					new_ip_hdr->daddr = aux_ip_hdr->saddr;
					new_ip_hdr->check = 0;
					new_ip_hdr->check = htons(checksum((uint16_t*)new_ip_hdr, sizeof(struct iphdr)));

					// ICMP HEADER
					struct icmphdr* new_icmp_hdr = malloc(sizeof(struct icmphdr));
					new_icmp_hdr->type = 11;
					new_icmp_hdr->code = 0;

					// LINK HEADERS
					void* full_packet = malloc(sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
					memcpy(full_packet, new_ether_header, sizeof(struct ether_header));
					memcpy(full_packet + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
					memcpy(full_packet + sizeof(struct ether_header) + sizeof(struct iphdr), new_icmp_hdr, sizeof(struct icmphdr));
					memcpy(full_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), aux_ip_hdr, (sizeof(struct iphdr) + 8));

					free(new_ether_header);
					free(new_ip_hdr);
					free(new_icmp_hdr);

					// update checksum
					struct icmphdr* aux_icmp_hdr = ((struct icmphdr*)(full_packet + sizeof(struct ether_header) + sizeof(struct iphdr)));
					aux_icmp_hdr->checksum = 0;
					aux_icmp_hdr->checksum = htons(checksum((uint16_t*)aux_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

					send_to_link(interface, (char*)full_packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

					continue;
				}
				
				// CAUTARE TRIE
				struct route_table_entry *found_address = longest_prefix_match(aux_ip_hdr->daddr, root);

				if(!found_address) {
					// DESTINATION UNREACHABLE
					// ether header
					struct ether_header* new_ether_header = malloc(sizeof(struct ether_header));

					uint8_t* mac_interface_to_send = malloc(6 * sizeof(uint8_t));
					get_interface_mac(interface, mac_interface_to_send);

					memcpy(new_ether_header->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(new_ether_header->ether_shost, mac_interface_to_send, 6);
					new_ether_header->ether_type = eth_hdr->ether_type;

					// IP header
					struct iphdr* new_ip_hdr = malloc(sizeof(struct iphdr));
					new_ip_hdr->tos = 0;
					new_ip_hdr->ihl = 5;
					new_ip_hdr->version = 4;
					new_ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
					new_ip_hdr->id = htons(0x01);
					new_ip_hdr->frag_off = 0;
					new_ip_hdr->ttl = 255;
					new_ip_hdr->protocol = 1;
					new_ip_hdr->saddr = inet_addr(get_interface_ip(interface));
					new_ip_hdr->daddr = aux_ip_hdr->saddr;
					new_ip_hdr->check = 0;
					new_ip_hdr->check = htons(checksum((uint16_t*)new_ip_hdr, sizeof(struct iphdr)));

					// ICMP header
					struct icmphdr* new_icmp_hdr = malloc(sizeof(struct icmphdr));
					new_icmp_hdr->type = 3;
					new_icmp_hdr->code = 0;

					// leg headerele
					void* full_packet = malloc(sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
					memcpy(full_packet, new_ether_header, sizeof(struct ether_header));
					memcpy(full_packet + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
					memcpy(full_packet + sizeof(struct ether_header) + sizeof(struct iphdr), new_icmp_hdr, sizeof(struct icmphdr));
					memcpy(full_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), aux_ip_hdr, (sizeof(struct iphdr) + 8));

					free(new_ether_header);
					free(new_ip_hdr);
					free(new_icmp_hdr);

					// update checksum
					struct icmphdr* aux_icmp_hdr = ((struct icmphdr*)(full_packet + sizeof(struct ether_header) + sizeof(struct iphdr)));
					aux_icmp_hdr->checksum = 0;
					aux_icmp_hdr->checksum = htons(checksum((uint16_t*)aux_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

					send_to_link(interface, (char*)full_packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

					continue;
				}
				
				// update checksum
				aux_ip_hdr->check = 0;
				aux_ip_hdr->check = checksum((uint16_t*)aux_ip_hdr, sizeof(struct iphdr));

				// ARP DYNAMIC - stocat intr-o lista
				list arp_iterator = arp_table_list;
				int found_entry = 0;

				//cautare entry existent
				uint8_t mac_next_hop[6];
				while(arp_iterator) {
					if(((struct arp_entry*)arp_iterator->element)->ip == found_address->next_hop) {
						memcpy(mac_next_hop, ((struct arp_entry*)arp_iterator->element)->mac, 6);
						found_entry = 1;
						break;
					}
					arp_iterator = arp_iterator->next;
				}

				// daca nu s-a gasit
				if(found_entry == 0) {
					uint8_t* next_hop_int_mac = malloc(sizeof(uint8_t) * 6);
					get_interface_mac(found_address->interface, next_hop_int_mac);

					// pun pachet in coada
					memcpy(eth_hdr->ether_shost, next_hop_int_mac, 6 * sizeof(uint8_t));
					aux_ip_hdr->check = htons(aux_ip_hdr->check);
					
					void* queue_new_elem = malloc(MAX_PACKET_LEN);
					memcpy(queue_new_elem, buf, len);
					queue_enq(waiting_arp_queue, queue_new_elem);

					// ARP REQUEST
					// ether header
					struct ether_header* eth_hdr_arp = malloc(sizeof(struct ether_header));
					eth_hdr_arp->ether_type = htons(0x0806);
					
					memcpy(eth_hdr_arp->ether_shost, next_hop_int_mac, 6);
					memcpy(eth_hdr_arp->ether_dhost, broadcast_mac, 6);

					// arp header
					struct arp_header* arp_hdr = malloc(sizeof(struct arp_header));
					arp_hdr->htype = htons(1);
					arp_hdr->ptype = htons(0x0800);
					arp_hdr->hlen = 6;
					arp_hdr->plen = 4;
					arp_hdr->op = htons(1);
					memcpy(arp_hdr->sha, next_hop_int_mac, 6);
					memcpy(arp_hdr->tha, target_zeros_mac, 6);
					arp_hdr->spa = (inet_addr(get_interface_ip(found_address->interface)));
					arp_hdr->tpa = (found_address->next_hop);

					// leg headerele pentru a trimite pachetul
					void* arp_request_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
					memcpy(arp_request_packet, eth_hdr_arp, sizeof(struct ether_header));
					memcpy((char*)arp_request_packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

					free(eth_hdr_arp);
					free(arp_hdr);

					// introduc nou entry in arp table
					void* arp_new_entry = malloc(sizeof(struct arp_entry));
					((struct arp_entry*)arp_new_entry)->ip = found_address->next_hop;
					aux_arp_table_list = cons(arp_new_entry, arp_table_list);
					arp_table_list = aux_arp_table_list;

					// trimit pachetul ARP REQUEST
					send_to_link(found_address->interface, (char*)arp_request_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
					continue;
				}
				// daca exista deja un MAC asociat ip-ului next hop-ului
				else {
					uint8_t* found_interface_mac = malloc(sizeof(uint8_t) * 6);
					get_interface_mac(found_address->interface, found_interface_mac);

					memcpy(eth_hdr->ether_dhost, mac_next_hop, 6 * sizeof(uint8_t));
					memcpy(eth_hdr->ether_shost, found_interface_mac, 6 * sizeof(uint8_t));

					aux_ip_hdr->check = htons(aux_ip_hdr->check);
	
					send_to_link(found_address->interface, buf, len);
				}
			}
		// ARP
		} else if(ntohs(eth_hdr->ether_type) == 0x0806) {
			struct arp_header *aux_arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));
			// HANDLER ARP REPLY
			if(ntohs(aux_arp_hdr->op) == 2) {
				uint32_t arp_reply_ip = ntohl(aux_arp_hdr->spa);

				uint8_t* arp_reply_mac = malloc(6 * sizeof(uint8_t));
				memcpy(arp_reply_mac, aux_arp_hdr->sha, 6);

				// trimit pachet IPV4 inapoi
				if(!queue_empty(waiting_arp_queue)) {
					// extrag pachetul corespunzator reply-ului din coada
					void* waiting_packet = queue_deq(waiting_arp_queue);
			
					memcpy(((struct ether_header*)waiting_packet)->ether_dhost, arp_reply_mac, 6);

					// updatez MAC-ul in ARP table la entry-ul corespunzator
					list arp_iterator = arp_table_list;
					memcpy(((struct arp_entry*)arp_iterator->element)->mac, aux_arp_hdr->sha, 6);

					struct iphdr* ip_hdr_waiting_packet = (struct iphdr*)((char*)waiting_packet + sizeof(struct ether_header));

					// CAUTARE TRIE
					struct route_table_entry *found_address = longest_prefix_match(ip_hdr_waiting_packet->daddr, root);

					send_to_link(found_address->interface, (char*)waiting_packet, sizeof(struct ether_header) + sizeof(struct iphdr));
				}
				
			// HANDLER ARP REQUEST 
			} else if(ntohs(aux_arp_hdr->op) == 1) {
					struct arp_header* arp_hdr_request = (struct arp_header*) (buf + sizeof(struct ether_header));
					
					// ether header
					struct ether_header* eth_hdr_arp = malloc(sizeof(struct ether_header));
					eth_hdr_arp->ether_type = htons(0x0806);
					
					memcpy(eth_hdr_arp->ether_dhost, arp_hdr_request->sha, 6);

					// arp header
					struct arp_header* arp_hdr_reply = malloc(sizeof(struct arp_header));
					arp_hdr_reply->htype = htons(1);
					arp_hdr_reply->ptype = htons(0x0800);
					arp_hdr_reply->hlen = 6;
					arp_hdr_reply->plen = 4;
					arp_hdr_reply->op = htons(2);
					memcpy(arp_hdr_reply->tha, arp_hdr_request->sha, 6);
					arp_hdr_reply->spa = arp_hdr_request->tpa;
					arp_hdr_reply->tpa = arp_hdr_request->spa;

					// CAUTARE TRIE
					struct route_table_entry *found_address = longest_prefix_match(arp_hdr_reply->tpa, root);

					uint8_t* reply_mac = malloc(6 * sizeof(uint8_t));
					get_interface_mac(found_address->interface, reply_mac);

					memcpy(eth_hdr_arp->ether_shost, reply_mac, 6);
					memcpy(arp_hdr_reply->sha, reply_mac, 6);

					// leg headerele
					void* arp_reply_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
					memcpy(arp_reply_packet, eth_hdr_arp, sizeof(struct ether_header));
					memcpy((char*)arp_reply_packet + sizeof(struct ether_header), arp_hdr_reply, sizeof(struct arp_header));

					free(eth_hdr_arp);
					free(arp_hdr_reply);

					send_to_link(found_address->interface, (char*)arp_reply_packet, sizeof(struct ether_header) + sizeof(struct arp_header));

					continue;
			}

		} else continue;
	}
}
