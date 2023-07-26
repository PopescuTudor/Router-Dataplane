#include "queue.h"
#include "lib.h"

#include "utils.h"
struct route_table_entry *rtable;
int rtable_len;

//ARP
struct arp_entry *arp_cache;
int arp_cache_entries;
int arp_table_len;
queue arp_queue;

struct route_table_entry *get_best_route(uint32_t ip_dest)
{

	for (int i = 0; i < rtable_len; i++)
	{

		// Cum tabela este sortata, primul match este prefixul cel mai specific
		if (rtable[i].prefix == (ip_dest & rtable[i].mask))
		{
			printf("Prefixul este %d\n", rtable[i].prefix);
			printf("Interfata este %d\n", rtable[i].interface);
			return &rtable[i];
		}
	}
	return NULL;
}

struct arp_entry *get_mac_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_cache[i].ip == given_ip)
		{
			printf("IP_UL ESTE %d\n", arp_cache[i].ip);
			return &arp_cache[i];
		}
	}
	return NULL;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	arp_cache = calloc(MAX_ARP_ENTRIES, sizeof(struct arp_entry));
	DIE(arp_cache == NULL, "memory");
	arp_cache_entries = 0;
	
	arp_queue = queue_create();
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		int flag = 1;
		uint8_t mac[6];
		get_interface_mac(interface, mac);
		for(int i = 0; i < 6; i++) {
			if(eth_hdr->ether_dhost[i] != mac[i]) {
				printf("Pachetul nu este pentru mine!\n");
				flag = 0;
				break;
			}
		}
		
		if(flag == 0) {
			flag = 1;
			for(int i = 0; i < 6; i++) //broadcast check
			{
				if(eth_hdr->ether_dhost[i] != 0xff) {
					flag = 0;
					break;
				}
			}
		}
		if(flag == 0) continue;
		
		if(eth_hdr->ether_type == htons(0x0800))
		{	
			printf("pachet ip\n");
			struct in_addr int_ip;
			inet_aton(get_interface_ip(interface), &int_ip);
			
			struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));
			printf("%X, %X\n", int_ip.s_addr, ip_hdr->daddr);						
			
			if(int_ip.s_addr == ip_hdr->daddr){ //pachet pt router
				if(ip_hdr->protocol == 1) {
					struct icmphdr *icmp_hdr = (struct icmphdr *) ((void*)ip_hdr+ sizeof(struct iphdr));
					if(icmp_hdr != NULL)
					{
						if(icmp_hdr->type == 8 && icmp_hdr->code == 0) { //icmp echo
							uint16_t old_check = icmp_hdr->checksum;
							icmp_hdr->checksum = 0;
							uint16_t new_check = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));
							if(old_check != new_check) continue;

							packet aux;
							aux.len = len;
							aux.interface = interface;
							memcpy(aux.payload, buf, len);
							generate_icmp(&aux, 0, 0); //icmp echo reply
							send_to_link(aux.interface, aux.payload, aux.len);
							continue;
						}
						else
						{
							printf("Pachetul nu este ICMP ECHO!\n");
							continue;
						}
					}
					else 
					{
						printf("ceva\n");
						continue;
					}
				}
				else
				{
					printf("Pachetul nu este ICMP!\n");
					continue;
				}
    		}
			else //pachetul nu are ca destinatie router-ul
			{
				uint16_t old_check = ip_hdr->check;
				ip_hdr->check = htons(0);
				if(htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) != old_check)
				{
					printf("checksum gresit pt iphdr\n");
					continue;
				}
				if(ip_hdr->ttl <= 1)
				{
					packet aux;
					aux.len = len;
					aux.interface = interface;
					memcpy(aux.payload, buf, len);
					generate_icmp(&aux, 11, 0); //icmp time exceeded
					send_to_link(aux.interface, aux.payload, aux.len);
					printf("tll << \n");
					continue;
				}
				else
				{
					ip_hdr->ttl--;
					ip_hdr->check = 0;
					ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				}
				struct route_table_entry *best_router = get_best_route(ip_hdr->daddr);
				if (best_router == NULL)
				{
					packet aux;
					aux.len = len;
					aux.interface = interface;
					memcpy(aux.payload, buf, len);
					generate_icmp(&aux, 3, 0); //icmp destination unreachable
					send_to_link(aux.interface, aux.payload, aux.len);
					continue;
				}
				
				int arp_entry = get_arp_entry(best_router->next_hop);
				if (arp_entry == -1)
				{
					struct arp_queue_entry* entry = (struct arp_queue_entry*) calloc(1, sizeof(struct arp_queue_entry));
									
					entry->ip = best_router->next_hop;
					entry->p.len = len;
					memcpy(entry->p.payload, buf, len);
					entry->interface = best_router->interface;
					queue_enq(arp_queue, entry);
					packet arp_request;
					generate_arp_request(best_router->next_hop, best_router->interface, &arp_request);
					send_to_link(arp_request.interface, arp_request.payload, arp_request.len);
					continue;
				}
				else
				{
					memcpy(eth_hdr->ether_dhost, arp_cache[arp_entry].mac, 6);
					uint8_t mac[6];
					get_interface_mac(best_router->interface, mac);
					memcpy(eth_hdr->ether_shost, mac, 6);
					int interface = best_router->interface;
				
					send_to_link(interface, buf, len);
					continue;
				}
			}
		}
		else if(eth_hdr->ether_type == htons(0x0806))
		{
			packet m;
			m.len = len;
			m.interface = interface;
			memcpy(m.payload, buf, len);

			struct arp_header* arp_hdr = get_arp_header(&m);
			if(arp_hdr != NULL) {
				arp_cache[arp_cache_entries].ip = arp_hdr->spa;
				memcpy(arp_cache[arp_cache_entries].mac, arp_hdr->sha, 6);
				arp_cache_entries++;
				if(ntohs(arp_hdr->op) == 1){ //arp request
					printf("Am primit un arp request\n");
					packet aux;
					memcpy(&aux, &m, sizeof(packet));
					generate_arp_reply(&aux);
					send_to_link(aux.interface, aux.payload, aux.len);
					continue;
				} else if(ntohs(arp_hdr->op) == 2){ //arp reply
					arp_queue = send_waiting_packets(arp_hdr);
					continue;
				}
			}
			else {
				continue;
			}
		}
		else
		{
			printf("non-IPv4/ARP packet received\n");
			continue;
		}
	}
		
	free(arp_cache);
	free(rtable);
	while(!queue_empty(arp_queue)){
		queue_deq(arp_queue);
	}
	free(arp_queue);
	return 1;
}

