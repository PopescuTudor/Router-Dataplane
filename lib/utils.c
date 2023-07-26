#include "queue.h"
#include "lib.h"
#include "utils.h"

extern struct arp_entry* arp_cache;
extern int arp_cache_entries;
extern queue arp_queue;

int compare (const void *p, const void *q) {
	uint32_t a = ((struct route_table_entry *)p)->prefix;
    uint32_t b = ((struct route_table_entry *)q)->prefix;
	int res = b - a;
	if(res == 0){
		return ((struct route_table_entry *)q)->mask - ((struct route_table_entry *)p)->mask;
	}
    return res;
}
void generate_icmp(packet *p, uint8_t type, u_int8_t code){
    struct ether_header* eth_hdr = (struct ether_header *)p->payload;
	struct iphdr* ip_hdr = (struct iphdr *)((void*)eth_hdr + sizeof(struct ether_header));
    uint32_t daddr = ip_hdr->daddr;
    uint32_t saddr = ip_hdr->saddr;
    struct iphdr old_ip_hdr;
    struct icmphdr old_icmp_hdr;
    memcpy(&old_ip_hdr, ip_hdr, sizeof(struct iphdr));
    memcpy(&old_icmp_hdr, (void *)ip_hdr + sizeof(struct iphdr), sizeof(struct icmphdr));
    struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0
	};
    if(type == 0 && code == 0){
        icmp_hdr.un.echo.id = old_icmp_hdr.un.echo.id;
        icmp_hdr.un.echo.sequence = old_icmp_hdr.un.echo.sequence;
    }
    else{
        get_interface_ip(p->interface);
        struct in_addr int_ip;
        inet_aton(get_interface_ip(p->interface), &int_ip);
        daddr = int_ip.s_addr;
    }
    uint8_t sha[6];
    memcpy(sha, eth_hdr->ether_shost, 6);
    uint8_t dha[6];
    memcpy(dha, eth_hdr->ether_dhost, 6);

    ip_hdr->protocol = (uint8_t)1;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->frag_off = 0;
    ip_hdr->id = htons(1);
    ip_hdr->tos = 0;
    // ip_hdr->ttl = ip_hdr->ttl - 1;
    ip_hdr->check = 0;
    ip_hdr->daddr = saddr;
    ip_hdr->saddr = daddr;
    ip_hdr->check = htons(0);
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
    icmp_hdr.checksum = 0;
    uint16_t new_check = htons(checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr)));
    icmp_hdr.checksum = new_check;
    memcpy(eth_hdr->ether_dhost, sha, 6);
    memcpy(eth_hdr->ether_shost, dha, 6);

    void * payload = p->payload;
    payload += sizeof(struct ether_header) + sizeof(struct iphdr);
    memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
    p->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    if(!(type == 0 && code == 0)){ //packet error
        ip_hdr->tot_len += ICMP_ERROR_OFFSET;
        p->len = p->len + ICMP_ERROR_OFFSET;
        memcpy(payload + sizeof(struct icmphdr), &old_ip_hdr, sizeof(struct iphdr));
        payload += sizeof(struct icmphdr) + sizeof(struct iphdr);
        memcpy(payload, &old_icmp_hdr, sizeof(struct icmphdr));
        struct icmphdr * new_icmp = (struct icmphdr *)(p->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
        new_icmp->checksum = 0;
        new_icmp->checksum = checksum((uint16_t *)new_icmp, ip_hdr->tot_len - sizeof(struct iphdr));
    }
    
}

int get_arp_entry(uint32_t ip){
    for(int i = 0; i < arp_cache_entries; i++){
        if(arp_cache[i].ip == ip){
            return i;
        }
    }
    return -1;
}
void generate_arp_reply(packet * p){
    struct ether_header * eth_hdr = (struct ether_header *)p->payload;
    struct arp_header * arp_hdr = get_arp_header(p);
    uint8_t this_mac[6];
    uint8_t sender_mac[6];
    //MAC propriu
    get_interface_mac(p->interface, this_mac);
    //MAC sender
    memcpy(sender_mac, arp_hdr->sha, 6);
    // Setez Op 2 (ARP Reply)
    arp_hdr->op = htons(2);
    //setez adresa MAC a senderului ca fiind adresa MAC a destinatarului din ARP Request
    memcpy(arp_hdr->sha, this_mac, 6);
    //setez adresa MAC a destinatarului ca fiind adresa MAC a senderului din ARP Request
    memcpy(arp_hdr->tha, sender_mac, 6);
    uint32_t spa = arp_hdr->spa;
    uint32_t tpa = arp_hdr->tpa;
    // Target IP = Sender IP
    arp_hdr->tpa = spa;
    // Sender-ul este acum destinatarul
    arp_hdr->spa = tpa;
    // Actualizez ETHERNET Header cu adresa MAC a destinatarului
    memcpy(eth_hdr->ether_dhost, sender_mac, 6);
    memcpy(eth_hdr->ether_shost, this_mac, 6);
    p->len = sizeof(struct ether_header) + sizeof(struct arp_header);
}

void generate_arp_request(uint32_t daddr, int next_interface, packet * p){
    memset(p, 0, sizeof(packet));
    struct ether_header * p_eth_hdr = (struct ether_header *)p->payload;
    // Destinatie broadcast 
    for(int i = 0; i < 6; i++){
        p_eth_hdr->ether_dhost[i] = 0xff;
    }
    uint8_t shost[6];
    get_interface_mac(next_interface, shost);
    // Sursa este adresa MAC a interfetei
    memcpy(p_eth_hdr->ether_shost, shost, 6);
    p_eth_hdr->ether_type = htons(0x0806);
    struct arp_header arp_hdr;
    arp_hdr.htype = htons(1);
    arp_hdr.ptype = htons(2048);
    arp_hdr.op = htons(1);
    arp_hdr.hlen = 6;
    arp_hdr.plen = 4;
    memcpy(arp_hdr.sha, shost, 6);
    memset(arp_hdr.tha, 0, 6);
    arp_hdr.spa = inet_network(get_interface_ip(next_interface));
    arp_hdr.tpa = daddr;
    memcpy(p->payload + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
    p->interface = next_interface;
    p->len = sizeof(struct ether_header) + sizeof(struct arp_header);
}

struct arp_header* get_arp_header(packet *p){
    struct arp_header* arp_hdr = NULL;
    arp_hdr = (struct arp_header*)(p->payload + sizeof(struct ether_header));
    return arp_hdr;
}

queue send_waiting_packets(struct arp_header* arp_reply_hdr){
    queue aux = queue_create();
    while(!queue_empty(arp_queue)){
        struct arp_queue_entry *entry = queue_deq(arp_queue);
        if(entry->ip == arp_reply_hdr->spa){
            //Daca exista un pachet in asteptare, il trimit
            entry->p.interface = entry->interface;
            uint8_t mac[6];
            get_interface_mac(entry->interface, mac);
            struct ether_header* eth_hdr = (struct ether_header*)entry->p.payload;
            memcpy(eth_hdr->ether_shost, mac, 6);
            memcpy(eth_hdr->ether_dhost, arp_reply_hdr->sha, 6);
            send_to_link(entry->p.interface, entry->p.payload, entry->p.len);
            free(entry);
        } else {
            //Daca nu, il pun inapoi in coada
            queue_enq(aux, entry);
        }
    }
    return aux;
}


