#ifndef _UTILS_H_
#define _UTILS_H_

#include "lib.h"
#include "queue.h"


#define MAX_ARP_ENTRIES 15
#define ICMP_ERROR_OFFSET 64

struct arp_queue_entry{
    packet p;
    uint32_t ip;
	int interface;
};

void generate_icmp(packet *p, uint8_t type, u_int8_t code);

int compare (const void *p, const void *q);

int get_arp_entry(uint32_t ip);

void generate_arp_reply(packet * p);

void generate_arp_request(uint32_t daddr, int next_interface, packet * p);

queue send_waiting_packets(struct arp_header* arp_reply_hdr);

struct arp_header* get_arp_header(packet *p);

#endif /* _UTILS_H_ */