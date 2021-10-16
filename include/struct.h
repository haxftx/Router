#pragma once

int N;//numarul de elemente din tabela de rutare
typedef struct rute {//structura datelor din tabela de rutare
	uint32_t prefix, next_hop, mask, interface;
}Trout;

typedef struct arp {//structura datelor din tabela arp
	uint8_t ip[4];
	uint8_t mac[ETH_ALEN];
}Tarp;

struct	ether_arp {
	unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
	uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	uint8_t arp_spa[4];		/* sender protocol address */
	uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	uint8_t arp_tpa[4];		/* target protocol address */
};

uint32_t inet_ip(char *ip);
uint32_t ip_vec_to_int(uint8_t *ip);
uint8_t * ip_int_to_vec(uint32_t ip);
int lineFile(char *name_file);
Trout *setTrout(char *line_route);
int compareTrout(const void *a, const void *b);
int compareIp(Trout t, uint32_t ip);
int findRtable(Trout *table, int left, int right, uint32_t ip);
void read_rtable(Trout *table, char *name_file); 
uint16_t rfc_checksum(uint16_t old_checksum, uint8_t ttl, uint8_t protocol);
Tarp *findArp(list *table, uint8_t *ip);
void reply_icmp(packet m);
void send_icmp(packet m, uint8_t type_icmp);
void send_arp_request(Trout *data);
void packet_ip(packet m, Trout *rtable, list *atable, queue *pakets);
void packet_arp(packet m, Trout *rtable, list *atable, queue *pakets);