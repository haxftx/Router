#include "skel.h"
#include "struct.h"

int8_t BROADCAST_MAC[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};


void reply_icmp(packet m) {
	//trimite packetul de reply la request catre router
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + 
								sizeof(struct ether_header) + sizeof(struct iphdr));
	uint8_t mac[6];
	memcpy(mac, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_shost, mac, sizeof(eth_hdr->ether_shost));
	uint32_t ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip;
	ip_hdr->check = 0;
	ip_hdr->check = rfc_checksum(ip_hdr->check, ip_hdr->ttl, ip_hdr->protocol);
	icmp_hdr->type =  ICMP_ECHOREPLY;
	ip_hdr->tot_len = ntohl(m.len - sizeof(struct ether_header));
	ip_hdr->ttl--;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = ip_checksum(icmp_hdr,  m.len - 
						(sizeof(struct ether_header) + sizeof(struct iphdr)));
	send_packet(m.interface, &m);
}

void send_icmp(packet m, uint8_t tip) {
	packet m1;//trimite packet icmp Destination unreachable si Time exceeded
	m1.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct ether_header *eth_hdr1 = (struct ether_header *)m1.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	struct iphdr *ip_hdr1 = (struct iphdr *)(m1.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr1 = (struct icmphdr *)(m1.payload + 
								sizeof(struct ether_header) + sizeof(struct iphdr));
	//setez campurile packetului ip
	eth_hdr1->ether_type = htons(ETHERTYPE_IP);
	memcpy(eth_hdr1->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr1->ether_dhost));
	memcpy(eth_hdr1->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr1->ether_shost));
	ip_hdr1->tot_len = m1.len - sizeof(struct ether_header);
	ip_hdr1->protocol = 1;
	ip_hdr1->frag_off = 0;
	ip_hdr1->check = 0;

	if(tip == 3) {//daca e desinatio unrechable
		ip_hdr1->id = ip_hdr->id;
		ip_hdr1->ttl = ip_hdr->ttl--;
	} else if(tip == 11) {//daca e time exceeded
		ip_hdr1->id = 0x1234;
		ip_hdr1->ttl = 255;
	} else return;
	ip_hdr1->daddr = ip_hdr->saddr;
	ip_hdr1->saddr = htons(inet_ip(get_interface_ip(m.interface)));
	ip_hdr1->check = ip_checksum(ip_hdr1, sizeof(ip_hdr1));
	icmp_hdr1->type = tip;
	icmp_hdr1->code = 0;
	icmp_hdr1->checksum = ip_checksum(icmp_hdr1, sizeof(icmp_hdr1));
	m1.interface = m.interface;
	send_packet(m1.interface, &m1);
}

void send_arp_request(Trout *rtable) {//trimite un mesaj de arp request
	packet m;
	uint32_t next_hop = ntohl(rtable->next_hop);
	m.interface = rtable->interface;
	m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	struct ether_header *eth_hdr = (struct ether_header *)(m.payload);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(m.interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, BROADCAST_MAC, ETH_ALEN);
	struct ether_arp *arp_hdr  = (struct ether_arp *)(m.payload + 
															sizeof(struct ether_header));
	arp_hdr->ar_op = htons(ARPOP_REQUEST);
	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(ETHERTYPE_IP);
	arp_hdr->ar_hln = ETH_ALEN;
	arp_hdr->ar_pln = 4;
	uint32_t ip = inet_addr(get_interface_ip(m.interface));
	memcpy(arp_hdr->arp_spa, &ip, sizeof(arp_hdr->arp_spa));
	memcpy(arp_hdr->arp_tpa, &next_hop, sizeof(arp_hdr->arp_tpa));
	memcpy(arp_hdr->arp_tha, BROADCAST_MAC, sizeof(arp_hdr->arp_tha));
	get_interface_mac(m.interface, arp_hdr->arp_sha);
	send_packet(m.interface, &m);
}