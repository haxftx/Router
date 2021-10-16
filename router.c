#include "skel.h"
#include "struct.h"

void packet_ip(packet m, Trout *rtable, list *larp, queue *packets) {
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header)
																+ sizeof(struct iphdr));
	int i = findRtable(rtable, 0, N - 1, htonl(ip_hdr->daddr));//caut ip in tabela
	if(i == -1) {//daca nu exista trimit mesajul respectiv
		send_icmp(m, ICMP_DEST_UNREACH);
		return;
	}
	int ip = inet_ip(get_interface_ip(rtable[i].interface));//ip intefetei
	if(htonl(ip) == ip_hdr->daddr) {//daca e adreaat router-lui
		if(ip_hdr->protocol == 1 && icmp_hdr->type == ICMP_ECHO) {
			reply_icmp(m);//daca e icmp request trimit replay
		}
		return;
	}else if(ip_hdr->ttl <= 1) {//daca e time exceeded
		send_icmp(m, ICMP_TIME_EXCEEDED);
		return;
	}
	uint16_t sum = ip_hdr->check;
	ip_hdr->check = 0;
	if(sum != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
		return;
	}
	ip_hdr->check = rfc_checksum(sum, ip_hdr->ttl, ip_hdr->protocol);
	ip_hdr->ttl--;
	m.interface = rtable[i].interface;
	Tarp *adr = findArp(larp, ip_int_to_vec((rtable[i].next_hop)));
	if(adr) {//daca am gasit ip in tabela arp
		get_interface_mac(m.interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, adr->mac, sizeof(eth_hdr->ether_dhost));
		send_packet(m.interface, &m);

	} else {//daca nu trimit arp reques
		packet *msg = (packet *)malloc(sizeof(packet));
		memcpy(msg, &m, sizeof(packet));
		queue_enq(*packets, msg);
		send_arp_request(&rtable[i]);
	}
}

void packet_arp(packet m, Trout *rtable, list *arp, queue *packets) {

	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct ether_arp *arp_eth = (struct ether_arp *)(m.payload +
										sizeof(struct ether_header));
	uint32_t dip = ip_vec_to_int(arp_eth->arp_tpa);
	
	if(arp_eth->ar_op == htons(ARPOP_REQUEST)) {//daca e request
		int i = findRtable(rtable, 0, N - 1, dip);//caut ip
		int ip = inet_ip(get_interface_ip(rtable[i].interface));//ip intefetei
		if(ip == dip) {//daca ip interfetei e cel cautat
			//setez datele packetului
			memcpy(arp_eth->arp_tha, arp_eth->arp_sha, sizeof(arp_eth->arp_tha));
			memcpy(arp_eth->arp_tpa, arp_eth->arp_spa, sizeof(arp_eth->arp_tpa));
			memcpy(arp_eth->arp_spa, ip_int_to_vec(ip), sizeof(arp_eth->arp_spa));
			get_interface_mac(rtable[i].interface, arp_eth->arp_sha);
			arp_eth->ar_op = htons(ARPOP_REPLY);
			memcpy(eth_hdr->ether_dhost,eth_hdr->ether_shost,sizeof eth_hdr->ether_dhost);
			memcpy(eth_hdr->ether_shost, arp_eth->arp_sha, sizeof(eth_hdr->ether_shost));
			send_packet(m.interface, &m);//trimit
		}
	} else if(arp_eth->ar_op == htons(ARPOP_REPLY)) {//daca e reply
		Tarp *ip_mac = calloc(1, sizeof(Tarp));
		memcpy(ip_mac->ip, arp_eth->arp_spa, sizeof(ip_mac->ip));
		memcpy(ip_mac->mac, arp_eth->arp_sha, sizeof(ip_mac->mac));
		*arp = cons(ip_mac, *arp);
		struct ether_header *eth_hdr_msg;
		packet *msg;
		while (!queue_empty(*packets)) {//cat sunt packete in coada
			msg = (packet *)queue_deq(*packets);
			eth_hdr_msg = (struct ether_header *)m.payload;
			msg->interface = m.interface;
			memcpy(eth_hdr_msg->ether_dhost, ip_mac->mac, sizeof(ip_mac));
			send_packet(msg->interface, msg);//le trimit
		}
	}
}

int main(int argc, char *argv[]) {

	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;
	init();
	N = lineFile("rtable.txt");
	Trout *rtable = (Trout *)calloc(N , sizeof(Trout));
	DIE(rtable == NULL, "alocare rtable");
	list arp = NULL;
	queue packets = queue_create();
	read_rtable(rtable, "rtable.txt");
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		//verific tipul packetului
		if(eth_hdr->ether_type == htons(ETHERTYPE_IP)) 
			packet_ip(m, rtable, &arp, &packets);
		else if( eth_hdr->ether_type == htons(ETHERTYPE_ARP)) 
			packet_arp(m, rtable, &arp, &packets);	
	}
	while (arp)//eliberez tabela arp
		arp = cdr_and_free(arp);
	while (!queue_empty(packets))//eliberez coada de packete
		queue_deq(packets);
	
	return 0;
}
