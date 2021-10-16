#include "skel.h"
#include "struct.h"

uint32_t inet_ip(char *str) {//transforma dintrun strin intrun int ip
	int val = 0;
	uint32_t ip = 0;
	for(int i = 0; i < strlen(str); i++) {
		if(str[i] >= '0' && str[i] <= '9') {
			val += (str[i] - '0');
		} if(str[i] == '.'){
			ip <<= 8; 
			ip |= (val / 10);
			val = 0;
		}
		val *= 10;
	}
	ip = (ip << 8) | (val / 10);
	return ip;
}

uint32_t ip_vec_to_int(uint8_t *ip) {//transforma ip-l intr-un int
	uint32_t res = 0;
	for(int i = 0 ; i < 4 ; i++) {
		res = res << 8 | ip[i];
	}
	return res;
}

uint8_t *ip_int_to_vec(uint32_t ip){
	uint8_t *res = calloc(4, sizeof(uint8_t));
	DIE(res == NULL, "eroare calloc");
	for(int i = 0 ; i < 4; i++)
		res[i] = (ip >> 8 * (3 - i));
	
	return res;
}

int lineFile(char *name) {//calculeaza liniile din fisierul tabelei de rutare
	FILE *file = fopen(name, "r");
	DIE(file == NULL, "nu exista fisierul");
	int count = 0;
	char buff[50];
	while(fgets(buff, sizeof(buff), file) != NULL){
		count++;
	}
	return count;
}

uint16_t rfc_checksum(uint16_t hc, uint8_t ttl, uint8_t protocol) {
	//calculare checksum incremental
	uint16_t m = ttl;
	m <<= 8;
	m += protocol;
	uint16_t mp = ttl--;
	mp <<= 8;
	mp += protocol;
	return hc - ~m - mp;
}

Trout *setTrout(char *str) {//creaza o linie din tabela de rutare
	char *token = strtok(str, " ");
	int j = 0;
	uint32_t ip;
	Trout *rute = (Trout *)malloc(sizeof(Trout));
	DIE(rute == NULL, "alocare de memorie");
	while(token != NULL){
		ip = inet_ip(token);
		if(j == 0)
			rute->prefix = ip;
		if(j == 1)
			rute->next_hop = ip;
		if(j == 2)
			rute->mask = ip;
		if(j == 3)
			rute->interface = atoi(token);
		j++;
		token = strtok(NULL, " ");
	}
	return rute;
}

int compareTrout(const void *a, const void *b) {
	//compara 2 celule din tabela de rutare
	Trout p = *(const Trout*)a;
	Trout q = *(const Trout*)b;
	if(p.prefix == q.prefix)
		return p.mask - q.mask;
	return p.prefix - q.prefix;
}

int compareIp(Trout t, uint32_t x) {//compara 2 ip in dependenta de mask
	return (t.prefix & t.mask) - (x & t.mask);
}

int findRtable(Trout *vec, int l, int r, uint32_t x) {//cauta un ip in tabela
    if (r >= l) { 
        int mid = l + (r - l) / 2;
		int f = compareIp(vec[mid], x);
        if (!f) {//daca am gasit ip-l aleg pe cel cu maska mai mare
			while(vec[mid].prefix == vec[mid + 1].prefix)
				mid++;
			return mid;
		}
        if (f > 0) 
            return findRtable(vec, l, mid - 1, x); 

        return findRtable(vec, mid + 1, r, x); 
    }
    return -1; 
} 

void read_rtable(Trout *rtable, char *name) {
	//citeste tabela de rutare din fisier
	FILE *in = fopen(name, "r");
	DIE(in == NULL, "nu exista fisierul");
	char buff[50];
	int i = 0;
	while(fgets(buff, 50, in) != NULL) {
		memcpy(&rtable[i++], setTrout(buff), sizeof(Trout));
	}
	qsort(rtable, N, sizeof(Trout), compareTrout);//sorteaza
}

Tarp *findArp(list *larp, uint8_t *ip) {//cauta in tabela arp un ip
	list l = *larp;
	Tarp *cel;
	while (l) {
		cel = (Tarp *)(l->element);
		if(ip_vec_to_int(ip) == ip_vec_to_int(cel->ip))
			return cel;
		l = l->next;
	}
	return NULL;
}