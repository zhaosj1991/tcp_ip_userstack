

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sys/poll.h>
#include <arpa/inet.h>

#define NETMAP_WITH_LIBS 

#include <net/netmap_user.h>


#define PROTO_IP		0x0800
#define PROTO_ARP		0x0806

#define PROTO_UDP		17
#define PROTO_ICMP		1

#pragma pack(1)

#define ETH_MAC_LENGTH		6


#define NETWORK_NAME 	"netmap:ens33"
#define HOST_IP			"192.168.6.132"
#define HOST_MAC		"00:0c:29:fd:ad:be"

struct ethhdr {

	unsigned char h_dest[ETH_MAC_LENGTH];
	unsigned char h_source[ETH_MAC_LENGTH];
	unsigned short h_proto;

};


struct iphdr {

	unsigned char version;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short flag_off;
	unsigned char ttl;
	unsigned char proto;
	unsigned short check;

	unsigned int saddr;
	unsigned int daddr;

	//unsigned char opt[0];

};


struct udphdr {

	unsigned short sport;
	unsigned short dport;
	unsigned short len;
	unsigned short check;

};

struct udppkt {

	struct ethhdr eh;
	struct iphdr ip;
	struct udphdr udp;

	unsigned char body[0];

};


struct arphdr {

	unsigned short h_type;
	unsigned short h_proto;
	unsigned char h_addrlen;
	unsigned char protolen;
	unsigned short oper;
	unsigned char smac[ETH_MAC_LENGTH];
	unsigned int sip;
	unsigned char dmac[ETH_MAC_LENGTH];
	unsigned int dip;

};

struct arppkt {

	struct ethhdr eh;
	struct arphdr arp;

};


/*struct icmphdr {

	unsigned char type;
	unsigned char code;
	unsigned short check;
	
};

struct icmpecho {

	unsigned short id;
	unsigned short seq;
	unsigned char data[32];
	
};

struct icmppkt {

	struct ethhdr eh;
	struct iphdr ip;
	struct icmphdr icmp;
	union {

		struct icmpecho echo;

	};
	
};*/

struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short check;
	unsigned short identifier;
	unsigned short seq;
	unsigned char data[0];
};

struct icmppkt {
	struct ethhdr eh;
	struct iphdr ip;
	struct icmphdr icmp;
};

unsigned short ip_cksum(unsigned short* buffer, int size)
{
	unsigned long cksum = 0;
	while(size>1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if(size)
	{
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum>>16) + (cksum&0xffff); 
	cksum += (cksum>>16); 
	return (unsigned short)(~cksum);
}

unsigned short in_cksum(unsigned short *addr, int len) {

	register int nleft = len;
	register unsigned short *w = addr;
	register int sum = 0;
	unsigned short answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	
	sum += (sum >> 16);			
	answer = ~sum;
	
	return (answer);

}

int str2mac(char *mac, char *str) {

	char *p = str;
	unsigned char value = 0x0;
	int i = 0;

	while (p != '\0') {
		
		if (*p == ':') {
			mac[i++] = value;
			value = 0x0;
		} else {
			
			unsigned char temp = *p;
			if (temp <= '9' && temp >= '0') {
				temp -= '0';
			} else if (temp <= 'f' && temp >= 'a') {
				temp -= 'a';
				temp += 10;
			} else if (temp <= 'F' && temp >= 'A') {
				temp -= 'A';
				temp += 10;
			} else {	
				break;
			}
			value <<= 4;
			value |= temp;
		}
		p ++;
	}

	mac[i] = value;

	return 0;
}

void echo_arp_pkt(struct arppkt *arp, struct arppkt *arp_rt, char *hmac) {

	memcpy(arp_rt, arp, sizeof(struct arppkt));

	memcpy(arp_rt->eh.h_dest, arp->eh.h_source, ETH_MAC_LENGTH);
	str2mac(arp_rt->eh.h_source, hmac);
	arp_rt->eh.h_proto = arp->eh.h_proto;

	arp_rt->arp.h_addrlen = 6;
	arp_rt->arp.protolen = 4;
	arp_rt->arp.oper = htons(2);
	
	str2mac(arp_rt->arp.smac, hmac);
	arp_rt->arp.sip = arp->arp.dip;
	
	memcpy(arp_rt->arp.dmac, arp->arp.smac, ETH_MAC_LENGTH);
	arp_rt->arp.dip = arp->arp.sip;

}

/*void echo_icmp_pkt(struct icmppkt *icmp, struct icmppkt *icmp_rt)
{
	printf("echo_icmp_pkt step into !!!\n");
	memcpy(icmp_rt, icmp, sizeof(struct icmppkt));
	icmp_rt->icmp.code = 0;
	icmp_rt->icmp.type = 0;
	icmp_rt->icmp.check = 0;
	memcpy(icmp_rt->eh.h_dest, icmp->eh.h_source, ETH_MAC_LENGTH);
	memcpy(icmp_rt->eh.h_source, icmp->eh.h_dest, ETH_MAC_LENGTH);

	icmp_rt->ip.daddr = icmp->ip.saddr;
	icmp_rt->ip.saddr = icmp->ip.daddr;
	
	icmp_rt->icmp.check = htons(in_cksum((unsigned short *)icmp_rt, sizeof(struct icmppkt)));
	//icmp_rt->ip.check = htons(in_cksum((unsigned short *)&icmp_rt->ip, sizeof(struct iphdr)));
}*/

void nty_icmp_pkt(struct icmppkt *icmp, struct icmppkt *icmp_rt, int icmp_len) 
{
	printf("step into nty_icmp_pkt !!!\n");
	
	memcpy(icmp_rt, icmp, icmp_len);

	printf("step into nty_icmp_pkt  2  !!!\n");

	icmp_rt->icmp.type = 0x0; //
	icmp_rt->icmp.code = 0x0; //
	icmp_rt->icmp.check = 0x0;

	icmp_rt->ip.saddr = icmp->ip.daddr;
	icmp_rt->ip.daddr = icmp->ip.saddr;

	memcpy(icmp_rt->eh.h_dest, icmp->eh.h_source, ETH_MAC_LENGTH);
	memcpy(icmp_rt->eh.h_source, icmp->eh.h_dest, ETH_MAC_LENGTH);

	icmp_rt->icmp.check = in_cksum((unsigned short *)&icmp_rt->icmp, icmp_len);
	//icmp_rt->ip.length = htons(icmp_len + sizeof(struct iphdr));
	//icmp_rt->ip.check = 0;
	//icmp_rt->ip.check = htons(ip_cksum((unsigned short *)&icmp_rt->ip, sizeof(struct iphdr)));
}


int main() {

	struct nm_desc *nmr = nm_open(NETWORK_NAME, NULL, 0, NULL);
	if (nmr == NULL) {
		return -1;
	}

	struct pollfd pfd = {0};
	pfd.fd = nmr->fd;
	pfd.events = POLLIN;

	unsigned char *stream = NULL;
	struct nm_pkthdr h;

	while (1) {

		int ret = poll(&pfd, 1, -1);
		if (ret < 0) continue;

		if (pfd.revents & POLLIN) {

			stream = nm_nextpkt(nmr, &h);
			struct ethhdr *eh = (struct ethhdr*)stream;

			printf("proto: %x\n", ntohs(eh->h_proto));
			if (ntohs(eh->h_proto) == PROTO_IP) {

				struct icmppkt *icmp = (struct icmppkt *)stream;
				if (icmp->ip.proto == PROTO_ICMP) {

					if (icmp->icmp.type == 8 &&  icmp->icmp.code == 0) {

						int icmp_len = icmp->ip.length - sizeof(struct iphdr);
						struct icmppkt *icmp_rt = (struct icmppkt *) malloc(icmp_len);
						memset(icmp_rt, 0, icmp_len);
						nty_icmp_pkt(icmp, icmp_rt, icmp_len);
						nm_inject(nmr, icmp_rt, icmp_len);
						free(icmp_rt);
						continue;
					}

				}

				struct udppkt *udp = (struct udppkt *)stream;
				
				printf("udp->ip.proto: %d\n", udp->ip.proto);
				if (udp->ip.proto == PROTO_UDP) {

					int udp_length = ntohs(udp->udp.len);

					udp->body[udp_length-8] = '\0';
					printf("udp-> %s\n", udp->body);
				
				}
				
			} else if (ntohs(eh->h_proto) == PROTO_ARP) {

				struct arppkt *arp = (struct arppkt*)stream;
				struct arppkt arp_rt;

				if (arp->arp.dip == inet_addr(HOST_IP)) {

					echo_arp_pkt(arp, &arp_rt, HOST_MAC);
					nm_inject(nmr, &arp_rt, sizeof(struct arppkt));
					
				}
				

			}
			
		}

	}

}



