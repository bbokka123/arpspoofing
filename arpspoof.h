#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <pcap.h>
#include <pthread.h>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

typedef struct _arp_hdr {
    uint8_t sender_mac1[6];
    uint8_t target_mac1[6];
    uint16_t ethertype;
    uint16_t hd_type;
	uint16_t p_type;
	uint8_t hd_len;
	uint8_t p_len;
	uint16_t opcode;
	uint8_t sender_mac2[6];
	uint8_t sender_ip[4];
	uint8_t target_mac2[6];
	uint8_t target_ip[4];
}arp_hdr;

struct Address {
	uint8_t MAC[6];
	uint8_t IP[4];
};

struct session_class {
	struct Address sender;
	struct Address target;
};

int getpacket(pcap_t *, struct pcap_pkthdr **, const u_char **);
void printMAC(struct Address *);
void printIP(struct Address *);
int getpacket(pcap_t *, struct pcap_pkthdr **, const u_char **);
int isARP(const u_char *p);
void getMACaddr(pcap_t *, struct Address *, struct Address *);
void sendARP(pcap_t *, struct session_class *, struct Address *);
