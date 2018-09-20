#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>

int min(int a, int b){
	if(a<b) return a;
	return b;
}

void dump_data(u_char*p, int len){
	if(len == 0){ 
		printf("None\n");
		return;
	}
	printf("\n");
	for(int i=0; i< len; i++){
		printf("%02x ", *p);
		p++;
		if((i&0x0f) == 0x0f)
			printf("\n");
	}
}

void print_mac(u_char * p){
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
}
	
void print_packet(u_char * p){
	struct ether_header * ehdr = (struct ether_header *) p;
	struct ip * ihdr = (struct ip*)(p+sizeof(ether_header));
	struct tcphdr * thdr = (struct tcphdr*)(p+sizeof(ether_header)+ihdr->ip_hl*4);
	int datalen = ntohs(ihdr->ip_len) - ihdr->ip_hl*4 - thdr->th_off*4;
	u_char * data = p + sizeof(ether_header) + ihdr->ip_hl*4 + thdr->th_off*4;

	if (ntohs(ehdr->ether_type) != ETHERTYPE_IP) return;
	if (ihdr->ip_p != IPPROTO_TCP) return;
	
	printf("--------------------------------------------------\n");
	printf("[MAC src] : ");print_mac(ehdr->ether_shost);
	printf("[MAC dst] : ");print_mac(ehdr->ether_dhost);
	printf("[IP src] : %s\n", inet_ntoa(ihdr->ip_src));
	printf("[IP dst] : %s\n", inet_ntoa(ihdr->ip_dst));
	printf("[Port src] : %hu\n", ntohs(thdr->th_sport));
	printf("[Port dst] : %hu\n", ntohs(thdr->th_dport));
	printf("[Data] : ");
	dump_data(data, min(datalen,32));
	printf("--------------------------------------------------\n\n\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char * argv[]){
/*
	if (argc != 2) {
    usage();
    return -1;
  }
*/
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  //pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  pcap_t * handle = pcap_open_offline("/home/mink/tcp-port-80-test.gilgil.pcap",errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
	print_packet((u_char*)packet);
  }

  pcap_close(handle);
  return 0;
}
