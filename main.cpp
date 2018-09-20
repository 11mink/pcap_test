#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>

int min(int32_t a, int32_t b){
	if(a<b) return a;
	return b;
}

void dump_data(uint8_t* p, int32_t len){
	if(len == 0){ 
		printf("None\n");
		return;
	}
	printf("\n");
	for(uint32_t i=0; i< len; i++){
		printf("%02x ", *p);
		p++;
		if((i&0x0f) == 0x0f)
			printf("\n");
	}
}

void print_mac(uint8_t * p){
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
}
	
void print_packet(uint8_t * p){
	struct ether_header * ehdr = (struct ether_header *) p;
	struct ip * ihdr = (struct ip*)((uint8_t*)ehdr + sizeof(ether_header));
	struct tcphdr * thdr = (struct tcphdr*)((uint8_t*)ihdr + ihdr->ip_hl*4);
	uint8_t * data = (uint8_t*)thdr + thdr->th_off*4;
	int32_t data_len = ntohs(ihdr->ip_len) - ihdr->ip_hl*4 - thdr->th_off*4;

	if (ntohs(ehdr->ether_type) != ETHERTYPE_IP) return;
	if (ihdr->ip_p != IPPROTO_TCP) return;
	
	printf("------------------------------------------------\n");
	printf("[MAC src] : ");print_mac(ehdr->ether_shost);
	printf("[MAC dst] : ");print_mac(ehdr->ether_dhost);
	printf("[IP src] : %s\n", inet_ntoa(ihdr->ip_src));
	printf("[IP dst] : %s\n", inet_ntoa(ihdr->ip_dst));
	printf("[Port src] : %hu\n", ntohs(thdr->th_sport));
	printf("[Port dst] : %hu\n", ntohs(thdr->th_dport));
	printf("[Data] : ");
	dump_data(data, min(data_len,32));
	printf("------------------------------------------------\n\n\n");
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
  pcap_t * handle = pcap_open_offline("/home/mink/pcap_test/tcp-port-80-test.gilgil.pcap",errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
	print_packet((uint8_t*)packet);
  }

  pcap_close(handle);
  return 0;
}
