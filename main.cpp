#include <pcap.h>
#include "airodump.h"

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}
parsed_info out;

int main(int argc, char* argv[]) {
	if(argc!=2){
		usage();
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		parse(header->caplen,packet,&out);
	}
	pcap_close(pcap);
}
