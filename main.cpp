#include <pcap.h>
#include <map>
#include "airodump.h"

struct info
{
	char ESSID[32];
	int8_t PWR;
	uint8_t ENC;
	uint32_t beacons;
	uint32_t datas;
};

std::map<uint64_t,info> con;

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}
parsed_info out;

const char ENC_l[4][5]={"NULL","WPA ","WPA2","????"};

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
		uint64_t id=0;
		for(int i=0;i<6;i++)
		{
			id<<=8;
			id|=out.BSSID[i];
		}
		con[id].PWR=out.PWR;
		printf("%d ",out.isbeacon);
		if(out.isbeacon)
		{
			con[id].ENC=out.ENC;
			for(int i=0;i<out.ESSID_len;i++)
			{
				con[id].ESSID[i]=out.ESSID[i];
			}
			con[id].ESSID[out.ESSID_len]=0;
			con[id].beacons+=1;
			//printf("ENC:%d ",out.ENC);
			//printf("%s",out.ESSID);
		}
		else
		{
			con[id].datas+=1;
		}
		
		printf("BSSID              PWR Beacons #Data ENC ESSID\n");
		for(auto it=con.begin();it!=con.end();++it)
		{
			id=it->first;
			for(int i=5;i>=0;i--)
			{
				printf("%02x",(id>>(i<<3))&0xFF);
				if(i)printf(":");
			}
			printf("%5d%8d%6d %s %s\n",con[id].PWR,con[id].beacons,con[id].datas,ENC_l[con[id].ENC],con[id].ESSID);
		}
	}
	pcap_close(pcap);
}
