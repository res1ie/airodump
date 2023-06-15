#include "airodump.h"


static int fcshdr = 0;

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
	case IEEE80211_RADIOTAP_FLAGS:
	case IEEE80211_RADIOTAP_RATE:
	case IEEE80211_RADIOTAP_CHANNEL:
	case IEEE80211_RADIOTAP_FHSS:
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		printf("\tsignal: %d\n", (char)*iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_ANTENNA:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_TX_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
		if (fcshdr) {
			printf("\tFCS in header: %.8x\n",
				le32toh(*(uint32_t *)iter->this_arg));
			break;
		}
		printf("\tRX flags: %#.4x\n",
			le16toh(*(uint16_t *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}


static const struct radiotap_override overrides[] = {
	{ .field = 14, .align = 4, .size = 4, }
};


void parse(uint32_t len,const u_char* packet,struct parsed_info *out)
{
	struct ieee80211_radiotap_iterator iter;
	int err;
	out->isbeacon=false;
	out->ESSID_len=0;
	out->ENC=0;
	if(err=ieee80211_radiotap_iterator_init(&iter, packet, len, &vns))
	{
		printf("malformed radiotap header (init returned %d)\n",err);
		return;
	}
	while (!(err=ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			
		} else if (iter.is_radiotap_ns)
			{
				//print_radiotap_namespace(&iter);
				if(iter.this_arg_index==IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
					//printf("\tsignal: %d\n", (char)*iter.this_arg);
					out->PWR=*iter.this_arg;
				}
			}
	}
	uint32_t idx=iter._rtheader->it_len;
	if(idx>=len)return;
	struct ieee80211_beacon_frame *beacon_frame=(struct ieee80211_beacon_frame*)(packet+idx);
	out->isbeacon=(0x80==beacon_frame->frame_control);
	for(int i=0;i<6;i++){
		out->BSSID[i]=beacon_frame->BSSID[i];
		//printf("%02x",out->BSSID[i]);
		//if(i<5)printf(":");
	}
	//printf("\n");
	if(!out->isbeacon)return;
	idx+=sizeof(struct ieee80211_beacon_frame);
	if(idx>=len)return;
	if(!packet[idx])
	{
		out->ESSID_len=packet[idx+1];
		for(int i=0;i<packet[idx+1];i++)
		{
			out->ESSID[i]=packet[idx+i+2];
		}
		out->ESSID[out->ESSID_len]=0;
		//printf("%s\n",out->ESSID);
	}
	while(idx<len&&packet[idx]!=0xdd)idx+=packet[idx+1]+2;
	uint32_t OUI=0;
	if(packet[idx]==0xdd)
	{
		OUI=*(uint32_t*)(packet+idx+2)&0xFFFFFF;
		if(OUI==0xF25000)out->ENC=1;
		else if(OUI==0xAC0F00)out->ENC=2;
		else out->ENC=3;
	}
}
