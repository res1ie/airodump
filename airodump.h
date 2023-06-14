#include <stdbool.h>
#include <stdio.h>
#include <pcap.h>
#include "radiotap_iter.h"

struct parsed_info
{
	bool isbeacon;
	uint8_t BSSID[6];
	uint8_t ESSID_len;
	uint8_t ENC;
	int8_t PWR;
	uint8_t ESSID[32];
};

#ifdef __cplusplus
#define CALLING_CONVENTION "C"
#else
#define CALLING_CONVENTION
#endif

extern CALLING_CONVENTION void parse(uint32_t len,const u_char* packet,struct parsed_info *out);
