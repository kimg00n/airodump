#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump wlan0\n");
}

struct radiotap_header {
	u_int8_t version;
	u_int8_t pad;
	u_int16_t length;
	u_int32_t present;
} __attribute__((__packed__));

struct bss_t {
  u_int8_t bssid[6];
  u_int32_t beacons;
  u_int8_t ssid[33];
  struct bss_t *next;
} __attribute__ ((packed));

/* Linked list of BSSIDs */
struct bss_t *bss_head = NULL;


typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
  int num_channels, channel, *channels;
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
    struct bss_t *bss;
    const u_char *ssid;
    int ssid_len;
    struct radiotap_header* radio = (struct radiotap_header*)packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

    if (packet[radio->length] != 0x80) continue;
    //printf("recieved beacon packet!\n");
    //printf("radiotap header length: %d\n", radio->length);
    //printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
		//	packet[radio->length + 0x10], packet[radio->length + 0x11], packet[radio->length + 0x12],
		//	packet[radio->length + 0x13], packet[radio->length + 0x14], packet[radio->length + 0x15]);

    bss = bss_head;
    ssid = packet + radio->length + 0x10 + 0x16;
    ssid_len = *(ssid - 1);
    void *bssid = &packet[radio->length + 10];
    int count = 0;
    //printf("ESSID : %.*s\n",ssid_len, ssid);
    while (bss != NULL) {
      count++;
      if (memcmp(bss->bssid, bssid, 6) == 0) {
        /* BSSID found, update beacon count and sequence control */
        bss->beacons++;
        break;
      }
      bss = bss->next;
    }
    if (bss == NULL) {
      /* BSSID not found, add to list */
      bss = (struct bss_t *)malloc(sizeof(struct bss_t));
      memcpy(bss->bssid, bssid, 6);
      bss->beacons = 1;
      memcpy(bss->ssid, ssid, ssid_len);
      bss->ssid[ssid_len] = '\0';
      bss->next = bss_head;
      bss_head = bss;
    }
    system("clear");
    printf("BSSID\t\t\tBeacons\t\t\t\t   ESSID\n");
    bss = bss_head;
    while(bss->next != NULL){
      for(int i=0;i<6;i++){
        printf("%02X",bss->bssid[i]);
        if(i!=5)
          printf(":");
      }
		printf("\t%d\t\t\t\t%s\n",bss->beacons,bss->ssid);
		bss = bss->next;
	}
  }
	pcap_close(pcap);
}