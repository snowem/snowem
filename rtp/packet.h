#ifndef _ICE_PACKET_H_
#define _ICE_PACKET_H_

#include <stdint.h>
#include "core/linux_list.h"

#define RTP_PACKET_AUDIO   0
#define RTP_PACKET_VIDEO   1

//packet type
#define UNKNOWN_PT 0
#define RTP_PT     1
#define RTCP_PT    2
#define DTLS_PT    3

/* RTP packet */
typedef struct rtp_packet rtp_packet_t;
struct rtp_packet {
	char *data;
	int length;

   uint8_t type:1;      //0 - audio, 1 - video
   uint8_t control:1;   //0 - rtp, 1 - rtcp
   uint8_t keyframe:1;  //0 - non-key frame, 1 - key frame
   uint8_t encrypted:1;
   uint8_t reserve:4;

	uint64_t last_retransmit;

   struct list_head list;
};

void rtp_list_add(rtp_packet_t* head, rtp_packet_t *item);
rtp_packet_t* rtp_list_remove_last(rtp_packet_t* head);
int rtp_list_size(rtp_packet_t* head);



#endif //_ICE_PACKET_H_


