#ifndef _SNOW_RTP_RTCP_STATS_H_
#define _SNOW_RTP_RTCP_STATS_H_

#include <stdint.h>

#include "core/linux_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTP_SEQ_NUM_MAX   (1<<16)
#define RTP_SLIDEWIN_SIZE 16
#define RTP_SYNC_TIME_MAX 500000 //500ms

#define RTP_LOST 0
#define RTP_RECV 1

#define RTCP_MIN_RR_INTERVAL 500 // miliseconds
#define RTCP_MIN_SR_INTERVAL 1000 // miliseconds

typedef struct nack_data nack_data_t;
struct nack_data {
   uint16_t seq;
   uint16_t blp;
};

typedef struct nack_payload nack_payload_t;
struct nack_payload {
   union {
      nack_data_t pl;
      uint32_t    num;
   } data;
};

typedef struct rtp_seq rtp_seq_t;
struct rtp_seq {
   uint16_t  seq;
   uint16_t  status;
   uint64_t  ts;
   char     *pkt;
   int       len;
};

typedef struct rtp_slidewin rtp_slidewin_t;
struct rtp_slidewin {
   uint32_t   ssrc;
   uint16_t   head;
   uint16_t   base_seq;
   uint16_t   cycles;
   uint16_t   max_seq;
   uint16_t   last_seq;
   int64_t    last_ts;
   rtp_seq_t  seqlist[RTP_SLIDEWIN_SIZE];
};

typedef struct snw_rtcp_stats snw_rtcp_stats_t;
struct snw_rtcp_stats {
   struct list_head list;
   uint32_t ssrc;
   int      type;
   
   //stats
   uint32_t   recv_pkt_cnt;            // accummulcated packet count
   uint32_t   recv_byte_cnt;           // accummulcated byte count
   uint32_t   sent_pkt_cnt;            // accummulcated packet count
   uint32_t   sent_byte_cnt;           // accummulcated byte count

   // info of the last send report
   int64_t    last_sr_recv_ts;    // local time of the last sr
   uint32_t   last_sr_ntp;        // mid ntp of the last sr
   uint32_t   last_sr_rtp_ts;     // rtp ts of the last sr

   // info of the last receiver report
   int64_t    last_rr_recv_ts;    // local time of the last sr
	uint32_t   last_rr_cum_lost;
	uint32_t   last_rr_frac_lost;
	uint32_t   last_rr_hi_seqno;
	uint32_t   last_rr_jitter;
	uint32_t   last_rr_lsr;
	uint32_t   last_rr_dlsr;


   int64_t    last_send_sr_ts;    // local time of the last sr
   int64_t    rtcp_sr_interval;
   int64_t    last_send_rr_ts;    // local time of the last sr
   int64_t    rtcp_rr_interval;

   //uint32_t bad_seq;
   //uint32_t probation;

   uint32_t   sended;         // total num of sended pkts
   uint32_t   received;       // total num of received pkts
   uint32_t   expected_prior; // last expected num of received pkts
   uint32_t   received_prior; // last num of received pkts

   int64_t    transit;
   double     jitter;

   rtp_slidewin_t    seq_win;

   //additional stats
   int64_t    last_sent_fir_ts;    // local time of the last fir/pli
   uint32_t   nack_cnt;
   uint32_t   fir_cnt;
   uint32_t   pli_cnt;
};

typedef struct snw_rtp_ctx snw_rtp_ctx_t;

snw_rtcp_stats_t*
snw_rtcp_stats_find(snw_rtp_ctx_t *ctx, snw_rtcp_stats_t *s, uint32_t ssrc);

snw_rtcp_stats_t*
snw_rtcp_stats_new(snw_rtp_ctx_t *ctx, snw_rtcp_stats_t *s, uint32_t ssrc);

void
snw_rtp_slidewin_reset(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq);

int
snw_rtp_slidewin_is_retransmit(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq);

uint32_t
snw_rtp_slidewin_put(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq);

#ifdef __cplusplus
}
#endif

#endif
