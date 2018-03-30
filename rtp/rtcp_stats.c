#include "core/log.h"
#include "core/types.h"
#include "rtp/rtcp_stats.h"
#include "rtp/rtp.h"

snw_rtcp_stats_t*
snw_rtcp_stats_find(snw_rtp_ctx_t *ctx, snw_rtcp_stats_t *s, uint32_t ssrc) {
   snw_log_t *log = 0;
   snw_rtcp_stats_t* stats = 0;
   struct list_head *n;

   if (!ctx) return 0;
   log = ctx->log;

   list_for_each(n,&s->list) {
      snw_rtcp_stats_t* s = list_entry(n,snw_rtcp_stats_t,list);
      if (s->ssrc == ssrc) {
         stats = s;
         break;
      }
   }

   return stats;
}

snw_rtcp_stats_t*
snw_rtcp_stats_new(snw_rtp_ctx_t *ctx, snw_rtcp_stats_t *s, uint32_t ssrc) {
   snw_log_t *log = 0;
   snw_rtcp_stats_t* stats = 0;
   struct list_head *n;

   if (!ctx) return 0;
   log = ctx->log;
   
   stats = SNW_MALLOC(snw_rtcp_stats_t);
   if (!stats) {
      ERROR(log,"not enough memory");
      return 0;
   }

   DEBUG(log,"new source stats, ssrc=%u", ssrc);
   SNW_MEMZERO(stats,snw_rtcp_stats_t);
   stats->ssrc = ssrc;
   stats->last_send_sr_ts = ctx->epoch_curtime;
   stats->last_send_rr_ts = ctx->epoch_curtime;
   stats->last_sr_recv_ts = ctx->epoch_curtime;
   stats->last_rr_recv_ts = ctx->epoch_curtime;
   stats->last_sent_fir_ts = ctx->epoch_curtime;
   stats->rtcp_rr_interval = RTCP_MIN_RR_INTERVAL;
   stats->rtcp_sr_interval = RTCP_MIN_SR_INTERVAL;
   list_add(&stats->list,&s->list);

   return stats;
}

void
snw_rtp_slidewin_reset(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq) {
   snw_log_t *log = 0;
   int idx = 0;

   if (!ctx || !win) return;
   log = ctx->log;

   memset(win,0,sizeof(*win)); //reset all
   idx = seq % RTP_SLIDEWIN_SIZE; 
   win->head = idx;
   win->base_seq = seq;
   win->last_seq = seq;
   win->max_seq = seq;
   win->last_ts  = ctx->epoch_curtime;
   win->seqlist[idx].status = RTP_RECV;
   win->seqlist[idx].seq = seq;

   return;
}

void
snw_rtp_slidewin_print(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win) {
   snw_log_t *log = 0;
   int16_t seq;
   int i = 0;

   if (!ctx) return;
   log = ctx->log;
  
   seq = win->seqlist[win->head].seq ;
   DEBUG(log,"slide window, head=%u, head_seq=%u", win->head, seq);
   for (i=0; i< RTP_SLIDEWIN_SIZE; i++) {
      DEBUG(log,"win[%u]=%u(%s)",i,win->seqlist[i].seq, 
           win->seqlist[i].status == RTP_LOST ? "miss" : "recv");
   }
}

uint32_t
snw_rtp_slidewin_update(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq, uint16_t end) {
   snw_log_t *log = 0;
   nack_payload_t *nack;
   uint32_t ret = 0;
   int i = 0;

   if (!ctx) return ret;
   log = ctx->log;
   nack = (nack_payload_t*)&ret; 

   seq++;
   i = seq % RTP_SLIDEWIN_SIZE;
   while(seq != end) {
      if (win->seqlist[i].seq != seq) {
         TRACE(log, "lost seq, seq=%u, end=%u", seq, end);
         win->seqlist[i].seq = seq;
         win->seqlist[i].status = RTP_LOST;
         if (nack->data.pl.seq == 0) {
            nack->data.pl.seq = win->seqlist[i].seq;
         } else {
            uint16_t blp = ntohs(nack->data.pl.blp);
            blp |= 1 << (win->seqlist[i].seq - nack->data.pl.seq - 1);
            nack->data.pl.blp = htons(blp);
         }
      } else {
         //check status of seq
      }
      seq++;
      i = seq % RTP_SLIDEWIN_SIZE;
   }

   //HEXDUMP(log,(char*)&ret, 4, "nack");
   //DEBUG(log,"generated nack, nack=%u", ret);

   return ret;
}

int
snw_rtp_slidewin_is_retransmit(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq) {
   uint16_t udelta;
   int i = 0;

   //TODO: adjust slidewin size to better handling of retransmit status.
   for (i=0; i<RTP_SLIDEWIN_SIZE; i++) {
      if ((win->seqlist[i].seq == seq) && 
          (win->seqlist[i].status == RTP_RECV))
         return 1;
   }

   return 0;
}

uint32_t
snw_rtp_slidewin_put(snw_rtp_ctx_t *ctx, rtp_slidewin_t *win, uint16_t seq) {
   snw_log_t *log = 0;
   nack_payload_t nack;
   uint16_t udelta;
   int nseq = seq;
   int nlast_seq = win->last_seq;
   int idx = 0;

   if (!ctx || !win) 
      return 0;
   log = ctx->log;

   nack.data.num = 0;
   udelta = seq - win->last_seq;
   TRACE(log, "slidewin put, i=%u, udelta=%u, seq=%u, last_seq=%u, head=%u",
         udelta, seq, win->last_seq, win->head);

   if (ctx->epoch_curtime - win->last_ts > RTP_SYNC_TIME_MAX) {
      WARN(log, "stream out of sync, seq=%u", seq);
      snw_rtp_slidewin_reset(ctx, win, seq);
      win->last_ts = ctx->epoch_curtime;
      return 0;
   }

   if (udelta < RTP_SLIDEWIN_SIZE) {
      //in order
      idx = seq % RTP_SLIDEWIN_SIZE;
      win->seqlist[idx].seq = seq;
      win->seqlist[idx].status = RTP_RECV;
      nack.data.num = snw_rtp_slidewin_update(ctx, win, win->last_seq, seq);
      win->head = idx;
      win->last_ts = ctx->epoch_curtime;
      win->last_seq = seq;
      win->max_seq = seq;
   } else if (udelta < RTP_SEQ_NUM_MAX - RTP_SLIDEWIN_SIZE) {
      //make a large jump
      //TODO: generate nack before reset 
      //WARN(log, "stream out of sync, udelta=%u, seq=%u", udelta, seq);
      snw_rtp_slidewin_reset(ctx, win, seq);
      return 0;
   } else {
      //duplicated or reordered pkt
      //WARN(log, "reordered pkt, udelta=%u, seq=%u", udelta, seq); 
      idx = seq % RTP_SLIDEWIN_SIZE;
      win->seqlist[idx].seq = seq;
      win->seqlist[idx].status = RTP_RECV;
   }

   return nack.data.num;
}



