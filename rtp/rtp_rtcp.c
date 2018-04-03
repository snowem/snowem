/*
 * (C) Copyright 2017 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "rtp/rtcp.h"
#include "rtp/rtp_nack.h"
#include "rtp/rtp_rtcp.h"

#define USE_MODULE_RTCP
snw_rtp_module_t *g_rtp_rtcp_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_RTCP

int
snw_rtp_rtcp_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   TRACE(log,"init rtp rtcp");
   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_rtcp_modules[i];
      if (!m) break;

      TRACE(log,"init module, name=%s",m->name);
      m->init(ctx);
   }

   return 0;
}

int
snw_rtcp_resend_pkt(snw_rtp_ctx_t *ctx, int video, int seqno) {
   /*snw_log_t *log = ctx->log;
   snw_ice_session_t *session;
   int64_t now = 0;

   if (!ctx) return -1;
   log = ctx->log;
   session = (snw_ice_session_t*)ctx->session;

   //FIXME: impl
   //DEBUG(log, "resend seq, flowid=%u, seqno=%u, ts=%llu",
   //      session->flowid, seqno, now);
   */
    
   return 0;
}

int
snw_rtcp_nack_handle_pkg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log;
   snw_rtcp_nack_t *nack;
   char *end;
   uint16_t pid = 0;
   uint16_t blp = 0;
   int i, cnt = 0;
   int video = 0;
   
   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   if (rtcp->hdr.pt != RTCP_RTPFB || 
       rtcp->hdr.rc != RTCP_RTPFB_GENERIC_FMT) {
      ERROR(log,"wrong fb msg, pt=%u, rc=%u", rtcp->hdr.pt, rtcp->hdr.rc);
      return -1;
   }

   nack = rtcp->pkt.fb.fci.nack;
   end = (char*)rtcp + 4*(ntohs(rtcp->hdr.len) + 1);

   cnt = 0;
   video = ctx->pkt_type && RTP_VIDEO;
   do {
      pid = ntohs(nack->pid);
      blp = ntohs(nack->blp);
      snw_rtcp_resend_pkt(ctx,video,pid);
      for (i=0; i<16; i++) {
         if ((blp & (1 << i)) >> i) {
            snw_rtcp_resend_pkt(ctx,video,pid+i+1);
         }
      }
      cnt++;
      nack++;
      // make sure no loop
      if (cnt > RTCP_PKT_NUM_MAX) break;

   } while ((char*)nack < end);

   //DEBUG(log, "total lost packets, flowid=%u, num=%d", s->flowid, cnt);

   return 0;
}

int
snw_rtp_rtcp_fb_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log;
  
   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   if (rtcp->hdr.rc == RTCP_RTPFB_GENERIC_FMT) {
      snw_rtcp_nack_handle_pkg(ctx,rtcp);
   } else {
      WARN(log, "unknown transport layer rtcp-fb format, fmt=%u", 
           rtcp->hdr.rc);
   }

   return 0;
}

int
snw_rtp_rtcp_psfb_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;
   snw_rtcp_fb_t *fb = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   fb = &rtcp->pkt.fb;
   TRACE(log,"rtcp pt psfb, ssrc=%u, media=%u", 
         ntohl(fb->ssrc), ntohl(fb->media));

   switch (rtcp->hdr.rc) {
      case RTCP_PSFB_PLI_FMT:
         // rfc 4585 6.3.1
         //FIXME: store the last key frame, and send it
         break;
      case RTCP_PSFB_SLI_FMT:
         // rfc 4585 6.3.2
         break;
      case RTCP_PSFB_RPSI_FMT:
         // rfc 4585 6.3.3
         break;

      case RTCP_PSFB_FIR_FMT:
         // rfc 5104 4.3.1
         break;
      case RTCP_PSFB_TSTR_FMT:
         // rfc 5104 4.3.2
         break;
      case RTCP_PSFB_TSTN_FMT:
         // rfc 5104 4.3.3
         break;
      case RTCP_PSFB_VBCM_FMT:
         // rfc 5104 4.3.4
         break;

      case RTCP_PSFB_REMB_FMT:
         TRACE(log,"rtcp remb");
         //FIXME: impl it
         break;

      default:
         break;
   }

   return 0;
}

int
snw_rtp_rtcp_fir_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp fir msg");

   return 0;
}

int
snw_rtp_rtcp_sr_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;
   snw_rtcp_sr_t *sr = 0;
   snw_rtcp_stats_t *stats = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   sr = &rtcp->pkt.sr;
   TRACE(log,"rtcp sr, ssrc=%u , ntp_ts=%llu, rtp_ts=%u, "
         "packet_cnt=%u, octet_cnt=%u", ntohl(sr->ssrc), be64toh(sr->ntp_ts), 
         ntohl(sr->rtp_ts), ntohl(sr->pkt_cnt), ntohl(sr->byte_cnt));

   stats = snw_rtcp_stats_find(ctx,&ctx->receiver_stats, ntohl(sr->ssrc));
   if (!stats) {
      ERROR(log, "no rtcp stats found, ssrc=%u", ntohl(sr->ssrc));
      return -1;
   }

   //.1 collect ntp and rtp
   stats->last_sr_ntp = ntohl((rtcp->pkt.sr.ntp_ts << 16) >> 32);
   stats->last_sr_rtp_ts = ntohl(rtcp->pkt.sr.rtp_ts);
   stats->last_sr_recv_ts = ctx->epoch_curtime;

   //.2 sender bandwidth estimation, SenderBandwidthEstimationHandler
   
   return 0;
}

void
snw_rtp_rtcp_print_rb(snw_log_t *log, snw_report_block_t *rb) {

   if (!log || !rb) return;

   DEBUG(log,"rtcp rr rb, cum_lost=%u, frac_lost=%u, hi_seqno=%u, jitter=%u, lsr=%u, dlsr=%u", 
         rb->cum_lost,
         rb->frac_lost,
         ntohl(rb->hi_seqno),
         ntohl(rb->jitter),
         ntohl(rb->lsr),
         ntohl(rb->dlsr));
   return;
}

int
snw_rtp_rtcp_rr_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;
   snw_rtcp_rr_t *rr = 0;
   snw_rtcp_stats_t *stats = 0;
   int i = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   rr = &rtcp->pkt.rr;
   TRACE(log,"rtcp rr, rc=%u, ssrc=%u", rtcp->hdr.rc, ntohl(rr->ssrc));
   
   for (i=0; i<rtcp->hdr.rc; i++) {
     snw_report_block_t *rb = &rr->rb[i];

     stats = snw_rtcp_stats_find(ctx,&ctx->sender_stats,ntohl(rb->ssrc));
     if (!stats) {
       stats = snw_rtcp_stats_new(ctx,&ctx->sender_stats,ntohl(rb->ssrc));
       if (!stats) continue;
     }
     TRACE(log, "rtcp rr update stats, ssrc=%u", ntohl(rb->ssrc));
     stats->last_rr_recv_ts = ctx->epoch_curtime;

     stats->last_rr_cum_lost = rb->cum_lost;
	   stats->last_rr_frac_lost = ntohl(rb->frac_lost);
   	 stats->last_rr_hi_seqno = ntohl(rb->hi_seqno);
   	 stats->last_rr_jitter = ntohl(rb->jitter);
   	 stats->last_rr_lsr = ntohl(rb->lsr);
   	 stats->last_rr_dlsr = ntohl(rb->dlsr);
   }

   return 0;
}

int
snw_rtp_rtcp_sdes_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   TRACE(log,"rtcp sdes msg");
   //TODO: handle this msg

   return 0;
}

int
snw_rtp_rtcp_bye_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp byte msg");

   return 0;
}

int
snw_rtp_rtcp_app_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp app msg");

   return 0;
}

int
snw_rtp_rtcp_handle_pkg_in(void *data, char *buf, int buflen) {
  snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
  snw_log_t *log;
  rtcp_pkt_t *rtcp = 0;
  int total = buflen;
  int length;
   
  if (!ctx || !buf || buflen <= 0) {
    return -1;
  }
  log = ctx->log;
   
  //print_rtcp_header(log,buf,buflen,"rtcp");
  //HEXDUMP(log,(char*)buf,buflen,"rtcp");

	rtcp = (rtcp_pkt_t *)buf;

	if (rtcp->hdr.v != RTCP_VERSION) return -2;

  TRACE(log,"rtcp pt, pt=%u", rtcp->hdr.pt);
	while (rtcp) {
      switch (rtcp->hdr.pt) {
         case RTCP_RTPFB:
            snw_rtp_rtcp_fb_msg(ctx,rtcp);
            break;
         case RTCP_PSFB:
            snw_rtp_rtcp_psfb_msg(ctx,rtcp);
            break;
         case RTCP_FIR:
            snw_rtp_rtcp_fir_msg(ctx,rtcp);
            break;
         case RTCP_SR:
            snw_rtp_rtcp_sr_msg(ctx,rtcp);
            break;
         case RTCP_RR:
            snw_rtp_rtcp_rr_msg(ctx,rtcp);
            break;
         case RTCP_SDES:
            snw_rtp_rtcp_sdes_msg(ctx,rtcp);
            break;
         case RTCP_BYE:
            snw_rtp_rtcp_bye_msg(ctx,rtcp);
            break;
         case RTCP_APP:
            snw_rtp_rtcp_app_msg(ctx,rtcp);
            break;
         default:
            WARN(log,"unknown rtcp packet type, type=%u",rtcp->hdr.pt);
            break;
      }
		length = ntohs(rtcp->hdr.len);
		if (length == 0)
			break;
		total -= length*4+4;
		if (total <= 0)
			break;
		rtcp = (rtcp_pkt_t *)((uint32_t*)rtcp + length + 1);
	}

   return 0;
}

int
snw_rtp_rtcp_handle_pkg_out(void *data, char *buf, int buflen) {

   return 0;
}

int
snw_rtp_rtcp_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_rtcp_module = { 
   "rtcp",
   0,/*ctx*/
   RTP_RTCP,
   0,
   snw_rtp_rtcp_init, 
   snw_rtp_rtcp_handle_pkg_in, 
   snw_rtp_rtcp_handle_pkg_out, 
   snw_rtp_rtcp_fini,
   0 /*next*/
};


