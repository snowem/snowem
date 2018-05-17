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
#include "ice/ice_component.h"
#include "ice/ice_session.h"
#include "ice/ice_stream.h"
#include "ice/process.h"
#include "rtp/rtp_nack.h"
#include "rtp/rtp_utils.h"


int
snw_rtp_nack_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_nack_module,M_FLAGS_INIT)) {
      WARN(log,"rtp nack aready init");
      return -1;
   }

   //FIXME init nack module

   MODULE_SET_FLAG(g_rtp_nack_module,M_FLAGS_INIT);

   return 0;
}

int
snw_rtp_send_pli_req(snw_rtp_ctx_t *ctx, uint32_t local_ssrc, uint32_t remote_ssrc) {
   char rtcpbuf[RTCP_PSFB_PLI_MSG_LEN];
   snw_log_t *log = 0;
   snw_ice_session_t *session = (snw_ice_session_t*)ctx->session;

   if (!ctx) return -1;
   log = ctx->log;

   TRACE(log,"sending pli request, flowid=%u, local_ssrc=%x, remote_ssrc=%x, video=%u",
                           session->flowid, local_ssrc, remote_ssrc, ctx->pkt_type & RTP_VIDEO);
   snw_rtcp_gen_pli(rtcpbuf, RTCP_PSFB_PLI_MSG_LEN, local_ssrc, remote_ssrc);
   ctx->send_pkt(session,1,1,rtcpbuf,RTCP_PSFB_PLI_MSG_LEN);
   return 0;
}

int
snw_rtp_send_fir_req(snw_rtp_ctx_t *ctx, uint32_t local_ssrc, uint32_t remote_ssrc) {
   char rtcpbuf[RTCP_PSFB_FIR_MSG_LEN];
   snw_log_t *log = ctx->log;
   snw_ice_session_t *session = (snw_ice_session_t*)ctx->session;
   snw_ice_component_t *component = (snw_ice_component_t*)ctx->component;

   component->fir_seq++;
   DEBUG(log,"sending fir request, flowid=%u, local_ssrc=%x, remote_ssrc=%x, fir_seq=%u",
                        session->flowid, local_ssrc, remote_ssrc, component->fir_seq);
                            
   snw_rtcp_gen_fir(rtcpbuf, RTCP_PSFB_FIR_MSG_LEN, 
                     local_ssrc, remote_ssrc, component->fir_seq);
   ctx->send_pkt(session,1,1,rtcpbuf,RTCP_PSFB_FIR_MSG_LEN);
 
   return 0;
}

int
snw_rtp_nack_handle_pkg_in(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   rtp_hdr_t *hdr = 0;
   snw_rtcp_stats_t *stats = 0;
   snw_log_t *log;
   uint32_t nack = 0;
   uint16_t seqno;
   int clockrate = 0;
   int64_t transit = 0;
   int delta = 0;
   int video = 0;
   int ret = 0;

   if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
      return -1;
   }
   log = ctx->log;

   //print_rtp_header(log,buf,buflen,"nack");
   video = (ctx->pkt_type & RTP_VIDEO) != 0;
   hdr = (rtp_hdr_t*)buf;
   seqno = ntohs(hdr->seq); 
   //TRACE(log, "handle package in, seq=%u, ssrc=%u, video=%u", 
   //      seqno, ntohl(hdr->ssrc), video);

   // collect and update stats
   stats = snw_rtcp_stats_find(ctx,&ctx->receiver_stats,ntohl(hdr->ssrc));
   if (!stats) {
      stats = snw_rtcp_stats_new(ctx,&ctx->receiver_stats,ntohl(hdr->ssrc));
      if (!stats) {
         WARN(log,"no stats on stream");
         return -2;
      }
      // init new slide window
      snw_rtp_slidewin_reset(ctx,&stats->seq_win,seqno-1);
   }

   stats->recv_pkt_cnt++; 
   stats->recv_byte_cnt += buflen - snw_rtp_get_hdrlen(hdr);
   stats->received++;

   if (!snw_rtp_slidewin_is_retransmit(ctx, &stats->seq_win, seqno)) {
      clockrate = video ? 90 : 48;
      transit = ctx->epoch_curtime * clockrate - ntohl(hdr->ts);
      if (stats->transit != 0) {
         delta = abs(stats->transit - transit);
         stats->jitter += (1.0/16.0)*(delta - stats->jitter);
      }
      stats->transit = transit;
   }

   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   //TODO: save rtp packets to resend them later
   
   //handle lost packets and generate NACK rtpfb message.
   nack = snw_rtp_slidewin_put(ctx, &stats->seq_win, seqno);
   if (nack != 0) {
      char rtcpbuf[RTCP_RTPFB_MSG_LEN];
      snw_ice_session_t *session = 0;
      snw_ice_stream_t *stream = 0;

      session = (snw_ice_session_t*)ctx->session;
      stream = (snw_ice_stream_t*)ctx->stream;
      //DEBUG(log,"sending rtpfb nack, flowid=%u, local_ssrc=%x,"
      //          " remote_ssrc=%x, payload=%x", session->flowid,
      //          stream->local_video_ssrc, stream->remote_video_ssrc, 
      //          nack);
      //FIXME: take audio stream into account?
      ret = snw_rtcp_gen_nack(rtcpbuf, RTCP_RTPFB_MSG_LEN, 
                        stream->local_video_ssrc, 
                        stream->remote_video_ssrc, 
                        nack);
      if (ret < 0) return -1;
      ctx->send_pkt(session,1,video,rtcpbuf,RTCP_RTPFB_MSG_LEN);
      stats->nack_cnt++;
   }

   //generate receiver report
   if (ctx->epoch_curtime - stats->last_send_rr_ts > stats->rtcp_rr_interval) {
      snw_report_block_t rb;
      uint32_t ext_seq = 0;
      uint32_t expected = 0;
      uint32_t lost = 0;
      uint32_t expected_interval = 0;
      uint32_t received_interval = 0;
      uint32_t lost_interval = 0;
      uint8_t  fraction;

      //TRACE(log, "generate receiver rb info, ssrc=%u, cycles=%u, "
      //           "max_seq=%u lastrr_time=%llu, curtime=%llu", 
      //      stats->ssrc, stats->seq_win.cycles, stats->seq_win.max_seq, 
      //      stats->last_send_rr_ts, ctx->epoch_curtime);
      
      // generate report block
      memset(&rb,0,sizeof(rb)); 
      rb.ssrc = htonl(stats->ssrc);

      ext_seq = (stats->seq_win.cycles << 16) + stats->seq_win.max_seq;
      expected = ext_seq - stats->seq_win.base_seq + 1;
      if (expected < stats->received || stats->expected_prior == 0)
         lost = 0;
      else 
         lost = expected - stats->received;

      //TRACE(log, "lost rb info, expected=%u, received=%u, lost=%u", 
      //      expected, stats->received, lost); 

      expected_interval = expected - stats->expected_prior;
      stats->expected_prior = expected;
      received_interval = stats->received - stats->received_prior;
      lost_interval = expected_interval - received_interval;
      if (expected_interval != 0) {
         fraction = ((lost_interval) << 8) / expected_interval;
      }
      stats->received_prior = stats->received;

      rb.frac_lost = fraction;
      rb.cum_lost = htonl(lost) >> 8;
      rb.hi_seqno = htonl((stats->seq_win.cycles << 16) + stats->seq_win.max_seq);
      rb.jitter = htonl((uint32_t)stats->jitter);
      rb.lsr = htonl(stats->last_sr_ntp);
      rb.dlsr = htonl((uint32_t)((ctx->epoch_curtime - stats->last_sr_recv_ts)*65536 / 1000));

      //TRACE(log, "generated report block, ssrc=%u, frac_lost=%u, "
      //           "cum_lost=%u, hi_seqno=%u, jitter=%u, lsr=%u, dlsr=%u",
      //      ntohl(rb.ssrc), rb.frac_lost, ntohl(rb.cum_lost)>>8, 
      //      ntohl(rb.hi_seqno), ntohl(rb.jitter), ntohl(rb.lsr), ntohl(rb.dlsr));
      //HEXDUMP(log,(char*)&rb,sizeof(rb),"rb");

      //FIXME: move this code block to a function.
      // generate rtcp pkt
      {
         char data[RTCP_RR_MSG_LEN] = {0};
         snw_ice_stream_t *stream = (snw_ice_stream_t*)ctx->stream;
         snw_ice_session_t *session = (snw_ice_session_t*)ctx->session;
         uint32_t local_ssrc =  0;
         int ret = 0;

         if (ctx->pkt_type & RTP_VIDEO)
            local_ssrc = stream->local_video_ssrc; 
         else
            local_ssrc = stream->local_audio_ssrc; 

         ret = snw_rtcp_gen_rr(data, RTCP_RR_MSG_LEN, local_ssrc, &rb);
         if (ret == RTCP_RR_MSG_LEN) {
            //DEBUG(log,"send rr msg, ret=%u, ssrc=%u",
            //      ret, ntohl(local_ssrc));
            ctx->send_pkt(session,1, ctx->pkt_type & RTP_VIDEO,data,
                 RTCP_RR_MSG_LEN);
         }
      }
      stats->last_send_rr_ts = ctx->epoch_curtime;
   }

   if (ctx->epoch_curtime - stats->last_sent_fir_ts > 3000) {
      snw_ice_stream_t *stream = (snw_ice_stream_t*)ctx->stream;

      //snw_rtp_send_fir_req(ctx, stream->local_video_ssrc, stream->remote_video_ssrc);
      snw_rtp_send_pli_req(ctx, stream->local_video_ssrc, stream->remote_video_ssrc);
      stats->last_sent_fir_ts = ctx->epoch_curtime;
   }

   return 0;
}

int
snw_rtp_send_empty_rr_rtcp(snw_rtp_ctx_t *ctx) {
   char data[RTCP_EMPTY_RR_MSG_LEN] = {0};
   snw_ice_session_t *session = (snw_ice_session_t*)ctx->session;
   int ret = 0;

   ret = snw_rtcp_gen_rr(data, RTCP_EMPTY_RR_MSG_LEN, 0, NULL);
   if (ret == RTCP_EMPTY_RR_MSG_LEN) {
      ctx->send_pkt(session,1, ctx->pkt_type & RTP_VIDEO,data,
           RTCP_RR_MSG_LEN);
   }

   return 0;
}

int
snw_rtp_send_sr_rtcp(snw_rtp_ctx_t *ctx, snw_rtcp_stats_t *stats, 
      uint32_t ssrc, uint32_t ts) {
   static char data[RTCP_SR_MSG_LEN] = {0};
   snw_rtcp_sr_t sr;
   snw_ice_session_t *session = (snw_ice_session_t*)ctx->session;
   int ret = 0;

   memset(&sr,0,sizeof(sr));
   sr.ssrc = htonl(ssrc);
	sr.ntp_ts = htobe64(ctx->epoch_curtime);
	sr.rtp_ts = htonl(ts);
	sr.pkt_cnt = htonl(stats->sent_pkt_cnt);
	sr.byte_cnt = htonl(stats->sent_byte_cnt);

   ret = snw_rtcp_gen_sr(data, RTCP_EMPTY_SR_MSG_LEN, &sr);

   if (ret == RTCP_EMPTY_SR_MSG_LEN) {
      ctx->send_pkt(session,1, ctx->pkt_type & RTP_VIDEO,data,
           RTCP_EMPTY_SR_MSG_LEN);
   }

   return 0;
}

int
snw_rtp_nack_handle_pkg_out(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log = 0;
   rtp_hdr_t *hdr = 0;
   snw_rtcp_stats_t *stats = 0;
   uint32_t ssrc = 0;
   uint16_t seq = 0;
   int video = 0;

   if (!data || !buf) return -1;
   log = ctx->log;

   video = (ctx->pkt_type & RTP_VIDEO) != 0;
   if (!video) return -1;

   hdr = (rtp_hdr_t*)buf;
   seq = ntohs(hdr->seq); 
   ssrc = ntohl(hdr->ssrc);
   TRACE(log, "handle package out, seq=%u, ssrc=%u, video=%u", 
         seq, ssrc, video);

   //get sender stats
   stats = snw_rtcp_stats_find(ctx,&ctx->sender_stats,ssrc);
   if (!stats) {
      stats = snw_rtcp_stats_new(ctx,&ctx->sender_stats,ssrc);
      if (!stats) {
         WARN(log,"no sender stats on stream");
         return -2;
      }
   }

   //update stats
   stats->sent_pkt_cnt++;
   stats->sent_byte_cnt += buflen - snw_rtp_get_hdrlen(hdr);

   if (ctx->epoch_curtime - stats->last_send_sr_ts <= stats->rtcp_sr_interval) {
      //nothing to do
      return 0;
   }
   stats->last_send_sr_ts = ctx->epoch_curtime;

   TRACE(log,"send empty rr and sr, ssrc=%u", ssrc);
   snw_rtp_send_empty_rr_rtcp(ctx);
   snw_rtp_send_sr_rtcp(ctx,stats,ssrc,ntohl(hdr->ts));

   return 0;
}

int
snw_rtp_nack_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_nack_module = { 
   "nack",
   0,/*ctx*/
   RTP_AUDIO|RTP_VIDEO,
   0,
   snw_rtp_nack_init, 
   snw_rtp_nack_handle_pkg_in, 
   snw_rtp_nack_handle_pkg_out, 
   snw_rtp_nack_fini,
   0 /*next*/
};


