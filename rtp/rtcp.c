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

#include "core/log.h"
#include "core/types.h"
#include "rtp/rtcp.h"
#include "rtp/rtp.h"

void
print_rtcp_header(snw_log_t *log, char *buf, int buflen, const char *msg) {
   rtcp_hdr_t *hdr;

   hdr = (rtcp_hdr_t*)buf;
   DEBUG(log, "rctp %s info, v=%u, p=%u, rc=%u, pt=%u, len=%u", 
         msg, hdr->v, hdr->p, hdr->rc, hdr->pt, ntohs(hdr->len));

   return;
}

int 
snw_rtcp_has_payload_type(char *buf, int len, int8_t type) {
	int total, length;
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)buf;

	if (rtcp->v != 2) return 0;

  total = len;
	while (rtcp) {
      if (rtcp->pt == type)
         return 1;
		length = ntohs(rtcp->len);
		if (length == 0)
			break;
		total -= (length+1)*RTCP_LEN_IN_WORDS;
		if (total <= 0)
			break;
		rtcp = (rtcp_hdr_t *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

uint32_t
snw_rtcp_get_ssrc(snw_rtp_ctx_t *ctx, char *buf, int len) {
   snw_log_t *log = 0;
   rtcp_pkt_t *rtcp = 0;
   char *end = buf + len;
   int rtcp_len;

   if (!ctx || !buf || len == 0) return 0;
   log = ctx->log;

   rtcp = (rtcp_pkt_t *)buf;
   if (rtcp->hdr.v != RTCP_VERSION) return 0;

   /* the first rtcp pkt must be either sender report or recevier report.*/
   while (rtcp) {
      switch (rtcp->hdr.pt) {
         case RTCP_SR: {
            DEBUG(log, "got sender report, rc=%u, len=%u", rtcp->hdr.rc, len);
            return ntohl(rtcp->pkt.sr.ssrc);
         }
         case RTCP_RR: {
            DEBUG(log, "got receiver report, rc=%u, len=%u", rtcp->hdr.rc, len);
            return ntohl(rtcp->pkt.rr.ssrc);
         }
         default: {
            break;
         }
      }

      rtcp_len = ntohs(rtcp->hdr.len);
      rtcp = (rtcp_pkt_t *)((uint32_t*)rtcp + rtcp_len + 1); // len + 1 in 32-bits word.
      if (rtcp_len ==0 || (char*)rtcp >= end) break;
   }
   return 0;
}

int
snw_rtcp_gen_fir(char *buf, int len, uint32_t local_ssrc, 
      uint32_t remote_ssrc, int seqnr) {

   if (!buf || len < RTCP_PSFB_FIR_MSG_LEN)
      return -1;

   memset(buf, 0, RTCP_PSFB_FIR_MSG_LEN);
   rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
   rtcp->hdr.v = RTCP_VERSION;
   rtcp->hdr.pt = RTCP_PSFB;
   rtcp->hdr.rc = RTCP_PSFB_FIR_FMT;
   if (len % RTCP_LEN_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
   rtcp->hdr.len = htons((len/RTCP_LEN_IN_WORDS)-1);

   rtcp->pkt.fb.ssrc = htonl(local_ssrc);
   rtcp->pkt.fb.media = htonl(remote_ssrc);
   rtcp->pkt.fb.fci.fir->ssrc = htonl(remote_ssrc);
   rtcp->pkt.fb.fci.fir->seqno = htonl(seqnr << 24);
	
	return RTCP_PSFB_FIR_MSG_LEN;
}

int snw_rtcp_gen_pli(char *buf, int len,
      uint32_t local_ssrc, uint32_t remote_ssrc) {

	if (buf == NULL || len < RTCP_PSFB_PLI_MSG_LEN)
		return -1;

	memset(buf, 0, RTCP_PSFB_PLI_MSG_LEN);
	rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
	rtcp->hdr.v = RTCP_VERSION;
	rtcp->hdr.pt = RTCP_PSFB;
	rtcp->hdr.rc = RTCP_PSFB_PLI_FMT;
   if (len % RTCP_LEN_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
	rtcp->hdr.len = htons((len/RTCP_LEN_IN_WORDS)-1);

   rtcp->pkt.fb.ssrc = htonl(local_ssrc);
   rtcp->pkt.fb.media = htonl(remote_ssrc);

	return RTCP_PSFB_PLI_MSG_LEN;
}

uint32_t
snw_rtcp_gen_nack(char *buf, int len,
      uint32_t local_ssrc, uint32_t remote_ssrc, uint32_t payload) {

	if (buf == NULL || len < RTCP_RTPFB_MSG_LEN)
		return -1;

	memset(buf, 0, RTCP_RTPFB_MSG_LEN);
	rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
	rtcp->hdr.v = RTCP_VERSION;
	rtcp->hdr.pt = RTCP_RTPFB;
	rtcp->hdr.rc = RTCP_RTPFB_GENERIC_FMT;
   if (len % RTCP_LEN_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
   rtcp->hdr.len = htons((len/RTCP_LEN_IN_WORDS)-1);

   rtcp->pkt.fb.ssrc = htonl(local_ssrc);
   rtcp->pkt.fb.media = htonl(remote_ssrc);
   memcpy(rtcp->pkt.fb.fci.nack, &payload, 4);

	return RTCP_PSFB_PLI_MSG_LEN;
}

uint32_t
snw_rtcp_gen_rr(char *buf, int len,
      uint32_t ssrc, snw_report_block_t *rb) {

	if (buf == NULL || len < RTCP_EMPTY_RR_MSG_LEN)
		return -1;

	memset(buf, 0, len);
	rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
	rtcp->hdr.v = RTCP_VERSION;
	rtcp->hdr.pt = RTCP_RR;
	rtcp->hdr.rc = 1;
   if (len % RTCP_LEN_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
   rtcp->hdr.len = htons((len/RTCP_LEN_IN_WORDS)-1);

   if (rb) {
      rtcp->pkt.rr.ssrc = htonl(ssrc);
      memcpy(rtcp->pkt.rr.rb, rb, sizeof(*rb));
	   return RTCP_RR_MSG_LEN;
   }

	return RTCP_EMPTY_RR_MSG_LEN;
}

//TODO: rewrite it with the following arguments
//snw_rtcp_gen_sr(char *buf, int len, snw_rtcp_sr_t *sr, snw_report_block_t *rb, int rblen)

uint32_t
snw_rtcp_gen_sr(char *buf, int len, snw_rtcp_sr_t *sr) {

	if (buf == NULL || len < RTCP_EMPTY_SR_MSG_LEN)
		return -1;

	memset(buf, 0, len);
	rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
	rtcp->hdr.v = RTCP_VERSION;
	rtcp->hdr.pt = RTCP_SR;
	rtcp->hdr.rc = 0;
   if (len % RTCP_LEN_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
   rtcp->hdr.len = htons((len/RTCP_LEN_IN_WORDS)-1);
   memcpy(&rtcp->pkt.sr, sr, sizeof(*sr));

   //FIXME: return written len
	//return RTCP_SR_MSG_LEN;
	return len;
}



