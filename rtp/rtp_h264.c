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
#include "rtp/rtp_h264.h"
#include "rtp/rtp_rtmp.h"

#define USE_MODULE_H264
snw_rtp_module_t *g_rtp_h264_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_H264

int
snw_rtp_h264_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_h264_module,M_FLAGS_INIT)) {
      WARN(log,"rtp h264 aready init");
      return -1;
   }

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_h264_modules[i];
      if (!m) break;

      //DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
   }

   MODULE_SET_FLAG(g_rtp_h264_module,M_FLAGS_INIT);

   return 0;
}

int
ice_h264_process_nal_unit(snw_rtp_ctx_t *ctx, int is_end_frame,  
       char *buf, int buflen) {
   //uint8_t nal_unit_type;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }

   //nal_unit_type = *buf & 0x1f;
   // 5bits, 7.3.1 NAL unit syntax,
   // H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
   //  7: SPS, 8: PPS, 5: I Frame, 1: P Frame, 9: AUD, 6: SEI
   //DEBUG(log, "nal unit info, nal_unit_type=%u, buflen=%d", 
   //      nal_unit_type, buflen);

#ifdef ENABLE_RTMP
   snw_rtmp_handle_pkg(ctx->rtmp_ctx,buf,buflen); 
#endif

   return 0;
}

int
ice_h264_process_stapa_unit(snw_rtp_ctx_t *ctx, int is_end_frame,
       char *buf, int buflen) {
   snw_log_t *log;
   char *p;
   //uint8_t nal_unit_type, fbit;
   int nal_size;
   int len;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   p = buf;
   len = buflen;
   //nal_unit_type = *p & 0x1f;
   //fbit = *p & 0x80;
   p++;
   len--;
   
   TRACE(log, "stapa unit info, buflen=%d, len=%d", buflen, len);

   while(len > 2) {
      //FIXME: p[1] not working
      //nal_size = p[0] << 8 | p[1];
      
      //HEXDUMP(log,(char*)p,2,"stata");
      //DEBUG(log, "stapa unit info, nal_size=%u, len=%d, p0=%u, p1=%u", 
      //           nal_size, len, *p, *(((char*)p)+1)); 
      //TODO: set stricter condition on nal_size
      nal_size = ntohs(*((short*)p));
      if (nal_size == 0) {
         ERROR(log,"wrong nal_size, nal_size=%u", nal_size);
         return -1;
      }
      ice_h264_process_nal_unit(ctx,is_end_frame,p+2, nal_size);
      
      p += nal_size + 2;
      len -= nal_size + 2;
   }
   
   return 0;
}

int
ice_h264_process_fua_unit(snw_rtp_ctx_t *ctx, int is_end_frame,
       char *buf, int buflen) {
   static char data[MAX_BUFFER_SIZE];
   static int len;
   snw_log_t *log;
   fua_indicator_t *indicator;
   fua_hdr_t *hdr;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;


   indicator = (fua_indicator_t*)buf;
   hdr = (fua_hdr_t*)(buf+1);
  
   TRACE(log, "fua indicator info, buflen=%u, f=%u, nir=%u, type=%u, size=%u", 
         buflen, indicator->f, indicator->nir, indicator->type, sizeof(fua_indicator_t));
   
   if (hdr->s) {
      fua_indicator_t ind;
      ind.f = indicator->f;
      ind.nir = indicator->nir;
      ind.type = hdr->type;
      memcpy(data,&ind,sizeof(ind));
      len = sizeof(ind);
   }

   memcpy(data+len, buf+2, buflen-2);
   len += buflen-2;
  
   if (hdr->e) {
      ice_h264_process_nal_unit(ctx,is_end_frame,data,len);
   }

   return 0;
}

int
snw_rtp_h264_handle_pkg_in(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   rtp_hdr_t *hdr;
   char *p;
   int hdrlen = 0;
   int extlen = 0;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   if (ctx->pkt_type != RTP_VIDEO)
      return 0;   

   hdr = (rtp_hdr_t*)buf;
   hdrlen = MIN_RTP_HEADER_SIZE + 4*hdr->cc;
   if (hdr->x) {
      //uint16_t id;
      uint16_t len;
      p = buf + hdrlen; 
      //id = ntohs(*((uint16_t*)p));
      len = ntohs(*((uint16_t*)(p+2)));
      extlen = 4 + 4*len;
      hdrlen += extlen;
   }

#ifdef ENABLE_RTMP
   if (!ctx->rtmp_ctx) {
      ctx->rtmp_ctx = snw_rtmp_ctx_new("rtmp://49.213.76.92:1935/live/livestream");
      if (!ctx->rtmp_ctx) {
         ERROR(log, "failed to allocate rtmp ctx");
         return -1;
      }
   }
   snw_rtmp_update_ts(ctx->rtmp_ctx, ntohl(hdr->ts));
#endif

   TRACE(log, "rtp info, seq=%u, hdrlen=%u, extlen=%u, v=%u,"
              " x=%u, cc=%u, pt=%u, m=%u", 
         htons(hdr->seq),  hdrlen, extlen, hdr->v, 
         hdr->x, hdr->cc, hdr->pt, hdr->m);

   //parsing h264 header
   p = buf + hdrlen;
   {
      uint8_t nal_unit_type = *p & 0x1f;
      // 5bits, 7.3.1 NAL unit syntax,
      // H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
      //  7: SPS, 8: PPS, 5: I Frame, 1: P Frame, 9: AUD, 6: SEI
      //DEBUG(log,"h264 header info, nal_unit_type=%u", nal_unit_type);

      switch(nal_unit_type) {
         case H264_PT_RSV0:
         case H264_PT_RSV1:
         case H264_PT_RSV2:
            TRACE(log,"reserved nal unit type, nal_unit_type=%u", nal_unit_type);
            break;

         case H264_PT_STAPA:
            ice_h264_process_stapa_unit(ctx,hdr->m,p,buflen - hdrlen);
            break;

         case H264_PT_STAPB:
         case H264_PT_MTAP16:
         case H264_PT_MTAP24:
         case H264_PT_FUB:
            TRACE(log,"stapb/mtap16/mtap24/fub not supported, nal_unit_type=%u", 
                   nal_unit_type);
            break;

         case H264_PT_FUA:
            ice_h264_process_fua_unit(ctx,hdr->m,p,buflen - hdrlen);
            break;

         default:
            ice_h264_process_nal_unit(ctx,hdr->m,p,buflen - hdrlen);
            break;
      }
   }
   return 0;
}

int
snw_rtp_h264_handle_pkg_out(void *data, char *buf, int buflen) {

   return 0;
}

int
snw_rtp_h264_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_h264_module = { 
   "h264",
   0,/*ctx*/
   RTP_VIDEO,
   0,
   snw_rtp_h264_init, 
   snw_rtp_h264_handle_pkg_in, 
   snw_rtp_h264_handle_pkg_out, 
   snw_rtp_h264_fini,
   0 /*next*/
};


