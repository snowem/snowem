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
#include "recording/recording.h"
#include "rtp/rtp_audio.h"
#include "rtp/rtp_nack.h"

#define USE_MODULE_AUDIO
snw_rtp_module_t *g_rtp_audio_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_AUDIO

int
snw_rtp_audio_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_audio_module,M_FLAGS_INIT)) {
      WARN(log,"rtp audio aready init");
      return -1;
   }

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_audio_modules[i];
      if (!m) break;

      //DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
   }

   MODULE_SET_FLAG(g_rtp_audio_module,M_FLAGS_INIT);

   return 0;
}

int
snw_rtp_audio_handle_pkg_in(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   int i = 0;

   if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
      return -1;
   }
   log = ctx->log;
   
   //print_rtp_header(log,buf,buflen,"audio"); 
   //HEXDUMP(log,(char*)buf,buflen,"rtp");

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_audio_modules[i];
      if (!m) break;

      //DEBUG(log,"audio-in handling, name=%s, m_pkt_type=%u, pkt_type=%u", 
      //         m->name, m->pkt_type, ctx->pkt_type);
      if (ctx->pkt_type & m->pkt_type)
         m->handle_pkg_in(ctx,buf,buflen);
   }


   return 0;
}

int
snw_rtp_audio_handle_pkg_out(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   int i = 0;

   if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
      return -1;
   }
   log = ctx->log;

   //print_rtp_header(log,buf,buflen,"audio"); 
   //HEXDUMP(log,(char*)buf,buflen,"rtp");

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_audio_modules[i];
      if (!m) break;

      DEBUG(log,"audio-out handling, name=%s, m_pkt_type=%u, pkt_type=%u", 
               m->name, m->pkt_type, ctx->pkt_type);
      if (ctx->pkt_type & m->pkt_type)
         m->handle_pkg_out(ctx,buf,buflen);
   }


   return 0;
}


int
snw_rtp_audio_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_audio_module = { 
   "audio",
   0,/*ctx*/
   RTP_AUDIO,
   0,
   snw_rtp_audio_init, 
   snw_rtp_audio_handle_pkg_in, 
   snw_rtp_audio_handle_pkg_out, 
   snw_rtp_audio_fini,
   0 /*next*/
};


