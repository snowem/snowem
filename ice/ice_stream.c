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

#include <assert.h>

#include "core/mempool.h"
#include "core/log.h"
#include "ice/ice.h"
#include "ice/ice_stream.h"

void 
snw_ice_stream_mempool_init(snw_ice_context_t *ctx) {

   if (!ctx) return;

   ctx->stream_mempool = snw_mempool_create(
         sizeof(snw_ice_stream_t),sizeof(snw_ice_stream_t)*1024,1);
   assert(ctx->stream_mempool!=NULL);

   return;
}

snw_ice_stream_t* 
snw_ice_stream_allocate(snw_ice_context_t *ctx) {
   snw_ice_stream_t* stream;

   if (!ctx || !ctx->stream_mempool)
      return 0;
   
   stream = (snw_ice_stream_t*) snw_mempool_allocate(ctx->stream_mempool); 
   if (!stream)
      return 0;

   memset(stream,0,sizeof(*stream));
   return stream;
}


void
snw_ice_stream_deallocate(snw_ice_context_t *ctx, snw_ice_stream_t* p) {

   if (!ctx || !ctx->stream_mempool)
      return;

   snw_mempool_free(ctx->stream_mempool, p);

   return;
}

snw_ice_stream_t*
snw_ice_stream_find(ice_stream_head_t *head, uint32_t id) {
   snw_ice_stream_t *s = 0;

   if (head == NULL)
      return NULL;
   
   LIST_FOREACH(s,head,list) {
      if (s->id == id)
         return s;
   }

   return NULL;
}

void
snw_ice_stream_insert(ice_stream_head_t *head, snw_ice_stream_t *item) {
   
   if ( head == NULL || item == NULL )
      return;

   LIST_INSERT_HEAD(head,item,list);

   return;
}

void
snw_ice_stream_free(ice_stream_head_t *streams, snw_ice_stream_t *stream) {

   return;
}


void
snw_ice_stream_print_ssrc(snw_ice_context_t *ctx, snw_ice_stream_t *s, const char *info) {
   snw_log_t *log = 0;

   if (!ctx || !s) return;
   log = ctx->log;

   DEBUG(log,"stream ssrc, info=%s, local_audio_ssrc=%u, remote_audio_ssrc=%u, "
             "local_video_ssrc=%u, remote_video_ssrc=%u", info,
         s->local_audio_ssrc,
         s->remote_audio_ssrc,
         s->local_video_ssrc,
         s->remote_video_ssrc);
}

