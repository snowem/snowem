#ifndef _SNOW_ICE_STREAM_H_
#define _SNOW_ICE_STREAM_H_

#include <inttypes.h>

#include "core/core.h"
#include "core/linux_list.h"
#include "ice/dtls.h"
#include "ice/ice_component.h"
#include "ice/ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_ice_stream {
   snw_ice_session_t *session;

   uint32_t id;
   uint32_t local_audio_ssrc;
   uint32_t local_video_ssrc;
   uint32_t remote_audio_ssrc;
   uint32_t remote_video_ssrc;

   int dtls_type;

   char remote_hashing[16];
   char remote_fingerprint[256];
   char remote_user[32];
   char remote_pass[64];

   snw_ice_component_t  components;
   snw_ice_component_t *rtp_component;
   snw_ice_component_t *rtcp_component;

   uint8_t gathering_done:1;
   uint8_t is_disable:1;
   uint8_t is_video:1;
   uint8_t reserved:5;

   struct list_head list;
};

void
snw_stream_mempool_init(snw_ice_context_t *ctx);

snw_ice_stream_t*
snw_stream_allocate(snw_ice_context_t *ctx);

void
snw_stream_deallocate(snw_ice_context *ctx, snw_ice_stream_t* p);

snw_ice_stream_t* 
snw_stream_find(snw_ice_stream_t *head, uint32_t id);

void
snw_stream_insert(snw_ice_stream_t *head, snw_ice_stream_t *item);

void
snw_stream_free(snw_ice_stream_t *streams, snw_ice_stream_t *stream);

void
snw_stream_print_ssrc(snw_ice_context *ctx, snw_ice_stream_t *s, const char *info);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_STREAM_H_



