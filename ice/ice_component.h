#ifndef _SNOW_ICE_COMPONENT_H_
#define _SNOW_ICE_COMPONENT_H_

#include <stdint.h>
#include <jansson.h>

#include "cice/agent.h"
#include "core/core.h"
#include "ice/dtls.h"
#include "ice/ice_types.h"
//#include "ice/vp8.h"
#include "rtp/packet.h"
#include "rtp/rtp.h"
#include "rtp/rtp_nack.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_ice_component {
   uint32_t          id;
   int               state;
   int               is_started;

   dtls_ctx_t       *dtls;
   snw_ice_stream_t *stream;
   candidate_t       remote_candidates;
   int64_t           fir_latest;   
   uint8_t           fir_seq;

   //TODO: store them in rtp_nack module
   rtp_slidewin_t    a_slidewin;
   rtp_slidewin_t    v_slidewin;

   struct list_head  list;
};

void
snw_component_mempool_init(snw_ice_context_t *ctx);

snw_ice_component_t*
snw_component_allocate(snw_ice_context_t *ctx);

void
snw_component_deallocate(snw_ice_context_t *ctx, snw_ice_component_t* p);

snw_ice_component_t*
snw_component_find(snw_ice_component_t *head, uint32_t id);

void
snw_component_insert(snw_ice_component_t *head, snw_ice_component_t *item);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_COMPONENT_H_




