#ifndef _SNOW_RTMP_RTMP_H_
#define _SNOW_RTMP_RTMP_H_

#include <stdint.h>

#include "log.h"
#include "srs_librtmp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUFFER_SIZE 16*1024*1024

typedef struct snw_rtmp_ctx snw_rtmp_ctx_t;
struct snw_rtmp_ctx {
   srs_rtmp_t          rtmp; //pointer to void

   // rtmp settings
   char               *rtmp_url;
   int                 rtmp_inited;
   int32_t             first_video_ts;
   int32_t             current_ts;

   uint32_t            pts;
   uint32_t            dts;

   // rtmp aac
   char               *audio_pos;
   char               *audio_raw;
   off_t               file_size;
   uint32_t            delta_ts;
   uint32_t            audio_ts;


};

snw_rtmp_ctx_t*
snw_rtmp_ctx_new(const char* url);

int
snw_rtmp_init(snw_rtmp_ctx_t *ctx, const char* rtmp_url);

void
snw_rtmp_update_ts(snw_rtmp_ctx_t *ctx, uint32_t ts);

int
snw_rtmp_handle_pkg(snw_rtmp_ctx_t *ctx, char *buf, int buflen);

#ifdef __cplusplus
}
#endif

#endif
