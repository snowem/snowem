#ifndef _SNOW_RTP_VIDEO_H_
#define _SNOW_RTP_VIDEO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rtp/rtp.h"

int snw_rtp_video_init(void *ctx);
int snw_rtp_video_handle_pkg_in(void *ctx, char *buffer, int len);
int snw_rtp_video_handle_pkg_out(void *ctx, char *buffer, int len);
int snw_rtp_video_fini();

extern snw_rtp_module_t g_rtp_video_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_VIDEO_H_



