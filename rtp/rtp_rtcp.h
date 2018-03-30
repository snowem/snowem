#ifndef _SNOW_RTP_RTP_RTCP_H_
#define _SNOW_RTP_RTP_RTCP_H_

#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

int snw_rtp_rtcp_init(void *ctx);
int snw_rtp_rtcp_handle_pkg_in(void *ctx, char *buffer, int len);
int snw_rtp_rtcp_handle_pkg_out(void *ctx, char *buffer, int len);
int snw_rtp_rtcp_fini();

extern snw_rtp_module_t g_rtp_rtcp_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_RTCP_H_



