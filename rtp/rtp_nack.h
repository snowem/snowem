#ifndef _SNOW_RTP_NACK_H_
#define _SNOW_RTP_NACK_H_

#include "rtp/rtcp.h"
#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

int snw_rtp_nack_init(void *ctx);
int snw_rtp_nack_handle_pkg_in(void *ctx, char *buffer, int len);
int snw_rtp_nack_handle_pkg_out(void *ctx, char *buffer, int len);
int snw_rtp_nack_fini();

extern snw_rtp_module_t g_rtp_nack_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_NACK_H_



