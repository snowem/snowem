#ifndef _SNOW_RTP_UITLS_H_
#define _SNOW_RTP_UITLS_H_

#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

int
snw_rtp_get_hdrlen(rtp_hdr_t *hdr);

#ifdef __cplusplus
}
#endif

#endif
