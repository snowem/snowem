#include "rtp/rtp_utils.h"

int
snw_rtp_get_hdrlen(rtp_hdr_t *hdr) {
   uint16_t id = 0;
   int hdrlen = 0;
   int extlen = 0;
   char *p, *buf;

   if (!hdr) return 0;

   hdrlen = MIN_RTP_HEADER_SIZE + 4*hdr->cc;
   buf = (char*)hdr;
   if (hdr->x) {
      uint16_t len;
      p = buf + hdrlen; 
      id = ntohs(*((uint16_t*)p));
      len = ntohs(*((uint16_t*)(p+2)));
      extlen = 4 + 4*len;
      hdrlen += extlen;
   }

   return hdrlen;
}
