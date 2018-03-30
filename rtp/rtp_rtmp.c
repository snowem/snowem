#include "core/log.h"
#include "rtp/rtp_rtmp.h"


int
snw_rtp_rtmp_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_rtmp_module,M_FLAGS_INIT)) {
      return -1;
   }

   TRACE(log,"init rtp rtmp");
   MODULE_IS_FLAG(g_rtp_rtmp_module,M_FLAGS_INIT);

   return 0;
}

int
snw_rtp_rtmp_handle_pkg_in(void *ctx, char *buffer, int len) {
   return 0;
}

int
snw_rtp_rtmp_handle_pkg_out(void *ctx, char *buffer, int len) {
   return 0;
}


int
snw_rtp_rtmp_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_rtmp_module = { 
   "rtmp",
   0,/*ctx*/
   RTP_VIDEO,
   0,
   snw_rtp_rtmp_init, 
   snw_rtp_rtmp_handle_pkg_in, 
   snw_rtp_rtmp_handle_pkg_out, 
   snw_rtp_rtmp_fini,
   0 /*next*/
};


