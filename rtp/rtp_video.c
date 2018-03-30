#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "rtp/rtp_h264.h"
#include "rtp/rtp_nack.h"
#include "rtp/rtp_video.h"

#define USE_MODULE_VIDEO
snw_rtp_module_t *g_rtp_video_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_VIDEO


int
snw_rtp_video_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   snw_rtp_module_t *prev = &g_rtp_video_module;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_video_module,M_FLAGS_INIT)) {
      return -1;
   }

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_video_modules[i];
      if (!m) break;

      TRACE(log,"init module, name=%s",m->name);
      m->init(ctx);
   }

   MODULE_SET_FLAG(g_rtp_video_module,M_FLAGS_INIT);

   return 0;
}


int
snw_rtp_video_handle_pkg_in(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   int i = 0;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;
   
   //print_rtp_header(log,buf,buflen,"video");

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_video_modules[i];
      if (!m) break;

      TRACE(log,"handle pkg, module=%s",m->name);
      m->handle_pkg_in(ctx,buf,buflen);
   }

    
   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   return 0;
}

int
snw_rtp_video_handle_pkg_out(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   int i = 0;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_video_modules[i];
      if (!m) break;

      m->handle_pkg_in(ctx,buf,buflen);
   }

    
   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   return 0;
}


int
snw_rtp_video_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_video_module = { 
   "video",
   0,/*ctx*/
   RTP_VIDEO,
   0,
   snw_rtp_video_init, 
   snw_rtp_video_handle_pkg_in, 
   snw_rtp_video_handle_pkg_out, 
   snw_rtp_video_fini,
   0 /*next*/
};


