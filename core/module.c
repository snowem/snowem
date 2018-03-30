
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "core.h"
#include "module.h"
#include "mq.h"
#include "linux_list.h"
#include "log.h"

void
snw_module_init(snw_context_t *ctx) {
   snw_log_t *log = 0;
   struct list_head *p;
   void *handle;
   void (*init)(void*);

   if (!ctx) return;
   log = ctx->log;

   list_for_each(p,&ctx->modules.list) {
      snw_module_t *m = list_entry(p,snw_module_t,list);
      handle = dlopen(m->sofile, RTLD_LAZY);
      if (!handle) {
         ERROR(ctx->log, "failed to load library s=%s", dlerror());
         exit(1);
      }
      m->ctx = ctx;
      init = (void (*)(void*))dlsym(handle, "module_init");
      m->init = init;
      init(m);
   }

   return;
}


void
snw_module_enqueue(void *mq, const time_t curtime, const void* data,
       uint32_t len, uint32_t flow) {
   snw_shmmq_enqueue((snw_shmmq_t *)mq, curtime, data, len, flow);
}

