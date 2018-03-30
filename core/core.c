#include <stdlib.h>
#include <signal.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core.h"
#include "mq.h"
#include "module.h"
#include "log.h"
#include "ice/ice.h"

snw_context_t*
snw_create_context() {   
   snw_context_t *ctx;

   ctx = (snw_context_t*)malloc(sizeof(snw_context_t));
   if ( ctx == NULL )
      return 0;

   memset(ctx, 0, sizeof(*ctx));
   INIT_LIST_HEAD(&ctx->modules.list);
   return ctx; 
}

void
daemonize() {
   pid_t pid;

   if ((pid = fork() ) != 0 ) 
   {   
      exit( 0); 
   }   

   setsid();

   signal( SIGINT,  SIG_IGN);
   signal( SIGHUP,  SIG_IGN);
   signal( SIGPIPE, SIG_IGN);
   signal( SIGTTOU, SIG_IGN);
   signal( SIGTTIN, SIG_IGN);
   signal( SIGCHLD, SIG_IGN);
   signal( SIGTERM, SIG_IGN);

   struct sigaction sig;

   sig.sa_handler = SIG_IGN;
   sig.sa_flags = 0;
   sigemptyset( &sig.sa_mask);
   sigaction( SIGHUP,&sig,NULL);

   if ((pid = fork() ) != 0 ) 
   {   
      exit(0);
   }   

   umask(0);
   setpgrp();

   return;
}


