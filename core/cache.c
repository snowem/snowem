/*
 * Copyright (c) 2015 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1 Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  2 Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *  3 Neither the name of the <organization> nor the 
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#)cache.c
 */


#include <math.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>

#include "cache.h"
#include "log.h"


void 
snw_cache_init_base(snw_hashbase_t *base)
{
   uint32_t isqrt;
   uint32_t i, j, k;
   uint32_t flag;

   if (base == NULL)
      return;

   base->hb_base = (uint32_t*)malloc(sizeof(uint32_t)*(base->hb_time));
   if ( base->hb_base == NULL ) {
      //printf("malloc failed"); 
      exit(-1);
      return;
   }

   isqrt = sqrt(base->hb_len);
   for (i = base->hb_len, j = 0; j <base->hb_time; i--) {
      flag = 1;
      for (k = 2; k <= isqrt; k++) {
         if (i % k == 0) {
            flag = 0;
            break;
         }
      }
      if (flag == 1) {
         base->hb_base[j] = i;
         if(i<=0) {
            //printf("HashBase[%d] = %d,HashLen[%d] is too small!\n",
            //      j,i,base->hb_len);
            exit(-2);
         }
         j++;
      }
   }
   return;
}

char*
snw_get_shm(uint32_t key, int32_t size, int32_t flag)
{
   int id; 
   char *addr;
   
   id = shmget(key, size, flag);

   if (id < 0) {
      return 0;
   }   

   addr = (char*)shmat(id, NULL, 0);

   if ( addr == NULL ) { 
      return 0;
   }   

   return addr;
}

int 
snw_cache_getshm(snw_hashbase_t *base, uint32_t key, int32_t size, int32_t create)
{
   char* pData;// = snw_get_shm(key, size, 0666);

   base->hb_size = size;

   pData = snw_get_shm(key, size, 0666);
   if (pData == NULL) {
      if (create) {
         pData = snw_get_shm(key, size, (0666|IPC_CREAT));
         if (pData == NULL) {
            return -1;
         }
         memset(pData, 0, size);
         base->hb_cache = pData;
      } else {
         return -2;
      }
   } else {
      memset(pData, 0, size);
      base->hb_cache = pData;
   }

    return 0;
}

int
snw_cache_init(snw_hashbase_t *base, uint32_t key, 
      uint32_t hashtime, uint32_t hashlen, uint32_t objsize, 
      uint32_t create, eqfn equal_fn, keyfn key_fn,
      isemptyfn isempty_fn, setemptyfn setempty_fn)
{
   int32_t iSize;
   uint32_t iKey;
   int32_t ret;

   if (!base) {
      printf("hash base is null, key=%d, objsize=%d\n", key, objsize);
      return -1;
   }

   base->hb_pid = 0;
   base->hb_time = hashtime;
   base->hb_len = hashlen;
   base->hb_objsize = objsize;
   base->hb_eqfn = equal_fn;
   base->hb_keyfn = key_fn;
   base->hb_isemptyfn = isempty_fn;
   base->hb_setemptyfn = setempty_fn;

   iSize = objsize * hashtime * hashlen;
   iKey = key + base->hb_pid;
   //printf("cache init, key=%x, size=%u\n",iKey, iSize);
   ret = snw_cache_getshm(base, iKey, iSize, create);

   if ((0 != ret) || (NULL == base->hb_cache)) {
      printf("cache init fail,key=%u,size=%u,ret=%d\n",iKey,iSize,ret);
      return -2;
   }

   snw_cache_init_base(base);
   return 0;
}

void*
snw_cache_get(snw_hashbase_t *base, void *sitem, int *is_new) 
{
   void *item = 0;
   char *table = 0;
   int   value = 0;
   uint32_t   i;  

   if (!sitem)
      return NULL;

   table = (char*)base->hb_cache;
   for (i=0; i < base->hb_time; i++ ) { 
      value = base->hb_keyfn(sitem) % base->hb_base[i];
      item = table + i*base->hb_len*base->hb_objsize
                   + value*base->hb_objsize;
      if (base->hb_isemptyfn(item)) {
         *is_new = 1;
         return item;
      }
      if (base->hb_eqfn(item, sitem)) {
         *is_new = 0;
         return item;
      }
   }   
   
   *is_new = 0;
   return NULL;
}

void*
snw_cache_search(snw_hashbase_t *base, void *sitem) 
{
   void *item = 0;
   char *table = 0;
   int      value = 0;
   uint32_t   i;  

   if (!sitem)
      return 0;

   table = (char*)base->hb_cache;

   if (base->hb_isemptyfn(sitem))
      return 0;
   
   for ( i=0; i < base->hb_time; i++ ) { 
      value = base->hb_keyfn(sitem) % base->hb_base[i];
      item = table + i*base->hb_len*base->hb_objsize
                   + value*base->hb_objsize;
      if (base->hb_eqfn(item, sitem))
         return item;
   }   
   
   return 0;
}

void*
snw_cache_insert(snw_hashbase_t *base, void *sitem) 
{
   void *item = 0;
   char *table = 0;
   int      value = 0;
   uint32_t i;  

   if ( !sitem )
      return 0;

   table = (char*)base->hb_cache;

   for ( i=0; i < base->hb_time; i++ ) { 
      value = base->hb_keyfn(sitem) % base->hb_base[i];
      item = table + i*base->hb_len*base->hb_objsize 
                   + value*base->hb_objsize;
      if ( base->hb_isemptyfn(item) ) {
         memcpy(item, sitem, base->hb_objsize);
         return item;
      }
   }   
   
   return 0;
}

int
snw_cache_remove(snw_hashbase_t *base, void *sitem) 
{
   if (!sitem)
      return -1;
   base->hb_setemptyfn(sitem);
   return 0;
}

int
snw_cache_finit(snw_hashbase_t *base)
{
   return 0;
}

void*
snw_cache_search_new(snw_hashbase_t *base, void *sitem, eqfn _eqfn) 
{
   void *item = 0;
   char *table = 0;
   int      value = 0;
   uint32_t i;  

   if (!sitem)
      return 0;

   table = (char*)base->hb_cache;

   for ( i=0; i < base->hb_time; i++ ) { 
      value = base->hb_keyfn(sitem) % base->hb_base[i];
      item = table + i*base->hb_len*base->hb_objsize
                   + value*base->hb_objsize;
      if (_eqfn(item, sitem))
         return item;
   }   
   
   return NULL;
}


