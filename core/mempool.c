/*
 * Copyright (C) 2015 EunYoung Jeong, Shinae Woo, Muhammad Jamshed, Haewon Jeong, 
 *                    Sunghwan Ihm, Dongsu Han, KyoungSoo Park
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the 
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the 
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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
 * @(#)mempool.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#ifdef __FreeBSD__
#include <malloc_np.h>
#endif //__FreeBSD__

#include "mempool.h"

snw_mempool_t*
snw_mempool_create(size_t chunk_size, size_t total_size, int is_hugepage)
{
   int res;
   snw_mempool_t *mp;

   if (chunk_size < sizeof(mem_chunk)) {
      return NULL;
   }
   if (chunk_size % 4 != 0) {
      return NULL;
   }

   //assert(chunk_size <= 2*1024*1024);
   mp = (snw_mempool_t *)calloc(1, sizeof(snw_mempool_t));
   if (mp == NULL) {
      exit(0);
   }
   mp->mp_type = is_hugepage;
   mp->mp_chunk_size = chunk_size;
   mp->mp_free_chunks = ((total_size + (chunk_size -1))/chunk_size);
   mp->mp_total_chunks = mp->mp_free_chunks;
   total_size = chunk_size * ((size_t)mp->mp_free_chunks);

   /* allocate the big memory chunk */
#ifdef HUGETABLE
   if (is_hugepage == 1 ) {
      mp->mp_startptr = get_huge_pages(total_size, NULL);
      if (!mp->mp_startptr) {
         assert(0);
         if (mp) free(mp);
         return (NULL);
      }
   } else {
#endif
      res = posix_memalign((void **)&mp->mp_startptr, getpagesize(), total_size);
      if (res != 0) {
         printf("posix_memalign failed, size=%ld\n", total_size);
         assert(0);
         if (mp) free(mp);
         return (NULL);
      }
#ifdef HUGETABLE
   }
#endif

   /* try mlock only for superuser */
   //if (geteuid() == 0) {
   //   if (mlock(mp->mp_startptr, total_size) < 0)
   //      printf("m_lock failed, size=%ld\n", total_size);
   //}

   mp->mp_freeptr = (mem_chunk_t)mp->mp_startptr;
   mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
   mp->mp_freeptr->mc_next = NULL;

   return mp;
}

void*
snw_mempool_allocate(snw_mempool_t *mp)
{
   mem_chunk_t p = mp->mp_freeptr;

   if (mp->mp_free_chunks == 0)
      return (NULL);
   assert(p->mc_free_chunks > 0 && p->mc_free_chunks <= p->mc_free_chunks);

   p->mc_free_chunks--;
   mp->mp_free_chunks--;
   if (p->mc_free_chunks) {
      /* move right by one chunk */
      mp->mp_freeptr = (mem_chunk_t)((char *)p + mp->mp_chunk_size);
      mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
      mp->mp_freeptr->mc_next = p->mc_next;
   }
   else {
      mp->mp_freeptr = p->mc_next;
   }

   return p;
}

void
snw_mempool_free(snw_mempool_t *mp, void *p)
{
   mem_chunk_t mcp = (mem_chunk_t)p;

   if (!mp || !p)
      return;

   assert(((char *)p - mp->mp_startptr) % mp->mp_chunk_size == 0);

   mcp->mc_free_chunks = 1;
   mcp->mc_next = mp->mp_freeptr;
   mp->mp_freeptr = mcp;
   mp->mp_free_chunks++;
}

void
snw_mempool_destroy(snw_mempool_t *mp)
{
#ifdef HUGETABLE
   if(mp->mp_type == MEM_HUGEPAGE) {
      free_huge_pages(mp->mp_startptr);
   } else {
#endif
      free(mp->mp_startptr);
#ifdef HUGETABLE
   }
#endif
   free(mp);
}

int
snw_mempool_capacity(snw_mempool_t *mp)
{
   return mp->mp_free_chunks;
}

