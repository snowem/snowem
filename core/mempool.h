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
 * @(#)mempool.h
 */

#ifndef _SNOW_CORE_MEMPOOL_H_
#define _SNOW_CORE_MEMPOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "types.h"

typedef struct tag_mem_chunk
{
   int mc_free_chunks;
   struct tag_mem_chunk *mc_next;
} mem_chunk;
typedef mem_chunk* mem_chunk_t;

typedef struct snw_mempool snw_mempool_t;
struct snw_mempool {
   char *mp_startptr;        /* start pointer */
   mem_chunk_t mp_freeptr;   /* pointer to the start memory chunk */
   int mp_free_chunks;       /* number of total free chunks */
   int mp_total_chunks;      /* number of total free chunks */
   int mp_chunk_size;        /* chunk size in bytes */
   int mp_type;
};

/* create a memory pool with a chunk size and total size
   an return the pointer to the memory pool */
snw_mempool_t*
snw_mempool_create(size_t chunk_size, size_t total_size, int is_hugepage);

/* allocate one chunk */
void*
snw_mempool_allocate(snw_mempool_t *mp);

/* free one chunk */
void
snw_mempool_free(snw_mempool_t *mp, void *p);

/* destroy the memory pool */
void
snw_mempool_destroy(snw_mempool_t *mp);

/* return the number of free chunks */
int
snw_mempool_capacity(snw_mempool_t *mp);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_MEMPOOL_H_ 


