/*
 * (C) Copyright 2015 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _SNOW_CORE_SHM_H_
#define _SNOW_CORE_SHM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/shm.h>
#include <stdint.h>

typedef struct snw_shm snw_shm_t;
struct snw_shm
{
	key_t key;
	size_t size;
	int id;
	char* addr;
};

snw_shm_t* 
snw_shm_open(key_t key, size_t size);

snw_shm_t* 
snw_shm_create(key_t key, size_t size);

char* 
snw_shmat(int _id);

void 
snw_shmdt(char* _mem);

int32_t
snw_shm_alloc(snw_shm_t *shm);

void 
snw_shm_free(snw_shm_t *shm);


#ifdef __cplusplus
}
#endif

#endif//_SNOW_CORE_SHM_H_

