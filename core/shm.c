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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#if __FreeBSD__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>

#endif

#include "shm.h"
#include "log.h"

static const int SHM_DEFAULT_OPEN_FLAG = 0666;

snw_shm_t* 
snw_shm_open(key_t key, size_t size) {
  snw_shm_t* shm = NULL;
  int id; 

  id = shmget(key, size, SHM_DEFAULT_OPEN_FLAG);
	if (id < 0) return 0;
	
  shm = (snw_shm_t *) malloc(sizeof(snw_shm_t));
  if ( shm == NULL ) return 0;
  shm->key = key;
  shm->size = size;
  shm->id = id;

	shm->addr = (char*)snw_shmat(id);
  if ( shm->addr == NULL ) {
    free(shm);
    return 0;
  }

	return shm;
}

snw_shm_t* 
snw_shm_create(key_t key, size_t size)
{
  snw_shm_t* shm = NULL;
  int id;

  id = shmget(key, size, SHM_DEFAULT_OPEN_FLAG | IPC_CREAT | IPC_EXCL);
	if (id < 0) return 0;

	shm = (snw_shm_t *) malloc(sizeof(snw_shm_t));
  if ( shm == NULL ) return 0;
  shm->key = key;
  shm->size = size;
  shm->id = id;

	shm->addr = (char*)snw_shmat(id);
  if (shm->addr == NULL) {
    free(shm);
    return 0;
  }

	return shm;
}

char* 
snw_shmat(int _id) {
	char* p = (char*) shmat(_id, NULL, 0);
	if (p == (char*)-1) {
    return 0;
  }

	return p;
}

int
snw_shmdt(char* _mem) {
	if (_mem == NULL)
		return -1;
	
	int ret = shmdt(_mem);
	if (ret < 0) {
    return -2;
  }

  return 0;
}

int
snw_shm_alloc(snw_shm_t *shm) {
  int  id;
   
  if ( shm->key == 0 )
     id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));
  else
     id = shmget(shm->key, shm->size, (SHM_R|SHM_W|IPC_CREAT));

  if (id == -1) {
      return -1;
  }

  shm->addr = (char*)shmat(id, NULL, 0);

  if (shm->addr == (void *) -1) {
        return -1;
  }

  return (shm->addr == (void *) -1) ? -3 : 0;
}

void snw_shm_free(snw_shm_t *shm)
{
  if (shmdt(shm->addr) == -1) {
    // TODO
  }
  return;
}

