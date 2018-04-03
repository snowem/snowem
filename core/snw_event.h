/*
 * (C) Copyright 2017 Jackie Dinh <jackiedinh8@gmail.com>
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

#ifndef _SNOW_CORE_EVENT_H__
#define _SNOW_CORE_EVENT_H__

#ifdef __cplusplus
extern "C" {
#endif

enum snw_event_type
{
	snw_ev_connect        = 1001,
	snw_ev_disconnect     = 1002,
	snw_ev_data           = 1003,
};

typedef struct snw_event snw_event_t;
struct snw_event {
	uint32_t magic_num;		// magic = 'EVNT'
	uint32_t event_type;
	uint32_t flow;	
	uint32_t ipaddr;
	uint32_t port;
	uint32_t other;	
};

#define SNW_EVENT_HEADER_LEN 24
#define SNW_EVENT_MAGIC_NUM 0x45564E54

#ifdef __cplusplus
}
#endif

#endif
