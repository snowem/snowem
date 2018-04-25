/*
 * (C) Copyright 2018 Jackie Dinh <jackiedinh8@gmail.com>
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

#ifndef _SNOW_CORE_JSON_MSG_H_
#define _SNOW_CORE_JSON_MSG_H_

#include "json-c/json.h"

#ifdef __cplusplus
extern "C" {
#endif

const char*
snw_json_msg_to_string(json_object *jobj);

int
snw_json_msg_get_int(json_object *jobj, const char *key);

const char*
snw_json_msg_get_string(json_object *jobj, const char *key);

json_object*
snw_json_msg_get_object(json_object *jobj, const char *key);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_JSON_MSG_H_
