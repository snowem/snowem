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

#include "ice/msg.h"

const char*
snw_ice_msg_to_string(json_object *jobj) {
   return json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
}

int
snw_ice_msg_get_int(json_object *jobj, const char *key) {
  int ret = -1;
  json_object *vobj = 0;

  json_object_object_get_ex(jobj,key,&vobj);
  if (!vobj || json_object_get_type(vobj) != json_type_int)
    return -1;
  ret = json_object_get_int(vobj);

  return ret;
}

const char*
snw_ice_msg_get_string(json_object *jobj, const char *key) {
  const char* ret = 0;
  json_object *vobj = 0;

  json_object_object_get_ex(jobj,key,&vobj);
  if (!vobj || json_object_get_type(vobj) != json_type_string)
    return 0;
  ret = json_object_get_string(vobj);

  return ret;
}

json_object*
snw_ice_msg_get_object(json_object *jobj, const char *key) {
  json_object *vobj = 0;

  json_object_object_get_ex(jobj,key,&vobj);
  if (!vobj || json_object_get_type(vobj) != json_type_object)
    return 0;

  return vobj;
}


