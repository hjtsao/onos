/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __PERMISSIONACL__
#define __PERMISSIONACL__

#include "headers.p4"
#include "defines.p4"

control permission_acl_ingress(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action set_user_pipeline_id_and_role_id(user_pipeline_id_t p_id, role_id_t r_id) {
        local_metadata.user_pipeline_id = p_id;
        local_metadata.role_id = r_id;
    }

    table permission_acl_ingress_table {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.vlan.vid                   : ternary;
            hdr.ipv4.src_addr              : ternary;
            hdr.ipv4.dst_addr              : ternary;
        }
        actions = {
            set_user_pipeline_id_and_role_id;
            _drop;
            NoAction;
        }
        const default_action = NoAction;
    }

    apply {
        permission_acl_ingress_table.apply();
     }
}

control permission_acl_egress(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {
    table permission_acl_egress_table {
             
        key = {
            local_metadata.role_id         : ternary;
            standard_metadata.egress_port  : ternary;
            hdr.vlan.vid                   : ternary;
            hdr.ipv4.src_addr              : ternary;
            hdr.ipv4.dst_addr              : ternary;
        }
        actions = {
            _drop;
            NoAction;
        }
        const default_action = NoAction;
    }

    apply {
        permission_acl_egress_table.apply();
     }
}

#endif
