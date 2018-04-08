/*
 * Copyright (c) 2018 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IPF_H
#define IPF_H 1

#include "dp-packet.h"
#include "openvswitch/types.h"

struct ipf_status {
   bool ifp_v4_enabled;
   unsigned int min_v4_frag_size;
   unsigned int nfrag_max;
   unsigned int nfrag;
   unsigned int n4frag_accepted;
   unsigned int n4frag_completed_sent;
   unsigned int n4frag_expired_sent;
   unsigned int n4frag_too_small;
   unsigned int n4frag_overlap;
   bool ifp_v6_enabled;
   unsigned int min_v6_frag_size;
   unsigned int n6frag_accepted;
   unsigned int n6frag_completed_sent;
   unsigned int n6frag_expired_sent;
   unsigned int n6frag_too_small;
   unsigned int n6frag_overlap;
};

/* Collects and reassembles fragments which are to be sent through
 * conntrack, if fragment processing is enabled or fragments are
 * in flight. */
void
ipf_preprocess_conntrack(struct dp_packet_batch *pb, long long now,
                         ovs_be16 dl_type, uint16_t zone, uint32_t hash_basis);

/* Updates the state of fragments associated with reassembled packets and
 * sends out fragments that are either associated with completed
 * packets or expired, if fragment processing is enabled or fragments are
 * in flight. */
void
ipf_postprocess_conntrack(struct dp_packet_batch *pb, long long now,
                          ovs_be16 dl_type);

void
ipf_init(void);

void
ipf_destroy(void);

#endif /* ipf.h */
