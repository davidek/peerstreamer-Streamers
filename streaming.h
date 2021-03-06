/*
 * Copyright (c) 2010-2011 Luca Abeni
 * Copyright (c) 2010-2011 Csaba Kiraly
 *
 * This file is part of PeerStreamer.
 *
 * PeerStreamer is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * PeerStreamer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with PeerStreamer.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef STREAMING_H
#define STREAMING_H

#include <stdbool.h>
#ifdef _WIN32
typedef long suseconds_t;
#endif

struct chunk;

void stream_init(int size, struct nodeID *myID);
int source_init(const char *fname, struct nodeID *myID, int *fds, int fds_size, int buff_size);
void received_chunk(struct nodeID *from, const uint8_t *buff, int len);
void send_chunk();
struct chunk *generated_chunk(suseconds_t *delta);
int add_chunk(struct chunk *c);
struct chunkID_set *get_chunks_to_accept(struct nodeID *fromid, const struct chunkID_set *cset_off, int max_deliver, uint16_t trans_id);
void send_offer();
void send_accepted_chunks(struct nodeID *to, struct chunkID_set *cset_acc, int max_deliver, uint16_t trans_id);
void send_bmap(struct nodeID *to);

void log_chunk(struct nodeID *from,struct nodeID *to,struct chunk *c,char *note);

#endif	/* STREAMING_H */
