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
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>

#include <net_helper.h>
#include <chunk.h> 
#include <chunkbuffer.h> 
#include <trade_msg_la.h>
#include <trade_msg_ha.h>
#include <peerset.h>
#include <peer.h>
#include <chunkidset.h>
#include <limits.h>
#include <trade_sig_ha.h>
#ifdef CHUNK_ATTRIB_CHUNKER
#include <chunkiser_attrib.h>
#endif

#include "streaming.h"
#include "streamer.h"
#include "output.h"
#include "input.h"
#include "dbg.h"
#include "chunk_signaling.h"
#include "chunklock.h"
#include "topology.h"
#include "measures.h"
#include "scheduling.h"
#include "transaction.h"
#include "node_addr.h"

#include "scheduler_la.h"

# define CB_SIZE_TIME_UNLIMITED 1e12
uint64_t CB_SIZE_TIME = CB_SIZE_TIME_UNLIMITED;	//in millisec, defaults to unlimited

static bool heuristics_distance_maxdeliver = false;
static int bcast_after_receive_every = 0;
static bool neigh_on_chunk_recv = false;
static bool send_bmap_before_push = false;

struct chunk_attributes {
  uint64_t deadline;
  uint16_t deadline_increment;
  uint16_t hopcount;
} __attribute__((packed));

extern bool chunk_log;

struct chunk_buffer *cb;
static struct input_desc *input;
static int cb_size;

static int offer_per_tick = 1;	//N_p parameter of POLITO

int _needs(struct chunkID_set *cset, int cb_size, int cid);

uint64_t gettimeofday_in_us(void)
{
  struct timeval what_time; //to store the epoch time

  gettimeofday(&what_time, NULL);
  return what_time.tv_sec * 1000000ULL + what_time.tv_usec;
}

void cb_print()
{
#ifdef DEBUG
  struct chunk *chunks;
  int num_chunks, i, id;
  chunks = cb_get_chunks(cb, &num_chunks);

  dprintf("\tchbuf :");
  i = 0;
  if(num_chunks) {
    id = chunks[0].id;
    dprintf(" %d-> ",id);
    while (i < num_chunks) {
      if (id == chunks[i].id) {
        dprintf("%d",id % 10);
        i++;
      } else if (chunk_islocked(id)) {
        dprintf("*");
      } else {
        dprintf(".");
      }
      id++;
    }
  }
  dprintf("\n");
#endif
}

void stream_init(int size, struct nodeID *myID)
{
  static char conf[32];

  cb_size = size;

  sprintf(conf, "size=%d", cb_size);
  cb = cb_init(conf);
  chunkDeliveryInit(myID);
  chunkSignalingInit(myID);
  init_measures();
}

int source_init(const char *fname, struct nodeID *myID, int *fds, int fds_size, int buff_size)
{
  input = input_open(fname, fds, fds_size);
  if (input == NULL) {
    return -1;
  }

  stream_init(buff_size, myID);
  return 0;
}

void chunk_attributes_fill(struct chunk* c)
{
  struct chunk_attributes * ca;
  int priority = 1;

  assert((!c->attributes && c->attributes_size == 0)
#ifdef CHUNK_ATTRIB_CHUNKER
      || chunk_attributes_chunker_verify(c->attributes, c->attributes_size)
#endif
  );

#ifdef CHUNK_ATTRIB_CHUNKER
  if (chunk_attributes_chunker_verify(c->attributes, c->attributes_size)) {
    priority = ((struct chunk_attributes_chunker*) c->attributes)->priority;
    free(c->attributes);
    c->attributes = NULL;
    c->attributes_size = 0;
  }
#endif

  c->attributes_size = sizeof(struct chunk_attributes);
  c->attributes = ca = malloc(c->attributes_size);

  ca->deadline = c->id;
  ca->deadline_increment = priority * 2;
  ca->hopcount = 0;
}

int chunk_get_hopcount(struct chunk* c) {
  struct chunk_attributes * ca;

  if (!c->attributes || c->attributes_size != sizeof(struct chunk_attributes)) {
    fprintf(stderr,"Warning, chunk %d with strange attributes block. Size:%d expected:%u\n", c->id, c->attributes ? c->attributes_size : 0, sizeof(struct chunk_attributes));
    return -1;
  }

  ca = (struct chunk_attributes *) c->attributes;
  return ca->hopcount;
}

void chunk_attributes_update_received(struct chunk* c)
{
  struct chunk_attributes * ca;

  if (!c->attributes || c->attributes_size != sizeof(struct chunk_attributes)) {
    fprintf(stderr,"Warning, received chunk %d with strange attributes block. Size:%d expected:%u\n", c->id, c->attributes ? c->attributes_size : 0, sizeof(struct chunk_attributes));
    return;
  }

  ca = (struct chunk_attributes *) c->attributes;
  ca->hopcount++;
  dprintf("Received chunk %d with hopcount %hu\n", c->id, ca->hopcount);
}

void chunk_attributes_update_sending(const struct chunk* c)
{
  struct chunk_attributes * ca;

  if (!c->attributes || c->attributes_size != sizeof(struct chunk_attributes)) {
    fprintf(stderr,"Warning, chunk %d with strange attributes block\n", c->id);
    return;
  }

  ca = (struct chunk_attributes *) c->attributes;
  ca->deadline += ca->deadline_increment;
  dprintf("Sending chunk %d with deadline %lu (increment: %d)\n", c->id, ca->deadline, ca->deadline_increment);
}

struct chunkID_set *cb_to_bmap(struct chunk_buffer *chbuf)
{
  struct chunk *chunks;
  int num_chunks, i;
  struct chunkID_set *my_bmap = chunkID_set_init("type=bitmap");
  chunks = cb_get_chunks(chbuf, &num_chunks);

  for(i=num_chunks-1; i>=0; i--) {
    chunkID_set_add_chunk(my_bmap, chunks[i].id);
  }
  return my_bmap;
}

// a simple implementation that request everything that we miss ... up to max deliver
struct chunkID_set *get_chunks_to_accept(struct nodeID *fromid, const struct chunkID_set *cset_off, int max_deliver, uint16_t trans_id){
  struct chunkID_set *cset_acc, *my_bmap;
  int i, d, cset_off_size;
  //double lossrate;
  struct peer *from = nodeid_to_peer(fromid, 0);

  cset_acc = chunkID_set_init("size=0");

  //reduce load a little bit if there are losses on the path from this guy
  //lossrate = get_lossrate_receive(from->id);
  //lossrate = finite(lossrate) ? lossrate : 0;	//start agressively, assuming 0 loss
  //if (rand()/((double)RAND_MAX + 1) >= 10 * lossrate ) {
    my_bmap = cb_to_bmap(cb);
    cset_off_size = chunkID_set_size(cset_off);
    for (i = 0, d = 0; i < cset_off_size && d < max_deliver; i++) {
      int chunkid = chunkID_set_get_chunk(cset_off, i);
      //dprintf("\tdo I need c%d ? :",chunkid);
      if (!chunk_islocked(chunkid) && _needs(my_bmap, cb_size, chunkid)) {
        chunkID_set_add_chunk(cset_acc, chunkid);
        chunk_lock(chunkid,from);
        dtprintf("accepting %d from %s", chunkid, node_addr_tr(fromid));
#ifdef MONL
        dprintf(", loss:%f rtt:%f", get_lossrate(fromid), get_rtt(fromid));
#endif
        dprintf("\n");
        d++;
      }
    }
    chunkID_set_free(my_bmap);
  //} else {
  //    dtprintf("accepting -- from %s loss:%f rtt:%f\n", node_addr_tr(fromid), lossrate, get_rtt(fromid));
  //}

  reg_offer_accept_in(chunkID_set_size(cset_acc) > 0 ? 1 : 0);

  return cset_acc;
}

void send_bmap(struct nodeID *toid)
{
  struct chunkID_set *my_bmap = cb_to_bmap(cb);
   sendBufferMap(toid,NULL, my_bmap, input ? 0 : cb_size, 0);
  chunkID_set_free(my_bmap);
}

void bcast_bmap()
{
  int i, n;
  struct peer **neighbours;
  struct peerset *pset;
  struct chunkID_set *my_bmap;

  pset = get_peers();
  n = peerset_size(pset);
  neighbours = peerset_get_peers(pset);

  my_bmap = cb_to_bmap(cb);	//cache our bmap for faster processing
  for (i = 0; i<n; i++) {
    sendBufferMap(neighbours[i]->id,NULL, my_bmap, input ? 0 : cb_size, 0);
  }
  chunkID_set_free(my_bmap);
}

void send_ack(struct nodeID *toid, uint16_t trans_id)
{
  struct chunkID_set *my_bmap = cb_to_bmap(cb);
  sendAck(toid, my_bmap,trans_id);
  chunkID_set_free(my_bmap);
}

double get_average_lossrate_pset(struct peerset *pset)
{
  int i, n;
  struct peer **neighbours;

  n = peerset_size(pset);
  neighbours = peerset_get_peers(pset);
  {
    struct nodeID *nodeids[n];
    for (i = 0; i<n; i++) nodeids[i] = neighbours[i]->id;
#ifdef MONL
    return get_average_lossrate(nodeids, n);
#else
    return 0;
#endif
  }
}

void ack_chunk(struct chunk *c, struct nodeID *from, uint16_t trans_id)
{
  //reduce load a little bit if there are losses on the path from this guy
  double average_lossrate = get_average_lossrate_pset(get_peers());
  average_lossrate = finite(average_lossrate) ? average_lossrate : 0;	//start agressively, assuming 0 loss
  if (rand()/((double)RAND_MAX + 1) < 1 * average_lossrate ) {
    return;
  }
  send_ack(from, trans_id);	//send explicit ack
}

void received_chunk(struct nodeID *from, const uint8_t *buff, int len)
{
  int res;
  static struct chunk c;
  struct peer *p;
  static int bcast_cnt;
  uint16_t transid;

  res = parseChunkMsg(buff + 1, len - 1, &c, &transid);
  if (res > 0) {
    chunk_attributes_update_received(&c);
    chunk_unlock(c.id);
    dprintf("Received chunk %d from peer: %s\n", c.id, node_addr_tr(from));
    if(chunk_log) log_chunk(from,get_my_addr(),&c,"RECEIVED");
//{fprintf(stderr, "TEO: Peer %s received chunk %d from peer: %s at: %"PRIu64" hopcount: %i Size: %d bytes\n", node_addr_tr(get_my_addr()),c.id, node_addr_tr(from), gettimeofday_in_us(), chunk_get_hopcount(&c), c.size);}
    output_deliver(&c);
    res = cb_add_chunk(cb, &c);
    reg_chunk_receive(c.id, c.timestamp, chunk_get_hopcount(&c), res==E_CB_OLD, res==E_CB_DUPLICATE);
    cb_print();
    if (res < 0) {
      dprintf("\tchunk too old, buffer full with newer chunks\n");
      if(chunk_log){fprintf(stderr, "TEO: Received chunk: %d too old (buffer full with newer chunks) from peer: %s at: %"PRIu64"\n", c.id, node_addr_tr(from), gettimeofday_in_us());}
      free(c.data);
      free(c.attributes);
    }
    p = nodeid_to_peer(from, neigh_on_chunk_recv);
    if (p) {	//now we have it almost sure
      chunkID_set_add_chunk(p->bmap,c.id);	//don't send it back
      gettimeofday(&p->bmap_timestamp, NULL);
    }
    ack_chunk(&c, from, transid);	//send explicit ack
    if (bcast_after_receive_every && bcast_cnt % bcast_after_receive_every == 0) {
       bcast_bmap();
    }
  } else {
    fprintf(stderr,"\tError: can't decode chunk!\n");
  }
}

struct chunk *generated_chunk(suseconds_t *delta)
{
  struct chunk *c;

  c = malloc(sizeof(struct chunk));
  if (!c) {
    fprintf(stderr, "Memory allocation error!\n");
    return NULL;
  }

  *delta = input_get(input, c);
  if (*delta < 0) {
    fprintf(stderr, "Error in input!\n");
    exit(-1);
  }
  if (c->data == NULL) {
    free(c);
    return NULL;
  }
  dprintf("Generated chunk %d of %d bytes\n",c->id, c->size);
  chunk_attributes_fill(c);
  return c;
}

int add_chunk(struct chunk *c)
{
  int res;

  res = cb_add_chunk(cb, c);
  if (res < 0) {
    free(c->data);
    free(c->attributes);
    free(c);
    return 0;
  }
  free(c);
  return 1;
}

uint64_t get_chunk_timestamp(int cid){
  const struct chunk *c = cb_get_chunk(cb, cid);
  if (!c) return 0;

  return c->timestamp;
}

/**
 *example function to filter chunks based on whether a given peer needs them.
 *
 * Looks at buffermap information received about the given peer.
 */
int needs(struct peer *n, int cid){
  struct peer * p = n;

  if (CB_SIZE_TIME < CB_SIZE_TIME_UNLIMITED) {
    uint64_t ts;
    ts = get_chunk_timestamp(cid);
    if (ts && (ts < gettimeofday_in_us() - CB_SIZE_TIME)) {	//if we don't know the timestamp, we accept
      return 0;
    }
  }

  //dprintf("\t%s needs c%d ? :",node_addr_tr(p->id),c->id);
  if (! p->bmap) {
    //dprintf("no bmap\n");
    return 1;	// if we have no bmap information, we assume it needs the chunk (aggressive behaviour!)
  }
  return _needs(p->bmap, p->cb_size, cid);
}

int _needs(struct chunkID_set *cset, int cb_size, int cid){

  if (cb_size == 0) { //if it declared it does not needs chunks
    return 0;
  }

  if (CB_SIZE_TIME < CB_SIZE_TIME_UNLIMITED) {
    uint64_t ts;
    ts = get_chunk_timestamp(cid);
    if (ts && (ts < gettimeofday_in_us() - CB_SIZE_TIME)) {	//if we don't know the timestamp, we accept
      return 0;
    }
  }

  if (chunkID_set_check(cset,cid) < 0) { //it might need the chunk
    int missing, min;
    //@TODO: add some bmap_timestamp based logic

    if (chunkID_set_size(cset) == 0) {
      //dprintf("bmap empty\n");
      return 1;	// if the bmap seems empty, it needs the chunk
    }
    missing = cb_size - chunkID_set_size(cset);
    missing = missing < 0 ? 0 : missing;
    min = chunkID_set_get_earliest(cset);
      //dprintf("%s ... cid(%d) >= min(%d) - missing(%d) ?\n",(cid >= min - missing)?"YES":"NO",cid, min, missing);
    return (cid >= min - missing);
  }

  //dprintf("has it\n");
  return 0;
}

double peerWeightReceivedfrom(struct peer **n){
  struct peer * p = *n;
  return timerisset(&p->bmap_timestamp) ? 1 : 0.1;
}

double peerWeightUniform(struct peer **n){
  return 1;
}

double peerWeightRtt(struct peer **n){
#ifdef MONL
  double rtt = get_rtt((*n)->id);
  //dprintf("RTT to %s: %f\n", node_addr_tr(p->id), rtt);
  return finite(rtt) ? 1 / (rtt + 0.005) : 1 / 1;
#else
  return 1;
#endif
}

//ordering function for ELp peer selection, chunk ID based
//can't be used as weight
double peerScoreELpID(struct nodeID **n){
  struct chunkID_set *bmap;
  int latest;
  struct peer * p = nodeid_to_peer(*n, 0);
  if (!p) return 0;

  bmap = p->bmap;
  if (!bmap) return 0;
  latest = chunkID_set_get_latest(bmap);
  if (latest == INT_MIN) return 0;

  return -latest;
}

double chunkScoreChunkID(int *cid){
  return (double) *cid;
}

uint64_t get_chunk_deadline(int cid){
  const struct chunk_attributes * ca;
  const struct chunk *c;

  c = cb_get_chunk(cb, cid);
  if (!c) return 0;

  if (!c->attributes || c->attributes_size != sizeof(struct chunk_attributes)) {
    fprintf(stderr,"Warning, chunk %d with strange attributes block\n", c->id);
    return 0;
  }

  ca = (struct chunk_attributes *) c->attributes;
  return ca->deadline;
}

double chunkScoreDL(int *cid){
  return - (double)get_chunk_deadline(*cid);
}

double chunkScoreTimestamp(int *cid){
  return (double) get_chunk_timestamp(*cid);
}

void send_accepted_chunks(struct nodeID *toid, struct chunkID_set *cset_acc, int max_deliver, uint16_t trans_id){
  int i, d, cset_acc_size, res;
  struct peer *to = nodeid_to_peer(toid, 0);

  transaction_reg_accept(trans_id, toid);

  cset_acc_size = chunkID_set_size(cset_acc);
  reg_offer_accept_out(cset_acc_size > 0 ? 1 : 0);	//this only works if accepts are sent back even if 0 is accepted
  for (i = 0, d=0; i < cset_acc_size && d < max_deliver; i++) {
    const struct chunk *c;
    int chunkid = chunkID_set_get_chunk(cset_acc, i);
    c = cb_get_chunk(cb, chunkid);
    if (!c) {	// we should have the chunk
      dprintf("%s asked for chunk %d we do not own anymore\n", node_addr_tr(toid), chunkid);
      continue;
    }
    if (!to || needs(to, chunkid)) {	//he should not have it. Although the "accept" should have been an answer to our "offer", we do some verification
      chunk_attributes_update_sending(c);
      res = sendChunk(toid, c, trans_id);
      if (res >= 0) {
        if(to) chunkID_set_add_chunk(to->bmap, c->id); //don't send twice ... assuming that it will actually arrive
        d++;
        reg_chunk_send(c->id);
      	if(chunk_log) log_chunk(get_my_addr(),toid,c,"SENT");
        //{fprintf(stderr, "TEO: Sending chunk %d to peer: %s at: %"PRIu64" Result: %d Size: %d bytes\n", c->id, node_addr_tr(toid), gettimeofday_in_us(), res, c->size);}
      } else {
        fprintf(stderr,"ERROR sending chunk %d\n",c->id);
      }
    }
  }
}

int offer_peer_count()
{
  return offer_per_tick;
}

int offer_max_deliver(struct nodeID *n)
{

  if (!heuristics_distance_maxdeliver) return 1;

#ifdef MONL
  switch (get_hopcount(n)) {
    case 0: return 5;
    case 1: return 2;
    default: return 1;
  }
#else
  return 1;
#endif
}

//get the rtt. Currenly only MONL version is supported
static double get_rtt_of(struct nodeID* n){
#ifdef MONL
  return get_rtt(n);
#else
  return NAN;
#endif
}

#define DEFAULT_RTT_ESTIMATE 0.5

static struct chunkID_set *compose_offer_cset(struct peer *p)
{
  int num_chunks, j;
  uint64_t smallest_ts, largest_ts;
  double dt;
  struct chunkID_set *my_bmap = chunkID_set_init("type=bitmap");
  struct chunk *chunks = cb_get_chunks(cb, &num_chunks);

  if (p) {
    dt = get_rtt_of(p->id);
  } else {
    dt = NAN;
  }
  if (isnan(dt)) dt = DEFAULT_RTT_ESTIMATE;
  dt *= 1e6;	//convert to usec

  smallest_ts = chunks[0].timestamp;
  largest_ts = chunks[num_chunks-1].timestamp;

  //add chunks in latest...earliest order
  if (am_i_source()) {
    j = (num_chunks-1) * 3/4;	//do not send offers for the latest chunks from the source
  } else {
    j = num_chunks-1;
  }
  for(; j>=0; j--) {
    if (chunks[j].timestamp > smallest_ts + dt)
    chunkID_set_add_chunk(my_bmap, chunks[j].id);
  }

  return my_bmap;
}


void send_offer()
{
  struct chunk *buff;
  int size, res, i, n;
  struct peer **neighbours;
  struct peerset *pset;

  pset = get_peers();
  n = peerset_size(pset);
  neighbours = peerset_get_peers(pset);
  dprintf("Send Offer: %d neighbours\n", n);
  if (n == 0) return;
  buff = cb_get_chunks(cb, &size);
  if (size == 0) return;

  {
    size_t selectedpeers_len = offer_peer_count();
    int chunkids[size];
    struct peer *nodeids[n];
    struct peer *selectedpeers[selectedpeers_len];

    //reduce load a little bit if there are losses on the path from this guy
    double average_lossrate = get_average_lossrate_pset(pset);
    average_lossrate = finite(average_lossrate) ? average_lossrate : 0;	//start agressively, assuming 0 loss
    if (rand()/((double)RAND_MAX + 1) < 10 * average_lossrate ) {
      return;
    }

    for (i = 0;i < size; i++) chunkids[size - 1 - i] = (buff+i)->id;
    for (i = 0; i<n; i++) nodeids[i] = neighbours[i];
    selectPeersForChunks(SCHED_WEIGHTING, nodeids, n, chunkids, size, selectedpeers, &selectedpeers_len, SCHED_NEEDS, SCHED_PEER);

    for (i=0; i<selectedpeers_len ; i++){
      int transid = transaction_create(selectedpeers[i]->id);
      int max_deliver = offer_max_deliver(selectedpeers[i]->id);
      struct chunkID_set *offer_cset = compose_offer_cset(selectedpeers[i]);
      dprintf("\t sending offer(%d) to %s, cb_size: %d\n", transid, node_addr_tr(selectedpeers[i]->id), selectedpeers[i]->cb_size);
      res = offerChunks(selectedpeers[i]->id, offer_cset, max_deliver, transid++);
      chunkID_set_free(offer_cset);
    }
  }
}

void log_chunk(struct nodeID *from,struct nodeID *to,struct chunk *c,char * note)
{
	// semantic: [CHUNK_LOG],log_date,sender,receiver,id,size(bytes),chunk_timestamp,hopcount,notes
	fprintf(stderr,"[CHUNK_LOG],%"PRIu64",%s,%s,%d,%d,%"PRIu64",%i,%s\n",gettimeofday_in_us(),node_addr_tr(from),node_addr_tr(to),c->id,c->size,c->timestamp,chunk_get_hopcount(c),note);
}

void send_chunk()
{
  struct chunk *buff;
  int size, res, i, n;
  struct peer **neighbours;
  struct peerset *pset;

  pset = get_peers();
  n = peerset_size(pset);
  neighbours = peerset_get_peers(pset);
  dprintf("Send Chunk: %d neighbours\n", n);
  if (n == 0) return;
  buff = cb_get_chunks(cb, &size);
  dprintf("\t %d chunks in buffer...\n", size);
  if (size == 0) return;

  /************ STUPID DUMB SCHEDULING ****************/
  //target = n * (rand() / (RAND_MAX + 1.0)); /*0..n-1*/
  //c = size * (rand() / (RAND_MAX + 1.0)); /*0..size-1*/
  /************ /STUPID DUMB SCHEDULING ****************/

  /************ USE SCHEDULER ****************/
  {
    size_t selectedpairs_len = 1;
    int chunkids[size];
    struct peer *nodeids[n];
    struct PeerChunk selectedpairs[1];
  
    for (i = 0;i < size; i++) chunkids[size - 1 - i] = (buff+i)->id;
    for (i = 0; i<n; i++) nodeids[i] = neighbours[i];
    SCHED_TYPE(SCHED_WEIGHTING, nodeids, n, chunkids, 1, selectedpairs, &selectedpairs_len, SCHED_NEEDS, SCHED_PEER, SCHED_CHUNK);
  /************ /USE SCHEDULER ****************/

    for (i=0; i<selectedpairs_len ; i++){
      struct peer *p = selectedpairs[i].peer;
      const struct chunk *c = cb_get_chunk(cb, selectedpairs[i].chunk);
      dprintf("\t sending chunk[%d] to ", c->id);
      dprintf("%s\n", node_addr_tr(p->id));

      if (send_bmap_before_push) {
        send_bmap(p->id);
      }

      chunk_attributes_update_sending(c);
      res = sendChunk(p->id, c, 0);	//we do not use transactions in pure push
      dprintf("\tResult: %d\n", res);
      if (res>=0) {
      	if(chunk_log) log_chunk(get_my_addr(),p->id,c,"SENT");
//{fprintf(stderr, "TEO: Sending chunk %d to peer: %s at: %"PRIu64" Result: %d Size: %d bytes\n", c->id, node_addr_tr(p->id), gettimeofday_in_us(), res, c->size);}
        chunkID_set_add_chunk(p->bmap,c->id); //don't send twice ... assuming that it will actually arrive
        reg_chunk_send(c->id);
      } else {
        fprintf(stderr,"ERROR sending chunk %d\n",c->id);
      }
    }
  }
}
