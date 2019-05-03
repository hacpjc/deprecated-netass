#ifndef SRC_PACKET_PACKET_POOL_H_
#define SRC_PACKET_PACKET_POOL_H_

#include "common.h"
#include "list.h"

#include "packet/packet_buf.h"

typedef struct packet_pool
{
	packet_t *tbl;
	unsigned int tbl_max;

	struct list_head list_free;
} packet_pool_t;

#define packet_pool_release_pkt(_pool, _pkt) packet_pool_push(_pool, _pkt)
#define packet_pool_release_pkt_single(_pool, _pkt) packet_pool_push_single(_pool, _pkt)
void packet_pool_hold_pkt(packet_pool_t *pool, packet_t *pkt);
void packet_pool_hold_pkt_single(packet_pool_t *pool, packet_t *pkt);
packet_t *packet_pool_pull(packet_pool_t *pool);
void packet_pool_push(packet_pool_t *pool, packet_t *pkt);
void packet_pool_push_single(packet_pool_t *pool, packet_t *pkt);

void packet_pool_free(packet_pool_t *pool);
packet_pool_t *packet_pool_alloc(unsigned int tbl_max);

#endif /* SRC_PACKET_PACKET_POOL_H_ */
