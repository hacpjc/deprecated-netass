#ifndef SRC_PACKET_PACKET_HANDLE_H_
#define SRC_PACKET_PACKET_HANDLE_H_

#include <net/if.h>

#include "list.h"
#include "packet/packet_buf.h"
#include "packet/packet_pool.h"
#include "packet/packet_hook.h"

typedef struct packet_handle
{
	int fd;
	char dev_name[31 + 1];
	struct ifreq if_idx;
	struct ifreq if_hwaddr;

	packet_pool_t *pkt_pool;

	struct list_head list_hook;
} packet_handle_t;

#define PACKET_HANDLE_INITIALIZER { .fd = -1, .pkt_pool = NULL }

static int packet_handle_alloc_pkt_pool(packet_handle_t *ph, unsigned int max)
{
	ph->pkt_pool = packet_pool_alloc(max);
	return (ph->pkt_pool) ? 0 : -1;
}

static void packet_handle_free_pkt_pool(packet_handle_t *ph)
{
	if (ph->pkt_pool)
	{
		packet_pool_free(ph->pkt_pool);
		ph->pkt_pool = NULL;
	}
}

static inline void packet_handle_hold_pkt(packet_t *pkt)
{
	packet_pool_hold_pkt((packet_pool_t *) pkt->carry.pool, pkt);
}

static inline void packet_handle_hold_pkt_single(packet_t *pkt)
{
	packet_pool_hold_pkt_single((packet_pool_t *) pkt->carry.pool, pkt);
}

static inline void packet_handle_release_pkt(packet_t *pkt)
{
	packet_pool_release_pkt((packet_pool_t *) pkt->carry.pool, pkt);
}

static inline void packet_handle_release_pkt_single(packet_t *pkt)
{
	packet_pool_release_pkt_single((packet_pool_t *) pkt->carry.pool, pkt);
}

static inline packet_t *packet_handle_pull_pkt(packet_handle_t *ph)
{
	if (ph->pkt_pool == NULL)
	{
		return NULL;
	}

	return packet_pool_pull(ph->pkt_pool);
}

static inline void packet_handle_push_pkt(packet_t *pkt)
{
	packet_pool_push((packet_pool_t *) pkt->carry.pool, pkt);
}

void packet_handle_del_hook(packet_handle_t *ph);
int packet_handle_add_hook(packet_handle_t *ph, const void *hook_conf_root);
void packet_handle_dump_hook(packet_handle_t *ph);
void packet_handle_show_hook(packet_handle_t *ph);
int packet_handle_run_tx_hook(packet_handle_t *ph, packet_t *pkt);
int packet_handle_run_rx_hook(packet_handle_t *ph, packet_t *pkt);

packet_hook_res_t packet_handle_xmit_l2eth(packet_handle_t *ph_rx, packet_handle_t *ph_tx, packet_t *pkt_tx);
int packet_handle_send_l2eth(packet_handle_t *ph, packet_t *pkt);
int packet_handle_recv_l2eth(packet_handle_t *ph, packet_t *pb, unsigned int timeout);
int packet_handle_recv_same_l2eth(packet_handle_t *ph,
	packet_t *pb, packet_t *pkt_check,
	unsigned int timeout);

void packet_handle_exit(packet_handle_t *ph);
int packet_handle_init_arp(packet_handle_t *ph, const char *dev_name);
int packet_handle_init(packet_handle_t *ph, const char *dev_name);

#endif /* SRC_PACKET_PACKET_HANDLE_H_ */
