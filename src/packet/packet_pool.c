#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>

#include "common.h"
#include "packet/packet_pool.h"

void packet_pool_hold_pkt_single(packet_pool_t *pool, packet_t *pkt)
{
	packet_inc_ref(pkt);
}

void packet_pool_hold_pkt(packet_pool_t *pool, packet_t *pkt)
{
	packet_t *pkt_child;

	/*
	 * First, hold this
	 */
	packet_inc_ref(pkt);

	/*
	 * Also hold all children
	 */
	list_for_each_entry(pkt_child, &(pkt->list_child), list)
	{
		packet_pool_hold_pkt(pool, pkt_child);
	}
}

packet_t *packet_pool_pull(packet_pool_t *pool)
{
	packet_t *pkt;

	BUG_ON(pool == NULL);

	/*
	 * Pull a empty pkt from pool
	 */
	if (list_empty(&pool->list_free))
	{
		WARN("Run out of packet");
		return NULL;
	}

	pkt = list_first_entry(&(pool->list_free), packet_t, list);
	list_del_init(&(pkt->list));

	/*
	 * Return back.
	 */
	packet_init(pkt);
	packet_pool_hold_pkt(pool, pkt);

	pkt->carry.pool = pool;

	return pkt;
}

void packet_pool_push_single(packet_pool_t *pool, packet_t *pkt)
{
	BUG_ON(pool == NULL || pkt == NULL);

	/*
	 * Push this.
	 */
	if (packet_dec_ref_and_test(pkt) == 0)
	{
		list_move(&(pkt->list), &(pool->list_free));
	}
}

void packet_pool_push(packet_pool_t *pool, packet_t *pkt)
{
	BUG_ON(pool == NULL || pkt == NULL);

	/*
	 * Push all children
	 */
	if (!list_empty(&pkt->list_child))
	{
		packet_t *pkt_child, *pkt_child_save;

		list_for_each_entry_safe(pkt_child, pkt_child_save, &(pkt->list_child), list)
		{
			packet_pool_push(pool, pkt_child);
		}
	}

	/*
	 * Push this.
	 */
	packet_pool_push_single(pool, pkt);
}

////////////////////////////////////////////////////////////////////////////////

void packet_pool_free(packet_pool_t *pool)
{
	BUG_ON(pool == NULL);

	if (pool->tbl)
	{
		int i;
		packet_t *pkt;

		for (i = 0; i < pool->tbl_max; i++)
		{
			pkt = &pool->tbl[i];

			if (pkt->ref_cnt != 0)
			{
				WARN("pkt ref_cnt=%d is not clean.", pkt->ref_cnt);
			}
		}

		free(pool->tbl);
	}

	free(pool);
}

static inline void init_packet_pool(packet_pool_t *pool)
{
	memset(pool, 0x00, sizeof(*pool));

	INIT_LIST_HEAD(&(pool->list_free));
}

packet_pool_t *packet_pool_alloc(unsigned int tbl_max)
{
	packet_pool_t *pool;

	pool = malloc(sizeof(*pool));
	if (pool == NULL)
	{
		ERR("Cannot alloc pool");
		return NULL;
	}
	else
	{
		VBS("Alloc a packet pool handle %d bytes", sizeof(*pool));
	}

	init_packet_pool(pool);

	{
		unsigned int nbytes;
		unsigned int i;

		pool->tbl_max = tbl_max;
		nbytes = sizeof(pool->tbl[0]) * pool->tbl_max;
		pool->tbl =	malloc(nbytes);
		if (pool->tbl == NULL)
		{
			goto ERROR;
		}
		else
		{
			memset(pool->tbl, 0x00, nbytes);
		}

		for (i = 0; i < pool->tbl_max; i++)
		{
			packet_init(&(pool->tbl[i]));
			list_add(&(pool->tbl[i].list), &(pool->list_free));
		}

		VBS("Alloc a packet pool %u bytes", nbytes);
	}

	return pool;

ERROR:
	packet_pool_free(pool);
	return NULL;
}
