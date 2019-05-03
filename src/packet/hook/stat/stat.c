#include "common.h"
#include "list.h"

#include "conf/lconf.h"

#include "packet/packet_hook.h"
#include "packet/packet_buf.h"

#define HOOK_NAME "stat"

typedef struct stat_ctx
{
	uint64_t tx;
	uint64_t rx;
} stat_ctx_t;

static void init_stat_ctx(stat_ctx_t *ctx)
{
	memset(ctx, 0x00, sizeof(*ctx));
}

static void cb_stat_close_ctx(void *ctx_void)
{
	stat_ctx_t *ctx = (stat_ctx_t *) ctx_void;

	if (ctx)
	{
		free(ctx);
	}
}

static void *cb_stat_open_ctx(void *conf)
{
	stat_ctx_t *ctx = NULL;

	/* Alloc new ctx */
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
	{
		return NULL;
	}

	init_stat_ctx(ctx);

	return ctx;
}

static inline unsigned int calc_tx_num(packet_t *pkt)
{
	register unsigned int num = 0;

	if (likely(list_empty(&(pkt->list_child))))
	{
		num = 1;
	}
	else
	{
		packet_t *pkt_child;

		list_for_each_entry(pkt_child, &(pkt->list_child), list)
		{
			num += calc_tx_num(pkt_child);
		}
	}

	return num;
}

static packet_hook_res_t cb_stat_tx(packet_hook_t *hook, packet_t *pkt)
{
	stat_ctx_t *ctx = packet_hook_get_ctx(hook, stat_ctx_t);

	BUG_ON(ctx == NULL);
	ctx->tx += calc_tx_num(pkt);
	return PACKET_HOOK_RES_OK;
}

static packet_hook_res_t cb_stat_rx(packet_hook_t *hook, packet_t *pkt)
{
	stat_ctx_t *ctx = packet_hook_get_ctx(hook, stat_ctx_t);

	BUG_ON(ctx == NULL);
	ctx->rx++;

	return PACKET_HOOK_RES_OK;
}

static void cb_stat_show(packet_hook_t *hook)
{
	stat_ctx_t *ctx;

	ctx = packet_hook_get_ctx(hook, stat_ctx_t);
	if (ctx)
	{
		PRT("\ttx: %lu", ctx->tx);
		PRT("\trx: %lu", ctx->rx);
	}
}

static packet_hook_t stat_packet_hook =
	PAKCET_HOOK_INITIALIZER(HOOK_NAME, NULL, NULL, cb_stat_open_ctx, cb_stat_close_ctx, cb_stat_tx, cb_stat_rx, cb_stat_show);
PACKET_HOOK_ACTIVATE(stat_packet_hook);
