#include "common.h"
#include "list.h"

#include "conf/lconf.h"

#include "packet/packet_hook.h"
#include "packet/packet_buf.h"

#define HOOK_NAME "pdump"

typedef struct pdump_ctx
{
	unsigned int enable_tx_dump;
	unsigned int enable_rx_dump;
} pdump_ctx_t;

extern void op_monitor_decode(uint8_t *l2, unsigned l2_len);

static void init_pdump_ctx(pdump_ctx_t *ctx)
{
	memset(ctx, 0x00, sizeof(*ctx));
}

static void cb_pdump_close_ctx(void *ctx_void)
{
	pdump_ctx_t *ctx = (pdump_ctx_t *) ctx_void;

	if (ctx)
	{
		free(ctx);
	}
}

static void *cb_pdump_open_ctx(void *conf)
{
	pdump_ctx_t *ctx = NULL;

	/* Alloc new ctx */
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
	{
		return NULL;
	}

	init_pdump_ctx(ctx);

	ctx->enable_tx_dump = conf_get_sym_bool_from_root(HOOK_NAME CONF_DELIM "enable_tx_dump", conf);
	ctx->enable_rx_dump = conf_get_sym_bool_from_root(HOOK_NAME CONF_DELIM "enable_rx_dump", conf);
	return ctx;
}

static packet_hook_res_t cb_pdump_tx(packet_hook_t *hook, packet_t *pkt)
{
	pdump_ctx_t *ctx = packet_hook_get_ctx(hook, pdump_ctx_t);

	if (ctx->enable_tx_dump == 0)
	{
		return PACKET_HOOK_RES_OK;
	}

	PRT_NONL(KBLU);
	hexdump(packet_l2(pkt), packet_l2_len(pkt));
	op_monitor_decode(packet_l2(pkt), packet_l2_len(pkt));
	PRT_NONL(KNRM);

	return PACKET_HOOK_RES_OK;
}

static packet_hook_res_t cb_pdump_rx(packet_hook_t *hook, packet_t *pkt)
{
	pdump_ctx_t *ctx = packet_hook_get_ctx(hook, pdump_ctx_t);

	if (ctx->enable_rx_dump == 0)
	{
		return PACKET_HOOK_RES_OK;
	}

	PRT_NONL(KCYN);
	hexdump(packet_l2(pkt), packet_l2_len(pkt));
	op_monitor_decode(packet_l2(pkt), packet_l2_len(pkt));
	PRT_NONL(KNRM);

	return PACKET_HOOK_RES_OK;
}

static packet_hook_t pdump_packet_hook =
	PAKCET_HOOK_INITIALIZER(HOOK_NAME,
		NULL, NULL,
		cb_pdump_open_ctx, cb_pdump_close_ctx,
		cb_pdump_tx, cb_pdump_rx, NULL);
PACKET_HOOK_ACTIVATE(pdump_packet_hook);

