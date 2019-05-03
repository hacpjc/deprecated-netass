#include "common.h"
#include "list.h"

#include "conf/lconf.h"

#include "packet/packet_hook.h"
#include "packet/packet_buf.h"

#define HOOK_NAME "xxx"

static packet_hook_res_t cb_xxx_tx(packet_hook_t *hook, packet_t *pkt)
{
	return PACKET_HOOK_RES_OK;
}

static packet_hook_res_t cb_xxx_rx(packet_hook_t *hook, packet_t *pkt)
{
	return PACKET_HOOK_RES_OK;
}

static void cb_xxx_show(packet_hook_t *hook)
{
	PRT("\txxx");
}

static packet_hook_t xxx_packet_hook =
	PAKCET_HOOK_INITIALIZER(HOOK_NAME, NULL, NULL, NULL, NULL, cb_xxx_tx, cb_xxx_rx, cb_xxx_show);
PACKET_HOOK_ACTIVATE(xxx_packet_hook);
