#include "common.h"
#include "list.h"
#include "dice.h"
#include "tm.h"
#include "net.h"

#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "conf/lconf.h"
#include "packet/packet.h"

#define HOOK_NAME "ipfrag"

typedef enum
{
	IPFRAG_ORDER_IN = 0,  /* DFL: in order */
	IPFRAG_ORDER_REVERSE, /* reverse order */
	IPFRAG_ORDER_RANDOM,  /* random */
	IPFRAG_ORDER_MAX
} ipfrag_order_t;

#define IPFRAG_ORDER_DFL (IPFRAG_ORDER_IN)

static ipfrag_order_t str2ipfrag_order(const char *str)
{
#define RETURN_IF_MATCH(_in, _key, _order) \
	do { \
		if (strcasecmp(_in, _key) == 0) \
		{ \
			return (_order); \
		} \
	} while (0)

	if (str == NULL)
	{
		ERR("Invalid ipfrag order string (nil)");
		return IPFRAG_ORDER_MAX;
	}

	RETURN_IF_MATCH(str, "dfl", IPFRAG_ORDER_IN);
	RETURN_IF_MATCH(str, "in_order", IPFRAG_ORDER_IN);
	RETURN_IF_MATCH(str, "reverse", IPFRAG_ORDER_REVERSE);
	RETURN_IF_MATCH(str, "random", IPFRAG_ORDER_RANDOM);

	return IPFRAG_ORDER_DFL;
}

typedef struct ipfrag_ctx
{
	/*
	 * "mtu"
	 */
	unsigned int mtu; /* Do frag if payload exceeds this size (bytes). */

	/*
	 * "probability"
	 */
	unsigned int probability; /* 0 ~ 1000 (0.0% ~ 100.0%) */
#define IPFRAG_PRABABILITY_LIMIT (1000)

	/*
	 * "order"
	 */
	ipfrag_order_t order;

	/*
	 * duplicate
	 */
	unsigned int duplicate; /* 0 ~ 1000 (0.0% ~ 100.0%) */
#define IPFRAG_DUPLICATE_LIMIT (1000)
} ipfrag_ctx_t;

static int init_ipfrag_ctx(ipfrag_ctx_t *ctx, void *conf)
{
	if (conf == NULL)
	{
		return -1;
	}

	/*
	 * "probability"
	 */
	ctx->probability = conf_get_sym_uint_from_root("probability", conf);
	if (ctx->probability > IPFRAG_PRABABILITY_LIMIT)
	{
		ERR("Invalid ipfrag probability %u (Range: 0 ~ %u)",
			ctx->probability, IPFRAG_PRABABILITY_LIMIT);
		return -1;
	}
	else
	{
		DBG("Configure ipfrag probability to %u/%u",
			ctx->probability, IPFRAG_PRABABILITY_LIMIT);
	}

	/*
	 * "mtu"
	 */
	ctx->mtu = conf_get_sym_uint_from_root("mtu", conf);
	if (ctx->mtu > (PACKET_MAX_FRAME_SIZE / 2) /* Be reasonable. */ ||
		(ctx->mtu % 8) != 0 /* Must be multiple of 8. */)
	{
		ERR("Invalid ipfrag mtu %u", ctx->mtu);
		return -1;
	}
	else
	{
		DBG("Configure ipfrag mtu to %u", ctx->mtu);
	}

	/*
	 * "order"
	 */
	ctx->order = str2ipfrag_order(conf_get_sym_str_from_root("order", conf));
	if (ctx->order >= IPFRAG_ORDER_MAX)
	{
		ERR("Invalid ipfrag order '%s'",
			conf_get_sym_str_from_root("order", conf));
		return -1;
	}
	else
	{
		DBG("Configure ipfrag order to %u", ctx->order);
	}

	/*
	 * "duplicate"
	 */
	ctx->duplicate = conf_get_sym_uint_from_root("duplicate", conf);
	if (ctx->duplicate > IPFRAG_DUPLICATE_LIMIT)
	{
		ERR("Invalid ipfrag duplicate %u (Range: 0 ~ %u)",
			ctx->duplicate, IPFRAG_DUPLICATE_LIMIT);
		return -1;
	}
	else
	{
		DBG("Configure ipfrag duplicate to %u/%u",
			ctx->duplicate, IPFRAG_DUPLICATE_LIMIT);
	}

	return 0;
}

static void exit_ipfrag_ctx(ipfrag_ctx_t *ctx)
{
	BUG_ON(ctx == NULL);
}

static void cb_ipfrag_close_ctx(void *ctx_void)
{
	ipfrag_ctx_t *ctx = (ipfrag_ctx_t *) ctx_void;

	if (ctx)
	{
		exit_ipfrag_ctx(ctx);
		free(ctx);
	}
}

static void *cb_ipfrag_open_ctx(void *conf)
{
	ipfrag_ctx_t *ctx = NULL;

	/* Alloc new ctx */
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0x00, sizeof(*ctx));

	if (init_ipfrag_ctx(ctx, conf_get_sym_obj_from_root(HOOK_NAME, conf)) < 0)
	{
		cb_ipfrag_close_ctx(ctx);
		return NULL;
	}

	return ctx;
}

////////////////////////////////////////////////////////////////////////////////
static inline int is_ipfrag_possible(ipfrag_ctx_t *ctx, packet_t *pkt)
{
	if (!list_empty(&pkt->list_child))
	{
		return 0; // Oops. Don't have space to add frag child.
	}

	if (packet_check_attr(pkt, PACKET_ATTR_FRAG))
	{
		return 0; // Oops. Input pkt is already an ip frag.
	}

	if (packet_l3(pkt) == NULL ||
		(packet_l3_len(pkt) - packet_l3h_len(pkt)) <= ctx->mtu)
	{
		return 0; // Don't need to do ip frag on small input.
	}

	return dice(ctx->probability, IPFRAG_PRABABILITY_LIMIT); // Maybe possible?
}

static inline void gen_frag_payload(packet_t *pkt_child, packet_t *pkt_mom, const unsigned int offset, const unsigned int mtu)
{
	int ret;
	int is_last_frag = 0;

	/*
	 * Copy l2 hdr
	 */
	{
		uint8_t *l2h;
		unsigned int l2h_len;

		l2h = packet_l2(pkt_mom);
		l2h_len = packet_l2h_len(pkt_mom);

		packet_set_l2(pkt_child);
		ret = packet_append(pkt_child, l2h_len);
		BUG_ON(ret < 0);

		memcpy(packet_l2(pkt_child), l2h, l2h_len);
		packet_pull(pkt_child, l2h_len);
	}

	/*
	 * Copy l3 hdr
	 */
	{
		uint8_t *l3h;
		unsigned int l3h_len;

		l3h = packet_l3(pkt_mom); /* left-most l3 hdr */
		l3h_len = packet_l3h_len(pkt_mom);

		packet_set_l3(pkt_child);
		ret = packet_append(pkt_child, l3h_len);
		BUG_ON(ret < 0);

		memcpy(packet_l3(pkt_child), l3h, l3h_len);
		packet_pull(pkt_child, l3h_len);
	}

	/*
	 * mom:
	 * +---------+-----+---------------+---
	 * | L2 | L3 | ... | child payload | ...
	 * +----+----+-----+---------------+-----
	 *                       |
	 *                       V
	 *                       copy to child
	 */
	{
		uint8_t *pay;
		unsigned int pay_len = mtu, max_pay_len;

		/* Don't care about l4 hdr for ip frags */
		packet_set_l7(pkt_child);

		pay = packet_l3(pkt_mom) + packet_l3h_len(pkt_mom);
		pay += offset;
		max_pay_len = packet_l3_len(pkt_mom) - packet_l3h_len(pkt_mom);
		if ((max_pay_len - offset) <= mtu)
		{
			is_last_frag = 1;
			pay_len = max_pay_len - offset;
		}
		else
		{
			pay_len = mtu;
		}

		ret = packet_append(pkt_child, pay_len);
		BUG_ON(ret < 0);

		memcpy(packet_l3(pkt_child) + packet_l3h_len(pkt_child), pay, pay_len);
	}

	/*
	 * Fix ip hdr
	 */
	{
		struct iphdr *iph = (struct iphdr *) packet_l3(pkt_child);

		/* Fix frag offset, and xDM bits */
		iph->frag_off = htons((offset >> 3));

		if (!is_last_frag)
		{
			/* Set more frag bit */
			iph->frag_off |= htons(0x2000);
		}

		/* Fix ip total length */
		iph->tot_len = htons(packet_l3_len(pkt_child));

		/* Fix ip hdr checksum */
#if 0
		iph->check = 0;
#else
		iph->check = 0;
		iph->check = net_ipv4_cksum(iph, packet_l3h_len(pkt_child));
#endif
	}

	packet_add_attr(pkt_child, PACKET_ATTR_FRAG);
}

static void add_frag_by_order_cfg(ipfrag_ctx_t *ctx, packet_t *pkt_child, packet_t *pkt_mom)
{
	switch (ctx->order)
	{
	case IPFRAG_ORDER_IN:
		list_add_tail(&pkt_child->list, &pkt_mom->list_child);
		break;

	case IPFRAG_ORDER_RANDOM: /* FIXME: This's not really random. */
		if (dice(1, 2))
		{
			list_add_tail(&pkt_child->list, &pkt_mom->list_child);
		}
		else
		{
			list_add(&pkt_child->list, &pkt_mom->list_child);
		}
		break;

	case IPFRAG_ORDER_REVERSE:
		list_add(&pkt_child->list, &pkt_mom->list_child);
		break;

	default:
		ERR("Invalid ipfrag order configuration %u (BUG)", ctx->order);
		BUG_ON(1);
		break;
	}
}

static packet_hook_res_t __do_ipfrag4(
	ipfrag_ctx_t *ctx, packet_handle_t *ph, packet_t *pkt)
{
	unsigned int pay_len, frag_num;

	pay_len = packet_l3_len(pkt) - packet_l3h_len(pkt);

	// Assume 26B -> (8B * 3) + 1 -> need 4 frag
	frag_num = (pay_len / ctx->mtu) + ((pay_len % ctx->mtu) ? 1 : 0);
	BUG_ON(frag_num <= 1); // Not possible

	packet_handle_hold_pkt_single(pkt);

	{
		int i;
		packet_t *pkt_child;

		for (i = 0; i < frag_num; i++)
		{
			/* Alloc a new pkt to save frag payload */
			pkt_child = packet_handle_pull_pkt(ph);
			if (pkt_child == NULL)
			{
				WARN("Cannot pull more pkt. Give up this ip frag");
				packet_handle_release_pkt(pkt); // Remove all children but reserve pkt itself.
				return PACKET_HOOK_RES_OK;
			}
			else
			{
				/* Append frag to pkt child */
				add_frag_by_order_cfg(ctx, pkt_child, pkt);
			}

			/* Copy payload to frag */
			gen_frag_payload(pkt_child, pkt, i * ctx->mtu, ctx->mtu);
		}
	}

	packet_handle_release_pkt_single(pkt);

	return PACKET_HOOK_RES_OK;
}

static packet_hook_res_t __do_ipfrag6(
	ipfrag_ctx_t *ctx, packet_handle_t *ph, packet_t *pkt)
{
	/*
	 * FIXME: Under development
	 */
	return PACKET_HOOK_RES_OK;
}

static inline packet_hook_res_t do_ipfrag(
	ipfrag_ctx_t *ctx, packet_handle_t *ph, packet_t *pkt)
{
	/*
	 * +-----+
	 * | L2  |
	 * +-----+
	 * | L2  |
	 * +-----+ <- l3 = ip4 hdr / ip6 hdr
	 * | L3  |
	 * +     +
	 * |     |
	 * +-----+
	 *
	 */
	switch (pkt->ether_type /* right-most ether type */)
	{
	case ETHERTYPE_IP:
		return __do_ipfrag4(ctx, ph, pkt);
	case ETHERTYPE_IPV6:
		return __do_ipfrag6(ctx, ph, pkt);
	default:
		break;
	}

	return PACKET_HOOK_RES_OK;
}
////////////////////////////////////////////////////////////////////////////////

/*!
 * \brief Split ip packet into small frag(s).
 */
static packet_hook_res_t cb_ipfrag_tx(packet_hook_t *hook, packet_t *pkt)
{
	ipfrag_ctx_t *ctx = packet_hook_get_ctx(hook, ipfrag_ctx_t);
	packet_handle_t *ph = packet_hook_get_packet_handle(hook);

	BUG_ON(ctx == NULL || ph == NULL);

	if (is_ipfrag_possible(ctx, pkt))
	{
		return do_ipfrag(ctx, ph, pkt);
	}

	return PACKET_HOOK_RES_OK;
}

/*!
 * \brief Reassemble IP frag(s) to origional one.
 */
static packet_hook_res_t cb_ipfrag_rx(packet_hook_t *hook, packet_t *pkt)
{
	ipfrag_ctx_t *ctx = packet_hook_get_ctx(hook, ipfrag_ctx_t);

	BUG_ON(ctx == NULL);

	return PACKET_HOOK_RES_OK;
}

static void cb_ipfrag_show(packet_hook_t *hook)
{
	ipfrag_ctx_t *ctx;

	ctx = packet_hook_get_ctx(hook, ipfrag_ctx_t);

	PRT(" ");
}

static packet_hook_t ipfrag_packet_hook =
	PAKCET_HOOK_INITIALIZER(HOOK_NAME,
		NULL, NULL,
		cb_ipfrag_open_ctx, cb_ipfrag_close_ctx,
		cb_ipfrag_tx, cb_ipfrag_rx, cb_ipfrag_show);
PACKET_HOOK_ACTIVATE(ipfrag_packet_hook);
