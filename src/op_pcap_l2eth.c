#include <stdio.h>
#include <stdlib.h>
#include <netinet/ether.h>

#include "common.h"

#include "dirtrav.h"
#include "net.h"
#include "tm.h"
#include "init_tbl.h"
#include "conf/lconf.h"
#include "packet/packet.h"

#include "pcap.h" // libpcap

#define OP_NAME "pcap_l2eth"

typedef struct local_conf_live
{
	const char *pcap_input_dev;
	unsigned int promisc;
} local_conf_live_t;

typedef struct local_conf_offline
{
	const char *pcap_input;
} local_conf_offline_t;

typedef struct local_conf
{
	const char *mode; // live | offline

	union
	{
		/* pcap mode - live */
		local_conf_live_t live;
		/* pcap mode - offline */
		local_conf_offline_t offline;
	} in;

	const char *pcap_filter;

	/*
	 * Replay device
	 */
	const char *dev1;
	const char *dev2;

	/*
	 * macdb
	 */
	const void *macdb_conf;

	/*
	 * packet system
	 */
	unsigned int packet_pool_size;

	/*
	 * packet hook
	 */
	const void *packet_hook_conf;
} local_conf_t;

static local_conf_t *lconf = NULL;

static int init_lconf(void)
{
	lconf = malloc(sizeof(*lconf));
	if (lconf == NULL)
	{
		ERR("Cannot alloc lconf %d bytes", sizeof(*lconf));
		return -1;
	}

	memset(lconf, 0x00, sizeof(*lconf));

	/*
	 * Read json conf
	 */
	LCONF_GET_STR_FROM_PARENT(lconf->mode, "mode", OP_NAME);

	if (strcasecmp(lconf->mode, "offline") == 0)
	{
		LCONF_GET_STR_FROM_PARENT(lconf->in.offline.pcap_input, "pcap_input", OP_NAME);
	}
	else if (strcasecmp(lconf->mode, "live") == 0)
	{
		LCONF_GET_STR_FROM_PARENT(lconf->in.live.pcap_input_dev, "pcap_input_dev", OP_NAME);
		lconf->in.live.promisc = LCONF_GET_UINT(OP_NAME CONF_DELIM "pcap_input_dev_promisc");
	}
	else
	{
		ERR("Invalid mode '%s'. We only accept 'live' or 'offline'", lconf->mode);
		return -1;
	}

	LCONF_GET_STR_FROM_PARENT(lconf->pcap_filter, "pcap_filter", OP_NAME);

	LCONF_GET_STR_FROM_PARENT(lconf->dev1, "dev1", OP_NAME);
	LCONF_GET_STR_FROM_PARENT(lconf->dev2, "dev2", OP_NAME);

	/*
	 * macdb
	 */
	LCONF_GET_SYM(lconf->macdb_conf, OP_NAME CONF_DELIM "macdb");

	/*
	 * packet system
	 */
	lconf->packet_pool_size = LCONF_GET_UINT(OP_NAME CONF_DELIM "packet_pool_size");

	/*
	 * packet hook
	 */
	LCONF_GET_SYM(lconf->packet_hook_conf, OP_NAME CONF_DELIM "hook");

	return 0;
}

static void exit_lconf(void)
{
	if (lconf)
	{
		free(lconf);
		lconf = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////

#include "macdb/macdb.h"

static macdb_t *macdb = NULL;

static int init_macdb(void)
{
	macdb = macdb_alloc_by_conf(lconf->macdb_conf);
	if (!macdb)
	{
		return -1;
	}

	return 0;
}

static void exit_macdb(void)
{
	if (macdb)
	{
		macdb_free(macdb);
		macdb = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////
#include "packet/packet.h"

static packet_handle_t packet_handle[2] =
{
	PACKET_HANDLE_INITIALIZER,
	PACKET_HANDLE_INITIALIZER
};

static int init_packet_handle(void)
{
	memset(packet_handle, 0x00, sizeof(packet_handle));

	/*
	 * init
	 */
	if (packet_handle_init(&packet_handle[0], lconf->dev1) < 0)
	{
		return -1;
	}

	if (packet_handle_init(&packet_handle[1], lconf->dev2) < 0)
	{
		return -1;
	}

	/*
	 * Alloc pkt pool
	 */
	if (packet_handle_alloc_pkt_pool(&packet_handle[0], lconf->packet_pool_size) < 0)
	{
		return -1;
	}

	if (packet_handle_alloc_pkt_pool(&packet_handle[1], lconf->packet_pool_size) < 0)
	{
		return -1;
	}

	/*
	 * Add hook
	 */
	if (packet_handle_add_hook(&packet_handle[0], lconf->packet_hook_conf) < 0)
	{
		return -1;
	}

	if (packet_handle_add_hook(&packet_handle[1], lconf->packet_hook_conf) < 0)
	{
		return -1;
	}

	return 0;
}

static void exit_packet_handle(void)
{
	if (packet_handle)
	{
		packet_handle_del_hook(&packet_handle[0]);
		packet_handle_del_hook(&packet_handle[1]);

		packet_handle_exit(&packet_handle[0]);
		packet_handle_exit(&packet_handle[1]);
	}
}

////////////////////////////////////////////////////////////////////////////////

#define PACKET_SHIFT(_packet, _packet_len, _size) \
	do \
	{ \
		if (_packet_len < ((uint32_t) (_size))) \
		{  \
			ERR("[%s:%d] Expect %u but only %u bytes left", \
				__FUNCTION__, __LINE__, (uint32_t) _size, (uint32_t) _packet_len); \
			return; \
		} \
		else \
		{ \
			_packet += ((uint32_t) (_size)); \
			_packet_len -= ((uint32_t) (_size)); \
		} \
	} while (0)

#define FILTER_SHIFT(_packet, _packet_len, _size) \
	do \
	{ \
		if (_packet_len < ((uint32_t) (_size))) \
		{  \
			ERR("[%s:%d] Expect %u but only %u bytes left", \
				__FUNCTION__, __LINE__, (uint32_t) _size, (uint32_t) _packet_len); \
			return 0; \
		} \
		else \
		{ \
			_packet += ((uint32_t) (_size)); \
			_packet_len -= ((uint32_t) (_size)); \
		} \
	} while (0)

#define IS_MAC_UNICAST(_mac) !( \
	((((uint8_t *) _mac)[0] & 0x80) == 0x80) || /* The first bit is 0: uni-cast, otherwise, multicast */ \
	((((uint16_t *) _mac)[0] == 0x0000) && (((uint16_t *) _mac)[1] == 0x0000) && (((uint16_t *) _mac)[2] == 0x0000)) \
	)

static int cb_create_macdb_node(macdb_node_t *node, void *priv)
{
	packet_handle_t *ph_save = (packet_handle_t *) priv;
	macdb_node_carry_t *carry = macdb_node_get_carry(node);

	if (carry->ph == NULL)
	{
		/* New node. Save packet handle. */
		carry->ph = ph_save;

		VBS("Set macdb node " MAC_OCTET_FMT " dev to " MAC_OCTET_FMT,
			MAC_OCTET_EXPAND(node->mac),
			MAC_OCTET_EXPAND(((packet_handle_t *) carry->ph)->if_hwaddr.ifr_hwaddr.sa_data));
	}
	else
	{
		/* This's possible. Don't activate alarm. */
	}

	return 0;
}

static __attribute__((unused)) int filter_out(const void *pay, unsigned int pay_len)
{
	const struct ether_header *l2h = (const struct ether_header *) pay;

	FILTER_SHIFT(pay, pay_len, sizeof(*l2h));

	switch (ntohs(l2h->ether_type))
	{
	case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
		VBS("Filter-out ARP/RARP");
		return 0;
	default:
		break;
	}

	return -1; // Do not filter out
}

static int dispatch_handle_by_l2eth(
	packet_handle_t **tx_handle, packet_handle_t **rx_handle,
	uint8_t *pay, unsigned int paylen)
{
#define GET_ANOTHER_HANDLE(_ph) ((_ph == &packet_handle[0]) ? (&packet_handle[1]) : (&packet_handle[0]))
	struct ether_header *pkt_l2h = (struct ether_header *) pay;

	macdb_node_t *node_src = NULL, *node_dst = NULL;
	packet_handle_t *ph_src = NULL, *ph_dst = NULL;

	if (net_cmp_mac(pkt_l2h->ether_shost, pkt_l2h->ether_dhost) == 0)
	{
		WARN("Do not support smac=dmac " MAC_OCTET_FMT " & " MAC_OCTET_FMT " Give up.",
			MAC_OCTET_EXPAND(pkt_l2h->ether_shost), MAC_OCTET_EXPAND(pkt_l2h->ether_dhost));
		return -1;
	}

	node_src = macdb_search(macdb, pkt_l2h->ether_shost);
	node_dst = macdb_search(macdb, pkt_l2h->ether_dhost);

	if (node_src)
	{
		ph_src = node_src->carry.ph;

		if (node_dst)
		{
			ph_dst = node_dst->carry.ph;

			if (ph_dst == ph_src)
			{
#if 1
				/* * TRICKY: Auto move one node to another packet handle. */
				WARN("macdb node " MAC_OCTET_FMT " & " MAC_OCTET_FMT " are using the same dev. Auto-fix.",
					MAC_OCTET_EXPAND(pkt_l2h->ether_shost), MAC_OCTET_EXPAND(pkt_l2h->ether_dhost));
				node_dst->carry.ph = GET_ANOTHER_HANDLE(ph_src);
				ph_dst = GET_ANOTHER_HANDLE(ph_src);
#else
				WARN("macdb node " MAC_OCTET_FMT " & " MAC_OCTET_FMT " are using the same dev. Give up",
					MAC_OCTET_EXPAND(pkt_l2h->ether_shost), MAC_OCTET_EXPAND(pkt_l2h->ether_dhost));
				return -1;
#endif
			}

			memcpy(pkt_l2h->ether_shost, ph_src->if_hwaddr.ifr_hwaddr.sa_data, 6);
			memcpy(pkt_l2h->ether_dhost, ph_dst->if_hwaddr.ifr_hwaddr.sa_data, 6);
		}
		else
		{
			ph_dst = GET_ANOTHER_HANDLE(ph_src);

			if (IS_MAC_UNICAST(pkt_l2h->ether_dhost) &&
				macdb_operate(macdb, MACDB_OPERATE_FLAG_ALLOC,
					pkt_l2h->ether_dhost, cb_create_macdb_node, ph_dst) < 0)
			{
				WARN("Run out of macdb node. Give up.");
				return -1;
			}

			memcpy(pkt_l2h->ether_shost, ph_src->if_hwaddr.ifr_hwaddr.sa_data, 6);
			if (IS_MAC_UNICAST(pkt_l2h->ether_dhost))
			{
				memcpy(pkt_l2h->ether_dhost, ph_dst->if_hwaddr.ifr_hwaddr.sa_data, 6);
			}
		}

		BUG_ON(ph_src == ph_dst);
	}
	else
	{
		if (node_dst)
		{
			ph_dst = node_dst->carry.ph;
			ph_src = GET_ANOTHER_HANDLE(ph_dst);

			if (IS_MAC_UNICAST(pkt_l2h->ether_shost) &&
				macdb_operate(macdb, MACDB_OPERATE_FLAG_ALLOC,
					pkt_l2h->ether_shost, cb_create_macdb_node, ph_src) < 0)
			{
				WARN("Run out of macdb node. Give up.");
				return -1;
			}

			memcpy(pkt_l2h->ether_dhost, ph_dst->if_hwaddr.ifr_hwaddr.sa_data, 6);
			if (IS_MAC_UNICAST(pkt_l2h->ether_shost))
			{
				memcpy(pkt_l2h->ether_shost, ph_src->if_hwaddr.ifr_hwaddr.sa_data, 6);
			}
		}
		else
		{
			ph_src = &packet_handle[0];
			ph_dst = GET_ANOTHER_HANDLE(ph_src);

			if (IS_MAC_UNICAST(pkt_l2h->ether_shost) &&
				macdb_operate(macdb, MACDB_OPERATE_FLAG_ALLOC,
					pkt_l2h->ether_shost, cb_create_macdb_node, ph_src) < 0)
			{
				WARN("Run out of macdb node. Give up.");
				return -1;
			}

			if (IS_MAC_UNICAST(pkt_l2h->ether_shost))
			{
				memcpy(pkt_l2h->ether_shost, ph_src->if_hwaddr.ifr_hwaddr.sa_data, 6);
			}

			if (IS_MAC_UNICAST(pkt_l2h->ether_dhost) &&
				macdb_operate(macdb, MACDB_OPERATE_FLAG_ALLOC,
					pkt_l2h->ether_dhost, cb_create_macdb_node, ph_dst) < 0)
			{
				WARN("Run out of macdb node. Give up.");
				return -1;
			}

			if (IS_MAC_UNICAST(pkt_l2h->ether_dhost))
			{
				memcpy(pkt_l2h->ether_dhost, ph_dst->if_hwaddr.ifr_hwaddr.sa_data, 6);
			}
		}

		BUG_ON(ph_src == ph_dst);
	}

	*tx_handle = ph_src;
	*rx_handle = ph_dst;

	return 0; // ok
}

/*
 * * TODO: Do ip frag if input packet exceeds mtu.
 */
static void cb_pcap_handler(uint8_t *unused,
	const struct pcap_pkthdr *pcap_hdr, const uint8_t *pcap_packet)
{
	uint8_t *p;
	uint32_t plen;

	struct ether_header *pkt_l2h;
	packet_handle_t *ph_tx = NULL, *ph_rx = NULL;
	packet_t *pkt = NULL, *pkt_rx_buf = NULL;

	p = (uint8_t *) pcap_packet;
	plen = pcap_hdr->caplen;

	/*
	 * L2 - Ethernet.
	 */
	if (unlikely(plen < sizeof(*pkt_l2h)))
	{
		ERR("Drop pcap with anomaly ether header. Expect %d but only %u bytes left.",
			sizeof(*pkt_l2h), plen);
		return;
	}

	pkt_l2h = (struct ether_header *) p;

	if (unlikely(filter_out((struct ether_header *) pkt_l2h, pcap_hdr->caplen) == 0))
	{
		return; /* Skip this. */
	}

	if (unlikely(dispatch_handle_by_l2eth(&ph_tx, &ph_rx, p, plen) < 0))
	{
		return;
	}
	else
	{
		BUG_ON(ph_tx == NULL || ph_rx == NULL);
	}

	pkt = packet_handle_pull_pkt(ph_tx);
	if (unlikely(pkt == NULL))
	{
		return;
	}

	packet_set_l2(pkt);

	if (packet_append(pkt, plen) < 0)
	{
		packet_handle_push_pkt(pkt);
		return;
	}
	else
	{
		memcpy(packet_l2(pkt), p, plen);

		packet_decode_l2eth(pkt);
		packet_handle_xmit_l2eth(ph_rx, ph_tx, pkt);
		packet_handle_push_pkt(pkt);
	}
}

static int cb_pcap_l2eth_offline(const char *path_in, void *unused)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program bpf;

	const char *pcap_filter = NULL;

	long ts_start;
	long ts_end;

#if 1
	/* FIXME: do this only if it's necessary. */
	macdb_dump(macdb);
#endif

	/*
	 * Prepare pcap input
	 */
	handle = pcap_open_offline(path_in, errbuf);
	if (handle == NULL)
	{
		ERR("Cannot open pcap file '%s' %s\n", path_in, errbuf);
		return -1;
	}

	pcap_filter = lconf->pcap_filter;
	if (pcap_filter && pcap_filter[0])
	{
		VBS("...Apply pcap filter '%s'.\n", pcap_filter);

		if (pcap_compile(handle, &bpf, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) < 0)
		{
			ERR("Cannot compile pcap filter '%s'\n", pcap_filter);
			return -1;
		}
		else
		{
			if (pcap_setfilter(handle, &bpf) < 0)
			{
				ERR("Cannot set pcap filter '%s'\n", pcap_filter);
				return -1;
			}
		}
	}

	/*
	 * Handle with pcap input
	 */
	ts_start = tm_uptime();

	/*
	 * typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
	 */
	pcap_loop(handle, -1,
		cb_pcap_handler, NULL /* priv data */);

	ts_end = tm_uptime();
	PRT(" * Spend %ld sec for input: %s", (ts_end - ts_start), path_in);
	packet_handle_show_hook(&packet_handle[0]);
	packet_handle_show_hook(&packet_handle[1]);

	pcap_close(handle);

	return 0;
}

static inline const char *get_filename_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');

    if (!dot || dot == filename)
    {
    	return NULL;
    }

    return dot + 1;
}

static int cb_pcap_offline_filter(const char *path_in, void *arg)
{
	const char *ext;

	ext = get_filename_ext(path_in);
	if ((ext == NULL) || (strcasestr(ext, "cap") == NULL)) /* At least: pcap, cap, pcapng */
	{
		WARN("Bypass unexpected file extension: '%s' of '%s'",
			ext == NULL ? "" : ext, path_in);
		return 0; // filter-out
	}

	return -1; // do not filter.
}

static int op_pcap_l2eth_offline(void)
{
	PRT("...Visit pcap file or dir at '%s'", lconf->in.offline.pcap_input);

	return dirtrav(lconf->in.offline.pcap_input, DIRTRAV_FLAG_DFL,
		cb_pcap_l2eth_offline, cb_pcap_offline_filter, NULL);
}

static int op_pcap_l2eth_live(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program bpf;

	const char *pcap_filter = NULL;

	/*
	 * Prepare pcap input
	 */
	handle = pcap_open_live(
		lconf->in.live.pcap_input_dev, // monitor dev
		PACKET_MAX_FRAME_SIZE,         // snaplen
		lconf->in.live.promisc,        // promisc
		0,                             // timeout (ms)
		errbuf);
	if (handle == NULL)
	{
		ERR("Cannot open dev '%s' %s\n", lconf->in.live.pcap_input_dev, errbuf);
		return -1;
	}

	pcap_filter = lconf->pcap_filter;
	if (pcap_filter && pcap_filter[0])
	{
		VBS("...Apply pcap filter '%s'.\n", pcap_filter);

		if (pcap_compile(handle, &bpf, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) < 0)
		{
			ERR("Cannot compile pcap filter '%s'\n", pcap_filter);
			return -1;
		}
		else
		{
			if (pcap_setfilter(handle, &bpf) < 0)
			{
				ERR("Cannot set pcap filter '%s'\n", pcap_filter);
				return -1;
			}
		}
	}

	/*
	 * typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
	 */
	pcap_loop(handle, -1,
		cb_pcap_handler, NULL /* priv data */);

	pcap_close(handle);

	return 0;
}

int op_pcap_l2eth(void)
{
	static DECLARE_INIT_TBL(init_tbl)
	{
		/*
		 * Always read conf first
		 */
		{init_lconf, exit_lconf, OP_NAME "_lconf"},
		/*
		 * Other sub system
		 */
		{init_macdb, exit_macdb, OP_NAME "_macdb"},
		{init_packet_handle, exit_packet_handle, OP_NAME "_packet_handle"}
	};

	DBG("Run %s", __FUNCTION__);

	if (init_tbl_run_init(init_tbl, init_tbl_get_size(init_tbl)) < 0)
	{
		return -1;
	}

	/*
	 * Run pcap loop
	 */
	if (strcasecmp(lconf->mode, "live") == 0)
	{
		if (op_pcap_l2eth_live() < 0)
		{
			goto ERROR;
		}
	}
	else if (strcasecmp(lconf->mode, "offline") == 0)
	{
		if (op_pcap_l2eth_offline() < 0)
		{
			goto ERROR;
		}
	}
	else
	{
		BUG_ON(1);
	}

	init_tbl_run_exit(init_tbl, init_tbl_get_size(init_tbl));
	return 0;

	ERROR:
	init_tbl_run_exit(init_tbl, init_tbl_get_size(init_tbl));
	return -1;
}
