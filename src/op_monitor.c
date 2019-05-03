#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>

#include <net/ethernet.h>

#include "common.h"
#include "init_tbl.h"
#include "tm.h"
#include "net.h"

#include "packet/packet.h"

////////////////////////////////////////////////////////////////////////////////
#include "conf/lconf.h"

typedef struct pcap_offline_conf
{
	const char *dev1;
} local_conf_t;

static local_conf_t *lconf = NULL;

static int init_lconf(void)
{
	lconf = malloc(sizeof(*lconf));
	if (lconf == NULL)
	{
		return -1;
	}

	memset(lconf, 0x00, sizeof(*lconf));

	LCONF_GET_STR_FROM_PARENT(lconf->dev1, "dev1", CONF_PARENT_MONITOR);

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

static packet_handle_t packet_handle = PACKET_HANDLE_INITIALIZER;

static int init_packet_handle(void)
{
	memset(&packet_handle, 0x00, sizeof(packet_handle));

	if (packet_handle_init(&packet_handle, lconf->dev1) < 0)
	{
		return -1;
	}

	return 0;
}

static void exit_packet_handle(void)
{
	packet_handle_exit(&packet_handle);
}

////////////////////////////////////////////////////////////////////////////////

struct statistics
{
	uint64_t total_rx_len;
	uint64_t total_rx;
	long ts_start;
};
static struct statistics statistics = { 0, 0, 0 };

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

#define PFX "\t"

#include <netinet/tcp.h>
static void simple_decode_tcp(uint8_t *pay, unsigned int pay_len)
{
	struct tcphdr *tcph = (struct tcphdr *) pay;

	/* Test tcp hdr */
	PACKET_SHIFT(pay, pay_len, sizeof(*tcph));

	/* Test tcp hdr (options) */
	if ((tcph->doff << 2) < sizeof(*tcph))
	{
		ERR("Invalid tcp data offset %u", (tcph->doff << 2));
		return;
	}
	PACKET_SHIFT(pay, pay_len, (tcph->doff << 2) - sizeof(*tcph));

	PRT(PFX "tcp: hdr %u, data %u, sport %u, dport %u%s%s%s%s%s",
		tcph->doff << 2, pay_len,
		ntohs(tcph->source), ntohs(tcph->dest),
		tcph->syn ? ", syn" : "",
		tcph->ack ? ", ack" : "",
		tcph->psh ? ", psh" : "",
		tcph->rst ? ", rst" : "",
		tcph->fin ? ", fin" : ""
		);
}

#include <netinet/udp.h>
static void simple_decode_udp(uint8_t *pay, unsigned int pay_len)
{
	struct udphdr *udph = (struct udphdr *) pay;

	PACKET_SHIFT(pay, pay_len, sizeof(*udph));

	PRT(PFX "udp: sport %u, dport %u",
		ntohs(udph->source), ntohs(udph->dest));
}

#include <netinet/ip.h>
#include <netinet/ip6.h>

static void simple_decode_ip6(uint8_t *pay, unsigned int pay_len);
static void simple_decode_ip4(uint8_t *pay, unsigned int pay_len)
{
	struct iphdr *iph = (struct iphdr *) pay;

	PACKET_SHIFT(pay, pay_len, (iph->ihl * 4));

	{
		uint16_t data_len = ntohs(iph->tot_len) - (iph->ihl * 4);

		PRT(PFX "ip4: sip " IPV4_OCTET_FMT ", dip " IPV4_OCTET_FMT ", proto %u, iph %u, data %u, real %u%s",
			IPV4_OCTET_EXPAND(((uint8_t *) &iph->saddr)), IPV4_OCTET_EXPAND(((uint8_t *) &iph->daddr)),
			iph->protocol,
			iph->ihl << 2, data_len, pay_len,
			(data_len != pay_len) ? " (padding)" : ""
			);
	}

	switch (iph->protocol)
	{
	case IPPROTO_TCP: // TCP
		simple_decode_tcp(pay, pay_len);
		break;

	case IPPROTO_UDP: // UDP
		simple_decode_udp(pay, pay_len);
		break;

	case IPPROTO_ICMP: // ICMP
		PRT(PFX "icmp:");
		break;

	case IPPROTO_IPV6: // IP6 in IP4
		simple_decode_ip6(pay, pay_len);
		break;

	default:
		PRT(PFX "Do not support ip4 proto %u", iph->protocol);
		break;
	}
}

static void simple_decode_ip6(uint8_t *pay, unsigned int pay_len)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr *) pay;

	PACKET_SHIFT(pay, pay_len, 40);
//	PACKET_SHIFT(pay, pay_len, (ntohs(ip6h->ip6_plen))); // include ext hdr.

	switch (ip6h->ip6_nxt /* 1 byte */)
	{
	case IPPROTO_TCP:
		simple_decode_tcp(pay, pay_len);
		break;

	case IPPROTO_UDP:
		simple_decode_udp(pay, pay_len);
		break;

	case IPPROTO_ICMPV6:
		PRT(PFX "icmp6:");
		break;

	case IPPROTO_IP:
		simple_decode_ip4(pay, pay_len);
		break;

	default:
		PRT(PFX "Do not support ip6 proto %u", ip6h->ip6_nxt);
		break;
	}
}

static void simple_decode_arp(uint8_t *pay, unsigned int pay_len)
{
	struct arph
	{
		uint16_t htype;
		uint16_t ptype;
		uint8_t  hlen;
		uint8_t  plen;
		uint16_t oper;
		uint8_t  source[6];
		uint8_t  source_addr[4];
		uint8_t  dest[6];
		uint8_t dest_addr[4];
	};

	struct arph *arph = (struct arph *) pay;

	PACKET_SHIFT(pay, pay_len, sizeof(*arph));

	if (arph->plen != 4)
	{
		PRT(PFX "arp: htype %u, ptype %u, hlen %u, plen %u, op %u, " MAC_OCTET_FMT "/" IPV4_OCTET_FMT " -> " MAC_OCTET_FMT "/" IPV4_OCTET_FMT,
			ntohs(arph->htype),
			ntohs(arph->hlen),
			arph->hlen,
			arph->plen,
			arph->oper,
			MAC_OCTET_EXPAND(arph->source),
			IPV4_OCTET_EXPAND(arph->source_addr),
			MAC_OCTET_EXPAND(arph->dest),
			IPV4_OCTET_EXPAND(arph->dest_addr)
			);
		return;
	}

	if (ntohs(arph->oper) == 1 /* req */)
	{
		PRT(PFX "arp: "MAC_OCTET_FMT " -> " MAC_OCTET_FMT ", Who has " IPV4_OCTET_FMT "? Tell " IPV4_OCTET_FMT,
			MAC_OCTET_EXPAND(arph->source), MAC_OCTET_EXPAND(arph->dest),
			IPV4_OCTET_EXPAND(arph->dest_addr), IPV4_OCTET_EXPAND(arph->source_addr)
			);
	}
	else
	{
		PRT(PFX "arp: " IPV4_OCTET_FMT " is at " MAC_OCTET_FMT,
			IPV4_OCTET_EXPAND(arph->source_addr), MAC_OCTET_EXPAND(arph->source)
			);
	}
}

static void simple_decode_rarp(uint8_t *pay, unsigned int pay_len)
{
	struct rarph
	{
		uint16_t htype;
		uint16_t ptype;
		uint8_t  hlen;
		uint8_t  plen;
		uint16_t oper;
		uint8_t  source[6];
		uint8_t  source_addr[4];
		uint8_t  dest[6];
		uint8_t dest_addr[4];
	};

	struct rarph *arph = (struct rarph *) pay;

	PACKET_SHIFT(pay, pay_len, sizeof(*arph));

	PRT(PFX "rarp: htype %u, ptype %u, hlen %u, plen %u, op %u, " MAC_OCTET_FMT "/" IPV4_OCTET_FMT " -> " MAC_OCTET_FMT "/" IPV4_OCTET_FMT,
		ntohs(arph->htype),
		ntohs(arph->hlen),
		arph->hlen,
		arph->plen,
		arph->oper,
		MAC_OCTET_EXPAND(arph->source),
		IPV4_OCTET_EXPAND(arph->source_addr),
		MAC_OCTET_EXPAND(arph->dest),
		IPV4_OCTET_EXPAND(arph->dest_addr)
		);
}

static void simple_decode(uint8_t *pay, unsigned int pay_len)
{
	struct ether_header *eth = (struct ether_header *) pay;

	uint16_t ethtype;

	PACKET_SHIFT(pay, pay_len, sizeof(*eth));

	ethtype = ntohs(eth->ether_type);
	PRT(PFX "eth: smac=" MAC_OCTET_FMT " -> dmac=" MAC_OCTET_FMT ", ethtype=0x%04x",
		MAC_OCTET_EXPAND(eth->ether_shost), MAC_OCTET_EXPAND(eth->ether_dhost),
		ethtype);

	switch (ethtype)
	{
	case ETHERTYPE_VLAN:
		PRT(PFX "vlan");
		break;
	case ETHERTYPE_IP:
		simple_decode_ip4(pay, pay_len);
		break;
	case ETHERTYPE_IPV6:
		simple_decode_ip6(pay, pay_len);
		break;
	case ETHERTYPE_ARP:
		simple_decode_arp(pay, pay_len);
		break;
	case ETHERTYPE_REVARP:
		simple_decode_rarp(pay, pay_len);
		break;
	case ETHERTYPE_LOOPBACK:
		PRT(PFX "loopback");
		break;
	default:
		PRT(PFX "Do not support ether 0x%04x", ethtype);
		break;
	}
}

/*
 * Export decoder here for other op to use.
 */
void op_monitor_decode(uint8_t *l2, unsigned l2_len)
{
	simple_decode(l2, l2_len);
}

static void print_statistics(int unused)
{
	long ts_diff = (tm_uptime() - statistics.ts_start);
	if (ts_diff == 0) ts_diff = 1;

	PRT("");
	PRT("#\n# Overall statistics:\n#");
	PRT(PFX "time sec: %ld", ts_diff);
	PRT(PFX "total rx: %lu",     statistics.total_rx);
	PRT(PFX "total rx len: %lu", statistics.total_rx_len);
	PRT(PFX "avg rx: %lu",       statistics.total_rx / ts_diff);
	PRT(PFX "avg rx len: %lu",   statistics.total_rx_len / ts_diff);

	packet_handle_show_hook(&packet_handle);
}

static void int_handler(int unused)
{
	print_statistics(0);
	exit(0);
}

#include <signal.h>

static int __monitor(void)
{
	uint64_t i;
	packet_t pkt, *pb = &pkt;

	statistics.ts_start = tm_uptime();
	signal(SIGUSR1, print_statistics);
	signal(SIGINT, int_handler);

	packet_init(pb);

	for (i = 0;; i++)
	{
		if (packet_handle_recv_l2eth(&packet_handle, pb, 0) < 0)
		{
			continue;
		}

		/*
		 * stat
		 */
		statistics.total_rx_len += packet_l2_len(pb);
		statistics.total_rx += 1;

		/*
		 * simple packet decode
		 */
		PRT(" * Decode input %u bytes:", packet_l2_len(pb));
		simple_decode(packet_l2(pb), packet_l2_len(pb));
	}

	return 0;
}

int op_monitor(void)
{
	static DECLARE_INIT_TBL(init_tbl)
	{
		/*
		 * Always read conf first
		 */
		{init_lconf, exit_lconf, "monitor_lconf"},
		/*
		 * Other sub system
		 */
		{init_packet_handle, exit_packet_handle, "monitor_packet_handle"}
	};

	int res;

	DBG("Run %s", __FUNCTION__);

	if (init_tbl_run_init(init_tbl, init_tbl_get_size(init_tbl)) < 0)
	{
		return -1;
	}

	res = __monitor();

	init_tbl_run_exit(init_tbl, init_tbl_get_size(init_tbl));
	return res;

	ERROR:
	init_tbl_run_exit(init_tbl, init_tbl_get_size(init_tbl));
	return -1;
}
