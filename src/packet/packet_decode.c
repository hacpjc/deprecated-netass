
#include "common.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>

/* Proto hdr */
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "packet/packet_buf.h"
#include "packet/packet_decode.h"
#include "net.h"

static packet_decode_res_t decode_tcp(packet_t *pkt)
{
	struct tcphdr *tcph = (struct tcphdr *) packet_pull(pkt, 0);

	uint8_t tcp_hlen;

	if (packet_try_pull(pkt, sizeof(*tcph)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	tcp_hlen = tcph->th_off << 2; // Max 60

	if (packet_try_pull(pkt, tcp_hlen) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	packet_set_l4(pkt);
	packet_pull(pkt, tcp_hlen);

	packet_set_l7(pkt);
	return PACKET_DECODE_RES_OK;
}

static packet_decode_res_t decode_udp(packet_t *pkt)
{
	struct udphdr *udph = (struct udphdr *) packet_pull(pkt, 0);

	uint16_t tot_len;

	if (packet_try_pull(pkt, sizeof(*udph)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	tot_len = ntohs(udph->len); // hdr + data

	if (tot_len < sizeof(*udph) || packet_try_pull(pkt, tot_len) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	packet_set_l4(pkt);
	packet_pull(pkt, sizeof(*udph));

	packet_set_l7(pkt);
	return PACKET_DECODE_RES_OK;
}

/*
 * +----------------------+
 * |                      |
 * +---------+------------+
 * |         | flag | off | <---
 * +---------+------------+
 * |
 * +----------------------+
 * |         SIP
 * +---
 * ...
 */
static inline int is_ip_frag(struct iphdr *iph)
{
	uint16_t word;

	word = ntohs(iph->frag_off);
	return (word & 0x3fff);
}

static packet_decode_res_t decode_ip4(packet_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) packet_pull(pkt, 0);
	uint8_t ihl;
	uint16_t tot_len;

	/*
	 * IP4 hdr
	 */
	if (packet_try_pull(pkt, sizeof(*iph)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	ihl = (iph->ihl << 2);

	if (packet_try_pull(pkt, ihl) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	packet_set_l3(pkt);

	/*
	 * Check anomaly.
	 */
	tot_len = ntohs(iph->tot_len);
	if (tot_len < ihl) // At least equal to header len
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	if (packet_try_pull(pkt, (tot_len)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	/*
	 * Check IP frag
	 */
	if (is_ip_frag(iph))
	{
		packet_add_attr(pkt, PACKET_ATTR_FRAG);
		return PACKET_DECODE_RES_OK; // Do not continue.
	}

	packet_pull(pkt, ihl);

	/*
	 * IP4 payload
	 */
	{
		uint8_t ip_proto = iph->protocol;

		switch (ip_proto)
		{
		case IPPROTO_TCP:
			return decode_tcp(pkt);
		case IPPROTO_UDP:
			return decode_udp(pkt);
#if 0 /* Other proto(s) are not important to this exec. */
		case IPPROTO_ICMP:
			break;
		case IPPROTO_IGMP:
			break;
#endif
		default:
			VBS("Do not support ip4 proto %u", ip_proto);
			break;
		}
	}

	/*
	 * Assume we don't have L4, and set L7.
	 */
	packet_set_l7(pkt);
	return PACKET_DECODE_RES_OK;
}

////////////////////////////////////////////////////////////////////////////////
#define IP6_NEXTHDR_HOP			0	/* Hop-by-Hop Option Header */
#define IP6_NEXTHDR_TCP			6	/* TCP */
#define IP6_NEXTHDR_UDP     	17	/* UDP */
#define IP6_NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define IP6_NEXTHDR_ROUTING		43	/* Routing Header */
#define IP6_NEXTHDR_FRAGMENT	44	/* Fragmentation Header */
#define IP6_NEXTHDR_ESP			50	/* Encapsulating Security Payload Header */
#define IP6_NEXTHDR_AUTH		51	/* Authentication Header */
#define IP6_NEXTHDR_ICMP		58	/* ICMPv6 */
#define IP6_NEXTHDR_NONE		59	/* No next header */
#define IP6_NEXTHDR_DEST		60	/* Destination Options Header */
#define IP6_NEXTHDR_MOBILITY    135 /* Mobility header */
#define IP6_NEXTHDR_MAX			255

#define IP6_MASK_HOPOPTS  (1 << 0)
#define IP6_MASK_DSTOPTS  (1 << 1)
#define IP6_MASK_ROUTING  (1 << 2)
#define IP6_MASK_FRAGMENT (1 << 3)
#define IP6_MASK_AH       (1 << 4)
#define IP6_MASK_ESP      (1 << 5)
#define IP6_MASK_NONE     (1 << 6)
#define IP6_MASK_MOBILITY (1 << 8)
//#define IP6_MASK_PROTO    (1 << 15) // XXX: deprecated

#define IS_IP6_EXT_HDR(_nexthdr)	\
	( \
		((_nexthdr) == IPPROTO_HOPOPTS)   || 	\
		((_nexthdr) == IPPROTO_ROUTING)   || 	\
		((_nexthdr) == IPPROTO_FRAGMENT)  || 	\
		((_nexthdr) == IPPROTO_ESP)       || 	\
		((_nexthdr) == IPPROTO_AH)        || 	\
		((_nexthdr) == IPPROTO_NONE)      || 	\
		((_nexthdr) == IPPROTO_DSTOPTS)   ||	\
		((_nexthdr) == IP6_NEXTHDR_MOBILITY /* FIXME */) \
	)

/* Routing header */
struct ip6_ext_rt_hdr
{
    uint8_t nexthdr;
    uint8_t hdrlen;

    /* rouing type */
    uint8_t type;
    /* # of listed nodes till final dest */
    uint8_t segments_left;

    /*
     *  type specific data
     *  variable length field
     */
    uint8_t data[0];
} __attribute__((packed));

/* Auth header */
struct ip6_ext_auth_hdr
{
	uint8_t nexthdr;
    /* length of AH in 4-byte unit, not including the first 8 bytes */
	uint8_t hdrlen;

    uint16_t reserved;

    uint32_t spi;
    uint32_t seq_no;           /* Sequence number */

    /* Length variable but >=4. Mind the 64 bit alignment! */
    uint8_t auth_data[0];
} __attribute__((packed));

/* ESP header */
struct ip6_ext_esp_hdr
{
	uint32_t spi;
    uint32_t seq_no;           /* Sequence number */
    /* Length variable but >=8. Mind the 64 bit alignment! */
    uint8_t enc_data[0];
} __attribute__((packed));

/* Fragmentation header */
struct ip6_ext_frag_hdr
{
	uint8_t nexthdr;
	uint8_t resv;    /*!< Should be 0 */
	uint16_t info;   /*!< offset: 13 rsv: 1 more: 1 */
	uint32_t id;
} __attribute__((packed));

/* Hop-by-Hop header */
struct ip6_ext_hop_hdr
{
    uint8_t nexthdr;
    uint8_t hdrlen;

    /* option dependent data */
    uint8_t opts[0];
} __attribute__((packed));

/* Destination header */
struct ip6_ext_dst_hdr
{
    uint8_t nexthdr;
    uint8_t hdrlen;

    /* option dependent data */
    uint8_t opts[0];
} __attribute__((packed));

/* Mobility header */
struct ip6_ext_mob_hdr
{
	uint8_t nexthdr;
	uint8_t hdrlen;
	uint8_t mh;
	uint8_t rsv;
	uint16_t cksum;

	uint8_t data[0];
} __attribute__((packed));

/* Generic ext hdr except ESP */
struct ip6_ext_gen_hdr
{
	uint8_t nexthdr;
	uint8_t hdrlen;
} __attribute__((packed));

/* Generic Type-Length-Value */
struct ip6_ext_tlv_hdr
{
	uint8_t type;
	uint8_t len;
	uint8_t value[0];
} __attribute__((packed));

static packet_decode_res_t decode_ip6_nexthdr(packet_t *pkt)
{
#define BUF_SHIFT(_buf, _buf_len, _buf_used_len, _shift) /* Check overflow before using it. */ \
	do { \
		if ((_shift) > (_buf_len)) { \
			DBG("ip ext - invalid len %u < %u\n", buf_len, _shift); \
			return PACKET_DECODE_RES_ANOMALY; \
		} else { \
			(_buf) += (_shift); \
			(_buf_len) -= (_shift); \
			(_buf_used_len) += (_shift); \
		} \
	} while (0)

	struct ip6_hdr *ip6h = packet_l3(pkt);
	uint8_t saved_proto;

	uint8_t *buf;
	uint32_t buf_len, buf_used_len = 0;

	buf = (uint8_t *) ip6h;
	buf_len = packet_l3_len(pkt) - 40;

	saved_proto = ip6h->ip6_nxt;

	/*
	 * Parse supported nexthdr, and stop at unknown nexthdr.
	 */
	while (IS_IP6_EXT_HDR(saved_proto))
	{
		struct ip6_ext_gen_hdr *hdr;
		int hdr_len;

		/*
		 * +-------------+
		 * | IPv6 header |
		 * |             |
		 * | saved_proto |
		 * +-------------+
		 *      \
		 *       +--> extension hdr (hdr = (struct ip6_ext_gen_hdr *) buf)
		 *            nexthdr
		 *              \
		 *               +--> ...
		 */

		if (unlikely(saved_proto == IP6_NEXTHDR_NONE))
		{
			break; // End of options & no more next header!
		}
		else if (unlikely(saved_proto == IP6_NEXTHDR_ESP))
		{
			/*
			 * Special case, can't continue next hdr if it's an ESP.
			 * * NOTE: The payload is also encrypted, we could simply bypass.
			 */
			break;
		}
		else if (unlikely(saved_proto == IP6_NEXTHDR_FRAGMENT))
		{
			packet_add_attr(pkt, PACKET_ATTR_FRAG);

			// Also pull the frag header to point to next-layer payload.
			BUF_SHIFT(buf, buf_len, buf_used_len, 8); // A frag option is 8 bytes.
			break;
		}

		/* Any extension hdr is at least 8 bytes */
		hdr = (struct ip6_ext_gen_hdr *) buf;
		if (unlikely(buf_len < sizeof(struct ip6_ext_gen_hdr)))
		{
			DBG("ip ext - invalid len %u < %u\n", buf_len, sizeof(struct ip6_ext_gen_hdr));
			return PACKET_DECODE_RES_ANOMALY;
		}

		/*
		 * 1. Just save the offset from IPv6 hdr so that we could use later.
		 * 2. Move to next extension hdr if there's any.
		 */
		switch (saved_proto)
		{
		case IP6_NEXTHDR_HOP:
			BUF_SHIFT(buf, buf_len, buf_used_len, 8 + (hdr->hdrlen << 3)); // 8 + (len * 8)
			break;

		case IP6_NEXTHDR_ROUTING:
			BUF_SHIFT(buf, buf_len, buf_used_len, 8 + (hdr->hdrlen << 3)); // 8 + (len * 8)
			break;

		case IP6_NEXTHDR_DEST:
			BUF_SHIFT(buf, buf_len, buf_used_len, 8 + (hdr->hdrlen << 3)); // 8 + (len * 8)
			break;

		case IP6_NEXTHDR_AUTH:
			BUF_SHIFT(buf, buf_len, buf_used_len, 8 + (hdr->hdrlen << 2)); // 8 + (len * 4)
			break;

		case IP6_NEXTHDR_MOBILITY:
			BUF_SHIFT(buf, buf_len, buf_used_len, 8 + (hdr->hdrlen << 3)); // 8 + (len * 8)
			break;

		default: // Not possible
			ERR(" * ERROR: Unexpected IP6 nexthdr %u. Possibly a bug.\n", saved_proto);
			return PACKET_DECODE_RES_BYPASS;
		}

		/* Save the address of the last nexthdr. Only for IP defrag. */
//		info->v6_frag_nhdr_off = &hdr->nexthdr - (unsigned char *) packet_l3(pkt);

		/* Continue with next proto */
		saved_proto = hdr->nexthdr;
	}

	packet_pull(pkt, buf_used_len);

	/*
	 * L4
	 */
	switch (saved_proto)
	{
	case IPPROTO_TCP:
		return decode_tcp(pkt);
	case IPPROTO_UDP:
		return decode_udp(pkt);
#if 0 /* Other proto(s) are not important to this exec. */
	case IPPROTO_ICMP:
		break;
	case IPPROTO_IGMP:
		break;
#endif
	default:
		VBS("Do not support ip6 nexthdr %u", saved_proto);
		break;
	}

	/*
	 * Assume we don't have L4, and set L7.
	 */
	packet_set_l7(pkt);
	return PACKET_DECODE_RES_OK;
}

/*
 *
 */
static packet_decode_res_t decode_ip6(packet_t *pkt)
{
	struct ip6_hdr *ip6h = packet_pull(pkt, 0);

	uint16_t plen;

	/*
	 * IP6 hdr
	 */
	if (packet_try_pull(pkt, sizeof(*ip6h)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	/* Verify payload length. */
	plen = ntohs(ip6h->ip6_plen);
	if (packet_try_pull(pkt, plen) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	packet_set_l3(pkt);
	packet_pull(pkt, sizeof(*ip6h));
	return decode_ip6_nexthdr(pkt);
}
////////////////////////////////////////////////////////////////////////////////

static packet_decode_res_t decode_arp4(packet_t *pkt)
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

	struct arph *arph = (struct arph *) packet_pull(pkt, 0);

	if (packet_try_pull(pkt, sizeof(*arph)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	return PACKET_DECODE_RES_OK;
}

static packet_decode_res_t decode_rarp4(packet_t *pkt)
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

	struct rarph *rarph = (struct rarph *) packet_pull(pkt, 0);

	if (packet_try_pull(pkt, sizeof(*rarph)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	return PACKET_DECODE_RES_OK;
}

/*
 * DMAC + SMAC + 0x8100 + PCP/DEI/VID (2B) + ether type + L3
 * +-----------+-------+------+------+-------------
 * |    MAC    | x8100 | VLAN | ETYPE|   L3
 * +-----------+-------+------+------+------
 *                     ^
 *                     |
 *                    start
 */
static packet_decode_res_t decode_vlan(packet_t *pkt)
{
	struct vlan_hdr
	{
		uint16_t vlan; // PCP: 3, CFI: 1, VID: 12
		uint16_t ether_type;
	} *vlanh = packet_pull(pkt, 0);

	uint8_t *l3h;

	if (packet_pull(pkt, sizeof(*vlanh)) == NULL)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	/* Save VLAN hdr */
	if (!packet_check_attr(pkt, PACKET_ATTR_VLAN))
	{
		pkt->vlan = vlanh;
		packet_add_attr(pkt, PACKET_ATTR_VLAN);
	}

	/* Re-update ether type */
	pkt->ether_type = ntohs(vlanh->ether_type);
	switch (pkt->ether_type)
	{
	/*
	 * Layer 3
	 */
	case ETHERTYPE_IP:
		return decode_ip4(pkt);
	case ETHERTYPE_IPV6:
		return decode_ip6(pkt);
	/*
	 * As-is
	 */
	case ETHERTYPE_ARP:
		return decode_arp4(pkt);
	case ETHERTYPE_REVARP:
		return decode_rarp4(pkt);
	default:
		VBS("Do not support eth type 0x%04x inside vlan", pkt->ether_type);
		break;
	}

	return PACKET_DECODE_RES_BYPASS;
}

#define is_last_mpls(_mpls) (((_mpls)->byte[2]) & 0x01) // Bit#23 is 1 -> last MPLS

/*
 *     Start                      Goal
 *       |                          |
 *       V                          V
 * +-----+--------+--------+--------+-------
 * | eth | MPLS#1 | MPLS#2 | MPLS#L | eth
 * +-----+--------+--------+--------+------
 *                     ^       ^
 *                     |       |
 *                   last   trailer
 */
static packet_decode_res_t decode_mpls(packet_t *pkt)
{
	struct
	{
		uint8_t byte[4];
	} *mpls_hdr = packet_pull(pkt, 0);

	unsigned int mpls_tot_len = 0;

	/*
	 * Calc total MPLS header length
	 */
	do
	{
		if (packet_try_pull(pkt, mpls_tot_len + sizeof(*mpls_hdr)) < 0)
		{
			return PACKET_DECODE_RES_ANOMALY;
		}

		mpls_tot_len += sizeof(*mpls_hdr);

		if (is_last_mpls(mpls_hdr))
		{
			break;
		}
		else
		{
			mpls_hdr++;
		}
	} while (1);

	/* Also skip the last MPLS tail */
	if (packet_try_pull(pkt, mpls_tot_len + sizeof(*mpls_hdr)) < 0)
	{
		return PACKET_DECODE_RES_ANOMALY;
	}

	mpls_tot_len += sizeof(*mpls_hdr);

	/* Done */
	packet_pull(pkt, mpls_tot_len);

	return packet_decode_l2eth(pkt); // Restart from ethernet.
}

packet_decode_res_t packet_decode_l2eth(packet_t *pkt)
{
	packet_decode_res_t res = PACKET_DECODE_RES_BYPASS;
	struct ether_header *eth = (struct ether_header *) packet_pull(pkt, 0);

	if (!packet_pull(pkt, sizeof(*eth)))
	{
		packet_add_attr(pkt, PACKET_ATTR_ANO);
		return PACKET_DECODE_RES_ANOMALY;
	}

	/*
	 * * NOTE: Don't set l2 header here!
	 */

	pkt->ether_type = ntohs(eth->ether_type);
	switch (pkt->ether_type)
	{
	/*
	 * Layer 3
	 */
	case ETHERTYPE_IP:
		res = decode_ip4(pkt);
		break;
	case ETHERTYPE_IPV6:
		res = decode_ip6(pkt);
		break;
	/*
	 * As-is
	 */
	case ETHERTYPE_VLAN:
		res = decode_vlan(pkt); // 0x8100
		break;
	case ETHERTYPE_ARP:
		res = decode_arp4(pkt);
		break;
	case ETHERTYPE_REVARP:
		res = decode_rarp4(pkt);
		break;
	case 0x8847: // MPLS
		res = decode_mpls(pkt);
		break;
	default:
		WARN("Do not support eth type 0x%04x", pkt->ether_type);
		break;
	}

	if (res == PACKET_DECODE_RES_ANOMALY)
	{
		packet_add_attr(pkt, PACKET_ATTR_ANO);
	}

	return res;
}
