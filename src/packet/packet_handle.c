#include <sys/time.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "common.h"
#include "tm.h"

#include "conf/lconf.h"

#include "packet/packet_buf.h"
#include "packet/packet_handle.h"
#include "packet/packet_hook.h"
#include "net.h"

struct cb_add_hook_param
{
	packet_handle_t *ph;
	void *hook_conf_root;
};

static unsigned int lconf_is_packet_hook_enable(const void *conf_root, const char *hook_name)
{
	const char *sym;
	unsigned int enable = 0; // 0: disable, 1: enable

	char sym_name[256 + 1];

	/*
	 * Get conf symbol "<hook>.enable"
	 */
	snprintf(sym_name, sizeof(sym_name), "%s" CONF_DELIM "%s", hook_name, "enable");
	sym = conf_get_sym_str_from_root(sym_name, conf_root);
	if (sym == NULL)
	{
		return 0;
	}
	else
	{
		enable = (unsigned int) atoi(sym);
	}

	return enable;
}

static int cb_add_hook(packet_hook_t *hook, void *priv)
{
	struct cb_add_hook_param *param = (struct cb_add_hook_param *) priv;
	packet_hook_t *new_hook;
	void *ctx;

	if (!lconf_is_packet_hook_enable(param->hook_conf_root, hook->ident))
	{
		DBG("hook '%s' is off.", hook->ident);
		return 0;
	}

	new_hook = malloc(sizeof(*new_hook));
	if (new_hook == NULL)
	{
		ERR("Cannot alloc new hook '%s'", hook->ident);
		return -1;
	}

	memcpy(new_hook, hook, sizeof(*new_hook));

	/*
	 * ctx
	 */
	if (packet_hook_check_open_ctx(hook))
	{
		ctx = packet_hook_do_open_ctx(new_hook, param->hook_conf_root);
		if (ctx == NULL)
		{
			free(new_hook);
			return -1;
		}

		packet_hook_set_ctx(new_hook, ctx);
	}

	/*
	 * handle
	 */
	packet_hook_set_packet_handle(new_hook, param->ph);

	/* FIFO, so the hook list is in order. */
	list_add_tail(&(new_hook->list), &(param->ph->list_hook));

	DBG("Successfully add packet hook '%s'", new_hook->ident);
	return 0;
}

int packet_handle_add_hook(packet_handle_t *ph, const void *hook_conf_root)
{
	int ret;
	struct cb_add_hook_param param = { .ph = ph, .hook_conf_root = (void *) hook_conf_root };

	/* Add packet hook to this handle. */
	ret = packet_hook_loop(cb_add_hook, (void *) &param);
	return ret;
}

void packet_handle_del_hook(packet_handle_t *ph)
{
	packet_hook_t *hook, *hook_save;

	list_for_each_entry_safe(hook, hook_save, &(ph->list_hook), list)
	{
		DBG("Close packet hook '%s'", hook->ident);

		/* ctx */
		if (packet_hook_check_close_ctx(hook))
		{
			packet_hook_do_close_ctx(hook, packet_hook_get_ctx(hook, void));
			packet_hook_set_ctx(hook, NULL);
		}

		/* handle */
		packet_hook_set_packet_handle(hook, NULL);

		/* free */
		packet_hook_free(hook);
	}
}

void packet_handle_dump_hook(packet_handle_t *ph)
{
	int i = 1;
	packet_hook_t *hook;

	list_for_each_entry(hook, &(ph->list_hook), list)
	{
		PRT("hook#%d = '%s' ", i, hook->ident);
	}
}

void packet_handle_show_hook(packet_handle_t *ph)
{
	packet_hook_t *hook;

	list_for_each_entry(hook, &(ph->list_hook), list)
	{
		if (packet_hook_check_show(hook))
		{
			PRT("#\n# Output of hook '%s'\n#", hook->ident);
			packet_hook_do_show(hook);
		}
	}
}

int packet_handle_run_tx_hook(packet_handle_t *ph, packet_t *pkt)
{
	packet_hook_t *hook;
	packet_hook_res_t res = PACKET_HOOK_RES_OK;

	list_for_each_entry(hook, &(ph->list_hook), list)
	{
		if (!packet_hook_check_tx(hook))
		{
			continue;
		}

		res = packet_hook_do_tx(hook, pkt);
		switch (res)
		{
		case PACKET_HOOK_RES_OK:
			break;
		case PACKET_HOOK_RES_STOP:
			VBS("Stop at hook '%s'", hook->ident);
			goto EXIT;
		case PACKET_HOOK_RES_ERROR:
			WARN("Can't run packet hook '%s'", hook->ident);
			break;
		default:
			ERR("Unexpected return code %d. Possibly a bug.", res);
			break;
		}
	}

EXIT:
	return res;
}

int packet_handle_run_rx_hook(packet_handle_t *ph, packet_t *pkt)
{
	packet_hook_t *hook;
	packet_hook_res_t res = PACKET_HOOK_RES_OK;

	list_for_each_entry_reverse(hook, &(ph->list_hook), list)
	{
		if (!packet_hook_check_rx(hook))
		{
			continue;
		}

		res = packet_hook_do_rx(hook, pkt);
		switch (res)
		{
		case PACKET_HOOK_RES_OK:
			break;
		case PACKET_HOOK_RES_STOP:
			VBS("Stop at hook '%s'", hook->ident);
			goto EXIT;
		case PACKET_HOOK_RES_ERROR:
			WARN("Can't run packet hook '%s'", hook->ident);
			break;
		default:
			ERR("Unexpected return code %d. Possibly a bug.", res);
			break;
		}
	}

EXIT:
	return res;
}

/*
 * * TCP ack packet is too small (called runt). The padding 6 bytes are altered on a linux bridge.
 *
 *
hexdump_f 60 <cb_pdump_tx>:
         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |01234567 89ABCDEF|
         -----------------------  -----------------------   -------- --------
00000000 00 90 FB 37 71 AB 00 90  FB 37 71 AC 08 00 45 00  |...7q... .7q...E.|
00000010 00 28 46 F6 40 00 7E 06  63 88 8C 81 28 CB DA A2  |.(F.@.~. c...(...|
00000020 C2 62 46 7F 0F 1E E1 88  B1 B6 CB 29 A6 40 50 10  |.bF..... ...).@P.|
00000030 FF FF 03 3C 00 00 FF FF  FF FF FF FF              |...<.... ....    |
	eth: smac=00:90:FB:37:71:AC -> dmac=00:90:FB:37:71:AB, ethtype=0x0800
	ip4: sip 140.129.40.203, dip 218.162.194.98, proto 6
	tcp: hdr 20, data 6, sport 18047, dport 3870, ack
[packet_handle_send_l2eth]   --> Send    60 (enp9s0f2)
[__packet_handle_recv] <<< Recv    60 (enp9s0f1)
 * WARNING: Recv an unexpected packet:
hexdump_f 60 <packet_handle_recv_same_l2eth>:
         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |01234567 89ABCDEF|
         -----------------------  -----------------------   -------- --------
00000000 00 90 FB 37 71 AB 00 90  FB 37 71 AC 08 00 45 00  |...7q... .7q...E.|
00000010 00 28 46 F6 40 00 7E 06  63 88 8C 81 28 CB DA A2  |.(F.@.~. c...(...|
00000020 C2 62 46 7F 0F 1E E1 88  B1 B6 CB 29 A6 40 50 10  |.bF..... ...).@P.|
00000030 FF FF 03 3C 00 00 00 00  00 00 00 00              |...<.... ....    |
	eth: smac=00:90:FB:37:71:AC -> dmac=00:90:FB:37:71:AB, ethtype=0x0800
	ip4: sip 140.129.40.203, dip 218.162.194.98, proto 6
	tcp: hdr 20, data 6, sport 18047, dport 3870, ack
 */
static int __rx_same_l2eth(packet_handle_t *ph, packet_t *pkt, packet_t *pkt_check, unsigned int timeout)
{
	if (packet_handle_recv_same_l2eth(ph, pkt, pkt_check, timeout) < 0)
	{
		return PACKET_HOOK_RES_ERROR;
	}

	return packet_handle_run_rx_hook(ph, pkt);
}

static packet_hook_res_t __tx_l2eth(packet_handle_t *ph_rx, packet_handle_t *ph_tx, packet_t *pkt_tx)
{
	packet_hook_res_t res;

	if (likely(list_empty(&(pkt_tx->list_child))))
	{
		/*
		 * Send out this.
		 */
		if (packet_handle_send_l2eth(ph_tx, pkt_tx) == packet_l2_len(pkt_tx))
		{
			packet_t *pkt_rx;

			/*
			 * Receive pkt at RX handle.
			 */
			pkt_rx = packet_handle_pull_pkt(ph_rx);
			if (unlikely(pkt_rx == NULL))
			{
				abort();
				return PACKET_HOOK_RES_ERROR;
			}

#if CONFIG_DISABLE_RECV_SAME
			res = PACKET_HOOK_RES_OK;
#else
			res = __rx_same_l2eth(ph_rx, pkt_rx, pkt_tx, 3 /* At least 2 sec */);
#endif
			packet_handle_push_pkt(pkt_rx);
			return res;
		}
		else
		{
			return PACKET_HOOK_RES_ERROR;
		}
	}
	else
	{
		/*
		 * Send children instead.
		 */
		packet_t *pkt_tx_child;

		list_for_each_entry(pkt_tx_child, &(pkt_tx->list_child), list)
		{
			res = __tx_l2eth(ph_rx, ph_tx, pkt_tx_child);

			switch (res)
			{
			case PACKET_HOOK_RES_OK:
				break;
			case PACKET_HOOK_RES_STOP:
				/*
				 * * TIRCKY: It's possibly stolen by RX hook.
				 */
				break;
			case PACKET_HOOK_RES_ERROR:
				return PACKET_HOOK_RES_ERROR;
			default:
				ERR("Invalid return code '%d'. Possibly a bug.", res);
				return PACKET_HOOK_RES_ERROR;
			}
		}

		return res;
	}

	BUG_ON(1);
	return PACKET_HOOK_RES_ERROR; // Oops?
}

packet_hook_res_t packet_handle_xmit_l2eth(packet_handle_t *ph_rx, packet_handle_t *ph_tx, packet_t *pkt_tx)
{
	packet_hook_res_t res;

	res = packet_handle_run_tx_hook(ph_tx, pkt_tx);
	switch (res)
	{
	case PACKET_HOOK_RES_OK:
		return __tx_l2eth(ph_rx, ph_tx, pkt_tx);
	case PACKET_HOOK_RES_STOP:
		return PACKET_HOOK_RES_STOP;
	case PACKET_HOOK_RES_ERROR:
		return PACKET_HOOK_RES_ERROR;
	default:
		ERR("Invalid packet hook result '%d'. Possibly a bug", res);
		return PACKET_HOOK_RES_ERROR;
	}

	BUG_ON(1);
	return PACKET_HOOK_RES_ERROR; // Impossible
}

////////////////////////////////////////////////////////////////////////////////

static int __packet_handle_recv(packet_handle_t *ph, packet_t *pb)
{
	int res;

	packet_reset_payload(pb);
	packet_set_l2(pb);

	res = recv(ph->fd,
		packet_l2(pb), packet_get_left_len(pb),
		0);
	if (res < 0)
	{
		ERR("Cannot recv any frame %d. %s", res, strerror(errno));
		errno = 0;
		return -1;
	}
	else
	{
		/* Recv n bytes. Copy to payload. */
		BUG_ON(res > packet_get_left_len(pb));
		packet_append(pb, res);

		VBS("<<< Recv %5d (%s)",
			res, ph->dev_name);
	}

	return 0;
}

#define L2ETH_MIN (64)

static int cmp_packet_l3_generic(
	packet_t *rx, /* The packet in recv buf */
	packet_t *tx /* The packet we send */)
{
	unsigned int cmp_len;

	if (packet_l2_len(tx) > L2ETH_MIN && packet_l2_len(tx) != packet_l2_len(rx))
	{
		return -1;
	}

	cmp_len = packet_l3_len(rx) < packet_l3_len(tx) ? packet_l3_len(rx) : packet_l3_len(tx);

	return memcmp((uint8_t *) packet_l3(rx), (uint8_t *) packet_l3(tx), cmp_len);
}

static int cmp_packet_l3_ip4(
	packet_t *rx, /* The packet in recv buf */
	packet_t *tx /* The packet we send */)
{
	struct iphdr *iph_rx, *iph_tx;
	unsigned int rx_len, tx_len, rx_data_len, tx_data_len;

	iph_rx = (struct iphdr *) packet_l3(rx);
	iph_tx = (struct iphdr *) packet_l3(tx);

	/* Validate ip hdr len */
	if ((packet_l3_len(rx) < sizeof(*iph_rx)) ||
		(packet_l3_len(tx) < sizeof(*iph_tx)))
	{
		goto DO_L3_GENERIC;
	}

	/* Validate ip hdr+data len */
	rx_len = ntohs(iph_rx->tot_len);
	tx_len = ntohs(iph_tx->tot_len);
	if (packet_l3_len(rx) < rx_len ||
		packet_l3_len(tx) < tx_len)
	{
		goto DO_L3_GENERIC;
	}

	/*
	 * Do cmp on hdr+data
	 */
	if (rx_len != tx_len)
	{
		return -1;
	}

	return memcmp(iph_rx, iph_tx, tx_len);

DO_L3_GENERIC:
	return cmp_packet_l3_generic(rx, tx);
}

static int cmp_packet_l3_ip6(
	packet_t *rx, /* The packet in recv buf */
	packet_t *tx /* The packet we send */)
{
	struct ip6_hdr *ip6h_rx, *ip6h_tx;
	unsigned int rx_len, tx_len;

	ip6h_rx = (struct ip6_hdr *) packet_l3(rx);
	ip6h_tx = (struct ip6_hdr *) packet_l3(tx);

	/* Validate ip hdr len */
	if (packet_l3_len(rx) < sizeof(*ip6h_rx) ||
		packet_l3_len(tx) < sizeof(*ip6h_tx))
	{
		goto DO_L3_GENERIC;
	}

	rx_len = sizeof(ip6h_rx) + ntohs(ip6h_rx->ip6_plen);
	tx_len = sizeof(ip6h_tx) + ntohs(ip6h_tx->ip6_plen);

	/* Validate ip hdr+data len */
	if (packet_l3_len(rx) < rx_len ||
		packet_l3_len(tx) < tx_len)
	{
		goto DO_L3_GENERIC;
	}

	/*
	 * Do cmp on hdr+data
	 */
	if (rx_len != tx_len)
	{
		return -1;
	}

	return memcmp(ip6h_rx, ip6h_tx, rx_len);

DO_L3_GENERIC:
	return cmp_packet_l3_generic(rx, tx);
}

/*
[packet_handle_send_l2eth]   --> Send    64 (enp9s0f1)
[__packet_handle_recv] <<< Recv    60 (enp9s0f2)
 * WARNING: Recv an unexpected packet:
hexdump_f 60 <packet_handle_recv_same_l2eth>:
         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |01234567 89ABCDEF|
         -----------------------  -----------------------   -------- --------
00000000 00 90 FB 37 71 AC 00 90  FB 37 71 AB 08 00 45 00  |...7q... .7q...E.|
00000010 00 2C 64 6F 40 00 C0 06  0C A5 CB 54 CC 45 8C 81  |.,do@... ...T.E..|
00000020 25 9C 00 50 10 84 DC 54  EA 9E F1 DA 53 92 60 50  |%..P...T ....S.`P|
00000030 1F 40 11 AC 00 00 02 04  05 B4 00 00              |.@...... ....    |
	eth: smac=00:90:FB:37:71:AB -> dmac=00:90:FB:37:71:AC, ethtype=0x0800
	ip4: sip 203.84.204.69, dip 140.129.37.156, proto 6, iph 20, data 24, real 26 (padding)
	tcp: hdr 24, data 2, sport 80, dport 4228, ack

 */
static int cmp_packet_l3(
	packet_t *rx, /* The packet in recv buf */
	packet_t *tx /* The packet we send */)
{
	switch (tx->ether_type)
	{
	case ETHERTYPE_IP:
		return cmp_packet_l3_ip4(rx, tx);
	case ETHERTYPE_IPV6:
		return cmp_packet_l3_ip6(rx, tx);
	default:
		return cmp_packet_l3_generic(rx, tx);
	}

	BUG_ON(1); // Not possible
	return -1;
}

/*!
 * \brief Compare payload except L2 ether header.
 *
 * \note In bridge network, ether header won't be modified. We need to compare the whole payload.
 */
static int cmp_packet_l2eth(
	packet_t *rx, /* The packet in recv buf */
	packet_t *tx /* The packet we send */)
{
#define RX (0)
#define TX (1)
	struct ethhdr *eth[2];
	unsigned int len[2];

	eth[RX] = (struct ethhdr *) packet_l2(rx);
	eth[TX] = (struct ethhdr *) packet_l2(tx);

	len[RX] = packet_l2_len(rx);
	len[TX] = packet_l2_len(tx);

	/*
	 * Run l3 cmp if l3 is set.
	 */
	if (packet_l3(rx) && packet_l3(tx))
	{
		if (rx->ether_type != tx->ether_type)
		{
			return -1;
		}

		if (packet_l2h_len(rx) != packet_l2h_len(tx))
		{
			return -1;
		}

		/* Run general cmp at l2 hdr. */
		if (memcmp((uint8_t *) eth[RX], (uint8_t *) eth[TX], packet_l2h_len(tx)) != 0)
		{
			return -1;
		}

		return cmp_packet_l3(rx, tx);
	}

	/*
	 * Run general cmp
	 */
	if (len[RX] != len[TX])
	{
		if (len[TX] < L2ETH_MIN && len[TX] < len[RX])
		{
			/* Padding is only possible for runt packets. */
		}
		else
		{
			return -1;
		}
	}

	return memcmp((uint8_t *) eth[RX], (uint8_t *) eth[TX], len[TX]);
}

int packet_handle_recv_same_l2eth(packet_handle_t *ph,
	packet_t *pb, packet_t *pkt_check,
	unsigned int timeout)
{
	long ts_start;

	fd_set rfds;
	struct timeval tv;
	int ret;

	FD_ZERO(&rfds);
	ts_start = tm_uptime();

	for (;;)
	{
		if (tm_uptime() > (ts_start + timeout))
		{
			PRT_NONL("...timeout\n");
#if CONFIG_DEBUG_UNEXPECTED_TX
			hexdump(packet_l2(pkt_check), packet_l2_len(pkt_check));
			op_monitor_decode(packet_l2(pkt_check), packet_l2_len(pkt_check));
#endif
			return -1; // timeout
		}

		/* Our timeout is based on sec, so a polling interval of 0.x is better. */
		tv.tv_sec  = 0;
		tv.tv_usec = 300000; // 0.3 sec

		FD_SET(ph->fd, &rfds);
		ret = select(ph->fd + 1, &rfds, NULL, NULL, &tv);

		if (ret < 0)
		{
			ERR("Get an error code %d by select", ret);
			return -1;
		}
		else if (ret)
		{
			if (__packet_handle_recv(ph, pb) < 0)
			{
				return -1;
			}

			packet_decode_l2eth(pb);

			/*
			 * * TODO: Compare with intelligent so that we know packet is dropped or modified.
			 */
			if (cmp_packet_l2eth(pb, pkt_check) == 0)
			{
				return 0;
			}
			else
			{
#if CONFIG_DEBUG_UNEXPECTED_RX
				WARN("Recv an unexpected packet:");
				if (packet_check_attr(pkt_check, PACKET_ATTR_FRAG))
				{
					WARN("This's an ip frag");
				}
				hexdump(packet_l2(pb), packet_l2_len(pb));
				op_monitor_decode(packet_l2(pb), packet_l2_len(pb));
#endif
			}
		}
		else
		{
			// timeout, continue
			PRT_NONL(".");
		}
	}

	BUG_ON(1);
	return -1;
}

int packet_handle_recv_l2eth(packet_handle_t *ph, packet_t *pb, unsigned int timeout)
{
	long ts_start;

	fd_set rfds;
	struct timeval tv;
	int ret;

	FD_ZERO(&rfds);
	ts_start = tm_uptime();

	while (1)
	{
		if (timeout && tm_uptime() > (ts_start + timeout))
		{
			PRT_NONL("...timeout\n");
			return -1; // timeout
		}

		/* Our timeout is based on sec, so a polling interval of 0.x is better. */
		tv.tv_sec  = 0;
		tv.tv_usec = 300000; // 0.3 sec

		FD_SET(ph->fd, &rfds);
		ret = select(ph->fd + 1, &rfds, NULL, NULL, &tv);

		if (ret < 0)
		{
			ERR("Get an error code %d by select", ret);
			return -1;
		}
		else if (ret)
		{
			return __packet_handle_recv(ph, pb);
		}
		else
		{
			// timeout, continue
			PRT_NONL(".");
		}
	}

	BUG_ON(1);
	return -1;
}

int packet_handle_send_l2eth(packet_handle_t *ph, packet_t *pkt)
{
	int res;
	struct sockaddr_ll sa_ll;

	memset(&sa_ll, 0x00, sizeof(sa_ll));

	/* Index of the network device */
	sa_ll.sll_ifindex = ph->if_idx.ifr_ifindex;

	/* Address length*/
	sa_ll.sll_halen = ETH_ALEN;

	/* Copy Destination MAC from packet */
	{
		struct ether_header *eth = (struct ether_header *) packet_l2(pkt);

		/* Destination MAC for kernel */
		net_copy_eth(sa_ll.sll_addr, eth->ether_dhost);
	}

	res = sendto(ph->fd,
		packet_l2(pkt), packet_l2_len(pkt),
		0, (struct sockaddr *) &sa_ll /* Keep compiler happy. */, sizeof(sa_ll));
	if (res < 0)
	{
		ERR("Cannot send a packet %u. %s", packet_l2_len(pkt), strerror(errno));
	}
	else
	{
		VBS("  --> Send %5u (%s)",
			packet_l2_len(pkt), ph->dev_name);
	}

	return res;
}

static int open_socket_fd(int eth_type)
{
	int fd;

	fd = socket(PF_PACKET, SOCK_RAW, htons(eth_type));
	if (fd < 0)
	{
		ERR("Cannot create socket %s with type 0x%04x",
			strerror(errno), eth_type);
		return -1;
	}

	VBS("Open socket fd %d with type 0x%04x", fd, eth_type);
	return fd;
}

static void close_socket_fd(int fd)
{
	if (fd >= 0)
	{
		VBS("Close sock fd %d", fd);
		close(fd);
	}
}

void packet_handle_exit(packet_handle_t *ph)
{
	/* fd */
	close_socket_fd(ph->fd);
	ph->fd = -1;

	/* ifr */
}

static int __packet_handle_init(packet_handle_t *ph, const char *dev_name, const int eth_type)
{
	/* fd */
	ph->fd = open_socket_fd(eth_type);
	if (ph->fd < 0)
	{
		return -1;
	}

	{
		struct ifreq ifopts;

		strncpy(ifopts.ifr_name, dev_name, IFNAMSIZ - 1);
		if (ioctl(ph->fd, SIOCGIFFLAGS, &ifopts) < 0)
		{
			ERR("Cannot do ioctl SIOCGIFFLAGS at fd %d %s",
				ph->fd, strerror(errno));
			goto ERROR;
		}

		ifopts.ifr_flags |= IFF_PROMISC;
		if (ioctl(ph->fd, SIOCSIFFLAGS, &ifopts) < 0)
		{
			ERR("Cannot do ioctl SIOCSIFFLAGS at fd %d %s",
				ph->fd, strerror(errno));
			goto ERROR;
		}
	}

	/* Allow the socket to be reused - incase connection is closed prematurely */
	VBS("Try SO_REUSEADDR at '%s'", dev_name);
	{
		int sockopt = 1; // enable
		if (setsockopt(ph->fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
		{
			ERR("Cannot set socket option (reuse addr) at fd %d %s",
				ph->fd, strerror(errno));
			goto ERROR;
		}
	}

	VBS("Try SO_BINDTODEVICE at '%s'", dev_name);
	if (setsockopt(ph->fd, SOL_SOCKET, SO_BINDTODEVICE, dev_name, strlen(dev_name) + 1) < 0)
	{
		ERR("Cannot set socket option (bind dev) at fd %d %s", ph->fd, strerror(errno));
		goto ERROR;
	}

	{
		struct sockaddr_ll sa;

		memset(&sa, 0x00, sizeof(sa));
		sa.sll_family   = PF_PACKET;
		sa.sll_protocol = htons(eth_type);
		sa.sll_ifindex  = if_nametoindex(dev_name);

		if (bind(ph->fd, (struct sockaddr*) &sa, sizeof(sa)) < 0)
		{
			ERR("Cannot bind dev at fd %d %s",
				ph->fd, strerror(errno));
			goto ERROR;
		}

		DBG("...Bind '%s' (idx %d) by fd %d", dev_name, sa.sll_ifindex, ph->fd);
	}


	/* ifr */
	if (net_do_ifreq(dev_name, &ph->if_idx, NET_DO_IFREQ_IFINDEX) < 0)
	{
		goto ERROR;
	}

	if (net_do_ifreq(dev_name, &ph->if_hwaddr, NET_DO_IFREQ_HWADDR) < 0)
	{
		goto ERROR;
	}

	/* Save dev name to debug */
	snprintf(ph->dev_name, sizeof(ph->dev_name), "%s", dev_name);

	/* hook list */
	INIT_LIST_HEAD(&ph->list_hook);

	/* pool */
	ph->pkt_pool = NULL;

	return 0;
ERROR:
	packet_handle_exit(ph);
	return -1;
}

int packet_handle_init_arp(packet_handle_t *ph, const char *dev_name)
{
	return __packet_handle_init(ph, dev_name, ETH_P_ARP);
}

int packet_handle_init(packet_handle_t *ph, const char *dev_name)
{
	return __packet_handle_init(ph, dev_name, ETH_P_ALL);
}
