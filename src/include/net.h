#ifndef SRC_INCLUDE_NET_H_
#define SRC_INCLUDE_NET_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>

#include <sys/ioctl.h>
#include <bits/ioctls.h>

#include "common.h"

#define MAC_OCTET_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_OCTET_EXPAND(o) ((uint8_t) o[0]), ((uint8_t) o[1]), ((uint8_t) o[2]), ((uint8_t) o[3]), ((uint8_t) o[4]), ((uint8_t) o[5])
#define IPV4_OCTET_FMT "%u.%u.%u.%u"
#define IPV4_OCTET_EXPAND(o) (uint8_t) o[0], (uint8_t) o[1], (uint8_t) o[2], (uint8_t) o[3]

#define IPV6_OCTET_FMT "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X"
#define IPV6_OCTET_EXPAND(o) \
	(uint8_t) o[0], (uint8_t) o[1], (uint8_t) o[2], (uint8_t) o[3], \
	(uint8_t) o[4], (uint8_t) o[5], (uint8_t) o[6], (uint8_t) o[7], \
	(uint8_t) o[8], (uint8_t) o[9], (uint8_t) o[10], (uint8_t) o[11], \
	(uint8_t) o[12], (uint8_t) o[13], (uint8_t) o[14], (uint8_t) o[15]

#define net_cmp_mac(_l, _r) \
	!(\
		(((uint16_t *) (_l))[0] == ((uint16_t *) (_r))[0]) && \
		(((uint16_t *) (_l))[1] == ((uint16_t *) (_r))[1]) && \
		(((uint16_t *) (_l))[2] == ((uint16_t *) (_r))[2]) \
	)

static unsigned short net_calc_cksum_udp(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short) (~sum);
}

#define NET_DO_IFREQ_HWADDR  SIOCGIFHWADDR
#define NET_DO_IFREQ_IFINDEX SIOCGIFINDEX

static int net_do_ifreq(const char *dev_name, struct ifreq *ifr, int command)
{
	int sd;

	BUG_ON(ifr == NULL);

	if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		ERR("Cannot open socket to lookup dev '%s' mac. %s",
			dev_name, strerror(errno));
		return -1;
	}

	memset(ifr, 0x00, sizeof(*ifr));
	snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", dev_name);
	if (ioctl(sd, command, ifr) < 0)
	{
		ERR("Cannot do ioctl to get dev '%s' mac. %s",
			dev_name, strerror(errno));
		return -1;
	}

#if CONFIG_DEBUG_MODE
	switch (command)
	{
	case NET_DO_IFREQ_HWADDR:
		if (ifr->ifr_hwaddr.sa_family != 1 /* ARPHRD_ETHER - ethernet */)
		{
			ERR("Input dev (family %d) is not a ether device",
				ifr->ifr_hwaddr.sa_family);
			close(sd);
			return -1;
		}

		DBG("Get dev '%s' mac: " MAC_OCTET_FMT,
			dev_name, MAC_OCTET_EXPAND((ifr->ifr_hwaddr.sa_data)));
		break;
	case NET_DO_IFREQ_IFINDEX:
		DBG("Get dev '%s' idx: %d", dev_name, ifr->ifr_ifindex);
		break;
	default:
		ERR("Unknow command %d", command);
		break;
	}
#endif

	close(sd);
	return 0;
}

static inline void net_copy_ip(void *dst, const void *src, const uint8_t ip_ver)
{
#define GET_UINT32P(_p) ((uint32_t *) _p)

	switch (ip_ver)
	{
	case 4:
		*GET_UINT32P(dst) = *GET_UINT32P(src);
		break;
	case 6:
		GET_UINT32P(dst)[0] = GET_UINT32P(src)[0];
		GET_UINT32P(dst)[1] = GET_UINT32P(src)[1];
		GET_UINT32P(dst)[2] = GET_UINT32P(src)[2];
		GET_UINT32P(dst)[3] = GET_UINT32P(src)[3];
		break;
	default:
		ERR("Unknown ip version %u", ip_ver);
		break;
	}
}

static inline void net_copy_eth(void *dst, const void *src)
{
	((uint32_t *) dst)[0] = ((uint32_t *) src)[0];
	((uint16_t *) dst)[2] = ((uint16_t *) src)[2];
}

/**
 * @internal Calculate a sum of all words in the buffer.
 * Helper routine for the rte_raw_cksum().
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @param sum
 *   Initial value of the sum.
 * @return
 *   sum += Sum of all words in the buffer.
 */
static inline uint32_t
__net_raw_cksum(const void *buf, size_t len, uint32_t sum)
{
	uint32_t *ptr = (uint32_t *) buf;
	const uint16_t *u16 = (const uint16_t *) ptr;

	while (len >= (sizeof(*u16) * 4))
	{
		sum += u16[0];
		sum += u16[1];
		sum += u16[2];
		sum += u16[3];
		len -= sizeof(*u16) * 4;
		u16 += 4;
	}
	while (len >= sizeof(*u16))
	{
		sum += *u16;
		len -= sizeof(*u16);
		u16 += 1;
	}

	/* if length is in odd bytes */
	if (len == 1)
		sum += *((const uint8_t *) u16);

	return sum;
}
/**
 * @internal Reduce a sum to the non-complemented checksum.
 * Helper routine for the rte_raw_cksum().
 *
 * @param sum
 *   Value of the sum.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
__net_raw_cksum_reduce(uint32_t sum)
{
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	return (uint16_t) sum;
}


/**
 * Process the non-complemented checksum of a buffer.
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
net_raw_cksum(const void *buf, size_t len)
{
	uint32_t sum;

	sum = __net_raw_cksum(buf, len, 0);
	return __net_raw_cksum_reduce(sum);
}

/**
 * Process the IPv4 checksum of an IPv4 header.
 *
 * The checksum field must be set to 0 by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
net_ipv4_cksum(const struct iphdr *ipv4_hdr, const unsigned int ipv4_hdr_len)
{
	uint16_t cksum;
	cksum = net_raw_cksum(ipv4_hdr, ipv4_hdr_len);
	return (cksum == 0xffff) ? cksum : ~cksum;
}

#endif /* SRC_INCLUDE_NET_H_ */
