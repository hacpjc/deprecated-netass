#ifndef SRC_PACKET_PACKET_BUF_H_
#define SRC_PACKET_PACKET_BUF_H_

#include <stdint.h>
#include <assert.h>

#include "common.h"
#include "list.h"

#define PACKET_PRIVATE_HDR_SIZE (128) // Can't be 0
#define PACKET_MAX_FRAME_SIZE   (9512)

/*
 * pkt
 * +----------+----------------------+------
 * | priv hdr |   L2 frame (eth)     | L3
 * +----------+----------------------+---------
 *            ^                      ^
 *            |                      |
 *           L2 eth                  L3
 */
typedef struct packet
{
	/*
	 * Payload
	 */
	uint8_t pay[PACKET_PRIVATE_HDR_SIZE + PACKET_MAX_FRAME_SIZE];
	uint32_t pay_len;
	uint32_t pay_off;

	uint16_t l2;
	uint16_t l3;

	uint16_t l4;
	uint16_t l7;

	/*
	 * Cache
	 */
	void *vlan;
	uint16_t attr;
	uint16_t ether_type; /* Save right most ether type in host order (Remove VLAN) */

	/*
	 * Internal
	 */
	int ref_cnt;

	struct list_head list_child;
	struct list_head list;

	struct
	{
		void *pool; /* packet handle (pool) */
	} carry;
} packet_t;

#define PACKET_ATTR_NONE (0x0000)
#define PACKET_ATTR_VLAN (1 << 0) //!< VLAN inside
#define PACKET_ATTR_FRAG (1 << 1) //!< IP4/IP6 fragment
#define PACKET_ATTR_ANO  (1 << 2) //!< Anomaly

#define packet_set_attr(_pkt, _attr) do { (_pkt)->attr = (_attr); } while (0)
#define packet_get_attr(_pkt) ((_pkt)->attr)
#define packet_add_attr(_pkt, _attr) do { (_pkt)->attr |= (_attr); } while (0)
#define packet_del_attr(_pkt, _attr) do { (_pkt)->attr &= (~(_attr)); } while (0)
#define packet_check_attr(_pkt, _attr) (((_pkt->attr) & (_attr)) == (_attr))
#define packet_init_attr(__pkt) packet_set_attr(__pkt, PACKET_ATTR_NONE)

static void packet_inc_ref(packet_t *pkt)
{
	pkt->ref_cnt++;
}

static inline int packet_dec_ref_and_test(packet_t *pkt)
{
	pkt->ref_cnt--;
	BUG_ON(pkt->ref_cnt < 0);

	if (pkt->ref_cnt == 0)
	{
		return 0; // true
	}

	return (-1); // false
}

#define packet_get_len(_pkt) (_pkt)->pay_len
#define packet_get_left_len(_pkt) (PACKET_MAX_FRAME_SIZE - _pkt->pay_len)

static inline void packet_reset_payload(packet_t *pkt)
{
	pkt->pay_len = 0;
	pkt->pay_off = PACKET_PRIVATE_HDR_SIZE;

	pkt->l2 = 0;
	pkt->l3 = 0;
	pkt->l4 = 0;
	pkt->l7 = 0;

	packet_init_attr(pkt);
}

static inline void packet_init(packet_t *pkt)
{
	packet_reset_payload(pkt);

	pkt->ref_cnt = 0;

	INIT_LIST_HEAD(&pkt->list_child);
	INIT_LIST_HEAD(&pkt->list);

	/*
	 * carry
	 */
	memset(&pkt->carry, 0x00, sizeof(pkt->carry));
}

static inline void packet_exit(packet_t *pkt)
{
	list_del_init(&pkt->list);
}

static inline int packet_try_pull(packet_t *pkt, unsigned int len)
{
	unsigned int used_len = pkt->pay_off - PACKET_PRIVATE_HDR_SIZE;

	if (used_len + len <= pkt->pay_len)
	{
		return 0; // Safe to pull
	}

	return -1; // Not enough to pull.
}

static inline void *packet_pull(packet_t *pkt, unsigned int len)
{
	if (pkt->pay_off + len > sizeof(pkt->pay))
	{
		ERR("Cannot pull packet %u (off %u / %d) bytes",
			len, pkt->pay_off, sizeof(pkt->pay));
		return NULL;
	}

	pkt->pay_off += len;
	return (uint8_t *) (pkt->pay + pkt->pay_off);
}

static inline uint8_t *packet_push(packet_t *pkt, unsigned int len)
{
	if (pkt->pay_off < len)
	{
		ERR("Cannot push packet %u (off %u / %u) bytes",
			len, pkt->pay_off, sizeof(pkt->pay));
		return NULL;
	}

	pkt->pay_off -= len;
	return (uint8_t *) (pkt->pay + pkt->pay_off);
}

static inline uint8_t *packet_l2(packet_t *pkt)
{
	if (pkt->l2 == 0)
	{
		return NULL;
	}

	return (uint8_t *) (pkt->pay + pkt->l2);
}

static inline uint8_t *packet_set_l2(packet_t *pkt)
{
	pkt->l2 = pkt->pay_off;
	return packet_l2(pkt);
}

static inline uint8_t *packet_l3(packet_t *pkt)
{
	if (pkt->l3 == 0)
	{
		return NULL;
	}

	return (uint8_t *) (pkt->pay + pkt->l3);
}

static inline uint8_t *packet_set_l3(packet_t *pkt)
{
	pkt->l3 = pkt->pay_off;
	return packet_l3(pkt);
}

static inline uint8_t *packet_l4(packet_t *pkt)
{
	if (pkt->l4 == 0)
	{
		return NULL;
	}

	return (uint8_t *) (pkt->pay + pkt->l4);
}

static inline uint8_t *packet_set_l4(packet_t *pkt)
{
	pkt->l4 = pkt->pay_off;
	return packet_l4(pkt);
}

static inline uint8_t *packet_l7(packet_t *pkt)
{
	if (pkt->l7 == 0)
	{
		return NULL;
	}

	return (uint8_t *) (pkt->pay + pkt->l7);
}

static inline uint8_t *packet_set_l7(packet_t *pkt)
{
	pkt->l7 = pkt->pay_off;

	return packet_l7(pkt);
}

static inline int packet_append(packet_t *pkt, uint32_t len)
{
	if (pkt->pay_len + len > PACKET_MAX_FRAME_SIZE)
	{
		ERR("Cannot append a packet %u bytes. (%u / %d)",
			len, pkt->pay_len, PACKET_MAX_FRAME_SIZE);
		return -1;
	}

	pkt->pay_len += len;

	return 0;
}

static inline uint32_t packet_l2_len(packet_t *pkt)
{
	return pkt->pay_len - (pkt->l2 - PACKET_PRIVATE_HDR_SIZE);
}

static inline uint32_t packet_l3_len(packet_t *pkt)
{
	return pkt->pay_len - (pkt->l3 - PACKET_PRIVATE_HDR_SIZE);
}

static inline uint32_t packet_l4_len(packet_t *pkt)
{
	return pkt->pay_len - (pkt->l4 - PACKET_PRIVATE_HDR_SIZE);
}

static inline uint32_t packet_l2h_len(packet_t *pkt)
{
	if (pkt->l3)
	{
		return pkt->l3 - pkt->l2;
	}
	else
	{
		BUG_ON(1);
	}

	return 0;
}

static inline uint32_t packet_l3h_len(packet_t *pkt)
{
	if (pkt->l4)
	{
		return pkt->l4 - pkt->l3;
	}
	else if (pkt->l7)
	{
		/* Don't have l4 hdr. Use l7 instead. */
		return pkt->l7 - pkt->l3;
	}
	else
	{
		BUG_ON(1);
	}

	return 0;
}

static inline uint32_t packet_l4h_len(packet_t *pkt)
{
	if (pkt->l7)
	{
		return pkt->l7 - pkt->l3;
	}
	else
	{
		BUG_ON(1);
	}

	return 0;
}

static inline void packet_add_child(packet_t *mom, packet_t *child)
{
	list_add_tail(&child->list, &mom->list_child);
}

#endif /* SRC_PACKET_PACKET_BUF_H_ */
