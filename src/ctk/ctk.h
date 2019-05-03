#ifndef SRC_CTK_CTK_H_
#define SRC_CTK_CTK_H_

#include "common.h"
#include "list.h"
#include "tm.h"

typedef uint8_t ip4addr_t [4];
typedef uint8_t ip6addr_t [16];

typedef struct ctk_tuple
{
	uint8_t ver;
	uint8_t proto;
	uint8_t rsv[2];

	union
	{
		ip4addr_t sip4;
		ip6addr_t sip6;
		ip6addr_t sip;
	};

	union
	{
		ip4addr_t dip4;
		ip6addr_t dip6;
		ip6addr_t dip;
	};

	uint16_t sport;
	uint16_t dport;
} ctk_tuple_t;

typedef struct ctk_entry
{
	ctk_tuple_t tuple;

	uint64_t ts;
	uint64_t ts_create;

	struct list_head list;
	struct list_head list_lru;
} ctk_entry_t;

#define ctk_entry_sip4(_e)  ((uint8_t *) ((_e)->tuple.sip4))
#define ctk_entry_dip4(_e)  ((uint8_t *) ((_e)->tuple.dip4))
#define ctk_entry_sip6(_e)  ((uint8_t *) ((_e)->tuple.sip6))
#define ctk_entry_dip6(_e)  ((uint8_t *) ((_e)->tuple.dip6))
#define ctk_entry_proto(_e) (_e)->tuple.proto
#define ctk_entry_sport(_e) (_e)->tuple.sport
#define ctk_entry_dport(_e) (_e)->tuple.dport

typedef struct ctk
{
	unsigned int timeout;

	struct list_head *hash_tbl;
	unsigned int hash_tbl_max;

	ctk_entry_t *tbl;
	unsigned int tbl_max;

	struct list_head list_free;
	struct list_head list_lru;
} ctk_t;

#endif /* SRC_CTK_CTK_H_ */
