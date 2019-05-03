#include "common.h"

#include "ctk/ctk.h"

static inline unsigned int get_hash_idx_ip4(
	unsigned int hash_max,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
#define IP4NUM(_ip4) *((const uint32_t *) _ip4)
	return (((IP4NUM(sip) * sport) + (IP4NUM(dip) * dport)) * proto) % hash_max;
}

static inline unsigned int get_hash_idx_ip6(
	unsigned int hash_max,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
#define IP6NUM(_ip6) *((const uint32_t *) (((const uint8_t *) _ip6) + 12))
	return (((IP6NUM(sip) * sport) + (IP6NUM(dip) * dport)) * proto) % hash_max;
}

static int cmp_entry_ip4(ctk_entry_t *e,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
	if (ctk_entry_proto(e) == proto)
	{
		if	(ctk_entry_sport(e) == sport &&
			ctk_entry_dport(e) == dport &&
			memcmp(ctk_entry_sip4(e), sip, 4) == 0 &&
			memcmp(ctk_entry_dip4(e), dip, 4) == 0)
		{
			return 0;
		}

		if	(ctk_entry_sport(e) == dport &&
			ctk_entry_dport(e) == sport &&
			memcmp(ctk_entry_sip4(e), dip, 4) == 0 &&
			memcmp(ctk_entry_dip4(e), sip, 4) == 0)
		{
			return 0;
		}
	}

	return -1;
}

ctk_entry_t *ctk_search_entry_ip4(ctk_t *ctk,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
	unsigned int hash_idx;
	ctk_entry_t *this;

	hash_idx = get_hash_idx_ip4(ctk->hash_tbl_max, proto, sip, dip, sport, dport);

	list_for_each_entry(this, &(ctk->hash_tbl[hash_idx]), list)
	{
		if (cmp_entry_ip4(this, proto, sip, dip, sport, dport) == 0)
		{
			return this;
		}
	}

	return NULL;
}

static int cmp_entry_ip6(ctk_entry_t *e,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
	if (ctk_entry_proto(e) == proto)
	{
		if	(ctk_entry_sport(e) == sport &&
			ctk_entry_dport(e) == dport &&
			memcmp(ctk_entry_sip6(e), sip, 16) == 0 &&
			memcmp(ctk_entry_dip6(e), dip, 16) == 0)
		{
			return 0;
		}

		if	(ctk_entry_sport(e) == dport &&
			ctk_entry_dport(e) == sport &&
			memcmp(ctk_entry_sip6(e), dip, 16) == 0 &&
			memcmp(ctk_entry_dip6(e), sip, 16) == 0)
		{
			return 0;
		}
	}

	return -1;
}

ctk_entry_t *ctk_search_entry_ip6(ctk_t *ctk,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
	unsigned int hash_idx;
	ctk_entry_t *this;

	hash_idx = get_hash_idx_ip6(ctk->hash_tbl_max, proto, sip, dip, sport, dport);

	list_for_each_entry(this, &(ctk->hash_tbl[hash_idx]), list)
	{
		if (cmp_entry_ip6(this, proto, sip, dip, sport, dport) == 0)
		{
			return this;
		}
	}

	return NULL;
}

ctk_entry_t *ctk_search_entry(ctk_t *ctk,
	uint8_t ip_ver,
	uint8_t proto,
	const uint8_t *sip, const uint8_t *dip, uint16_t sport, uint16_t dport)
{
	ctk_entry_t *e = NULL;

	switch (ip_ver)
	{
	case 4:
		return ctk_search_entry_ip4(ctk, proto, sip, dip, sport, dport);
	case 6:
		return ctk_search_entry_ip6(ctk, proto, sip, dip, sport, dport);
	default:
		WARN("Invalid IP version %u", ip_ver);
		break;
	}

	return e;
}

static void init_ctk(ctk_t *ctk)
{
	memset(ctk, 0x00, sizeof(*ctk));

	INIT_LIST_HEAD(&ctk->list_free);
	INIT_LIST_HEAD(&ctk->list_lru);
}

void ctk_free(ctk_t *ctk)
{
	if (ctk->hash_tbl)
	{
		free(ctk->hash_tbl);
	}

	if (ctk->tbl)
	{
		free(ctk->tbl);
	}

	free(ctk);
}

ctk_t *ctk_alloc(unsigned int tbl_max, unsigned int hash_tbl_max, unsigned int timeout)
{
	ctk_t *ctk;
	unsigned int nbytes;

	BUG_ON(tbl_max == 0 || hash_tbl_max == 0);

	ctk = malloc(sizeof(*ctk));
	if (ctk == NULL)
	{
		ERR("Cannot alloc ctk handle %d bytes. %s", sizeof(*ctk), strerror(errno));
		return NULL;
	}
	else
	{
		VBS("Alloc ctk handle %d bytes", sizeof(*ctk));
	}

	init_ctk(ctk);

	ctk->tbl_max = tbl_max;
	nbytes = sizeof(ctk->tbl[0]) * ctk->tbl_max;
	ctk->tbl = malloc(nbytes);
	if (!ctk->tbl)
	{
		ERR("Cannot alloc ctk handle %d bytes. %s",
			nbytes, strerror(errno));
		goto ERROR;
	}
	else
	{
		VBS("Alloc ctk tbl %u bytes", nbytes);
	}

	ctk->hash_tbl_max = hash_tbl_max;
	nbytes = sizeof(ctk->hash_tbl[0]) * ctk->hash_tbl_max;
	ctk->hash_tbl = malloc(nbytes);
	if (!ctk->hash_tbl)
	{
		ERR("Cannot alloc ctk handle %d bytes. %s",
			nbytes, strerror(errno));
		goto ERROR;
	}
	else
	{
		VBS("Alloc ctk hash tbl %u bytes", nbytes);
	}

	ctk->timeout = timeout;
	VBS("Configure ctk timeout to %u sec", ctk->timeout);

	return ctk;

ERROR:
	ctk_free(ctk);
	return NULL;
}
