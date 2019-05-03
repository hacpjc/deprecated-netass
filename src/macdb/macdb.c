#include "common.h"
#include "list.h"
#include "tm.h"
#include "net.h"
#include "conf/lconf.h"

#include "macdb.h"

#define MACDB_COPY_MAC(_dst, _src) \
	do { \
		((uint16_t *) _dst)[0] = ((uint16_t *) _src)[0]; \
		((uint16_t *) _dst)[1] = ((uint16_t *) _src)[1]; \
		((uint16_t *) _dst)[2] = ((uint16_t *) _src)[2]; \
	} while (0)

#define MACDB_MAC_EQUAL(_l, _r) \
	(\
		(((uint16_t *) (_l))[0] == ((uint16_t *) (_r))[0]) && \
		(((uint16_t *) (_l))[1] == ((uint16_t *) (_r))[1]) && \
		(((uint16_t *) (_l))[2] == ((uint16_t *) (_r))[2]) \
	)

static inline unsigned int get_hash_idx(uint16_t *mac, unsigned int hash_tbl_max)
{
	unsigned int sum = 0;

	sum = (mac[0] * mac[1]) + mac[2];

	return sum % hash_tbl_max;
}

static void __update_macdb_node_tick(macdb_t *db, macdb_node_t *node)
{
	node->ts = tm_uptime();

	list_move_tail(&(node->list_lru), &(db->list_lru)); // Move new node to tail
}

static void __free_macdb_node(macdb_t *db, macdb_node_t *node)
{
	list_move(&(node->list), &(db->list_free));
	list_del_init(&(node->list_lru));
}

static macdb_node_t *__alloc_macdb_node(macdb_t *db, uint8_t *mac)
{
	macdb_node_t *node;
	unsigned int hash_idx;

	if (list_empty(&(db->list_free)))
	{
		return NULL;
	}

	node = list_first_entry(&(db->list_free), macdb_node_t, list);

	MACDB_COPY_MAC(node->mac, mac);

	node->ts_create = tm_uptime();
	node->ts        = node->ts_create;

	hash_idx = get_hash_idx((uint16_t *) node->mac, db->hash_tbl_max);
	list_move(&(node->list), &(db->hash_tbl[hash_idx]));

	list_add_tail(&(node->list_lru), &(db->list_lru)); // Keep new nodes at tail.

	/* Carry */
	memset(&node->carry, 0x00, sizeof(node->carry));
	return node;
}

static void __remove_expired_macdb_node(macdb_t *db)
{
	uint64_t ts_now = (uint64_t) tm_uptime();
	macdb_node_t *node, *node_save;

	list_for_each_entry_safe(node, node_save, &(db->list_lru), list_lru)
	{
		if ((node->ts + db->timeout_sec) < ts_now)
		{
			VBS("Remove macdb node " MAC_OCTET_FMT " life=%u",
				MAC_OCTET_EXPAND(node->mac), ts_now - node->ts_create);
			__free_macdb_node(db, node);
		}
	}
}

macdb_node_t *search_node(struct list_head *hash_head, uint8_t *mac)
{
	macdb_node_t *node;

	list_for_each_entry(node, hash_head, list)
	{
		if (MACDB_MAC_EQUAL(mac, node->mac))
		{
			return node;
		}
	}

	return NULL;
}

macdb_node_t *macdb_search(macdb_t *db, uint8_t *mac)
{
	unsigned int hash_idx;
	macdb_node_t *node;

	BUG_ON(db == NULL || mac == NULL);

	hash_idx = get_hash_idx((uint16_t *) mac, db->hash_tbl_max);
	node = search_node(&(db->hash_tbl[hash_idx]), mac);

	return node;
}

int macdb_operate(macdb_t *db, const macdb_operate_flag_t flag,
	uint8_t *mac, macdb_operate_cb_t cb, void *priv)
{
	unsigned int hash_idx;
	macdb_node_t *node;

	BUG_ON(db == NULL || mac == NULL);

	hash_idx = get_hash_idx((uint16_t *) mac, db->hash_tbl_max);
	node = search_node(&(db->hash_tbl[hash_idx]), mac);
	if (node == NULL)
	{
		if (!(flag & MACDB_OPERATE_FLAG_ALLOC))
		{
			/* Not found. Give up. */
			return -1;
		}

		/* Create new node since ALLOC flag is set. */
		node = __alloc_macdb_node(db, mac);
		if (node == NULL)
		{
			/* Remove expired nodes and try again. */
			__remove_expired_macdb_node(db);

			node = __alloc_macdb_node(db, mac);
			if (node == NULL)
			{
				ERR("Run out of macdb nodes (max %u)", db->node_pool_max);
				return -1;
			}
		}

		VBS("Create new macdb node " MAC_OCTET_FMT, MAC_OCTET_EXPAND(mac));
	}

	if (cb(node, priv) < 0)
	{
		/* Revmoe node if func returns negative. */
		__free_macdb_node(db, node);

		/* Remove expired nodes */
		__remove_expired_macdb_node(db);

		return 0;
	}

	/* Keep node alive */
	__update_macdb_node_tick(db, node);

	/* Remove expired nodes */
	__remove_expired_macdb_node(db);

	return 0;
}

static void __dump_macdb_node(macdb_node_t *node)
{
	PRT(" * mac " MAC_OCTET_FMT ", ts=%llu, create=%llu",
		MAC_OCTET_EXPAND(node->mac), node->ts, node->ts_create);
}

void macdb_dump(macdb_t *db)
{
	macdb_node_t *node;

	list_for_each_entry(node, &(db->list_lru), list_lru)
	{
		__dump_macdb_node(node);
	}
}

static void init_macdb(macdb_t *db)
{
	memset(db, 0x00, sizeof(*db));

	INIT_LIST_HEAD(&(db->list_free));
	INIT_LIST_HEAD(&(db->list_lru));
}

void macdb_free(macdb_t *db)
{
	if (db->node_pool)
	{
		VBS("Free macdb node pool at %p", db->node_pool);
		free(db->node_pool);
	}

	if (db->hash_tbl)
	{
		VBS("Free macdb hash tbl at %p", db->hash_tbl);
		free(db->hash_tbl);
	}

	VBS("Free macdb %p", db);
	free(db);
}

macdb_t *macdb_alloc(unsigned int pool_size, unsigned int hash_size,
	unsigned int timeout_sec)
{
	macdb_t *db;

	db = malloc(sizeof(*db));
	if (!db)
	{
		ERR("Cannot malloc db handle %d bytes", sizeof(*db));
		return NULL;
	}

	init_macdb(db);

	/* alloc tbl */
	db->node_pool_max = pool_size;
	db->hash_tbl_max  = hash_size;
	BUG_ON(db->node_pool_max == 0 || db->hash_tbl_max == 0);

	VBS("Alloc macdb: pool=%u hash=%u timeout=%u",
		db->node_pool_max, db->hash_tbl_max, timeout_sec);

	{
		int i;
		int nbytes;

		macdb_node_t *node;

		nbytes = sizeof(db->node_pool[0]) * db->node_pool_max;
		db->node_pool = (macdb_node_t *) malloc(nbytes);
		if (!db->node_pool)
		{
			goto ERROR;
		}
		VBS("Alloc node pool %d bytes at %p", nbytes, db->node_pool);

		for (i = 0; i < db->node_pool_max; i++)
		{
			node = &(db->node_pool[i]);
			list_add_tail(&(node->list), &(db->list_free));
			INIT_LIST_HEAD(&(node->list_lru));
		}

		nbytes = sizeof(db->hash_tbl[0]) * db->hash_tbl_max;
		db->hash_tbl = (struct list_head *) malloc(nbytes);
		if (!db->hash_tbl)
		{
			goto ERROR;
		}
		VBS("Alloc hash tbl %d bytes at %p", nbytes, db->hash_tbl);

		for (i = 0; i < db->hash_tbl_max; i++)
		{
			INIT_LIST_HEAD(&(db->hash_tbl[i]));
		}
	}

	/* Configure timeout */
	db->timeout_sec = timeout_sec;
	VBS("Configure timeout to %u",
		db->timeout_sec);

	return db;

ERROR:
	if (db)
	{
		macdb_free(db);
	}

	return db;
}

macdb_t *macdb_alloc_by_conf(const void *conf_root)
{
	macdb_t *db = NULL;

	unsigned int node_pool_max, hash_tbl_max, timeout_sec;

	/*
	 * \todo Fix SEGV if input is wrong.
	 */
	node_pool_max = atoi(conf_get_sym_str_from_root("node_pool_max", conf_root));
	hash_tbl_max = atoi(conf_get_sym_str_from_root("hash_tbl_max", conf_root));
	timeout_sec = atoi(conf_get_sym_str_from_root("timeout_sec", conf_root));

	return macdb_alloc(node_pool_max, hash_tbl_max, timeout_sec);

ERROR:
	if (db)
	{
		macdb_free(db);
	}

	return NULL;
}
