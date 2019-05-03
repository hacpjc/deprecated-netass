#ifndef SRC_MACDB_MACDB_H_
#define SRC_MACDB_MACDB_H_

#include <stdint.h>

#include "common.h"
#include "list.h"

#define macdb_node_get_carry(_node) &((_node)->carry)

typedef struct macdb_node_carry
{
	void *ph;
} macdb_node_carry_t;

typedef struct macdb_node
{
	uint8_t mac[6];
	uint8_t rsv[2];

	uint64_t ts;
	uint64_t ts_create;

	struct list_head list_lru;
	struct list_head list;

	/* Carry */
	macdb_node_carry_t carry;
} macdb_node_t;

typedef struct macdb
{
	macdb_node_t *node_pool;
	unsigned int  node_pool_max;

	struct list_head *hash_tbl;
	unsigned int     hash_tbl_max;

	unsigned int timeout_sec; //!< How many sec to remove idle nodes.

	struct list_head list_lru; //!< Add new node to tail.
	struct list_head list_free;
} macdb_t;

macdb_node_t *macdb_search(macdb_t *db, uint8_t *mac);

#define MACDB_OPERATE_FLAG_NONE  (0x00)
#define MACDB_OPERATE_FLAG_ALLOC (0x01)
#define MACDB_OPERATE_FLAG_DFL   (MACDB_OPERATE_FLAG_ALLOC)
typedef uint8_t macdb_operate_flag_t;
typedef int (* macdb_operate_cb_t) (macdb_node_t *node, void *priv);
int macdb_operate(macdb_t *db, macdb_operate_flag_t flag, uint8_t *mac, macdb_operate_cb_t cb, void *priv);

void macdb_dump(macdb_t *db);
void macdb_free(macdb_t *db);
macdb_t *macdb_alloc(unsigned int pool_size, unsigned int hash_size,
	unsigned int timeout_sec);
macdb_t *macdb_alloc_by_conf(const void *conf_root);

#endif /* SRC_MACDB_MACDB_H_ */
