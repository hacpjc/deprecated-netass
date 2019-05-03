#ifndef SRC_INCLUDE_INIT_TBL_H_
#define SRC_INCLUDE_INIT_TBL_H_

#include "common.h"

typedef struct init_tbl_entry
{
	int (*cb_init)(void);
	void (*cb_exit)(void);

	char *name;
} init_tbl_entry_t;

#define init_tbl_get_size(_tbl) (sizeof(_tbl) / sizeof(_tbl[0]))
#define DECLARE_INIT_TBL(__name) const init_tbl_entry_t __name[] =

static int init_tbl_run_init(const init_tbl_entry_t *init_tbl, int init_tbl_size)
{
	int i;
	int (*cb_init)(void);
	void (*cb_exit)(void);

	for (i = 0; i < init_tbl_size; i++)
	{
		cb_init = init_tbl[i].cb_init;

		if (cb_init)
		{
			VBS("Run '%s' init func", init_tbl[i].name);
			if (cb_init() < 0)
			{
				ERR("Cannot run '%s' init func successfully.", init_tbl[i].name);
				goto __error;
			}
		}
	}

	return 0;

__error:
	/* exit reversely except the failed function. */
	while (--i >= 0)
	{
		cb_exit = init_tbl[i].cb_exit;

		if (cb_exit)
		{
			VBS("Run '%s' cleanup func", init_tbl[i].name);
			cb_exit();
		}
	}

	return -1;
}

static void init_tbl_run_exit(const init_tbl_entry_t *init_tbl, int init_tbl_size)
{
	int i;
	void (*cb_exit)(void);

	for (i = init_tbl_size - 1; i >= 0; i--)
	{
		cb_exit = init_tbl[i].cb_exit;

		if (cb_exit)
		{
			VBS("Run '%s' cleanup func", init_tbl[i].name);
			cb_exit();
		}
	}
}

#endif /* SRC_INCLUDE_INIT_TBL_H_ */
