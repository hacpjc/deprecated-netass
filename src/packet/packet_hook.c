#include "common.h"

#include "packet/packet_hook.h"

void packet_hook_dump(void)
{
	packet_hook_t **hook;

	for_each_packet_hook(hook)
	{
		PRT("hook [%p] = %s", (*hook), (*hook)->ident);
	}
}

int packet_hook_loop(packet_hook_loop_func_t cb, void *priv)
{
	packet_hook_t **hook;
	int ret = 0;

	BUG_ON(cb == NULL);
	for_each_packet_hook(hook)
	{
		ret = cb(*hook, priv);
		if (ret < 0)
		{
			WARN("Stop loop at hook '%s' with ret %d", (*hook)->ident, ret);
			break;
		}
	}

	return ret;
}

int packet_hook_init(void)
{
	packet_hook_t **hook;
	packet_hook_func_t *func;

	int ret;

	for_each_packet_hook(hook)
	{
		func = &((*hook)->func);

		if (func->cb_init == NULL)
		{
			continue;
		}

		ret = func->cb_init();
		if (ret < 0)
		{
			ERR("Cannot init packet hook '%s' (%d)", (*hook)->ident, ret);
			return -1;
		}
	}

	return 0;
}

void packet_hook_exit(void)
{
	packet_hook_t **hook;
	packet_hook_func_t *func;

	for_each_packet_hook(hook)
	{
		func = &((*hook)->func);

		if (func->cb_exit == NULL)
		{
			continue;
		}

		func->cb_exit();
	}
}

void packet_hook_free(packet_hook_t *hook)
{
	BUG_ON(hook == NULL || hook->ctx != NULL);

	list_del_init(&(hook->list));
	free(hook);
}

packet_hook_t *packet_hook_alloc(const char *ident)
{
	packet_hook_t *new_hook;

	new_hook = malloc(sizeof(*new_hook));
	if (new_hook == NULL)
	{
		return NULL;
	}

	/* Init hook */
	{
		packet_hook_t **hook;

		for_each_packet_hook(hook)
		{
			if (strcmp((*hook)->ident, ident) == 0)
			{
				memcpy(new_hook, *hook, sizeof(*new_hook));

				INIT_LIST_HEAD(&(new_hook->list));
				return new_hook;
			}
		}
	}

	ERR("Cannot find packet hook '%s'in registered list", ident);
	free(new_hook);
	return NULL;
}

