#ifndef SRC_CONF_LCONF_H_
#define SRC_CONF_LCONF_H_

#include "common.h"
#include "conf/conf.h"

#define LCONF_GET_UINT(_sym_name) conf_get_sym_uint(_sym_name)
#define LCONF_GET_INT(_sym_name)  conf_get_sym_int(_sym_name)

#define LCONF_GET_SYM(_obj, _sym_name) \
	do { \
		(_obj) = conf_get_sym_obj(_sym_name); \
		if ((_obj) == NULL) \
		{ \
			return -1; \
		} \
	} while (0)

#define LCONF_GET_STR(_str, _sym_name) \
	do { \
		(_str) = conf_get_sym_str(_sym_name); \
		if ((_str) == NULL) \
		{ \
			return -1; \
		} \
	} while (0)

#define LCONF_GET_STR_FROM_PARENT(_str, _sym_name, _parent) \
	do { \
		(_str) = conf_get_sym_str(_parent CONF_DELIM _sym_name); \
		if ((_str) == NULL) \
		{ \
			return -1; \
		} \
	} while (0)

#define LCONF_GET_INT_FROM_PARENT(_sym_name, _parent) \
	(conf_get_sym_int(_parent CONF_DELIM _sym_name))

#define LCONF_GET_UINT_FROM_PARENT(_sym_name, _parent) \
	(conf_get_sym_uint(_parent CONF_DELIM _sym_name))

#define LCONF_FORBID_EMPTY_STR(_sym) do { assert(_sym != NULL && strlen(_sym) > 0); } while (0)

#endif /* SRC_CONF_LCONF_H_ */
