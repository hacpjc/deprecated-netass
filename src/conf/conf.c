#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "json-c/json.h"
#include "conf/conf.h"

static json_object *conf_jso = NULL;

static json_object *get_sym_obj(json_object *root, const char *sym)
{
	char sym_copy[255 + 1]; // Don't waste stack
	char *sym_this, *save = NULL;

	json_object *parent = root;
	json_object *child = NULL;

	snprintf(sym_copy, sizeof(sym_copy), "%s", sym);

	sym_this = strtok_r(sym_copy, CONF_DELIM, &save);
	for (; sym_this != NULL; )
	{
		if (parent == NULL)
		{
			break;
		}

		if (json_object_get_type(parent) != json_type_object)
		{
			WARN("Invalid parent obj type %d", json_object_get_type(parent));
			break;
		}

		child = json_object_object_get(parent, sym_this);

		sym_this = strtok_r(NULL, CONF_DELIM, &save);
		if (sym_this == NULL)
		{
			return child;
		}
		else
		{
			if (NULL == child)
			{
				break;
			}
			else
			{
				parent = child;
				continue;
			}
		}
	} // end for

	return NULL;
}

const void *conf_get_sym_obj(const char *sym)
{
	json_object *sym_obj;

	BUG_ON(sym == NULL);
	BUG_ON(conf_jso == NULL);

	sym_obj = get_sym_obj(conf_jso, sym);
	return sym_obj;
}

const char *conf_get_sym_str(const char *sym)
{
	json_object *sym_obj;

	sym_obj = (json_object *) conf_get_sym_obj(sym);
	if (sym_obj == NULL)
	{
		WARN("Cannot get conf obj '%s'", sym);
		return NULL;
	}

	if (json_object_get_type((json_object *) sym_obj) != json_type_string)
	{
		WARN("Invalid conf obj type %d", json_object_get_type((json_object *) sym_obj));
		return NULL;
	}

	return json_object_get_string((json_object *) sym_obj);
}

const unsigned int conf_get_sym_bool(const char *sym)
{
	const char *str = conf_get_sym_str(sym);

	if (str == NULL)
	{
		return 0;
	}

	return (unsigned int) (!!(atoi(str) != 0));
}

const unsigned int conf_get_sym_uint(const char *sym)
{
	const char *str = conf_get_sym_str(sym);

	if (str == NULL)
	{
		return 0;
	}

	return (unsigned int) atoi(str);
}

const int conf_get_sym_int(const char *sym)
{
	const char *str = conf_get_sym_str(sym);

	if (str == NULL)
	{
		return 0;
	}

	return (int) atoi(str);
}

static json_object *__conf_get_sym_obj_from_root(const char *sym, const void *conf_root)
{
	json_object *json_conf_root = (json_object *) conf_root;
	json_object *sym_obj;

	BUG_ON(sym == NULL);
	BUG_ON(json_conf_root == NULL);

	sym_obj = get_sym_obj(json_conf_root, sym);
	return sym_obj;
}

const void *conf_get_sym_obj_from_root(const char *sym, const void *conf_root)
{
	return __conf_get_sym_obj_from_root(sym, conf_root);
}

const char *conf_get_sym_str_from_root(const char *sym, const void *conf_root)
{
	json_object *sym_obj;

	sym_obj = __conf_get_sym_obj_from_root(sym, conf_root);
	if (sym_obj == NULL)
	{
		WARN("Cannot get conf obj '%s' from root %p", sym, conf_root);
		return NULL;
	}

	if (json_object_get_type((json_object *) sym_obj) != json_type_string)
	{
		WARN("Invalid conf obj type %d", json_object_get_type((json_object *) sym_obj));
		return NULL;
	}

	return json_object_get_string((json_object *) sym_obj);
}

const unsigned int conf_get_sym_bool_from_root(const char *sym, const void *conf_root)
{
	const char *str;

	str = conf_get_sym_str_from_root(sym, conf_root);
	if (str == NULL)
	{
		return 0;
	}

	return (unsigned int) (!!(atoi(str) != 0));
}

const unsigned int conf_get_sym_uint_from_root(const char *sym, const void *conf_root)
{
	const char *str;

	str = conf_get_sym_str_from_root(sym, conf_root);
	if (str == NULL)
	{
		return 0;
	}

	return (unsigned int) (atoi(str));
}

////////////////////////////////////////////////////////////////////////////////
void conf_dump(const void *conf_root)
{
	json_object *json_obj = (json_object *) conf_root;

	BUG_ON(json_obj == NULL);

	PRT("%s:\n%s",
		__FUNCTION__,
		json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY));
}

void conf_reset(void)
{
	if (conf_jso)
	{
		json_object_put(conf_jso);
		conf_jso = NULL;
	}
}

static void *alloc_file_buf_safe(const int size, int retry)
{
	void *buf;

	do
	{
		buf = malloc(size);
		if (buf)
		{
			memset(buf, 0x00, size);
			return buf;
		}
		else
		{
			WARN("Cannot alloc %d bytes to read file");
		}
	} while (retry--);

	return NULL; // Impossible.
}

static void *read_file_simple(const char *path)
{
	int fd;
	struct stat st;

	void *buf;
	int buf_len;

	fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		ERR("Cannot open file '%s' %s", path, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) < 0)
	{
		ERR("Cannot get stat of file '%s' %s", path, strerror(errno));
		return NULL;
	}

	VBS("Alloc buf to read file '%s' %d bytes", path, st.st_size);

	{
		buf_len = st.st_size + 1; // Add '\0' padding for json lib.

		buf = alloc_file_buf_safe(buf_len, 3);
		if (buf == NULL)
		{
			ERR("Cannot malloc %d bytes to read file '%s' %s",
				buf_len, path, strerror(errno));
			return NULL;
		}
	}

	{
		int off = 0;

		do
		{
			int res;

			if (off == st.st_size)
			{
				VBS("Finish reading file '%s' %d bytes", path, off);
				break;
			}

			res = read(fd, buf + off, st.st_size - off);
			if (res == 0)
			{
				ERR("Expect to read %d bytes, but there're %d bytes left",
					st.st_size, st.st_size - off);
				goto FREE_BUF; // No more? Oops, we still expect to read something.
			}
			else if (res < 0)
			{
				ERR("Cannot read file '%s' %s", path, strerror(errno));
				goto FREE_BUF;
			}

			off += res;
		} while (1);
	}

	return buf;

FREE_BUF:
	free(buf);
	return NULL;
}

static void close_file_simple(void *buf)
{
	if (buf) free(buf);
}

int conf_check_json_syntax(const char *path)
{
	json_object *jso;
	enum json_tokener_error jso_error;

	char *cont = NULL;

	cont = read_file_simple(path);

	jso = json_tokener_parse_verbose(cont, &jso_error);
	if (jso == NULL)
	{
		ERR("Cannot parse input json file %s. %s",
			path,
			json_tokener_error_desc(jso_error));
		return -1;
	}

	close_file_simple(cont);

	PRT("%s",
		json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));

	return 0;
}

/*
 * {"root": { "obj":"v", "obj2":"v2" } }
 */
int conf_parse(const char *path)
{
	BUG_ON(path == NULL);

	conf_reset();
	conf_jso = json_object_from_file(path);
	if (conf_jso == NULL)
	{
		ERR("Cannot parse conf file '%s'.", path);
		return -1;
	}

#if CONFIG_VERBOSE_MODE
	conf_dump(conf_jso);
#endif
	return 0;
}

int conf_init(void)
{
	conf_jso = NULL;

	return 0;
}

void conf_exit(void)
{
	conf_reset();
}
