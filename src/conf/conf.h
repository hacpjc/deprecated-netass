#ifndef SRC_CONF_CONF_H_
#define SRC_CONF_CONF_H_

#define CONF_PARENT_MACDB "macdb"
#define CONF_PARENT_PCAP_OFFLINE "pcap_offline"
#define CONF_PARENT_MONITOR "monitor"
#define CONF_PARENT_PACKET  "packet"
#define CONF_PARNET_HOOK    "hook"

#define CONF_DELIM "." // Do not change.

const void *conf_get_sym_obj(const char *sym);
const char *conf_get_sym_str(const char *sym);
const unsigned int conf_get_sym_bool(const char *sym);
const unsigned int conf_get_sym_uint(const char *sym);
const int conf_get_sym_int(const char *sym);
const char *conf_get_sym_str_from_root(const char *sym, const void *conf_root);
const void *conf_get_sym_obj_from_root(const char *sym, const void *conf_root);
const unsigned int conf_get_sym_bool_from_root(const char *sym, const void *conf_root);
const unsigned int conf_get_sym_uint_from_root(const char *sym, const void *conf_root);

void conf_dump(const void *conf_root);
void conf_reset(void);
int conf_check_json_syntax(const char *path);
int conf_parse(const char *path);
int conf_init(void);
void conf_exit(void);

#endif /* SRC_CONF_CONF_H_ */
