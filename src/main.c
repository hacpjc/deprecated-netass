#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>

#include <getopt.h>

#include "common.h"
#include "init_tbl.h"

/* sub system */
#include "conf/conf.h"
#include "packet/packet.h"

typedef struct cmd_arg
{
	const char *path_conf;
} cmd_arg_t;

static void init_cmd_arg(cmd_arg_t *ca)
{
	memset(ca, 0x00, sizeof(*ca));
}

static void exit_cmd_arg(cmd_arg_t *ca)
{
#define FREE_SAFE(_p) do { if (_p) { free(_p); } } while (0)

	FREE_SAFE((void *) ca->path_conf);
}

////////////////////////////////////////////////////////////////////////////////

#include "op_monitor.h"
#include "op_pcap_l2eth.h"

typedef int (*op_cb_t)(void);

typedef struct op_tbl_entry
{
	const char *name;
	op_cb_t cb;
	const char *usage;
} op_tbl_entry_t;

static const op_tbl_entry_t op_tbl[] =
{
	{"monitor", op_monitor, "<-c|--conf netass.conf>"},
	{"pcap_l2eth", op_pcap_l2eth, "-c|--conf netass.conf"},
};

static op_cb_t search_op_cb(const char *op_name)
{
	int i;

	if (op_name == NULL)
	{
		return NULL;
	}

	for (i = 0; i < sizeof(op_tbl) / sizeof(op_tbl[0]); i++)
	{
		if (strcasecmp(op_tbl[i].name, op_name) == 0)
		{
			return op_tbl[i].cb;
		}
	}

	return NULL;
}

static int run_op(void)
{
	const char *op_name;
	op_cb_t cb;

	op_name = conf_get_sym_str("op");
	if (op_name == NULL)
	{
		return -1;
	}

	cb = search_op_cb(op_name);
	if (cb == NULL)
	{
		ERR("Cannot find appropriate op '%s'", op_name);
		return -1;
	}

	return cb();
}

static void print_usage(const char *cmd)
{
#define PFX "\t root># "
	PRT("net assistant is not net ass.", cmd);

	/* Exception */
	PRT(PFX "%s <-p|--parse-conf-syntax netass.conf>", cmd);

	/* General op */
	{
		int i;

		for (i = 0; i < sizeof(op_tbl) / sizeof(op_tbl[0]); i++)
		{
			PRT("\nOperation mode '%s':", op_tbl[i].name);
			PRT(PFX "%s %s", cmd, op_tbl[i].usage);
		}
	}
}

static int parse_argv(cmd_arg_t *ca, int argc, char **argv)
{
#define TEST_OPTARG() do { if (optarg == NULL || strlen(optarg) == 0) { goto USAGE; } } while (0)
#define DUP_OPTARG(_p) \
	do { \
		TEST_OPTARG(); \
		(_p) = (const char *) strdup(optarg); \
		if ((_p) == NULL) { ERR("Possibly memory leak %s", strerror(errno)); return -1; } \
	} while (0)

	int c;
	int digit_optind = 0;

	while (1)
	{
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] =
		{
			{"--parse-conf-syntax", required_argument, NULL, 'p'},
			{"--conf", required_argument, NULL, 'c'},
			{"--help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
		};

        c = getopt_long(argc, argv, "hc:p:",
                 long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'p': // --parse-conf-syntax
        	exit(conf_check_json_syntax(optarg));

        case 'c': // --conf
        	DUP_OPTARG(ca->path_conf);
        	break;

        case 'h':
        default:
        	goto USAGE;
        }
	} // end while

    if (optind < argc)
    {
        fprintf(stderr, "non-option ARGV-elements: ");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");

        return -1;
    }

	return 0;

USAGE:
	print_usage(argv[0]);
	return -1;
}

int main(int argc, char **argv)
{
	cmd_arg_t ca;
	int res;

	DECLARE_INIT_TBL(init_tbl)
	{
		{conf_init, conf_exit, "conf"},
		{packet_hook_init, packet_hook_exit, "packet_hook"}
	};

	/*
	 * Handle with cmd arg
	 */
	init_cmd_arg(&ca);

	if (parse_argv(&ca, argc, argv) < 0)
	{
		exit_cmd_arg(&ca);
		return -1;
	}

	/* Verify cmd arg */
	if (ca.path_conf == NULL)
	{
		ERR("Invalid argument. Try -h");
		exit_cmd_arg(&ca);
		return -1;
	}

	/*
	 * Init sub system
	 */
	if (init_tbl_run_init(init_tbl, init_tbl_get_size(init_tbl)) < 0)
	{
		return -1;
	}

	/*
	 * Read conf
	 */
	if (conf_parse(ca.path_conf) < 0)
	{
		goto ERROR;
	}

	/*
	 * Do task
	 */
	res = run_op();

	init_tbl_run_exit(init_tbl, init_tbl_get_size(init_tbl));
	return res;

ERROR:

	init_tbl_run_exit(init_tbl, init_tbl_get_size(init_tbl));
	exit_cmd_arg(&ca);

	return -1;
}
