#ifndef SRC_INCLUDE_COMMON_H_
#define SRC_INCLUDE_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "config.h"
#include "list.h"

#if CONFIG_USE_COLOR_TEXT
#define KNRM  "\x1B[0m" // Reset color
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#else
#define KNRM
#define KRED
#define KGRN
#define KYEL
#define KBLU
#define KMAG
#define KCYN
#define KWHT
#endif

/*
 * misc
 */
#define ARRAY_SIZE(_tbl) (sizeof(_tbl) / sizeof(_tbl[0]))

#define likely(_x)   __builtin_expect((_x), 1)
#define unlikely(_x) __builtin_expect((_x), 0)

/*
 * msg
 */
#if CONFIG_DEBUG_MODE
#define DBG(_fmt, _args...) printf("[%s] " _fmt "\n", __FUNCTION__, ##_args)
#define WARN(_fmt, _args...) fprintf(stderr, KMAG " * WARNING: "  _fmt KNRM "\n", ##_args)
#define BUG_ON(_expr) assert(!(_expr))
#else
#define DBG(_fmt, _args...) do { } while (0)
#define WARN(_fmt, _args...) fprintf(stderr, KMAG " * WARNING: " _fmt KNRM "\n", ##_args)
#define BUG_ON(_expr) assert(!(_expr))
#endif

#if CONFIG_VERBOSE_MODE
#define VBS(_fmt, _args...) printf("[%s] " _fmt "\n", __FUNCTION__, ##_args)
#else
#define VBS(_fmt, _args...) do { } while (0)
#endif

#define PRT(_fmt, _args...) fprintf(stdout, _fmt "\n", ##_args)
#define PRT_NONL(_fmt, _args...) do { fprintf(stdout, _fmt, ##_args); fflush(stdout); } while (0)
#define ERR(_fmt, _args...) fprintf(stderr, KRED " * ERROR: " _fmt KNRM "\n", ##_args)

static int inline __is_text(const unsigned char ch)
{
	if ((ch >= ' ' && ch <= '~') && (ch != '\\'))
	{
		return 1;
	}

	return 0;
}

static void asciidump_limit(const unsigned char *data, const int nbytes, const int limit)
{
	int i;
	register unsigned char ch;

    if (data == NULL)
        return;

    printf("\033[0;35m +%d>\033[0m ", nbytes);
    for (i = 0; i < nbytes && (limit == 0 || i < limit); i++)
    {
    	ch = data[i];

    	if (!__is_text(ch))
    	{
    		printf("\033[0;33m\\%02x\033[0m", ch);
    	}
    	else
    	{
    		printf("%c", ch);
    	}
    }

    printf("\n");
}

#define asciidump(__p, __plen) asciidump_limit(__p, __plen, 0)

static inline void hexdump_f(FILE *fp, const char *desc, const unsigned char *data, const int nbytes)
{
	register int i;
	unsigned int line = 0;
	char hd[50] = { 0 };
	char hr[20] = { 0 };
	char hdtmp[8] = { 0 };
	char hrtmp[8] = { 0 };

	if (data == NULL)
		return;

	fprintf(fp, "%s %d <%s>:\n",
		__FUNCTION__,
		nbytes,
		desc == NULL ? "" : desc
		);

	for (i = 0; i < 16; i++)
	{
		snprintf(hdtmp, sizeof(hdtmp), "%02X ", i);
		snprintf(hrtmp, sizeof(hrtmp), "%X", i);

		strncat(hd, hdtmp, sizeof(hd));
		strncat(hr, hrtmp, sizeof(hr));
		if ((i % 16) == 7)
		{
			strncat(hr, " ", sizeof(hr));
			strncat(hd, " ", sizeof(hd));
		}
	}

	fprintf(fp,
		"         %-49s |%s|\n         -----------------------  -----------------------   -------- --------\n",
		hd, hr);
	hd[0] = '\0';
	hr[0] = '\0';

	for (i = 0; i < nbytes; i++)
	{
		snprintf(hdtmp, sizeof(hdtmp), "%02X ", data[i]);
		strncat(hd, hdtmp, sizeof(hd));

		if (data[i] < 0x21 || data[i] > 0x7e)
		{
			strncat(hr, ".", sizeof(hr));
		}
		else
		{
			snprintf(hrtmp, sizeof(hrtmp), "%c", data[i]);
			strncat(hr, hrtmp, sizeof(hr));
		}

		if ((i % 16) == 7)
		{
			strncat(hr, " ", sizeof(hr));
			strncat(hd, " ", sizeof(hd));
		}
		else if ((i % 16) == 15)
		{
			fprintf(fp, "%08X %-49s |%-17s|\n", 0x10 * line, hd, hr);
			hr[0] = '\0';
			hd[0] = '\0';
			line++;
		}
	}

	if (strlen(hr) > 0)
	{
		fprintf(fp, "%08X %-49s |%-17s|\n", 0x10 * line, hd, hr);
	}
}

/*!
 * \brief print content in hexdump command format
 * \param data content to print
 * \param nbytes content length
 */
#define hexdump(_p, _nbytes) hexdump_f(stdout, __FUNCTION__, (_p), (_nbytes))

#endif /* SRC_INCLUDE_COMMON_H_ */
