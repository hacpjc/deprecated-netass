#ifndef SRC_INCLUDE_TM_H_
#define SRC_INCLUDE_TM_H_

#include <sys/sysinfo.h>

typedef long uptime_t;

/*!
 * \brief Get system up time (sec)
 *
 * \return system up time (sec)
 * \return 0 if we cannot get up time.
 */
static long tm_uptime(void)
{
	struct sysinfo info;
	int res;

	res = sysinfo(&info);
	if (res < 0) {
		return 0;
	}

	return info.uptime;
}

#endif /* SRC_INCLUDE_TM_H_ */
