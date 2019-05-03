
#ifndef DICE_H_
#define DICE_H_

#include <stdlib.h>

static inline __attribute__((unused))
unsigned int dice(const unsigned int rate, const unsigned int max)
{
	int num;

	num = rand() % max;
	if (num < rate)
	{
		return 1; /* Bravo! */
	}

	return 0; /* Oops, sorry. */
}

#endif /* DICE_H_ */
