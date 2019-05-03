#ifndef SRC_MACDB_MACDB_ARPH_H_
#define SRC_MACDB_MACDB_ARPH_H_

#include <pthread.h>

#include "packet/packet.h"

typedef struct macdb_arph
{
	pthread_t th_id;
	pthread_attr_t th_attr;
	int th_join_flag;
	void *priv;

	packet_handle_t ph;
} macdb_arph_t;

#endif /* SRC_MACDB_MACDB_ARPH_H_ */
