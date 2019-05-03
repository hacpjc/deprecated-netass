#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>

#include <pthread.h>

#include "macdb.h"
#include "macdb_arph.h"

static void do_arp_task(macdb_arph_t *arph, packet_t *pkt)
{

}

/*
 * Start ARP handler
 */
static void *macdb_arph_main(void *priv)
{
	macdb_arph_t *arph = (macdb_arph_t *) priv;
	macdb_t *db = (macdb_t *) arph->priv;

	packet_t pkt_container, *pkt = &pkt_container;

	DBG("...Running pthread with priv %p", arph);

	/* Bind socket to ARP packet */
	for (;;)
	{
		if (arph->th_join_flag)
		{
			DBG("...Recv msg to stop pthread");
			break;
		}

		if (packet_handle_recv_l2eth(&arph->ph, pkt, 0) > 0)
		{
			do_arp_task(arph, pkt);
		}
	}

	return NULL;
}

static int create_pthread(pthread_t *thread_id, pthread_attr_t *thread_attr, void *priv)
{
	struct sched_param sched_param = { .sched_priority = 0 };

	pthread_attr_init(thread_attr);
	pthread_attr_setdetachstate(thread_attr, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setinheritsched(thread_attr, PTHREAD_EXPLICIT_SCHED);

	if (pthread_attr_setschedparam(thread_attr, &sched_param) < 0)
	{
		WARN("Cannot configure pthread prio to %d",
			sched_param.sched_priority);
	}

	if (pthread_create(thread_id, thread_attr, macdb_arph_main, priv) < 0)
	{
		ERR("Cannot create pthread %s", strerror(errno));
		return -1;
	}

	return 0;
}

macdb_arph_t *macdb_arph_start(macdb_t *db, const char *dev_name)
{
	macdb_arph_t *arph;

	/* Alloc handle */
	arph = (macdb_arph_t *) malloc(sizeof(*arph));
	if (arph == NULL)
	{
		ERR("Cannot alloc arph %d bytes", sizeof(*arph));
		return NULL;
	}

	memset(arph, 0x00, sizeof(*arph));

	/* Bind socket */
	if (packet_handle_init(&arph->ph, dev_name) < 0)
	{
		return NULL;
	}

	/* Create pthread */
	if (create_pthread(&arph->th_id, &arph->th_attr, arph) < 0)
	{
		return NULL;
	}

	return 0;
}

void macdb_arph_stop(macdb_arph_t *arph)
{
	arph->th_join_flag = 1; // signal pthread to stop

	pthread_join(arph->th_id, NULL);
}
