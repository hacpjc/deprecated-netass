#ifndef SRC_PACKET_PACKET_HOOK_H_
#define SRC_PACKET_PACKET_HOOK_H_

#include "common.h"
#include "list.h"

#include "packet/packet_buf.h"

typedef enum
{
	PACKET_HOOK_RES_OK = 0,
	PACKET_HOOK_RES_STOP,
	PACKET_HOOK_RES_ERROR,
	PACKET_HOOK_RES_MAX
} packet_hook_res_t;

/*
 * packet hook - callback func proto
 */
struct packet_hook;
typedef int    (*packet_hook_init_t)(void);
typedef void   (*packet_hook_exit_t)(void);
typedef void * (*packet_hook_open_ctx_t)(void *conf_root);
typedef void   (*packet_hook_close_ctx_t)(void *ctx);
typedef packet_hook_res_t (*packet_hook_run_t)(struct packet_hook *hook, packet_t *pkt);
typedef void (*packet_hook_show_t)(struct packet_hook *hook);

typedef struct packet_hook_func
{
	packet_hook_open_ctx_t  cb_open_ctx;
	packet_hook_close_ctx_t cb_close_ctx;
	packet_hook_run_t   cb_tx;
	packet_hook_run_t   cb_rx;
	packet_hook_show_t  cb_show;

	/* One-time func. */
	packet_hook_init_t  cb_init;
	packet_hook_exit_t  cb_exit;
} packet_hook_func_t;

#define __PACKET_HOOK_FUNC_INITIALIZER(__init, __exit, __open_ctx, __close_ctx, __tx, __rx, __show) \
	.func.cb_init = __init, \
	.func.cb_exit = __exit, \
	.func.cb_open_ctx = __open_ctx, \
	.func.cb_close_ctx = __close_ctx, \
	.func.cb_tx = __tx, \
	.func.cb_rx = __rx, \
	.func.cb_show = __show

/*
 * packet hook
 */
typedef struct packet_hook
{
	char *ident; //!< Packet hook name
	packet_hook_func_t func;

	/* priv */
	void *ctx;
	void *packet_handle;
	struct list_head list;
} packet_hook_t;

/*
 * packet hook - handle
 */
#define packet_hook_set_packet_handle(_hook, _packet_handle) do { (_hook)->packet_handle = (_packet_handle); } while (0)
#define packet_hook_get_packet_handle(_hook) ((packet_handle_t *) (_hook)->packet_handle)

/*
 * packet hook - ctx
 */
#define packet_hook_set_ctx(_hook, _ctx) do { (_hook)->ctx = (_ctx); } while (0)
#define packet_hook_get_ctx(_hook, _type) ((_type *) (_hook)->ctx)

/*
 * packet hook - func
 */
#define packet_hook_check_open_ctx(_hook)  ((_hook)->func.cb_open_ctx != NULL)
#define packet_hook_check_close_ctx(_hook) ((_hook)->func.cb_close_ctx != NULL)
#define packet_hook_check_tx(_hook)        ((_hook)->func.cb_tx != NULL)
#define packet_hook_check_rx(_hook)        ((_hook)->func.cb_rx != NULL)
#define packet_hook_check_show(_hook)      ((_hook)->func.cb_show != NULL)

#define packet_hook_do_open_ctx(_hook, _conf) (_hook)->func.cb_open_ctx(_conf)
#define packet_hook_do_close_ctx(_hook, _ctx) (_hook)->func.cb_close_ctx(_ctx)
#define packet_hook_do_tx(_hook, _pkt)        (_hook)->func.cb_tx(_hook, _pkt)
#define packet_hook_do_rx(_hook, _pkt)        (_hook)->func.cb_rx(_hook, _pkt)
#define packet_hook_do_show(_hook)            (_hook)->func.cb_show(_hook)

/*!
 * \brief Loop all packet hook
 *
 * \param _hook A pointer with type (packet_hook_t **)
 */
#define for_each_packet_hook(_hook) \
	for ((_hook) = __start_pkthook; (_hook) < __stop_pkthook; hook++)

/*
 * Register a packet hook.
 */
#define PAKCET_HOOK_INITIALIZER(__ident, __cb_init, __cb_exit, __cb_open_ctx, __cb_close_ctx, __cb_tx, __cb_rx, __cb_show) \
	{ \
		.ident = (__ident), \
		.ctx = NULL, \
		.packet_handle = NULL, \
		__PACKET_HOOK_FUNC_INITIALIZER(__cb_init, __cb_exit, __cb_open_ctx, __cb_close_ctx, __cb_tx, __cb_rx, __cb_show) \
	}

#define PACKET_HOOK_ACTIVATE(_hook) \
	static packet_hook_t *packet_hook_##_hook __attribute__((used)) __attribute__((__section__("pkthook"))) = &(_hook);

extern packet_hook_t *__start_pkthook[];
extern packet_hook_t *__stop_pkthook[];

typedef int (*packet_hook_loop_func_t)(packet_hook_t *hook, void *priv);

extern int packet_hook_loop(packet_hook_loop_func_t cb, void *priv);
extern void packet_hook_dump(void);

extern int packet_hook_init(void);
extern void packet_hook_exit(void);

extern void packet_hook_free(packet_hook_t *hook);
extern packet_hook_t *packet_hook_alloc(const char *ident);

#endif /* SRC_PACKET_PACKET_HOOK_H_ */
