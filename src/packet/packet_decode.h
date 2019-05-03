
#ifndef SRC_PACKET_PACKET_DECODE_H_
#define SRC_PACKET_PACKET_DECODE_H_

typedef enum
{
	PACKET_DECODE_RES_OK = 0,
	PACKET_DECODE_RES_ANOMALY,
	PACKET_DECODE_RES_BYPASS,
	PACKET_DECODE_RES_MAX
} packet_decode_res_t;

packet_decode_res_t packet_decode_l2eth(packet_t *pkt);

#endif /* SRC_PACKET_PACKET_DECODE_H_ */
