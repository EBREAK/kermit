#ifndef _KERMIT_H_
#define _KERMIT_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
  BASIC KERMIT PROTOCOL
 */

#ifndef kermit_assert
#define kermit_assert assert
#endif

#define kermit_tochar(x) ((x) + 32)
#define kermit_unchar(x) ((x) - 32)
#define kermit_tosum(x) (kermit_tochar(((x) + (((x) & 192) >> 6)) & 63))

enum {
	KERMIT_SEQ_MASK = 0x3F,
};

enum {
	KERMIT_MARK = 0x00,
	KERMIT_LEN = 0x01,
	KERMIT_SEQ = 0x02,
	KERMIT_TYPE = 0x03,
	KERMIT_DATA = 0x04,
	KERMIT_HDR_SIZE = 0x04,
	KERMIT_CHK_SIZE = 0x01,
	KERMIT_EOL_SIZE = 0x01
};

enum {
	KERMIT_PARAM_MAXL = 0x00,
	KERMIT_PARAM_TIMO = 0x01,
	KERMIT_PARAM_NPAD = 0x02,
	KERMIT_PARAM_PADC = 0x03,
	KERMIT_PARAM_EOLC = 0x04,
	KERMIT_PARAM_QCTL = 0x05,
};

#ifndef KERMIT_BUFSIZE
#define KERMIT_BUFSIZE (2 + kermit_unchar(126) + KERMIT_EOL_SIZE)
#endif

enum {
	KERMIT_ROLE_RECV = 0,
	KERMIT_ROLE_SEND = 1
};

struct kermit_context {
	uint8_t role;
	uint8_t buf[KERMIT_BUFSIZE];
	uint8_t idx;
	bool rxdone;
	uint8_t lseqn;

	void (*link_send)(uint8_t *buf, uint8_t len);
	void (*sinit_cb)(struct kermit_context *kctx);
	void (*fhdr_cb)(struct kermit_context *kctx);
	void (*data_cb)(struct kermit_context *kctx);
	void (*eof_cb)(struct kermit_context *kctx);
	void (*break_cb)(struct kermit_context *kctx);
	void (*error_cb)(struct kermit_context *kctx);
	void (*unknown_cb)(struct kermit_context *kctx);
};

#define KERMIT_INIT(ROLE)           \
	{                           \
		.role = ROLE,       \
		.idx = 0,           \
		.rxdone = false,    \
		.lseqn = 0,         \
		.link_send = NULL,  \
		.sinit_cb = NULL,   \
		.fhdr_cb = NULL,    \
		.data_cb = NULL,    \
		.eof_cb = NULL,     \
		.break_cb = NULL,   \
		.error_cb = NULL,   \
		.unknown_cb = NULL, \
	}

extern void kermit_mark_upd(uint8_t *pkt);
extern uint8_t kermit_len_get(uint8_t *pkt);
extern void kermit_len_set(uint8_t *pkt, uint8_t newlen);
extern void kermit_len_plus(uint8_t *pkt, int8_t val);
extern uint8_t kermit_seq_get(uint8_t *pkt);
extern void kermit_seq_set(uint8_t *pkt, uint8_t newseq);
extern uint8_t kermit_type_get(uint8_t *pkt);
extern void kermit_type_set(uint8_t *pkt, uint8_t newtype);
extern void kermit_pkt_init(uint8_t *pkt, uint8_t seq, uint8_t type);
extern uint8_t kermit_sum_get(uint8_t *pkt);
extern void kermit_sum_set(uint8_t *pkt, uint8_t newsum);
extern uint8_t kermit_sum_gen(uint8_t *pkt);
extern void kermit_sum_upd(uint8_t *pkt);
extern bool kermit_sum_chk(uint8_t *pkt);
extern uint8_t kermit_datalen_get(uint8_t *pkt);
extern uint8_t kermit_decode(const uint8_t *in, uint8_t *out);
extern uint8_t kermit_decode_buf(const uint8_t *in, int8_t inlen, uint8_t *out);
extern uint8_t kermit_encode(uint8_t in, uint8_t *out);
extern uint8_t kermit_data_append(uint8_t *pkt, uint8_t c);
extern void kermit_eol_upd(uint8_t *pkt);
extern bool kermit_pkt_chk(uint8_t *pkt);
extern void kermit_handle_char(struct kermit_context *kctx, uint8_t c);
extern void kermit_rx_reset(struct kermit_context *kctx);
extern void kermit_pkt_send(struct kermit_context *kctx);
extern void kermit_nak(struct kermit_context *kctx);
extern void kermit_ack(struct kermit_context *kctx, uint8_t seqn);
extern uint8_t kermit_param_fill(uint8_t *out, uint8_t outmaxlen);
extern void kermit_make_sinit(uint8_t *pkt, uint8_t pktmaxsize, uint8_t seqn);
extern bool kermit_seq_isdup(struct kermit_context *kctx, uint8_t seqn);
extern bool kermit_seq_isout(struct kermit_context *kctx, uint8_t seqn);
extern void kermit_error(struct kermit_context *kctx, const char *errmsg);
extern void kermit_handle_rxpkt(struct kermit_context *kctx);

extern void kermit_selftest(void);

#endif
