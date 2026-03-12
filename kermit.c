#include "kermit.h"

void kermit_mark_upd(uint8_t *pkt)
{
	pkt[KERMIT_MARK] = 0x01;
}

uint8_t kermit_len_get(uint8_t *pkt)
{
	return kermit_unchar(pkt[KERMIT_LEN]) + 2;
}

void kermit_len_set(uint8_t *pkt, uint8_t newlen)
{
	kermit_assert(newlen < KERMIT_BUFSIZE);
	pkt[KERMIT_LEN] = kermit_tochar(newlen - 2);
}

void kermit_len_plus(uint8_t *pkt, int8_t val)
{
	pkt[KERMIT_LEN] += val;
}

uint8_t kermit_seq_get(uint8_t *pkt)
{
	return kermit_unchar(pkt[KERMIT_SEQ]);
}

void kermit_seq_set(uint8_t *pkt, uint8_t newseq)
{
	kermit_assert(newseq <= KERMIT_SEQ_MASK);
	pkt[KERMIT_SEQ] = kermit_tochar(newseq);
}

uint8_t kermit_type_get(uint8_t *pkt)
{
	return pkt[KERMIT_TYPE];
}

void kermit_type_set(uint8_t *pkt, uint8_t newtype)
{
	pkt[KERMIT_TYPE] = newtype;
}

void kermit_pkt_init(uint8_t *pkt, uint8_t seq, uint8_t type)
{
	kermit_mark_upd(pkt);
	kermit_len_set(pkt, KERMIT_HDR_SIZE + KERMIT_CHK_SIZE);
	kermit_seq_set(pkt, seq);
	kermit_type_set(pkt, type);
}

uint8_t kermit_sum_get(uint8_t *pkt)
{
	return pkt[kermit_len_get(pkt) - KERMIT_CHK_SIZE];
}

void kermit_sum_set(uint8_t *pkt, uint8_t newsum)
{
	kermit_assert((kermit_len_get(pkt) - KERMIT_CHK_SIZE) < KERMIT_BUFSIZE);
	pkt[kermit_len_get(pkt) - KERMIT_CHK_SIZE] = newsum;
}

uint8_t kermit_sum_gen(uint8_t *pkt)
{
	uint8_t sum = 0;
	uint8_t len = kermit_len_get(pkt) - KERMIT_CHK_SIZE;
	// SKIP MARK
	pkt += 1;
	len -= 1;
	do {
		sum += pkt[0];
		len -= 1;
		pkt += 1;
	} while (len > 0);
	return kermit_tosum(sum);
}

void kermit_sum_upd(uint8_t *pkt)
{
	kermit_sum_set(pkt, kermit_sum_gen(pkt));
}

bool kermit_sum_chk(uint8_t *pkt)
{
	return (kermit_sum_get(pkt) == kermit_sum_gen(pkt));
}

uint8_t kermit_datalen_get(uint8_t *pkt)
{
	return kermit_len_get(pkt) - KERMIT_HDR_SIZE - KERMIT_CHK_SIZE;
}

uint8_t kermit_decode(const uint8_t *in, uint8_t *out)
{
	const uint8_t *si = in;
	uint8_t *di = out;
	uint8_t nxtc;
	if ((si[0] & 0x7F) == '#') {
		nxtc = si[1];
		if (((nxtc & 0x7F) >= 0x3F) && ((nxtc & 0x7F) <= 0x5F)) {
			di[0] = nxtc ^ 0x40;
			return 2;
		}
		di[0] = nxtc;
		return 2;
	}
	di[0] = si[0];
	return 1;
}

uint8_t kermit_decode_buf(const uint8_t *in, int8_t inlen, uint8_t *out)
{
	uint8_t ret = 0;
	uint8_t tmp;
	kermit_assert(inlen >= 0);
	while (inlen > 0) {
		tmp = kermit_decode(in, out);
		in += tmp;
		inlen -= tmp;
		out += 1;
		ret += 1;
	}
	return ret;
}

uint8_t kermit_encode(uint8_t in, uint8_t *out)
{
	if ((in & 0x7F) == '#') {
		out[0] = '#';
		out[1] = in;
		return 2;
	}
	if (((in & 0x7F) < 0x20) || ((in & 0x7F) == 0x7F)) {
		out[0] = '#';
		out[1] = in ^ 0x40;
		return 2;
	}
	out[0] = in;
	return 1;
}

uint8_t kermit_data_append(uint8_t *pkt, uint8_t c)
{
	uint8_t idx;
	idx = kermit_len_get(pkt) - KERMIT_CHK_SIZE;
	kermit_len_plus(pkt, kermit_encode(c, &pkt[idx]));
	return kermit_len_get(pkt);
}

void kermit_eol_upd(uint8_t *pkt)
{
	uint8_t idx;
	idx = kermit_len_get(pkt);
	kermit_assert(idx < KERMIT_BUFSIZE);
	pkt[idx] = '\r';
}

bool kermit_pkt_chk(uint8_t *pkt)
{
	uint8_t len;
	len = kermit_len_get(pkt);
	if (len < (KERMIT_HDR_SIZE + KERMIT_CHK_SIZE)) {
		return false;
	}
	if (len >= (KERMIT_BUFSIZE - 1)) {
		return false;
	}
	return kermit_sum_chk(pkt);
}

void kermit_handle_char(struct kermit_context *kctx, uint8_t c)
{
	if (kctx->rxdone == true) {
		return;
	}
	if (kctx->idx >= KERMIT_BUFSIZE) {
		kctx->idx = 0;
	}
	if ((kctx->idx == 0) && (c != 0x1)) {
		return;
	}
	if (c == '\r') {
		kctx->rxdone = true;
		return;
	}
	kctx->buf[kctx->idx] = c;
	kctx->idx += 1;
}

void kermit_rx_reset(struct kermit_context *kctx)
{
	kctx->idx = 0;
	kctx->rxdone = false;
}

void kermit_pkt_send(struct kermit_context *kctx)
{
	if (kermit_pkt_chk(kctx->buf) == false) {
		return;
	}
	if (kctx->link_send == NULL) {
		return;
	}
	kctx->link_send(kctx->buf, kermit_len_get(kctx->buf) + KERMIT_EOL_SIZE);
}

void kermit_nak(struct kermit_context *kctx)
{
	kermit_pkt_init(kctx->buf, kctx->lseqn, 'N');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kermit_pkt_send(kctx);
}

void kermit_ack(struct kermit_context *kctx, uint8_t seqn)
{
	kermit_pkt_init(kctx->buf, seqn, 'Y');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kermit_pkt_send(kctx);
}

uint8_t kermit_param_fill(uint8_t *out, uint8_t outmaxlen)
{
	uint8_t ret = 0;
	uint8_t maxl = 0;
	maxl = KERMIT_BUFSIZE - KERMIT_HDR_SIZE - KERMIT_CHK_SIZE -
	       KERMIT_EOL_SIZE;
	if (maxl > kermit_unchar(126)) {
		maxl = kermit_unchar(126);
	}
	if (outmaxlen > KERMIT_PARAM_MAXL) {
		out[KERMIT_PARAM_MAXL] = kermit_tochar(maxl);
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_TIMO) {
		out[KERMIT_PARAM_TIMO] = kermit_tochar(1);
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_NPAD) {
		out[KERMIT_PARAM_NPAD] = kermit_tochar(0);
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_PADC) {
		out[KERMIT_PARAM_PADC] = 0 ^ 0x40;
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_EOLC) {
		out[KERMIT_PARAM_EOLC] = kermit_tochar('\r');
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_QCTL) {
		out[KERMIT_PARAM_QCTL] = '#';
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_QBIN) {
		out[KERMIT_PARAM_QBIN] = 'N';
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_CHKT) {
		out[KERMIT_PARAM_CHKT] = '1';
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_REPT) {
		out[KERMIT_PARAM_REPT] = ' ';
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_CAPS) {
		out[KERMIT_PARAM_CAPS] = kermit_tochar(KERMIT_CAP_SWIN);
		ret += 1;
	}
	if (outmaxlen > KERMIT_PARAM_WIND) {
		out[KERMIT_PARAM_WIND] = kermit_tochar(KERMIT_WINSIZE);
		ret += 1;
	}
	return ret;
}

void kermit_make_sinit(uint8_t *pkt, uint8_t pktmaxsize, uint8_t seqn)
{
	uint8_t paramlen;
	kermit_assert(pktmaxsize >=
		      (KERMIT_HDR_SIZE + KERMIT_CHK_SIZE + KERMIT_EOL_SIZE));
	kermit_pkt_init(pkt, seqn, 'S');
	paramlen = kermit_param_fill(&pkt[KERMIT_DATA],
				     pktmaxsize - KERMIT_HDR_SIZE -
				     KERMIT_CHK_SIZE - KERMIT_EOL_SIZE);
	kermit_len_plus(pkt, paramlen);
	kermit_sum_upd(pkt);
	kermit_eol_upd(pkt);
}

void kermit_handle_sinit(struct kermit_context *kctx)
{
	kctx->lseqn = 1; /* RESET LOCAL SEQN */
	kermit_make_sinit(kctx->buf,
			  kermit_len_get(kctx->buf) + KERMIT_EOL_SIZE,
			  kermit_seq_get(kctx->buf));
	kermit_type_set(kctx->buf, 'Y');
	kermit_sum_upd(kctx->buf);
	kermit_pkt_send(kctx);
}

bool kermit_seq_acked(struct kermit_context *kctx, uint8_t seqn)
{
	uint8_t dist = (seqn - kctx->lseqn) & KERMIT_SEQ_MASK;
	return dist >= ((KERMIT_SEQ_MASK + 1) >> 1);
}

bool kermit_seq_isout(struct kermit_context *kctx, uint8_t seqn)
{
	if (kermit_seq_acked(kctx, seqn)) {
		return false;
	}
	if (kctx->lseqn == seqn) {
		return false;
	}
	return true;
}

void kermit_error(struct kermit_context *kctx, const char *errmsg)
{
	kermit_pkt_init(kctx->buf, kctx->lseqn, 'E');
	uint8_t len_errmsg = strlen(errmsg);
	while (len_errmsg > 0) {
		kermit_data_append(kctx->buf, errmsg[0]);
		if (kermit_len_get(kctx->buf) >=
		    KERMIT_BUFSIZE - KERMIT_HDR_SIZE - KERMIT_CHK_SIZE -
			    KERMIT_EOL_SIZE) {
			break;
		}
		errmsg += 1;
		len_errmsg -= 1;
	}
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kermit_pkt_send(kctx);
}

void kermit_handle_unknown(struct kermit_context *kctx)
{
	if (kctx->unknown_cb != NULL) {
		kctx->unknown_cb(kctx);
		return;
	}
	kermit_error(kctx, "UNHANDLE TYPE");
	return;
}

void kermit_handle_fhdr(struct kermit_context *kctx)
{
	if (kctx->fhdr_cb != NULL) {
		kctx->fhdr_cb(kctx);
		return;
	}
	kermit_ack(kctx, kermit_seq_get(kctx->buf));
	kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
	return;
}

void kermit_handle_data(struct kermit_context *kctx)
{
	if (kctx->data_cb != NULL) {
		kctx->data_cb(kctx);
		return;
	}
	kermit_ack(kctx, kermit_seq_get(kctx->buf));
	kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
}

void kermit_handle_eof(struct kermit_context *kctx)
{
	if (kctx->eof_cb != NULL) {
		kctx->eof_cb(kctx);
		return;
	}
	kermit_ack(kctx, kermit_seq_get(kctx->buf));
	kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
}

void kermit_handle_break(struct kermit_context *kctx)
{
	if (kctx->break_cb != NULL) {
		kctx->break_cb(kctx);
		return;
	}
	kermit_ack(kctx, kermit_seq_get(kctx->buf));
}

void kermit_handle_error(struct kermit_context *kctx)
{
	if (kctx->error_cb != NULL) {
		kctx->error_cb(kctx);
		return;
	}
}

void kermit_handle_rxpkt(struct kermit_context *kctx)
{
	uint8_t rtype, rseqn;
	if (kctx->rxdone == false) {
		return;
	}
	if (kermit_pkt_chk(kctx->buf) == false) {
		/* BAD PACKET */
		kermit_nak(kctx);
		kermit_rx_reset(kctx);
		return;
	}
	rtype = kermit_type_get(kctx->buf);
	switch (rtype) {
	case 'S':
		kermit_handle_sinit(kctx);
		kermit_rx_reset(kctx);
		return;
	case 'B':
		kermit_handle_break(kctx);
		kermit_rx_reset(kctx);
		return;
	case 'E':
		kermit_handle_error(kctx);
		kermit_rx_reset(kctx);
		return;
	}
	rseqn = kermit_seq_get(kctx->buf);
	if (kermit_seq_isout(kctx, rseqn) == true) {
		kermit_nak(kctx);
		kermit_rx_reset(kctx);
		return;
	}
	if (kermit_seq_acked(kctx, rseqn) == true) {
		kermit_ack(kctx, kermit_seq_get(kctx->buf));
		kermit_rx_reset(kctx);
		return;
	}
	switch (rtype) {
	case 'F':
		kermit_handle_fhdr(kctx);
		break;
	case 'D':
		kermit_handle_data(kctx);
		break;
	case 'Z':
		kermit_handle_eof(kctx);
		break;
	default:
		kermit_handle_unknown(kctx);
		break;
	}

	kermit_rx_reset(kctx);
}
