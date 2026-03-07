#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define kermit_tochar(x) ((x) + 32)
#define kermit_unchar(x) ((x) - 32)
#define kermit_tosum(x) (kermit_tochar(((x) + (((x) & 192) >> 6)) & 63))

enum { SOH = 0x01 };

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

enum { KERMIT_SEQ_MASK = 0x3F };

uint8_t kermit_lseqn = 0; /* LOCAL SEQ */

int file_fd;
int link_tx_fd = STDOUT_FILENO;
int link_rx_fd = STDIN_FILENO;
int read_timo_cnt = 0;

void timer_cb(int sign)
{
	(void)sign;
	return;
}
uint8_t kermit_rxpkt[128];
uint8_t kermit_rxidx = 0;
bool kermit_rxdup = false;

uint8_t kermit_len_get(uint8_t *pkt)
{
	return 2 + kermit_unchar(pkt[KERMIT_LEN]);
}

uint8_t kermit_sum_gen(uint8_t *pkt)
{
	uint8_t len = kermit_len_get(pkt);
	uint8_t sum = 0;
	uint8_t i;
	for (i = 1; i < (len - KERMIT_CHK_SIZE); i++) {
		sum += pkt[i];
	}
	return kermit_tosum(sum);
}

uint8_t kermit_sum_get(uint8_t *pkt)
{
	return pkt[kermit_len_get(pkt) - KERMIT_CHK_SIZE];
}

void kermit_sum_set(uint8_t *pkt, uint8_t sum)
{
	pkt[kermit_len_get(pkt) - KERMIT_CHK_SIZE] = sum;
}

void kermit_sum_upd(uint8_t *pkt)
{
	kermit_sum_set(pkt, kermit_sum_gen(pkt));
}

bool kermit_sum_chk(uint8_t *pkt)
{
	return (kermit_sum_gen(pkt) == kermit_sum_get(pkt));
}

void kermit_eol_upd(uint8_t *pkt)
{
	pkt[kermit_len_get(pkt)] = '\r';
}

uint8_t kermit_seq_get(uint8_t *pkt)
{
	return kermit_unchar(pkt[KERMIT_SEQ]);
}

void kermit_send(uint8_t *pkt)
{
	uint8_t sended = 0;
	uint8_t total = kermit_len_get(pkt) + KERMIT_EOL_SIZE;
	int ret;
	while (sended < total) {
		ret = write(link_tx_fd, &pkt[sended], total - sended);
		if (ret < 0) {
			perror("LINK WRITE FAILED");
			return;
		}
		sended += ret;
	}
}

void kermit_nak(uint8_t *buf)
{
	buf[KERMIT_MARK] = SOH;
	buf[KERMIT_LEN] = kermit_tochar(KERMIT_HDR_SIZE + KERMIT_CHK_SIZE - 2);
	buf[KERMIT_SEQ] = kermit_tochar(kermit_lseqn);
	buf[KERMIT_TYPE] = 'N';
	kermit_sum_upd(buf);
	kermit_eol_upd(buf);
	kermit_send(buf);
}

void kermit_ack(uint8_t *buf, uint8_t seq)
{
	buf[KERMIT_MARK] = SOH;
	buf[KERMIT_LEN] = kermit_tochar(KERMIT_HDR_SIZE + KERMIT_CHK_SIZE - 2);
	buf[KERMIT_SEQ] = kermit_tochar(seq);
	buf[KERMIT_TYPE] = 'Y';
	kermit_sum_upd(buf);
	kermit_eol_upd(buf);
	kermit_send(buf);
}

void kermit_handle_sinit(uint8_t *rxpkt)
{
	kermit_lseqn = 1;
	kermit_ack(rxpkt, kermit_seq_get(rxpkt));
}

uint8_t kermit_decode_inplace(uint8_t *rxpkt)
{
	uint8_t inlen = kermit_len_get(rxpkt) - KERMIT_CHK_SIZE;
	uint8_t si, di;
	uint8_t nxtc;
	si = di = KERMIT_DATA;
	while ((si < inlen) && (di < inlen)) {
		if (rxpkt[si] == '#') { /* QCTL */
			nxtc = rxpkt[si + 1];
			/* CONTROL CHAR UNPREFIX : 0X00-0X1F,0X7F */
			/* CONTROL CHAR PREFIXED : 0X40-0X5F,0X3F */
			if (((nxtc & 0x7F) >= 0x3F) &&
			    ((nxtc & 0x7F) <= 0x5F)) {
				rxpkt[di] = nxtc ^ 0x40;
				si += 2;
				di += 1;
				continue;
			}
			rxpkt[di] = nxtc;
			si += 2;
			di += 1;
			continue;
		}
		rxpkt[di] = rxpkt[si];
		si += 1;
		di += 1;
	}
	return (di - KERMIT_DATA);
}

void file_write(uint8_t *buf, uint8_t len)
{
	uint8_t idx = 0;
	int ret;
	while (idx < len) {
		ret = write(file_fd, &buf[idx], len - idx);
		if (ret < 0) {
			perror("FILE WRITE FAILED");
			exit(EXIT_FAILURE);
		}
		idx += ret;
	}
}

void kermit_handle_data(uint8_t *rxpkt)
{
	uint8_t declen;
	if (kermit_rxdup == false) {
		kermit_lseqn = (kermit_lseqn + 1) & KERMIT_SEQ_MASK;
		declen = kermit_decode_inplace(rxpkt);
		file_write(&rxpkt[KERMIT_DATA], declen);
		fprintf(stderr, ".");
		fflush(stdout);
	}
	kermit_ack(rxpkt, kermit_seq_get(rxpkt));
}

void kermit_handle_fhdr(uint8_t *rxpkt)
{
	if (kermit_rxdup == false) {
		kermit_lseqn = (kermit_lseqn + 1) & KERMIT_SEQ_MASK;
		lseek(file_fd, 0, 0);
	}
	kermit_ack(rxpkt, kermit_seq_get(rxpkt));
}

void kermit_handle_eof(uint8_t *rxpkt)
{
	if (kermit_rxdup == false) {
		kermit_lseqn = (kermit_lseqn + 1) & KERMIT_SEQ_MASK;
		close(file_fd);
	}
	kermit_ack(rxpkt, kermit_seq_get(rxpkt));
}

void kermit_handle_break(uint8_t *rxpkt)
{
	kermit_ack(rxpkt, kermit_seq_get(rxpkt));
	exit(EXIT_SUCCESS);
}

void kermit_handle_error(uint8_t *rxpkt)
{
	uint8_t declen;
	char *errmsg;
	declen = kermit_decode_inplace(rxpkt);
	errmsg = (char *)&rxpkt[KERMIT_DATA];
	errmsg[declen] = '\0';
	fprintf(stderr, "KERMIT ERROR: %s\r\n", errmsg);
	exit(EXIT_FAILURE);
}

void kermit_handle_rxpkt(uint8_t *rxpkt, uint8_t len)
{
	uint8_t rtype; /* REMOTE TYPE */
	uint8_t rseqn; /* REMOTE SEQ */
	if (len < (KERMIT_HDR_SIZE + KERMIT_CHK_SIZE)) {
		kermit_nak(rxpkt);
		return;
	}
	if (kermit_sum_chk(rxpkt) == false) {
		fprintf(stderr,
			"PACKET CHK ERROR L%02X != R%02X TELL REMOTE RESEND\r\n",
			kermit_sum_gen(rxpkt), kermit_sum_get(rxpkt));
		kermit_nak(rxpkt);
		return;
	}
	rtype = rxpkt[KERMIT_TYPE];
	if (rtype == 'S') {
		kermit_handle_sinit(rxpkt);
		return;
	}
	rseqn = kermit_seq_get(rxpkt);
	kermit_rxdup = false;
	if (rseqn != kermit_lseqn) {
		if (rseqn != ((kermit_lseqn - 1) & KERMIT_SEQ_MASK)) {
			return; /* IGNORE BAD SEQ */
		}
		kermit_rxdup = true;
	}
	if (rtype == 'D') {
		kermit_handle_data(rxpkt);
		return;
	}
	if (rtype == 'F') {
		kermit_handle_fhdr(rxpkt);
		return;
	}
	if (rtype == 'Z') {
		kermit_handle_eof(rxpkt);
		return;
	}
	if (rtype == 'B') {
		kermit_handle_break(rxpkt);
		return;
	}
	if (rtype == 'E') {
		kermit_handle_error(rxpkt);
		return;
	}
}

void kermit_handle_char(uint8_t c)
{
	if (kermit_rxidx >= sizeof(kermit_rxpkt)) {
		kermit_nak(kermit_rxpkt);
		kermit_rxidx = 0;
	}
	if ((kermit_rxidx == 0) && (c != SOH)) {
		return;
	}
	if (c == '\r') {
		kermit_handle_rxpkt(kermit_rxpkt, kermit_rxidx);
		kermit_rxidx = 0;
		return;
	}
	kermit_rxpkt[kermit_rxidx] = c;
	kermit_rxidx += 1;
}

int main(int argc, char *argv[])
{
	char *filename = argv[1];
	uint8_t link_rxbuf[128];
	int i;
	int ret;
	if (argc < 2) {
		fprintf(stderr, "USAGE: %s FILE\r\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	file_fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG);
	if (file_fd < 0) {
		perror("FILE OPEN FAILED");
		exit(EXIT_FAILURE);
	}
	signal(SIGALRM, timer_cb);
	while (1) {
		alarm(1); /* start timer 1s */
		ret = read(link_rx_fd, link_rxbuf, sizeof(link_rxbuf) - 1);
		if (ret == 0) {
			fprintf(stderr, "LINK EOF");
			exit(EXIT_FAILURE);
		}
		if ((ret < 0) && (errno == EINTR)) {
			read_timo_cnt += 1;
			kermit_nak(link_rxbuf);
			fprintf(stderr, "LINK READ TIMEOUT %d\r\n",
				read_timo_cnt);
			continue;
		}
		alarm(0); /* stop timer */
		if (ret < 0) {
			perror("LINK READ ERROR");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < ret; i++) {
			kermit_handle_char(link_rxbuf[i]);
		}
	}
}
