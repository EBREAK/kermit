#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "kermit.h"

static char *file_name = NULL;
static int file_fd = -1;
static uint64_t file_sended = 0;
static uint8_t ktxbuf[KERMIT_BUFSIZE];

static void sigalrm_handler(int sig)
{
	(void)sig;
}

static void link_send(uint8_t *buf, uint8_t len)
{
	uint8_t idx = 0;
	int ret;
	while (idx < len) {
		ret = write(STDOUT_FILENO, &buf[idx], len - idx);
		if (ret < 0) {
			perror("STDOUT WRITE FAILED");
			exit(EXIT_FAILURE);
		}
		idx += ret;
	}
}

static void kermit_error_cb(struct kermit_context *kctx)
{
	char *msg;
	int msglen;
	msg = (char *)&kctx->buf[KERMIT_DATA];
	msglen = kermit_decode_buf(
		(uint8_t *)msg, kermit_datalen_get(kctx->buf), (uint8_t *)msg);
	msg[msglen] = '\0';
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(EXIT_FAILURE);
	return;
}

void kermit_resend_cb(struct kermit_context *kctx)
{
	kermit_pkt_send(kctx, ktxbuf);
}

int kermit_make_data(uint8_t *pkt, uint8_t lseqn)
{
	int ret = 0;
	kermit_pkt_init(pkt, lseqn, 'D');
	uint8_t buf[(KERMIT_BUFSIZE - KERMIT_HDR_SIZE - KERMIT_CHK_SIZE -
		     KERMIT_EOL_SIZE) /
		    2];
	ret = read(file_fd, buf, sizeof(buf));
	if (ret < 0) {
		perror("READ FILE FAILED");
		return ret;
	}
	if (ret == 0) {
		return 0;
	}
	int idx = 0;
	while (idx < ret) {
		kermit_data_append(pkt, buf[idx]);
		kermit_assert(kermit_len_get(pkt) <
			      KERMIT_BUFSIZE - KERMIT_EOL_SIZE);
		idx += 1;
		file_sended += 1;
	}
	kermit_sum_upd(pkt);
	kermit_eol_upd(pkt);
	return ret;
}

void kermit_send_next(struct kermit_context *kctx)
{
	ssize_t ret;
	switch (kctx->stat) {
	case 'S':
		kctx->lseqn = 0;
		kermit_make_sinit(ktxbuf, KERMIT_BUFSIZE, kctx->lseqn);
		kermit_pkt_send(kctx, ktxbuf);
		break;
	case 'F':
		kermit_make_fhdr(ktxbuf, file_name, kctx->lseqn);
		kermit_pkt_send(kctx, ktxbuf);
		break;
	case 'D':
	case 'Z': {
		ret = kermit_make_data(ktxbuf, kctx->lseqn);
		if (ret < 0) {
			kermit_error(kctx, "READ FILE FAILED");
			exit(EXIT_FAILURE);
		}
		if (ret == 0) {
			kctx->stat = 'Z';
			kermit_make_eof(ktxbuf, kctx->lseqn);
		}
		kermit_pkt_send(kctx, ktxbuf);
		break;
	}
	case 'B':
		kermit_make_break(ktxbuf, kctx->lseqn);
		kermit_pkt_send(kctx, ktxbuf);
		exit(EXIT_SUCCESS);
		break;
	default:
		fprintf(stderr, "%s: INVALID STATE %c %02X\n", __func__,
			kctx->stat, kctx->stat);
		exit(EXIT_FAILURE);
	}
}

void kermit_ack_cb(struct kermit_context *kctx)
{
	switch (kctx->stat) {
	case 'S':
		kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
		kctx->stat = 'F';
		kermit_send_next(kctx);
		break;
	case 'F':
		kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
		kctx->stat = 'D';
		kermit_send_next(kctx);
		break;
	case 'D':
		fprintf(stderr, "%lu\r", file_sended);
		kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
		kermit_send_next(kctx);
		break;
	case 'Z':
		kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
		kctx->stat = 'B';
		kermit_send_next(kctx);
		break;
	case 'B':
		kermit_send_next(kctx);
		break;
	default:
		fprintf(stderr, "%s: INVALID STATE %c %02X\n", __func__,
			kctx->stat, kctx->stat);
		exit(EXIT_FAILURE);
		break;
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "USAGE: %s FILE\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	file_name = argv[1];
	file_fd = open(file_name, O_RDONLY);
	if (file_fd < 0) {
		perror("OPEN FILE FAILED");
		exit(EXIT_FAILURE);
	}
	struct kermit_context kctx_main = KERMIT_INIT(KERMIT_ROLE_SEND);
	struct kermit_context *kctx = &kctx_main;
	uint8_t rxbuf[128];
	int ret;
	int i;
	(void)argc;
	(void)argv;
	kermit_selftest();
	kctx->stat = 'S';
	kctx->link_send = link_send;
	kctx->resend_cb = kermit_resend_cb;
	kctx->error_cb = kermit_error_cb;
	kctx->ack_cb = kermit_ack_cb;
	struct sigaction sa;
	sa.sa_handler = sigalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; // Do NOT set SA_RESTART
	sigaction(SIGALRM, &sa, NULL);
	kermit_send_next(kctx);
	while (1) {
		alarm(1);
		ret = read(STDIN_FILENO, rxbuf, sizeof(rxbuf));
		alarm(0);
		if ((ret < 0) && (errno == EINTR)) {
			fprintf(stderr, "KERMIT RECV TIMEOUT\n");
			kermit_resend_cb(kctx);
			continue;
		}
		if (ret < 0) {
			perror("STDIN READ FAILED");
			exit(EXIT_FAILURE);
		}
		if (ret == 0) {
			fprintf(stderr, "STDIN EOF\n");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < ret; i++) {
			kermit_handle_char(kctx, rxbuf[i]);
			kermit_handle_rxpkt(kctx);
		}
	}

	return 0;
}
