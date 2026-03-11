#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "kermit.h"

static int file_fd = -1;

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

static void kermit_fhdr_cb(struct kermit_context *kctx)
{
	char *fn;
	int fnlen;
	if (kermit_seq_isdup(kctx, kermit_seq_get(kctx->buf))) {
		kermit_ack(kctx, kermit_seq_get(kctx->buf));
		return;
	}
	if (file_fd >= 0) {
		close(file_fd);
	}
	fn = (char *)&kctx->buf[KERMIT_DATA];
	fnlen = kermit_decode_buf((uint8_t *)fn, kermit_datalen_get(kctx->buf),
				  (uint8_t *)fn);
	fn[fnlen] = '\0';
	fprintf(stderr, "FHDR: %s\n", fn);
	file_fd = open(fn, O_WRONLY | O_TRUNC);
	if (file_fd < 0) {
		file_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC,
			       S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (file_fd < 0) {
			perror("FILE OPEN FAILED");
			kermit_error(kctx, "FILE OPEN FAILED");
			exit(EXIT_FAILURE);
		}
	}
	kermit_ack(kctx, kctx->lseqn);
	kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
	return;
}

static void kermit_data_cb(struct kermit_context *kctx)
{
	uint8_t *wbuf;
	uint8_t idx, len;
	int ret;
	if (kermit_seq_isdup(kctx, kermit_seq_get(kctx->buf))) {
		kermit_ack(kctx, kermit_seq_get(kctx->buf));
		return;
	}
	if (file_fd < 0) {
		perror("NO FILE OPEN");
		kermit_error(kctx, "NO FILE OPEN");
		exit(EXIT_FAILURE);
	}
	wbuf = &kctx->buf[KERMIT_DATA];
	len = kermit_decode_buf(wbuf, kermit_datalen_get(kctx->buf), wbuf);
	idx = 0;
	while (idx < len) {
		ret = write(file_fd, &wbuf[idx], len - idx);
		if (ret < 0) {
			perror("FILE WRITE FAILED");
			kermit_error(kctx, "FILE WRITE FAILED");
			exit(EXIT_FAILURE);
		}
		idx += ret;
	}
	kermit_ack(kctx, kctx->lseqn);
	kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
	return;
}

static void kermit_eof_cb(struct kermit_context *kctx)
{
	if (kermit_seq_isdup(kctx, kermit_seq_get(kctx->buf))) {
		kermit_ack(kctx, kermit_seq_get(kctx->buf));
		return;
	}
	if (file_fd < 0) {
		perror("NO FILE OPEN");
		kermit_error(kctx, "NO FILE OPEN");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "EOF\n");
	close(file_fd);
	kermit_ack(kctx, kctx->lseqn);
	kctx->lseqn = (kctx->lseqn + 1) & KERMIT_SEQ_MASK;
	return;
}

static void kermit_break_cb(struct kermit_context *kctx)
{
	if (kermit_seq_isdup(kctx, kermit_seq_get(kctx->buf))) {
		kermit_ack(kctx, kermit_seq_get(kctx->buf));
		return;
	}
	kermit_ack(kctx, kctx->lseqn);
	fprintf(stderr, "BREAK\n");
	exit(EXIT_SUCCESS);
	return;
}

static void kermit_error_cb(struct kermit_context *kctx)
{
	char *msg;
	int msglen;
	msg = (char *)&kctx->buf[KERMIT_DATA];
	msglen = kermit_decode_buf((uint8_t *)msg, kermit_datalen_get(kctx->buf),
				  (uint8_t *)msg);
	msg[msglen] = '\0';
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(EXIT_FAILURE);
	return;
	
}

int main(int argc, char *argv[])
{
	struct kermit_context kctx_main = KERMIT_INIT(KERMIT_ROLE_RECV);
	struct kermit_context *kctx = &kctx_main;
	uint8_t rxbuf[128];
	int ret;
	int i;
	(void)argc;
	(void)argv;
	kermit_selftest();
	kctx->link_send = link_send;
	kctx->fhdr_cb = kermit_fhdr_cb;
	kctx->data_cb = kermit_data_cb;
	kctx->eof_cb = kermit_eof_cb;
	kctx->break_cb = kermit_break_cb;
	kctx->error_cb = kermit_error_cb;
	struct sigaction sa;
	sa.sa_handler = sigalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; // Do NOT set SA_RESTART
	sigaction(SIGALRM, &sa, NULL);
	while (1) {
		alarm(1);
		ret = read(STDIN_FILENO, rxbuf, sizeof(rxbuf));
		alarm(0);
		if ((ret < 0) && (errno == EINTR)) {
			fprintf(stderr, "KERMIT RECV TIMEOUT\n");
			kermit_nak(kctx);
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
