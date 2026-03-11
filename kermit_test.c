#include "kermit.h"

uint8_t *test_link_buf;
void test_link_send(uint8_t *buf, uint8_t len);

void kermit_selftest(void)
{
	kermit_assert(KERMIT_BUFSIZE < 128);
	kermit_assert(kermit_tochar(0) == 32);
	kermit_assert(kermit_unchar(32) == 0);
	kermit_assert(kermit_tochar(94) == 126);
	kermit_assert(kermit_unchar(126) == 94);
	kermit_assert(kermit_tosum(0) == 32);
	kermit_assert(kermit_tosum(124) == 93);
	kermit_assert(kermit_tosum(255) == 34);

	uint8_t _test_link_buf[KERMIT_BUFSIZE];
	test_link_buf = &_test_link_buf[0];

	struct kermit_context kctx_test = KERMIT_INIT(KERMIT_ROLE_RECV);
	struct kermit_context *kctx = &kctx_test;

	kctx->buf[KERMIT_MARK] = 0xFF;
	kermit_mark_upd(kctx->buf);
	kermit_assert(kctx->buf[KERMIT_MARK] == 0x01);

	kctx->buf[KERMIT_LEN] = kermit_tochar(0);
	kermit_assert(kermit_len_get(kctx->buf) == 2);

	kermit_len_set(kctx->buf, 20);
	kermit_assert(kermit_len_get(kctx->buf) == 20);

	kermit_len_set(kctx->buf, 10);
	kermit_len_plus(kctx->buf, 3);
	kermit_assert(kermit_len_get(kctx->buf) == 13);

	kermit_len_set(kctx->buf, 9);
	kermit_len_plus(kctx->buf, -3);
	kermit_assert(kermit_len_get(kctx->buf) == 6);

	kctx->buf[KERMIT_SEQ] = kermit_tochar(5);
	kermit_assert(kermit_seq_get(kctx->buf) == 5);

	kermit_seq_set(kctx->buf, 30);
	kermit_assert(kermit_seq_get(kctx->buf) == 30);

	kctx->buf[KERMIT_TYPE] = 'N';
	kermit_assert(kermit_type_get(kctx->buf) == 'N');

	kermit_type_set(kctx->buf, 'E');
	kermit_assert(kermit_type_get(kctx->buf) == 'E');

	kermit_len_set(kctx->buf, 5);
	kctx->buf[5 - 1] = 0x55;
	kermit_assert(kermit_sum_get(kctx->buf) == 0x55);

	kermit_len_set(kctx->buf, 7);
	kermit_sum_set(kctx->buf, 0xAA);
	kermit_assert(kermit_sum_get(kctx->buf) == 0xAA);

	kermit_pkt_init(kctx->buf, 30, 'Y');
	kermit_assert(kctx->buf[KERMIT_MARK] == 0x01);
	kermit_assert(kermit_len_get(kctx->buf) ==
		      (KERMIT_HDR_SIZE + KERMIT_CHK_SIZE));
	kermit_assert(kermit_seq_get(kctx->buf) == 30);
	kermit_assert(kermit_type_get(kctx->buf) == 'Y');

	kermit_pkt_init(kctx->buf, 63, 'E');
	kermit_assert(kctx->buf[KERMIT_MARK] == 0x01);
	kermit_assert(kermit_len_get(kctx->buf) ==
		      (KERMIT_HDR_SIZE + KERMIT_CHK_SIZE));
	kermit_assert(kermit_seq_get(kctx->buf) == 63);
	kermit_assert(kermit_type_get(kctx->buf) == 'E');

	kermit_pkt_init(kctx->buf, 0, 'N');
	kermit_sum_set(kctx->buf, 0);
	kermit_assert(kermit_sum_chk(kctx->buf) == false);
	kermit_assert(kermit_sum_gen(kctx->buf) == 51);
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_sum_get(kctx->buf) == 51);
	kermit_assert(kermit_sum_chk(kctx->buf) == true);

	kermit_pkt_init(kctx->buf, 1, 'N');
	kermit_sum_set(kctx->buf, 0);
	kermit_assert(kermit_sum_chk(kctx->buf) == false);
	kermit_assert(kermit_sum_gen(kctx->buf) == 52);
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_sum_get(kctx->buf) == 52);
	kermit_assert(kermit_sum_chk(kctx->buf) == true);

	kermit_pkt_init(kctx->buf, 2, 'Y');
	kermit_sum_set(kctx->buf, 0);
	kermit_assert(kermit_sum_chk(kctx->buf) == false);
	kermit_assert(kermit_sum_gen(kctx->buf) == 64);
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_sum_get(kctx->buf) == 64);
	kermit_assert(kermit_sum_chk(kctx->buf) == true);

	kermit_pkt_init(kctx->buf, 33, 'Y');
	kermit_assert(kermit_datalen_get(kctx->buf) == 0);

	kermit_pkt_init(kctx->buf, 55, 'Y');
	kermit_len_set(kctx->buf, 77);
	kermit_assert(kermit_datalen_get(kctx->buf) ==
		      (77 - KERMIT_HDR_SIZE - KERMIT_CHK_SIZE));

	const uint8_t decode_test_in0[] = {
		'#',
		'?',
	};
	kermit_assert(kermit_decode(decode_test_in0, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x7F);

	const uint8_t decode_test_in1[] = {
		'#',
		'@',
	};
	kermit_assert(kermit_decode(decode_test_in1, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x00);

	const uint8_t decode_test_in2[] = {
		'#',
		'A',
	};
	kermit_assert(kermit_decode(decode_test_in2, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x01);

	const uint8_t decode_test_in3[] = {
		'#',
		'^',
	};
	kermit_assert(kermit_decode(decode_test_in3, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x1E);

	const uint8_t decode_test_in4[] = {
		'#',
		'_',
	};
	kermit_assert(kermit_decode(decode_test_in4, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x1F);

	const uint8_t decode_test_in5[] = {
		'#' | 0x80,
		'?',
	};
	kermit_assert(kermit_decode(decode_test_in5, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x7F);

	const uint8_t decode_test_in6[] = {
		'#' | 0x80,
		'@',
	};
	kermit_assert(kermit_decode(decode_test_in6, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x00);

	const uint8_t decode_test_in7[] = {
		'#' | 0x80,
		'A',
	};
	kermit_assert(kermit_decode(decode_test_in7, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x01);

	const uint8_t decode_test_in8[] = {
		'#' | 0x80,
		'^',
	};
	kermit_assert(kermit_decode(decode_test_in8, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x1E);

	const uint8_t decode_test_in9[] = {
		'#' | 0x80,
		'_',
	};
	kermit_assert(kermit_decode(decode_test_in9, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == 0x1F);

	const uint8_t decode_test_in10[] = {
		'#' | 0x80,
		'?' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in10, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x7F | 0x80));

	const uint8_t decode_test_in11[] = {
		'#' | 0x80,
		'@' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in11, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x00 | 0x80));

	const uint8_t decode_test_in12[] = {
		'#' | 0x80,
		'A' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in12, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x01 | 0x80));

	const uint8_t decode_test_in13[] = {
		'#' | 0x80,
		'^' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in13, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x1E | 0x80));

	const uint8_t decode_test_in14[] = {
		'#' | 0x80,
		'_' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in14, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x1F | 0x80));

	const uint8_t decode_test_in15[] = {
		'#',
		'?' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in15, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x7F | 0x80));

	const uint8_t decode_test_in16[] = {
		'#',
		'@' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in16, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x00 | 0x80));

	const uint8_t decode_test_in17[] = {
		'#',
		'A' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in17, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x01 | 0x80));

	const uint8_t decode_test_in18[] = {
		'#',
		'^' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in18, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x1E | 0x80));

	const uint8_t decode_test_in19[] = {
		'#',
		'_' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in19, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (0x1F | 0x80));

	const uint8_t decode_test_in20[] = {
		'#',
		'#',
	};
	kermit_assert(kermit_decode(decode_test_in20, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('#'));

	const uint8_t decode_test_in21[] = {
		'#',
		' ',
	};
	kermit_assert(kermit_decode(decode_test_in21, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (' '));

	const uint8_t decode_test_in22[] = {
		'#',
		'>',
	};
	kermit_assert(kermit_decode(decode_test_in22, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('>'));

	const uint8_t decode_test_in23[] = {
		'#',
		'`',
	};
	kermit_assert(kermit_decode(decode_test_in23, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('`'));

	const uint8_t decode_test_in24[] = {
		'#',
		'~',
	};
	kermit_assert(kermit_decode(decode_test_in24, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('~'));

	const uint8_t decode_test_in25[] = {
		'#' | 0x80,
		'#',
	};
	kermit_assert(kermit_decode(decode_test_in25, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('#'));

	const uint8_t decode_test_in26[] = {
		'#' | 0x80,
		' ',
	};
	kermit_assert(kermit_decode(decode_test_in26, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (' '));

	const uint8_t decode_test_in27[] = {
		'#' | 0x80,
		'>',
	};
	kermit_assert(kermit_decode(decode_test_in27, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('>'));

	const uint8_t decode_test_in28[] = {
		'#' | 0x80,
		'`',
	};
	kermit_assert(kermit_decode(decode_test_in28, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('`'));

	const uint8_t decode_test_in29[] = {
		'#' | 0x80,
		'~',
	};
	kermit_assert(kermit_decode(decode_test_in29, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('~'));

	const uint8_t decode_test_in30[] = {
		'#' | 0x80,
		'#' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in30, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('#' | 0x80));

	const uint8_t decode_test_in31[] = {
		'#' | 0x80,
		' ' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in31, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (' ' | 0x80));

	const uint8_t decode_test_in32[] = {
		'#' | 0x80,
		'>' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in32, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('>' | 0x80));

	const uint8_t decode_test_in33[] = {
		'#' | 0x80,
		'`' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in33, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('`' | 0x80));

	const uint8_t decode_test_in34[] = {
		'#' | 0x80,
		'~' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in34, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('~' | 0x80));

	const uint8_t decode_test_in35[] = {
		'#',
		'#' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in35, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('#' | 0x80));

	const uint8_t decode_test_in36[] = {
		'#',
		' ' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in36, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == (' ' | 0x80));

	const uint8_t decode_test_in37[] = {
		'#',
		'>' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in37, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('>' | 0x80));

	const uint8_t decode_test_in38[] = {
		'#',
		'`' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in38, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('`' | 0x80));

	const uint8_t decode_test_in39[] = {
		'#',
		'~' | 0x80,
	};
	kermit_assert(kermit_decode(decode_test_in39, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == ('~' | 0x80));

	const uint8_t decode_buf_test_in0[] = {
		'#',	    '?',	'#',	    '@',	'#',
		'A',	    '#',	'^',	    '#',	'_',

		'#' | 0x80, '?',	'#' | 0x80, '@',	'#' | 0x80,
		'A',	    '#' | 0x80, '^',	    '#' | 0x80, '_',

		'#' | 0x80, '?' | 0x80, '#' | 0x80, '@' | 0x80, '#' | 0x80,
		'A' | 0x80, '#' | 0x80, '^' | 0x80, '#' | 0x80, '_' | 0x80,

		'#',	    '?' | 0x80, '#',	    '@' | 0x80, '#',
		'A' | 0x80, '#',	'^' | 0x80, '#',	'_' | 0x80,

		'#',	    '#',	'#',	    ' ',	'#',
		'>',	    '#',	'`',	    '#',	'~',

		'#' | 0x80, '#',	'#' | 0x80, ' ',	'#' | 0x80,
		'>',	    '#' | 0x80, '`',	    '#' | 0x80, '~',

		'#' | 0x80, '#' | 0x80, '#' | 0x80, ' ' | 0x80, '#' | 0x80,
		'>' | 0x80, '#' | 0x80, '`' | 0x80, '#' | 0x80, '~' | 0x80,

		'#',	    '#' | 0x80, '#',	    ' ' | 0x80, '#',
		'>' | 0x80, '#',	'`' | 0x80, '#',	'~' | 0x80,
	};

	const uint8_t decode_buf_test_out0[] = {
		0x7F,	     0x00,	  0x01,	       0x1E,	    0x1F,
		0x7F,	     0x00,	  0x01,	       0x1E,	    0x1F,
		0x7F | 0x80, 0x00 | 0x80, 0x01 | 0x80, 0x1E | 0x80, 0x1F | 0x80,
		0x7F | 0x80, 0x00 | 0x80, 0x01 | 0x80, 0x1E | 0x80, 0x1F | 0x80,

		'#',	     ' ',	  '>',	       '`',	    '~',
		'#',	     ' ',	  '>',	       '`',	    '~',
		'#' | 0x80,  ' ' | 0x80,  '>' | 0x80,  '`' | 0x80,  '~' | 0x80,
		'#' | 0x80,  ' ' | 0x80,  '>' | 0x80,  '`' | 0x80,  '~' | 0x80,
	};

	kermit_assert(kermit_decode_buf(decode_buf_test_in0,
					sizeof(decode_buf_test_in0),
					kctx->buf) < KERMIT_BUFSIZE);
	kermit_assert(kermit_decode_buf(
			      decode_buf_test_in0, sizeof(decode_buf_test_in0),
			      kctx->buf) == sizeof(decode_buf_test_out0));
	kermit_assert(memcmp(kctx->buf, decode_buf_test_out0,
			     sizeof(decode_buf_test_out0)) == 0);

	kermit_assert(kermit_encode(0x00, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == '@');

	kermit_assert(kermit_encode(0x01, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == 'A');

	kermit_assert(kermit_encode(0x1E, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == '^');

	kermit_assert(kermit_encode(0x1F, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == '_');

	kermit_assert(kermit_encode(0x7F, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == '?');

	kermit_assert(kermit_encode(0x00 | 0x80, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == ('@' | 0x80));

	kermit_assert(kermit_encode(0x01 | 0x80, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == ('A' | 0x80));

	kermit_assert(kermit_encode(0x1E | 0x80, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == ('^' | 0x80));

	kermit_assert(kermit_encode(0x1F | 0x80, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == ('_' | 0x80));

	kermit_assert(kermit_encode(0x7F | 0x80, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == ('?' | 0x80));

	kermit_assert(kermit_encode('#', kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == '#');

	kermit_assert(kermit_encode('#' | 0x80, kctx->buf) == 2);
	kermit_assert(kctx->buf[0] == '#');
	kermit_assert(kctx->buf[1] == ('#' | 0x80));

	kermit_assert(kermit_encode(' ', kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == ' ');

	kermit_assert(kermit_encode('"', kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == '"');

	kermit_assert(kermit_encode(')', kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == ')');

	kermit_assert(kermit_encode('~', kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == '~');

	kermit_assert(kermit_encode(' ' | 0x80, kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == (' ' | 0x80));

	kermit_assert(kermit_encode('"' | 0x80, kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == ('"' | 0x80));

	kermit_assert(kermit_encode(')' | 0x80, kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == (')' | 0x80));

	kermit_assert(kermit_encode('~' | 0x80, kctx->buf) == 1);
	kermit_assert(kctx->buf[0] == ('~' | 0x80));

	uint8_t ni = 0;
	uint8_t en, dn;
	while (1) {
		en = kermit_encode(ni, kctx->buf);
		dn = kermit_decode(kctx->buf, kctx->buf);
		kermit_assert(en == dn);
		kermit_assert(kctx->buf[0] == ni);
		ni += 1;
		if (ni == 0) { // round
			break;
		}
	}

	kermit_pkt_init(kctx->buf, 0, 'D');
	kermit_assert(kermit_data_append(kctx->buf, 0x00) ==
		      KERMIT_HDR_SIZE + KERMIT_CHK_SIZE + 2);
	kermit_assert(kermit_data_append(kctx->buf, 0x20) ==
		      KERMIT_HDR_SIZE + KERMIT_CHK_SIZE + 2 + 1);
	kermit_assert(kermit_data_append(kctx->buf, 0x80) ==
		      KERMIT_HDR_SIZE + KERMIT_CHK_SIZE + 2 + 1 + 2);
	kermit_assert(kermit_data_append(kctx->buf, 0xA0) ==
		      KERMIT_HDR_SIZE + KERMIT_CHK_SIZE + 2 + 1 + 2 + 1);

	kermit_pkt_init(kctx->buf, 0, 'D');
	kermit_data_append(kctx->buf, 0x99);
	kermit_eol_upd(kctx->buf);
	kermit_assert(kctx->buf[kermit_len_get(kctx->buf)] == '\r');

	kermit_pkt_init(kctx->buf, 0, 'N');
	kermit_eol_upd(kctx->buf);
	kermit_assert(kctx->buf[kermit_len_get(kctx->buf)] == '\r');

	kermit_pkt_init(kctx->buf, 33, 'N');
	kermit_len_plus(kctx->buf, -1);
	kermit_assert(kermit_pkt_chk(kctx->buf) == false);

	kermit_pkt_init(kctx->buf, 13, 'Y');
	kermit_len_set(kctx->buf, KERMIT_BUFSIZE - 1);
	kermit_len_plus(kctx->buf, 2);
	kermit_assert(kermit_pkt_chk(kctx->buf) == false);

	kermit_pkt_init(kctx->buf, 11, 'Y');
	kermit_len_set(kctx->buf, KERMIT_BUFSIZE - 1);
	kermit_len_plus(kctx->buf, 1);
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_pkt_chk(kctx->buf) == false);

	kermit_pkt_init(kctx->buf, 44, 'N');
	kermit_len_set(kctx->buf, KERMIT_BUFSIZE - 1);
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_pkt_chk(kctx->buf) == false);

	kermit_pkt_init(kctx->buf, 55, 'Y');
	kermit_len_set(kctx->buf, KERMIT_BUFSIZE - 2);
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_pkt_chk(kctx->buf) == true);

	kermit_pkt_init(kctx->buf, 33, 'N');
	kermit_sum_upd(kctx->buf);
	kermit_assert(kermit_pkt_chk(kctx->buf) == true);

	kctx->idx = 0;
	kctx->rxdone = false;
	kermit_handle_char(kctx, 0x1);
	kermit_assert(kctx->idx == 1);

	kctx->idx = 0;
	kctx->rxdone = false;
	kermit_handle_char(kctx, 0x2);
	kermit_assert(kctx->idx == 0);

	kctx->idx = 0;
	kctx->rxdone = false;
	kermit_handle_char(kctx, 0x0);
	kermit_assert(kctx->idx == 0);

	kctx->idx = 0;
	kctx->rxdone = false;
	kermit_handle_char(kctx, 0x1);
	kermit_handle_char(kctx, '\r');
	kermit_assert(kctx->idx == 1);
	kermit_assert(kctx->idx == true);

	kctx->idx = 0;
	kctx->rxdone = false;
	kermit_handle_char(kctx, 0x1);
	kermit_handle_char(kctx, '\r');
	kermit_assert(kctx->idx == 1);
	kermit_assert(kctx->idx == true);

	kctx->rxdone = true;
	kctx->idx = 99;
	kermit_rx_reset(kctx);
	kermit_assert(kctx->rxdone == false);
	kermit_assert(kctx->idx == 0);

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_pkt_init(kctx->buf, 1, 'Y');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kermit_pkt_send(kctx);
	kermit_assert(memcmp(kctx->buf, &test_link_buf[0],
			     kermit_len_get(kctx->buf) + KERMIT_EOL_SIZE) != 0);

	kctx->link_send = test_link_send;

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_pkt_init(kctx->buf, 0, 'N');
	kermit_pkt_send(kctx);
	kermit_assert(memcmp(kctx->buf, &test_link_buf[0],
			     kermit_len_get(kctx->buf) + KERMIT_EOL_SIZE) != 0);

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_pkt_init(kctx->buf, 1, 'Y');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kermit_pkt_send(kctx);
	kermit_assert(memcmp(kctx->buf, &test_link_buf[0],
			     kermit_len_get(kctx->buf) + KERMIT_EOL_SIZE) == 0);
	kermit_assert(test_link_buf[KERMIT_MARK] == 0x01);


	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_nak(kctx);
	kermit_assert(kermit_seq_get(kctx->buf) == kctx->lseqn);
	kermit_assert(kermit_type_get(kctx->buf) == 'N');
	kermit_assert(kermit_seq_get(test_link_buf) == kctx->lseqn);
	kermit_assert(kermit_type_get(test_link_buf) == 'N');
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_ack(kctx, 5);
	kermit_assert(kermit_seq_get(kctx->buf) == 5);
	kermit_assert(kermit_type_get(kctx->buf) == 'Y');
	kermit_assert(kermit_seq_get(test_link_buf) == 5);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_ack(kctx, 7);
	kermit_assert(kermit_seq_get(kctx->buf) == 7);
	kermit_assert(kermit_type_get(kctx->buf) == 'Y');
	kermit_assert(kermit_seq_get(test_link_buf) == 7);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);

	kermit_assert(kermit_param_fill(kctx->buf, 0) == 0);
	kermit_assert(kermit_param_fill(kctx->buf, 1) == 1);
	kermit_assert(kctx->buf[KERMIT_PARAM_MAXL] < (kermit_tochar(KERMIT_BUFSIZE) - KERMIT_EOL_SIZE));
	kermit_assert(kctx->buf[KERMIT_PARAM_MAXL] > 0x1F);
	kermit_assert(kctx->buf[KERMIT_PARAM_MAXL] < 0x7F);

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_make_sinit(kctx->buf, KERMIT_BUFSIZE, 0);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kctx->rxdone == false);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kermit_seq_get(test_link_buf) == 0);
	kermit_assert(kermit_datalen_get(test_link_buf) >= 1);
	kermit_assert(test_link_buf[KERMIT_DATA + KERMIT_PARAM_MAXL] > 0x1F);
	kermit_assert(test_link_buf[KERMIT_DATA + KERMIT_PARAM_MAXL] < 0x7F);
	kermit_assert(test_link_buf[KERMIT_PARAM_MAXL] < (kermit_tochar(KERMIT_BUFSIZE) - KERMIT_EOL_SIZE));

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kermit_make_sinit(kctx->buf, KERMIT_HDR_SIZE + KERMIT_CHK_SIZE + KERMIT_EOL_SIZE, 1);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kctx->rxdone == false);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kermit_seq_get(test_link_buf) == 1);
	kermit_assert(kermit_datalen_get(test_link_buf) == 0);

	kctx->lseqn = 0;
	kermit_assert(kermit_seq_isdup(kctx, 63) == true);
	kermit_assert(kermit_seq_isout(kctx, 63) == false);
	kermit_assert(kermit_seq_isdup(kctx, 0) == false);
	kermit_assert(kermit_seq_isout(kctx, 0) == false);

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn + 1) & KERMIT_SEQ_MASK, 0xFF);
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == kctx->lseqn);
	kermit_assert(kermit_type_get(test_link_buf) == 'N');

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn - 2) & KERMIT_SEQ_MASK, 0xFF);
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == kctx->lseqn);
	kermit_assert(kermit_type_get(test_link_buf) == 'N');

	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_error(kctx, "HELLO WORLD");
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == kctx->lseqn);
	kermit_assert(kermit_type_get(test_link_buf) == 'E');
	kermit_assert(kermit_decode_buf(&test_link_buf[KERMIT_DATA],
					kermit_datalen_get(test_link_buf),
					&test_link_buf[KERMIT_DATA]) ==
		      strlen("HELLO WORLD"));
	kermit_assert(memcmp(&test_link_buf[KERMIT_DATA], "HELLO WORLD",
			     strlen("HELLO WORD")) == 0);

	kctx->unknown_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, kctx->lseqn, 0xFF);
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == kctx->lseqn);
	kermit_assert(kermit_type_get(test_link_buf) == 'E');

	kctx->fhdr_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, kctx->lseqn, 'F');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == 0);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 1);

	kctx->fhdr_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn - 1) & KERMIT_SEQ_MASK, 'F');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == ((kctx->lseqn - 1) & KERMIT_SEQ_MASK));
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 0);

	kctx->data_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, kctx->lseqn, 'D');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == 0);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 1);

	kctx->data_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn - 1) & KERMIT_SEQ_MASK, 'D');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == ((kctx->lseqn - 1) & KERMIT_SEQ_MASK));
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 0);
	
	kctx->eof_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, kctx->lseqn, 'Z');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == 0);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 1);

	kctx->eof_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn - 1) & KERMIT_SEQ_MASK, 'Z');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == ((kctx->lseqn - 1) & KERMIT_SEQ_MASK));
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 0);

	kctx->break_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, kctx->lseqn, 'B');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == 0);
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 0);

	kctx->eof_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn - 1) & KERMIT_SEQ_MASK, 'B');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kermit_pkt_chk(test_link_buf) == true);
	kermit_assert(kermit_seq_get(test_link_buf) == ((kctx->lseqn - 1) & KERMIT_SEQ_MASK));
	kermit_assert(kermit_type_get(test_link_buf) == 'Y');
	kermit_assert(kctx->lseqn == 0);

	kctx->error_cb = NULL;
	bzero(&test_link_buf[0], KERMIT_BUFSIZE);
	kctx->lseqn = 0;
	kermit_pkt_init(kctx->buf, (kctx->lseqn - 4) & KERMIT_SEQ_MASK, 'E');
	kermit_sum_upd(kctx->buf);
	kermit_eol_upd(kctx->buf);
	kctx->rxdone = true;
	kermit_handle_rxpkt(kctx);
	kermit_assert(kctx->rxdone == false);
}

void test_link_send(uint8_t *buf, uint8_t len)
{
	memcpy(&test_link_buf[0], &buf[0],
	       len < KERMIT_BUFSIZE ? len : KERMIT_BUFSIZE);
}
