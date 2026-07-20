CFLAGS += -Wall -Wextra -Wpedantic -Oz -ggdb

all: kr ks

kr:
	$(CC) $(CFLAGS) kermit.c kermit_test.c kr.c -o kr

ks:
	$(CC) $(CFLAGS) kermit.c kermit_test.c ks.c -o ks

clean:
	rm -f *.out kr ks

ctags:
	ctags *.c *.h
