CFLAGS += -Wall -Wextra -Wpedantic -Oz -ggdb

kr:
	$(CC) $(CFLAGS) kermit.c kermit_test.c kr.c -o kr

clean:
	rm -f *.out kr
