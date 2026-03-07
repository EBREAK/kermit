CFLAGS += -Wall -Wextra -Wpedantic

krx:
	$(CC) $(CFLAGS) krx.c -o krx

clean:
	rm -f *.out krx ktx
