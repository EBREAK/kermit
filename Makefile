krx:
	cc -Wall -Wextra -Wpedantic krx.c -o krx

clean:
	rm -f *.out krx ktx
