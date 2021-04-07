CC= gcc
#CFLAGS= -Wall -w -O3 -g -std=c99 -mtune=native -DNDEBUG
#CFLAGS= -Wall -w -O3 -g -std=c99 -march=native -DNDEBUG
CFLAGS= -Werror -std=c99 -lpthread -Warray-bounds=2

all:
	$(CC) $(CFLAGS) *.c -o a.out

clean:
	rm -f *.exe *.out *.o
