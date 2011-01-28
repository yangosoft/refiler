CFLAGS=-Wall -Werror -D_GNU_SOURCE -g
OBJS= ptrace.o attach.o refiler.o

all: refiler

refiler: $(OBJS)

clean:
	rm -f refiler $(OBJS)
