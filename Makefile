PROGRAM = netprobe
OBJS = netprobe.o log.o debug.o parse_domain.o plugin.o plugins/tcp_retransmit.o

CFLAGS = -I. -Wall -g -O0
LDFLAGS =
LDLIBS = -lpcap

.SUFFIXES: .c .o

$(PROGRAM): $(OBJS)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(LDFLAGS) $(LDLIBS) $^

.PHONY: clean
clean:
	$(RM) $(PROGRAM) $(OBJS)

