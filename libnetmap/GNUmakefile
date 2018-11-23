CFLAGS=-O2
VPATH = $(SRCDIR)/libnetmap
SRCS=$(wildcard $(SRCDIR)/libnetmap/*.c)
OBJS=$(SRCS:.c=.o)

all: libnetmap.a

$(OBJS): libnetmap.h

libnetmap.a: $(OBJS)
	$(AR) r $@ $^

.PHONY: clean distclean
clean:
	rm -f *.o

distclean: clean
	rm -f libnetmap.a

+%:
	@echo $*=$($*)
