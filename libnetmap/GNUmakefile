CFLAGS=-O2
VPATH = $(SRCDIR)/libnetmap

libnetmap.a: nmreq.o nmport.o nmctx.o
	$(AR) r $@ $^

.PHONY: clean distclean
clean:
	rm -f *.o

distclean: clean
	rm -f libnetmap.a
