CC=gcc
CFLAGS=-O0 -g -Wall  -I. -I/usr/include/glib-2.0/ -I/usr/lib/glib-2.0/include/
LDFLAGS=-levent -lglib-2.0 -lpthread
OBJ-mgcpslapd=mgcpslapd.o mgcp.o socket.o valstring.o logging.o slap.o gw.o util.o

all: mgcpslapd

mgcpslapd: $(OBJ-mgcpslapd)
	gcc $(LDFLAGS) -o $@ $+

tags:
	ctags *.c *.h	

clean:
	-rm -f $(OBJ-mgcpslapd)
	-rm -f mgcpslapd
	-rm -f core vgcore.pid* core.* gmon.out
	-rm -f tags

distclean: clean
	-rm -rf CVS .cvsignore
