CC=gcc
CFLAGS=-O0 -g -Wall  -I. -I/usr/include/glib-2.0/ -I/usr/lib/glib-2.0/include/
LDFLAGS=-levent -lglib-2.0 -lpthread
OBJ-mgcpslapd=mgcpslapd.o mgcp.o socket.o valstring.o

all: mgcpslapd

mgcpslapd: $(OBJ-mgcpslapd)
	gcc $(LDFLAGS) -o $@ $+

clean:
	-rm -f $(OBJ-mgcpslapd)
	-rm -f mgcpslapd
	-rm -f core vgcore.pid* core.* gmon.out

distclean: clean
	-rm -rf CVS .cvsignore
