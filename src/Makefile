# Generated automatically from Makefile.in by configure.
CC=gcc
CFLAGS=-g -I/usr/include  -Wall 
LD=-L/usr/lib  -lssl -lcrypto
DISTDIR=openssl-examples-20010815
DISTFILE=${DISTDIR}.tar.gz

DIST= client.c \
	client.h \
	common.c \
	common.h \
	mkcert.c \
	server.c \
	server.h \
	server-revoke.c \
	wserver.c \
	read_write.c \
	read_write.h \
	wclient.c \
	rohan.pem \
	revoke.pem \
	server.pem \
	root.pem \
	dh1024.pem \
	README \
	RUNNING 

OBJS=common.o 

all:  wclient wserver ca

wclient: wclient.o client.o  $(OBJS)
	$(CC) wclient.o client.o $(OBJS) -o wclient $(LD)

wserver: server.o wserver.o  $(OBJS)
	$(CC) wserver.o server.o $(OBJS) -o wserver $(LD)

ca: mkcert.o
	$(CC) mkcert.o -o makecert $(LD)

clean:	
	rm *.o wclient wserver makecert
dist:
	rm -rf ${DISTDIR}; mkdir ${DISTDIR}
	cp ${DIST} ${DISTDIR}
	rm -f ${DISTFILE}
	tar cf - ${DISTDIR} | gzip > ${DISTFILE}
