
CC=gcc
CFLAGS=-g `apxs2 -q CFLAGS` -fPIC -DSHARED_MODULE -D_LARGEFILE64_SOURCE -I/usr/include/apache2 `apr-1-config --includes` -Ioxdigest/include
COMPILE=${CC} -c ${CFLAGS}
LD=ld
LIBS=-Loxdigest/lib -Loxdigest/base64/lib -loxdigest -lbase64 -lcrypto
LDFLAGS=-Bshareable
LINK=${LD} ${LDFLAGS}


all: mod_oxfilter.o mod_oxdigest.o bstrstr.o
	${LINK} -o mod_oxfilter.so mod_oxfilter.o bstrstr.o ${LIBS}
	${LINK} -o mod_oxdigest.so mod_oxdigest.o bstrstr.o ${LIBS}

mod_oxdigest.o: mod_oxdigest.c
	${COMPILE} $< -o $@

mod_oxfilter.o: mod_oxfilter.c
	${COMPILE} $< -o $@

clean:
	rm -f *.o *.so || true > /dev/null 2>&1

install:
	cp mod_oxfilter.so /usr/lib/apache2/modules
	cp mod_oxdigest.so /usr/lib/apache2/modules

