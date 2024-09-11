# in `elk/samples/chimera/Makefile`

CFLAGS  := -fPIC
LDFLAGS := -nostartfiles -nodefaultlibs -L. -Wl,-m_rpath='$$ORIGIN'

all: chimera

chimera: chimera.c
	gcc -c chimera.c ${CFLAGS}
	gcc chimera.o -o chimera ${LDFLAGS}

clean:
	rm -f chimera *.o *.so
