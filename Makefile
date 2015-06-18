LIBFILES = dedup.c libbtrfs.c sais.c search.c

EXES = dedup

all: $(EXES)

dedup: main.c $(LIBFILES)
	gcc -DDEDUP_DEBUG_REASONABLE -g -o dedup -Wall -Wextra -pedantic -std=c11 $< $(LIBFILES) -lsais64 -lsais -lbtrfs

clean:
	rm -f $(EXES) *.o
