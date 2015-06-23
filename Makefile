LIBFILES = dedup.c libbtrfs.c sais.c search.c

EXES = dedup

all: $(EXES)

dedup: main.c $(LIBFILES)
	$(CC) -DDEDUP_DEBUG_REASONABLE -DDEDUP_DEBUG_LINK_SRCFILE=srcfile -DDEDUP_DEBUG_STATIC_FS -g -o dedup -Wall -Wextra -pedantic -std=c11 $< $(LIBFILES) -lsais64 -lsais -lbtrfs

clean:
	rm -f $(EXES) *.o
