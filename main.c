#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <limits.h>
#include "dedup.h"
#include <argp.h>
#include <time.h>

struct arguments {
	uint64_t rtable_size;
	char *mount_point;
	unsigned minextlen;
	int minsumsize;
};

static struct argp_option options[] = {
	{"minisum", 'c', "CHECKSIZE", 0, "Use reduced checksum size CHECKSIZE for sais", 0},
	{"extlen", 'e', "EXTENT_LEN", 0, "Deduplicate extents of at least size EXTENT_LEN", 0},
	{"rtable", 'r', "EXTENT_LEN", 0, "Set root hashtable size", 0},
	{0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	int temp;
	switch(key) {
		case 'c':
			arguments->minsumsize = atoi(arg);
			if (2 != arguments->minsumsize) {
				fprintf(stderr, "Invalid reduced checksum size %d try 2\n", arguments->minsumsize);
				argp_usage(state);
			}
			break;
		case 'e':
			temp = atoi(arg);
			if (0 > temp || INT_MAX == temp) {
				fprintf(stderr, "Invalid minimum extent shared len %d\n", temp);
				argp_usage(state);
			}
			arguments->minextlen=temp;
			break;
		case 'r':
			temp = atoi(arg);
			if (0 > temp || INT_MAX == temp) {
				fprintf(stderr, "Invalid root hashtable size %d\n", temp);
				argp_usage(state);
			}
			arguments->rtable_size=temp;
			break;
		case ARGP_KEY_ARG:
			if (1 < state->arg_num) argp_usage(state);
			arguments->mount_point=arg;
			break;
		case ARGP_KEY_END:
			if (1 != state->arg_num) argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, "MOUNT_POINT", "Deduplicate a file system", 0, 0, 0};

int main(int argc, char **argv) {
	uint32_t *inmem=NULL;
	uint64_t *checkoffs=NULL;
	uint64_t *checkinds=NULL;
	uint64_t *dedups=NULL;
	int ret=0;
	time_t prevtime=time(NULL);
	
	struct arguments arguments;
	memset(&arguments,0,sizeof(arguments));
	arguments.minsumsize=2;
	arguments.minextlen=4;
	arguments.rtable_size=1024;
	
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	int atfd=open(arguments.mount_point, O_RDONLY);
	if (0 > atfd) {
		perror("Unable to open mount point");
		exit(EXIT_FAILURE);
	}
	ret=btrfs_syncfs(atfd);
	assert(0<=ret);

	int64_t generation=btrfs_get_generation(atfd);
	int64_t metalen = do_search(atfd, &inmem, &checkoffs, &checkinds);
	if (0>metalen) {
		fprintf(stderr, "Search failed with %s\n", strerror(-metalen));
		return EXIT_FAILURE;
	}
	assert(INT_MAX>metalen);
	printf("Search done %lu checksums in %lu pieces, took %lu s\n", checkinds[metalen],metalen, (uint64_t)(time(NULL)-prevtime));
	prevtime=time(NULL);
	int64_t deduplen = find_zeros(inmem, checkoffs, checkinds, &dedups, metalen, arguments.minextlen);
	assert(0<=deduplen);
	printf("Dedup zerofind done %lu candidates, took %lu s\n", deduplen, (uint64_t)(time(NULL)-prevtime));
	prevtime=time(NULL);
	free(inmem);
	free(checkinds);
	free(checkoffs);

	ret=do_dedups(atfd, dedups, deduplen, arguments.rtable_size, generation);
	assert(0 <= ret);
	printf("Hole punch done, took %lu s, %lu root cache misses\n", (uint64_t)(time(NULL)-prevtime), rtable_destroy());
	free(dedups);
#ifdef DEDUP_DEBUG_LINK_SRCFILE
	ret=renameat(atfd, DEDUP_DEBUG_LINK_SRCFILE_NAME, atfd, DEDUP_DEBUG_LINK_SRCFILE_NAME "-zeros");
	assert(0<=ret);
#endif
	ret=btrfs_syncfs(atfd);
	assert(0<=ret);

	generation=btrfs_get_generation(atfd);
	metalen = do_search(atfd, &inmem, &checkoffs, &checkinds);
	if (0>metalen) {
		fprintf(stderr, "Search failed with %s\n", strerror(-metalen));
		return EXIT_FAILURE;
	}
	assert(INT_MAX>metalen);
	printf("Search done %lu checksums in %lu pieces, took %lu s\n", checkinds[metalen],metalen, (uint64_t)(time(NULL)-prevtime));
	prevtime=time(NULL);
	deduplen = do_sais(inmem, checkoffs, checkinds, &dedups, metalen, arguments.minsumsize, arguments.minextlen);
	assert(0<=deduplen);
	printf("Dedup sort done %lu candidates, took %lu s\n", deduplen, (uint64_t)(time(NULL)-prevtime));
	prevtime=time(NULL);
	free(inmem);
	free(checkinds);
	free(checkoffs);

	ret=do_dedups(atfd, dedups, deduplen, arguments.rtable_size, generation);
	assert(0 <= ret);
	printf("Dedup done, took %lu s, %lu root cache misses\n", (uint64_t)(time(NULL)-prevtime), rtable_destroy());
	free(dedups);
	close(atfd);

	return !!ret;
}
