#ifndef _DEDUP_H
#define _DEDUP_H

#define CHECKSUMSIZE	4
#define	BLOCKSIZE	4096
#define MEBI (1024ULL*1024ULL)
#define MIN_SUBVOL 257

#define DEDUP_ZERO_CRC	0x98f94189

#define DEDUP_SPECIAL_OFFSET_ZEROES (-1ULL)

#include <assert.h>

#ifdef DEDUP_DEBUG_REASONABLE
# ifndef DEDUP_DEBUG_MAX_INODE
#  define DEDUP_DEBUG_MAX_INODE 10*MEBI
# endif
# ifndef DEDUP_DEBUG_MAX_ROOT
#  define DEDUP_DEBUG_MAX_ROOT MEBI
# endif
# ifndef DEDUP_DEBUG_MAX_LOGICAL
#  define DEDUP_DEBUG_MAX_LOGICAL 1000ULL*MEBI*MEBI
# endif
# ifndef DEDUP_DEBUG_MAX_FILEOFFSET
#  define DEDUP_DEBUG_MAX_FILEOFFSET 1024ULL*1024ULL*MEBI
# endif
# ifndef DEDUP_DEBUG_MAX_COUNT
#  define DEDUP_DEBUG_MAX_COUNT 1000
# endif
#endif

static inline void DEDUP_ASSERT_INODE(uint64_t inode) {
	(void)inode;
#ifdef DEDUP_DEBUG_MAX_INODE
	uint64_t max=(DEDUP_DEBUG_MAX_INODE);
	assert(max >= inode);
#endif
}

static inline void DEDUP_ASSERT_ROOT(uint64_t root) {
	(void)root;
#ifdef DEDUP_DEBUG_MAX_ROOT
	uint64_t max=(DEDUP_DEBUG_MAX_ROOT);
	assert(max >= root);
#endif
}

static inline void DEDUP_ASSERT_LOGICAL(uint64_t logical) {
#ifdef DEDUP_DEBUG_MAX_LOGICAL
	uint64_t max=(DEDUP_DEBUG_MAX_LOGICAL);
	assert(max >= logical);
#endif
	assert(0==logical%BLOCKSIZE);
}

static inline void DEDUP_ASSERT_FILEOFFSET(uint64_t fileoffset) {
#ifdef DEDUP_DEBUG_MAX_FILEOFFSET
	uint64_t max=(DEDUP_DEBUG_MAX_FILEOFFSET);
	assert(max >= fileoffset);
#endif
	assert(0==fileoffset%BLOCKSIZE);
}

static inline void DEDUP_ASSERT_COUNT(uint64_t count) {
#ifdef DEDUP_DEBUG_MAX_FILEOFFSET
	uint64_t max=(DEDUP_DEBUG_MAX_COUNT);
	assert(max >= count);
#endif
	assert(count);
}

static inline void DEDUP_ASSERT_STATIC_FS(int assertion) {
	(void)assertion;
#ifdef DEDUP_DEBUG_STATIC_FS
	assert(assertion);
#endif
}

#define DEDUP_DEBUG_STRINGIFY_MACRO(x) #x
#define DEDUP_DEBUG_NAME_MACRO(x) DEDUP_DEBUG_STRINGIFY_MACRO(x)
#define DEDUP_DEBUG_LINK_SRCFILE_NAME DEDUP_DEBUG_NAME_MACRO(DEDUP_DEBUG_LINK_SRCFILE)

#include <btrfs/ioctl.h>

static inline uint64_t MIN(uint64_t x, uint64_t y) {
	return (((x)>(y))?(y):(x));
}

typedef struct {
	uint64_t key;
	uint64_t index;
} metaindex_t;

uint64_t getmetaindex(uint64_t index, uint64_t *checkinds, uint64_t metalen);
int64_t do_search(int fd, uint32_t **checksums, uint64_t **checkoffs, uint64_t **checkinds);
int64_t do_extent_search(int fd, uint64_t **extsums, uint64_t **extoffs, uint64_t **extinds, uint64_t max_generation);

int64_t find_zeros(uint32_t *checksums, uint64_t *checkoffs, uint64_t *checkinds, uint64_t **dedups, uint64_t metalen, uint64_t minextlen);
int64_t do_sais(uint32_t *checksums, uint64_t *checkoffs, uint64_t *checkinds, uint64_t **dedups, uint64_t metalen, uint64_t minsumsize, uint64_t minextlen);

int rtable_init(uint64_t size);
uint64_t rtable_destroy();
size_t logical_resolve(int fd, uint64_t logical, uint64_t *results, size_t *size);
int open_by_inode(int atfd, uint64_t inum, uint64_t root);
int64_t btrfs_iterate_tree(int fd, uint64_t tree, void *private, int (*callback)(void*, struct btrfs_ioctl_search_header*, void*));
int btrfs_dedup(int fd, uint64_t logical, uint64_t len, int *fds, uint64_t *offsets, unsigned count, int64_t *results);
int64_t btrfs_get_generation(int fd);
int btrfs_clone_range(int src_fd, int dest_fd, uint64_t src_offset, uint64_t dest_offset, uint64_t len);
int btrfs_syncfs(int fd);

int do_dedups(int atfd, uint64_t *dedups, uint64_t deduplen, uint64_t rtable_size, uint64_t generation);

#endif


