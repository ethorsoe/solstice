#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <btrfs/ioctl.h>
#include <btrfs/ctree.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include "dedup.h"

typedef struct {
	uint64_t metaoffset;
	uint64_t metalen;
	uint64_t checklen;
	uint32_t *checksums;
	uint64_t *checkoffs;
	uint64_t *checkinds;
} search_ck_private_t;

static int search_checksum_cb(void *data, struct btrfs_ioctl_search_header *sh, void *private) {
	assert(sh->objectid == BTRFS_EXTENT_CSUM_OBJECTID);
	assert(sh->type == BTRFS_EXTENT_CSUM_KEY);
	assert(sh->len%CHECKSUMSIZE == 0);
	int nsums = sh->len/CHECKSUMSIZE;
	search_ck_private_t *my_private=private;

	uint64_t checkoffset=my_private->checkinds[my_private->metaoffset];
	memcpy(my_private->checksums+checkoffset, data, sh->len);
	checkoffset+=nsums;

	if (!my_private->metaoffset || (sh->offset-(my_private->checkoffs)[my_private->metaoffset-1]) != BLOCKSIZE*((my_private->checkinds)[my_private->metaoffset]-(my_private->checkinds)[my_private->metaoffset-1]) ) {
		(my_private->checkoffs)[my_private->metaoffset++]=sh->offset;
	}
	(my_private->checkinds)[my_private->metaoffset]=checkoffset;
	if (my_private->checklen-checkoffset < MEBI) {
		my_private->checklen+=32*MEBI;
		my_private->checksums=realloc(my_private->checksums, my_private->checklen*sizeof(uint32_t));
	}
	if (my_private->metalen-my_private->metaoffset <= MEBI) {
		my_private->metalen+=32*MEBI;
		my_private->checkoffs=realloc(my_private->checkoffs, my_private->metalen*sizeof(uint64_t));
		my_private->checkinds=realloc(my_private->checkinds, my_private->metalen*sizeof(uint64_t));
	}

	return 0;
}

typedef struct {
	uint64_t metaoffset;
	uint64_t metalen;
	uint64_t extlen;
	uint64_t *extsums;
	uint64_t *extoffs;
	uint64_t *extinds;
	uint64_t generation;
} search_extent_private_t;

enum allowed_type {
	TYPE_ERROR,
	TYPE_IGNORE,
	TYPE_ALLOW
};
enum allowed_type types[256];

static int search_extsum_cb(void *data, struct btrfs_ioctl_search_header *sh, void *private) {
	search_extent_private_t *my_private=private;
	uint64_t extoffset=my_private->extinds[my_private->metaoffset];
	assert(256 > sh->type);
	assert((16*1024) > sh->len);
	if (TYPE_IGNORE == types[sh->type])
		return 0;
	assert(TYPE_ALLOW == types[sh->type]);
	if (BTRFS_EXTENT_DATA_REF_KEY == sh->type){
			assert(0<my_private->metaoffset && my_private->extoffs[my_private->metaoffset-1] == sh->objectid);
			struct btrfs_extent_data_ref *eref=data;
			DEDUP_ASSERT_RELATIVE_FILEOFFSET(eref->offset);
			DEDUP_ASSERT_INODE(eref->objectid);
			DEDUP_ASSERT_ROOT(eref->root);
			DEDUP_ASSERT_COUNT(eref->count);
			my_private->extsums[extoffset++]=eref->objectid;
			my_private->extsums[extoffset++]=eref->offset;
			my_private->extsums[extoffset++]=eref->root;
			my_private->extsums[extoffset++]=eref->count;
			my_private->extinds[my_private->metaoffset]=extoffset;
	} else {
		assert(BTRFS_EXTENT_ITEM_KEY == sh->type);
		assert(24 < sh->len);
		struct btrfs_extent_item* eitem=data;
		if (2 == eitem->flags)
			return 0;
		if (my_private->generation < eitem->generation)
			return 0;
		assert(1 == eitem->flags);

		my_private->extsums[extoffset++]=sh->offset;

		int found=0;
		for (struct btrfs_extent_inline_ref *iref=(struct btrfs_extent_inline_ref*)(eitem+1); iref < (struct btrfs_extent_inline_ref *)(sh->len+(char*)data);) {
			if (BTRFS_SHARED_DATA_REF_KEY == iref->type) {
				struct btrfs_shared_data_ref *sref=(struct btrfs_shared_data_ref*)(iref+1);
				iref=(struct btrfs_extent_inline_ref*)(sref+1);
				continue;
			}
			assert(BTRFS_EXTENT_DATA_REF_KEY == iref->type);
			struct btrfs_extent_data_ref *eref=(void*)&(iref->offset);
			iref=(struct btrfs_extent_inline_ref*)(eref+1);

			if (BTRFS_FS_TREE_OBJECTID != eref->root && MIN_SUBVOL >= eref->root) {
				return 0;
			}

			DEDUP_ASSERT_RELATIVE_FILEOFFSET(eref->offset);
			DEDUP_ASSERT_INODE(eref->objectid);
			DEDUP_ASSERT_ROOT(eref->root);
			DEDUP_ASSERT_COUNT(eref->count);
			my_private->extsums[extoffset++]=eref->objectid;
			my_private->extsums[extoffset++]=eref->offset;
			my_private->extsums[extoffset++]=eref->root;
			my_private->extsums[extoffset++]=eref->count;

			found=1;
		}
		if (!found)
			return 0;

		my_private->extoffs[my_private->metaoffset++]=sh->objectid;
		my_private->extoffs[my_private->metaoffset]=sh->objectid+sh->offset;
		my_private->extinds[my_private->metaoffset]=extoffset;
	}
	if (my_private->extlen-extoffset < MEBI) {
		my_private->extlen+=32*MEBI;
		my_private->extsums=realloc(my_private->extsums, my_private->extlen*sizeof(uint64_t));
	}
	if (my_private->metalen-my_private->metaoffset <= MEBI) {
		my_private->metalen+=32*MEBI;
		my_private->extoffs=realloc(my_private->extoffs, my_private->metalen*sizeof(uint64_t));
		my_private->extinds=realloc(my_private->extinds, my_private->metalen*sizeof(uint64_t));
	}

	return 0;
}

uint64_t getmetaindex(uint64_t index, uint64_t *checkinds, uint64_t metalen) {
	uint64_t high=metalen, low=0;
	assert(index<checkinds[high]);
	while(1) {
		assert(high>low);
		if (high-1==low)
			return low;
		uint64_t next=(high+low)/2;
		if (index >= checkinds[next]) {
			low=next;
		}
		else
			high=next;
	}
	abort();
	return 0;
}

int64_t do_search(int fd, uint32_t **checksums, uint64_t **checkoffs, uint64_t **checkinds) {
	assert(sizeof(uint32_t)==CHECKSUMSIZE);
	
	search_ck_private_t private;

	private.metalen=32*MEBI;
	private.metaoffset=0;
	private.checklen=32*MEBI;
	private.checksums=malloc(private.checklen*sizeof(uint32_t));
	assert(private.checksums);
	private.checkoffs=malloc(private.metalen*sizeof(uint64_t));
	assert(private.checkoffs);
	private.checkinds=malloc(private.metalen*sizeof(uint64_t));
	assert(private.checkinds);
	private.checkinds[0]=0;

	int64_t ret=btrfs_iterate_tree(fd, BTRFS_CSUM_TREE_OBJECTID, &private, search_checksum_cb);

	if (0 > ret) {
		free(private.checksums);
		free(private.checkoffs);
		free(private.checkinds);
		return ret;
	}
	*checksums=private.checksums;
	*checkoffs=private.checkoffs;
	*checkinds=private.checkinds;
	return private.metaoffset;
}

#define allowtype(x) types[x]=TYPE_ALLOW
#define ignoretype(x) types[x]=TYPE_IGNORE
int64_t do_extent_search(int fd, uint64_t **extsums, uint64_t **extoffs, uint64_t **extinds, uint64_t max_generation) {
	assert(sizeof(uint32_t)==CHECKSUMSIZE);
	
	search_extent_private_t private;

	private.metalen=32*MEBI;
	private.metaoffset=0;
	private.extlen=32*MEBI;
	private.extsums=malloc(private.extlen*sizeof(uint64_t));
	assert(private.extsums);
	private.extoffs=malloc(private.metalen*sizeof(uint64_t));
	assert(private.extoffs);
	private.extinds=malloc(private.metalen*sizeof(uint64_t));
	assert(private.extinds);
	private.extinds[0]=0;
	private.generation=max_generation;

	memset(types, 0, sizeof(types));
	allowtype(BTRFS_EXTENT_ITEM_KEY);
	allowtype(BTRFS_EXTENT_DATA_REF_KEY);
	ignoretype(BTRFS_BLOCK_GROUP_ITEM_KEY);
	ignoretype(BTRFS_METADATA_ITEM_KEY);
	ignoretype(BTRFS_SHARED_DATA_REF_KEY);
	
	btrfs_iterate_tree(fd, BTRFS_EXTENT_TREE_OBJECTID, &private, search_extsum_cb);

	*extsums=private.extsums;
	*extoffs=private.extoffs;
	*extinds=private.extinds;
	return private.metaoffset;
}
