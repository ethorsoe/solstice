#define _XOPEN_SOURCE 9000
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <btrfs/ioctl.h>
#include <btrfs/rbtree.h>
#include <btrfs/btrfs-list.h>
#include <btrfs/ctree.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "dedup.h"

typedef struct {
	uint64_t rootid;
	int fd;
} roothash;

static roothash *rtable=NULL;
static uint64_t rtable_size=0;
static uint64_t rtable_misses=0;

int rtable_init(uint64_t size) {
	rtable_size=size;
	rtable=calloc(size,sizeof(roothash));
	if (!rtable)
		return -ENOMEM;
	for (uint64_t i=0; i<rtable_size;i++)
		rtable[i].fd=-1;
	return 0;
}

uint64_t rtable_destroy(){
	assert(rtable != NULL && rtable_size);
	for (uint64_t i=0; i<rtable_size;i++) {
		if (0 <= rtable[i].fd)
			close(rtable[i].fd);
	}
	free(rtable);
	rtable=NULL;
	rtable_size=0;
	return rtable_misses;
}

static int get_rootfd(int atfd, uint64_t root) {
	assert(rtable != NULL && rtable_size);
	if (BTRFS_FS_TREE_OBJECTID == root)
		return atfd;
	assert(MIN_SUBVOL<=root);

	uint64_t index = (root-MIN_SUBVOL)%rtable_size;
	if (rtable[index].rootid == root)
		return rtable[index].fd;
	rtable_misses++;

	char *name = btrfs_list_path_for_root(atfd, root);
	assert(name);
	if (IS_ERR(name)) {
		return -PTR_ERR(name);
	}
	int path_fd=openat(atfd,name,O_RDONLY);
	if (path_fd < 0) {
		path_fd=-errno;
	}
	free(name);

	if (0 <= path_fd) {
		if (rtable[index].rootid && close(rtable[index].fd))
			abort();
		rtable[index].fd=path_fd;
		rtable[index].rootid=root;
	}

	return path_fd;
}

static int __ino_to_path_fd(u64 inum, int atfd)
{
	int ret;
	struct btrfs_ioctl_ino_path_args ipa;

	struct {
		struct btrfs_data_container fspath;
		char padding[PATH_MAX];
	} stackalloc;

	memset(&stackalloc, 0, sizeof(stackalloc));
	memset(&ipa, 0, sizeof(ipa));
	ipa.inum = inum;
	ipa.size = 4096;
	ipa.fspath = ptr_to_u64(&stackalloc.fspath);

	ret = ioctl(atfd, BTRFS_IOC_INO_PATHS, &ipa);
	if (ret) {
		return -errno;
	}

	u64 ptr = (u64)(unsigned long)stackalloc.fspath.val;
	ptr += stackalloc.fspath.val[0];
	char *str = (char *)(unsigned long)ptr;
	ret=openat(atfd, str, O_RDONLY);

	return ret;
}

size_t logical_resolve(int fd, uint64_t logical, uint64_t *results, size_t *size) {
	struct btrfs_ioctl_logical_ino_args loi;
	size_t fullsize=sizeof(struct btrfs_data_container)+*size*3*sizeof(uint64_t);
	char stackalloc[fullsize];
	struct btrfs_data_container *inodes=(struct btrfs_data_container*)stackalloc;
	assert(inodes);

	memset(inodes, 0, fullsize);
	memset(&loi, 0, sizeof(struct btrfs_ioctl_logical_ino_args));
	loi.logical = logical;
	loi.size = *size*sizeof(uint64_t)*3+sizeof(struct btrfs_data_container);
	loi.inodes = ptr_to_u64(inodes);


	int ret = ioctl(fd, BTRFS_IOC_LOGICAL_INO, &loi);
	if (ret && errno == ENOENT)
		return 0;
	else if (ret)
		ret=-errno;
	else
		ret=inodes->elem_cnt/3;
	memcpy(results, inodes->val, *size*3*sizeof(uint64_t));
	if (inodes->elem_missed)
		*size=inodes->elem_missed+inodes->elem_cnt;

	return ret;
}

int open_by_inode(int atfd, uint64_t inum, uint64_t root) {
	int path_fd=get_rootfd(atfd, root);
	if (0 > path_fd)
		return path_fd;
	int ret=__ino_to_path_fd(inum, path_fd);
	return ret;
}

int64_t btrfs_iterate_tree(int fd, uint64_t tree, void *private, int (*callback)(void*, struct btrfs_ioctl_search_header*, void*)) {
	assert(0<=fd);
	assert(NULL != callback);
	struct btrfs_ioctl_search_args_v2 *args=calloc(MEBI+offsetof(struct btrfs_ioctl_search_args_v2,buf),1);
	if (NULL == args)
		return -ENOMEM;
	args->key.tree_id=tree;
	args->key.max_objectid=-1ULL;
	args->key.max_type=-1U;
	args->key.max_offset=-1ULL;
	args->key.max_transid=-1ULL;
	args->buf_size=MEBI;
	struct btrfs_ioctl_search_header *sh;
	int64_t ret=0;

	do {
		args->key.nr_items=-1U;
		if (ioctl(fd, BTRFS_IOC_TREE_SEARCH_V2, args)) {
			ret=-errno;
			goto out;
		}
		//assume Buffer of MEBI does not fit MEBI items
		assert(MEBI > args->key.nr_items);
		if (0 == args->key.nr_items)
			break;

		sh=(struct btrfs_ioctl_search_header*)args->buf;
		for (uint64_t i=0; i < args->key.nr_items; i++) {
			char *temp=(char*)(sh+1);
			if ((ret=callback(temp, sh, private)))
				goto out;

			args->key.min_offset=sh->offset+1;
			args->key.min_type=sh->type;
			args->key.min_objectid=sh->objectid;
			sh=(struct btrfs_ioctl_search_header*)(sh->len+temp);
		}
		ret+=args->key.nr_items;
	} while (1);

out:
	free(args);
	return ret;
}

static int get_generation_cb(void *data, struct btrfs_ioctl_search_header *sh, void *private) {
	if (BTRFS_ROOT_ITEM_KEY != sh->type )
		return 0;
	assert(sizeof(struct btrfs_root_item) <=sh->len);
	struct btrfs_root_item *ritem=(struct btrfs_root_item*)data;
	uint64_t *genptr=private;
	if (ritem->generation > *genptr)
		*genptr=ritem->generation;

	return 0;
}

int64_t btrfs_get_generation(int fd) {
	uint64_t generation=0;
	int64_t ret=btrfs_iterate_tree(fd, BTRFS_ROOT_TREE_OBJECTID, &generation, get_generation_cb);
	if (0>ret)
		return ret;
	return generation;
}

int btrfs_clone_range(int src_fd, int dest_fd, uint64_t src_offset, uint64_t dest_offset, uint64_t len) {
	struct btrfs_ioctl_clone_range_args args;
	args.src_fd=src_fd;
	args.src_offset=src_offset;
	args.src_length=len;
	args.dest_offset=dest_offset;

	int ret=ioctl(dest_fd, BTRFS_IOC_CLONE_RANGE, &args);
	if (0>ret) return -errno;
	return 0;
}

int btrfs_dedup(int fd, uint64_t logical, uint64_t len, int *fds, uint64_t *offsets, unsigned count, int64_t *results) {
	size_t fullsize=sizeof(struct btrfs_ioctl_same_args)+count*sizeof(struct btrfs_ioctl_same_extent_info);
	char stackalloc[fullsize];
	memset(stackalloc,0,fullsize);
	struct btrfs_ioctl_same_args *args=(struct btrfs_ioctl_same_args*)&stackalloc;
	args->logical_offset=logical;
	args->length=len;
	args->dest_count=count;
	for (unsigned i=0; i<count;i++) {
		args->info[i].fd=fds[i];
		args->info[i].logical_offset=offsets[i];
	}
	int ret=ioctl(fd, BTRFS_IOC_FILE_EXTENT_SAME, args);
	if (0>ret) return -errno;
	if (NULL != results) for (unsigned i=0; i<count;i++) {
		switch (BTRFS_SAME_DATA_DIFFERS==args->info[i].status) {
			case BTRFS_SAME_DATA_DIFFERS:
				results[i]=-EMEDIUMTYPE;
				break;
			case 0:
				results[i]=args->info[i].bytes_deduped;
				break;
			default:
				assert(0 > args->info[i].status);
				results[i]=args->info[i].status;
				break;
		}
	}

	return ret;
}
