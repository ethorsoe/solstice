#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <sais.h>
#include <sais64.h>
#include "dedup.h"

static int64_t get_extent_len(int fd, uint64_t offset, uint64_t expected) {
	char stackalloc[sizeof(struct fiemap)*sizeof(struct fiemap_extent)];
	struct fiemap *map=(struct fiemap*)stackalloc;
	memset(map, 0, sizeof(struct fiemap)*sizeof(struct fiemap_extent));
	int ret;
	map->fm_start=offset;
	map->fm_length=expected;
	map->fm_extent_count=1;
	if (0>ioctl(fd, FS_IOC_FIEMAP, map))
		ret=-errno;
	else
		ret=map->fm_extents[0].fe_length-offset+map->fm_extents[0].fe_logical;
	return ret;
}

static int dedup(int atfd, uint64_t offset1, uint64_t offset2, uint64_t len, int tmpfd,uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen) {
	uint64_t fileoffset1, inode1, root1;
	int fd1, fd2, ret=0;

	if (DEDUP_SPECIAL_OFFSET_ZEROES == offset1) {
		fd1=tmpfd;
		assert(INT_MAX>len);
		fileoffset1=0;
	} else {
		int64_t metaind1=getmetaindex(offset1, extoffs, metalen);
		if (0>metaind1) {
			printf("No files found for logical address %lu\n", offset1);
			return -ENOENT;
		}
		inode1=extsums[extinds[metaind1]+2];
		fileoffset1=extsums[extinds[metaind1]+3];
		root1 = extsums[extinds[metaind1]+4];
		DEDUP_ASSERT_LOGICAL(offset1);
		DEDUP_ASSERT_ROOT(root1);
		DEDUP_ASSERT_FILEOFFSET(fileoffset1);
		DEDUP_ASSERT_INODE(inode1);
		fd1=open_by_inode(atfd, inode1, root1);
		if (0>fd1) {
			printf("Inode %lu on root %lu disappeared\n", inode1, root1);
			return -ENOENT;
		}
		len=MIN(get_extent_len(fd1, fileoffset1, len), len);
	}

	int64_t metaind2=getmetaindex(offset2, extoffs, metalen);
	uint64_t inode2=extsums[extinds[metaind2]+2];
	uint64_t fileoffset2=extsums[extinds[metaind2]+3];
	uint64_t root2 = extsums[extinds[metaind2]+4];
	if (0 > metaind2) {
		printf("No files found for logical address %lu\n", offset2);
		ret=-ENOENT;
		goto out;
	}
	assert(0<=ret);
	fd2=open_by_inode(atfd, inode2, root2);
	if (0>fd2) {
		printf("Inode %lu on root %lu disappeared\n", inode2,root2);
		ret=-ENOENT;
		goto out;
	}
	len=MIN(get_extent_len(fd2, fileoffset2, len), len);

	DEDUP_ASSERT_ROOT(root2);
	DEDUP_ASSERT_LOGICAL(offset2);
	DEDUP_ASSERT_FILEOFFSET(fileoffset2);
	DEDUP_ASSERT_INODE(inode2);
	
	if (fd1 == tmpfd)
		printf("nonsparse zeroes %6lu @ %10lu [%lu] len %8lu\n", inode2, root2, fileoffset2, len);
	else
		printf("inode %6lu @ %6lu [%10lu] & %6lu @ %6lu [%10lu] len %8lu\n", inode2, root2, fileoffset2, inode1, root1, fileoffset1, len);


	close(fd2);
out:
	if (fd1 != tmpfd) close(fd1);

	return ret;
}

int do_dedups(int atfd, uint64_t *dedups, uint64_t deduplen, uint64_t rtable_size, uint64_t generation) {
	uint64_t *extsums;
	uint64_t *extoffs;
	uint64_t *extinds;
    int ret=rtable_init(rtable_size);
    assert(!ret);
	int tmpfd=openat(atfd, ".", O_RDWR|O_TMPFILE|O_EXCL);
	assert(0<=tmpfd);
	ret=ftruncate(tmpfd, INT_MAX);
    assert(!ret);
	int64_t metalen=do_extent_search(atfd, &extsums, &extoffs, &extinds);
	printf("Extent tree cache built\n");

    assert(0<=ret);
    for (uint64_t i=0; i<deduplen*3; i+=3) {
        if (0>(ret=dedup(atfd,dedups[i],dedups[i+1],dedups[i+2],tmpfd,extsums,extoffs,extinds,metalen)))
            fprintf(stderr, "Dedup of %lu & %lu of %lu failed with %s\n", dedups[i],dedups[i+1],dedups[i+2], strerror(-ret));
    }
	free(extsums);
	free(extoffs);
	free(extinds);
	close(tmpfd);
	return 0;
}
