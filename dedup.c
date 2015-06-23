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

#define DEDUP_MAX_ITERATIONS 1
#define DEDUP_OPERATION_DONE 0
#define DEDUP_OPERATION_TODO 1

typedef struct {
	uint64_t fileoffset;
	uint64_t extent;
	uint32_t len;
} relextent_t;

static int64_t get_extent_ref_info(int fd, uint64_t fileoffset, uint64_t extent, uint64_t extlen, uint64_t expected, relextent_t *rels, uint64_t nelem) {
	size_t fullsize=sizeof(struct fiemap)+nelem*sizeof(struct fiemap_extent);
	char stackalloc[fullsize];
	struct fiemap *map=(struct fiemap*)stackalloc;
	memset(map, 0, fullsize);
	int ret;
	map->fm_start=fileoffset;
	map->fm_length=expected;
	map->fm_extent_count=nelem;
	if (0>ioctl(fd, FS_IOC_FIEMAP, map))
		return -errno;

	ret=map->fm_mapped_extents;
	assert(0<=ret);
	uint64_t nfound=0;
	for (uint64_t i=0; i < (unsigned)ret; i++ ) {
		if (map->fm_extents[i].fe_physical >= extent+extlen || map->fm_extents[i].fe_physical < extent) {
			continue;
		}
		rels[nfound].extent=map->fm_extents[i].fe_physical;
		rels[nfound].fileoffset=map->fm_extents[i].fe_logical;
		assert(INT_MAX > map->fm_extents[i].fe_length);
		rels[nfound++].len=map->fm_extents[i].fe_length;
	}

	return nfound;
}

static int64_t get_extent_metaindex(uint64_t offset, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, uint64_t len) {
	int64_t ret=getmetaindex(offset, extoffs, metalen);
	if (0>ret)
		return ret;
	assert(metalen > (uint64_t)ret);
	assert(offset >= extoffs[ret] || 0 == ret);
	for (;(uint64_t)ret<metalen;ret++) {
		if (offset >extoffs[ret] + extsums[extinds[ret]])
			continue;
		if (offset+len < extoffs[ret])
			return -ENOENT;
		return ret;
	}
	return -ENOENT;
}

static int64_t ffwd_extent_metaindex(uint64_t offset, uint64_t index, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, uint64_t len) {
	index++;
	for (;index<metalen;index++) {
		if (offset >extoffs[index] + extsums[extinds[index]])
			continue;
		if (offset+len < extoffs[index])
			return -ENOENT;
		return index;
	}
	return -ENOENT;
}


#define DEDUP_LINKTYPE_CONTENT (1ULL << 0ULL)
#define DEDUP_LINKTYPE_CORONA (1ULL << 1ULL)
#define DEDUP_LINKTYPE_COPY (1ULL << 2ULL)

#define DEDUP_NEXTENTS 10

static int64_t copy_yes_overwrite(int srcfd, int destfd, uint64_t src_offset, uint64_t dest_offset, uint64_t len, char* dest_map, uint64_t type) {
	if (type & DEDUP_LINKTYPE_COPY) {
		if ((int64_t)len != pread(srcfd, dest_map+dest_offset, len, src_offset)) {
			return -errno;
		}
	} else {
		int64_t ret=btrfs_clone_range(srcfd, destfd, src_offset, dest_offset, len);
		if (0>ret)
			return ret;
	}
	return DEDUP_OPERATION_TODO;
}

static int64_t copy_no_overwrite(int srcfd, int destfd, uint64_t src_offset, uint64_t dest_offset, uint64_t len, char* dest_map, uint64_t type) {
	relextent_t rels[DEDUP_NEXTENTS];
	int64_t done=DEDUP_OPERATION_DONE;
	for (uint64_t current_dest_offset=dest_offset; current_dest_offset<dest_offset+len;){
		int64_t nextents=get_extent_ref_info(destfd, dest_offset, 0, -1ULL, len, rels, DEDUP_NEXTENTS);
		if (0>nextents)
			return nextents;
		if (DEDUP_NEXTENTS > nextents) {
			rels[nextents].len=0;
			rels[nextents].fileoffset=dest_offset+len;
			nextents++;
		}
		for (int64_t relindex=0; relindex<nextents; relindex++) {
			if (current_dest_offset >= rels[relindex].fileoffset) {
				current_dest_offset=rels[relindex].fileoffset+rels[relindex].len;
				continue;
			}
			uint64_t this_part_len=rels[relindex].fileoffset-current_dest_offset;
			uint64_t current_src_offset=src_offset+current_dest_offset-dest_offset;
			int64_t ret=copy_yes_overwrite(srcfd, destfd, current_src_offset, current_dest_offset, this_part_len, dest_map, type);
			if (0>ret) return ret;
			done=DEDUP_OPERATION_TODO;
		}
	}
	return done;
}

static int link_to_srcfile(int atfd, uint64_t offset, uint64_t len, int srcfile, char *src_map ,uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, uint64_t type) {
	int64_t ret=DEDUP_OPERATION_DONE, fd=-1;
	for (int64_t physextent=get_extent_metaindex(offset,extsums,extoffs,extinds,metalen,len); 0 <= physextent ;physextent=ffwd_extent_metaindex(offset, physextent, extsums, extoffs, extinds, metalen, len)) {
		uint64_t nextstep=3, extlen=extsums[extinds[physextent]], extent_offset=extoffs[physextent];
		DEDUP_ASSERT_FILEOFFSET(extlen);
		for (uint64_t refiter=extinds[physextent]+1; refiter < extinds[physextent+1]; refiter+=nextstep) {
			uint64_t inode=extsums[refiter];
			uint64_t fileoffset=extsums[refiter+1];
			uint64_t root= extsums[refiter+2];
			DEDUP_ASSERT_ROOT(root);
			DEDUP_ASSERT_FILEOFFSET(fileoffset);
			DEDUP_ASSERT_INODE(inode);
			fd=open_by_inode(atfd, inode, root);
			DEDUP_ASSERT_STATIC_FS(0<=fd);
			if (0>fd) {
				printf("Inode %lu on root %lu disappeared\n", inode, root);
				return -ENOENT;
			}
			relextent_t rel;
			int64_t nentries=get_extent_ref_info(fd, fileoffset, extent_offset, extlen, extlen, &rel, 1);
			if (0>nentries) {
				ret=nentries;
				goto out;
			}
			if (!nentries || fileoffset != rel.fileoffset || extlen+extent_offset < rel.extent+rel.len || rel.extent < extent_offset) {
				DEDUP_ASSERT_STATIC_FS(0);
				ret=-ENOENT;
				goto out;
			}
			if (type & DEDUP_LINKTYPE_COPY) {
				ret=copy_no_overwrite(fd, srcfile, fileoffset, rel.extent, rel.len, src_map, DEDUP_LINKTYPE_COPY);
				if (0>ret) goto out;
			} else{
				ret=copy_no_overwrite(fd, srcfile, fileoffset, rel.extent, rel.len, NULL, 0);
				if (0>ret) goto out;
			}
			ret=DEDUP_OPERATION_TODO;
			close(fd);
			fd=-1;
		}
	}
out:
	if (0<=fd) close(fd);
	return ret;
}

static int link_srcfile(int atfd, uint64_t offset1, uint64_t offset2, uint64_t len, int srcfile, char* src_map, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen) {
	DEDUP_ASSERT_LOGICAL(offset2);
	int ret;

	if (DEDUP_SPECIAL_OFFSET_ZEROES == offset1) {
		ret=link_to_srcfile(atfd, offset2, len, srcfile, src_map, extsums, extoffs, extinds, metalen, DEDUP_LINKTYPE_CORONA|DEDUP_LINKTYPE_COPY);

	} else {
		DEDUP_ASSERT_LOGICAL(offset1);
		if (0 >= (ret=link_to_srcfile(atfd, offset1, len, srcfile, src_map, extsums, extoffs, extinds, metalen, DEDUP_LINKTYPE_CONTENT)))
			return ret;
		if (0 > (ret=copy_no_overwrite(srcfile, srcfile, offset1, offset2, len, NULL, 0)))
			return ret;
		ret=link_to_srcfile(atfd, offset2, len, srcfile, src_map, extsums, extoffs, extinds, metalen, DEDUP_LINKTYPE_CONTENT|DEDUP_LINKTYPE_CORONA|DEDUP_LINKTYPE_COPY);
	}
	return ret;
}

static int dedup(int atfd, uint64_t offset, uint64_t len, int srcfd,uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen) {
	int64_t ret=DEDUP_OPERATION_DONE;
	int fd=-1;
	for (int64_t physextent=get_extent_metaindex(offset,extsums,extoffs,extinds,metalen,len); 0 <= physextent ;physextent=ffwd_extent_metaindex(offset, physextent, extsums, extoffs, extinds, metalen, len)) {
		uint64_t nextstep=3, extlen=extsums[extinds[physextent]], extent_offset=extoffs[physextent];
		DEDUP_ASSERT_FILEOFFSET(extlen);
		for (uint64_t refiter=extinds[physextent]+1; refiter < extinds[physextent+1]; refiter+=nextstep) {
			uint64_t inode=extsums[refiter];
			uint64_t fileoffset=extsums[refiter+1];
			uint64_t root= extsums[refiter+2];
			DEDUP_ASSERT_ROOT(root);
			DEDUP_ASSERT_FILEOFFSET(fileoffset);
			DEDUP_ASSERT_INODE(inode);
			fd=open_by_inode(atfd, inode, root);
			DEDUP_ASSERT_STATIC_FS(0<=fd);
			if (0>fd) {
				printf("Inode %lu on root %lu disappeared\n", inode, root);
				return -ENOENT;
			}
			relextent_t rel;
			int64_t nentries=get_extent_ref_info(fd, fileoffset, extent_offset, extlen, extlen, &rel, 1);
			if (0>nentries) {
				ret=nentries;
				goto out;
			}
			if (!nentries || fileoffset != rel.fileoffset || extlen+extent_offset < rel.extent+rel.len || rel.extent < extent_offset) {
				DEDUP_ASSERT_STATIC_FS(0);
				ret=-ENOENT;
				goto out;
			}
			int64_t result;
			ret=btrfs_dedup(srcfd, rel.extent, rel.len, &fd, &(rel.fileoffset), 1, &result);
			if (0>ret) goto out;
			if (0>result) return result;
			ret=DEDUP_OPERATION_TODO;
			close(fd);
			fd=-1;
		}
	}
out:
	if (0<=fd) close(fd);
	return ret;
}

int do_dedups(int atfd, uint64_t *dedups, uint64_t deduplen, uint64_t rtable_size, uint64_t generation) {
	uint64_t *extsums;
	uint64_t *extoffs;
	uint64_t *extinds;
	int ret=rtable_init(rtable_size);
	assert(!ret);
#ifdef DEDUP_DEBUG_LINK_SRCFILE
#define DEDUP_DEBUG_STRINGIFY(x) #x
#define DEDUP_DEBUG_NAME(x) DEDUP_DEBUG_STRINGIFY(x)
#define DEDUP_DEBUG_LINK_SRCFILE_NAME DEDUP_DEBUG_NAME(DEDUP_DEBUG_LINK_SRCFILE)
	int tmpfd=openat(atfd, DEDUP_DEBUG_LINK_SRCFILE_NAME, O_RDWR|O_CREAT|O_EXCL, S_IRWXU);
#undef DEDUP_DEBUG_LINK_SRCFILE_NAME
#undef DEDUP_DEBUG_NAME
#undef DEDUP_DEBUG_STRINGIFY
#else
	int tmpfd=openat(atfd, ".", O_RDWR|O_TMPFILE|O_EXCL);
#endif
	assert(0<=tmpfd);

	uint64_t leftind=0;
	int64_t metalen=do_extent_search(atfd, &extsums, &extoffs, &extinds, generation);
	uint64_t fs_max_logical_orig=extoffs[metalen-1]+extsums[extinds[metalen-1]];
	DEDUP_ASSERT_LOGICAL(fs_max_logical_orig);
	ret=ftruncate(tmpfd, INT_MAX+fs_max_logical_orig);
	assert(!ret);
	char *src_map=mmap(NULL,fs_max_logical_orig,PROT_READ|PROT_WRITE,MAP_SHARED,tmpfd,0);
	assert(NULL != src_map);
	printf("Extent tree cache built\n");
	assert(0 <= metalen);
	for (uint64_t i=0; i<deduplen*3; i+=3) {
		if (0>(ret=link_srcfile(atfd, dedups[i],dedups[i+1],dedups[i+2]*BLOCKSIZE, tmpfd, src_map, extsums, extoffs, extinds, metalen)))
			fprintf(stderr, "Link to srcfile of %lu & %lu of %lu failed with %s\n", dedups[i],dedups[i+1],dedups[i+2], strerror(-ret));
		if (DEDUP_OPERATION_TODO == ret) {
			dedups[leftind++]=dedups[i];
			dedups[leftind++]=dedups[i+1];
			dedups[leftind++]=dedups[i+2];
		}
	}
	deduplen=leftind/3;
	ret=munmap(src_map, fs_max_logical_orig);
	assert(!ret);
	free(extsums);
	free(extoffs);
	free(extinds);
	printf("Srcfile created, %lu items to handle\n", deduplen);

	for (uint64_t j=0; DEDUP_MAX_ITERATIONS > j; j++ ) {
		leftind=0;
		metalen=do_extent_search(atfd, &extsums, &extoffs, &extinds, generation);
		printf("Extent tree cache built\n");
		assert(0 <= metalen);

		for (uint64_t i=0; i<deduplen*3; i+=3) {
			if (0>(ret=dedup(atfd,dedups[i+1],dedups[i+2]*BLOCKSIZE,tmpfd,extsums,extoffs,extinds,metalen)))
				fprintf(stderr, "Dedup of %lu of %lu failed with %s\n", dedups[i+1],dedups[i+2], strerror(-ret));
			if (DEDUP_OPERATION_TODO == ret) {
				dedups[leftind++]=dedups[i];
				dedups[leftind++]=dedups[i+1];
				dedups[leftind++]=dedups[i+2];
			}
		}
		deduplen=leftind/3;
		free(extsums);
		free(extoffs);
		free(extinds);
	}

	close(tmpfd);
	return 0;
}
