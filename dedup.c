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

	uint64_t nfound=0, nextents, cur_offset=fileoffset;

	do {
		map->fm_start=cur_offset;
		map->fm_length=expected-(cur_offset-fileoffset);
		map->fm_extent_count=nelem;
		if (0>ioctl(fd, FS_IOC_FIEMAP, map)) {
			int ret;
			if (EINVAL == errno) {
				ret=nfound;
			} else {
				ret=-errno;
				assert(0>ret);
			}
			return ret;
		}

		nextents=map->fm_mapped_extents;
		for (uint64_t i=0; i < nextents; i++ ) {
			if (map->fm_extents[i].fe_physical >= extent+extlen || map->fm_extents[i].fe_physical < extent) {
				continue;
			}
			rels[nfound].extent=map->fm_extents[i].fe_physical;
			rels[nfound].fileoffset=map->fm_extents[i].fe_logical;
			rels[nfound++].len=MIN(map->fm_extents[i].fe_length, extlen - (map->fm_extents[i].fe_physical-extent));
			if (nelem == nfound)
				return nfound;
			assert(nelem > nfound);
		}
		cur_offset=map->fm_extents[nextents-1].fe_logical+map->fm_extents[nextents-1].fe_length;
	} while(0 < nextents && cur_offset < fileoffset+expected);

	return nfound;
}

static int64_t get_extent_metaindex(uint64_t offset, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, uint64_t len) {
	int64_t ret=getmetaindex(offset, extoffs, metalen);
	if (0>ret)
		return ret;
	assert(metalen > (uint64_t)ret);
	assert(offset >= extoffs[ret] || 0 == ret);
	for (;(uint64_t)ret<metalen;ret++) {
		if (offset >=extoffs[ret] + extsums[extinds[ret]])
			continue;
		if (offset+len <= extoffs[ret])
			return -ENOENT;
		return ret;
	}
	return -ENOENT;
}

static int64_t ffwd_extent_metaindex(uint64_t offset, uint64_t index, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, uint64_t len) {
	index++;
	for (;index<metalen;index++) {
		if (offset >= extoffs[index] + extsums[extinds[index]])
			continue;
		if (offset+len <= extoffs[index])
			return -ENOENT;
		return index;
	}
	return -ENOENT;
}

static int iterate_extent_range(int atfd, uint64_t offset, uint64_t len, int src_fd, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, int64_t (*callback)(int,int,relextent_t*,uint64_t,uint64_t,void*), void *private) {
	int64_t ret=DEDUP_OPERATION_DONE;
	int fd=-1;
	for (int64_t physextent=get_extent_metaindex(offset,extsums,extoffs,extinds,metalen,len); 0 <= physextent ;physextent=ffwd_extent_metaindex(offset, physextent, extsums, extoffs, extinds, metalen, len)) {
		uint64_t nextstep=4, extlen=extsums[extinds[physextent]], extent_offset=extoffs[physextent];
		DEDUP_ASSERT_FILEOFFSET(extlen);
		for (uint64_t refiter=extinds[physextent]+1; refiter < extinds[physextent+1]; refiter+=nextstep) {
			uint64_t inode=extsums[refiter];
			uint64_t fileoffset=extsums[refiter+1];
			uint64_t cut_extlen=extlen;
			if (extlen+fileoffset < fileoffset) {
				cut_extlen+=fileoffset;
				fileoffset=0;
			}
			uint64_t root=extsums[refiter+2];
			uint64_t refcount=extsums[refiter+3];
			DEDUP_ASSERT_ROOT(root);
			DEDUP_ASSERT_FILEOFFSET(fileoffset);
			DEDUP_ASSERT_INODE(inode);
			DEDUP_ASSERT_COUNT(refcount);
			fd=open_by_inode(atfd, inode, root);
			DEDUP_ASSERT_STATIC_FS(0<=fd);
			if (0>fd) {
				printf("Inode %lu on root %lu disappeared\n", inode, root);
				return -ENOENT;
			}

			assert(1000 >= refcount);
			relextent_t rels[1000];
			int64_t nentries=get_extent_ref_info(fd, fileoffset, extent_offset, extlen, cut_extlen, rels, refcount);
			if (0>nentries) {
				ret=nentries;
				goto out;
			}
			if (!nentries) {
				ret=-ENOENT;
				goto out;
			}
			for (int64_t i=0; i<nentries; i++) {
				assert(fileoffset <= rels[i].fileoffset && extlen+extent_offset >= rels[i].extent+rels[i].len && rels[i].extent >= extent_offset);
				if ((ret=callback(fd, src_fd, &rels[i], extent_offset, extlen, private)))
					goto out;
			}

			close(fd);
			fd=-1;
			ret=DEDUP_OPERATION_TODO;
		}
	}
out:
	if (0<=fd) close(fd);
	return ret;
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
	uint64_t offset_diff=0;
	for (uint64_t current_dest_offset=dest_offset; current_dest_offset<dest_offset+len;){
		int64_t nextents=get_extent_ref_info(destfd, current_dest_offset, 0, -1ULL, len-offset_diff, rels, DEDUP_NEXTENTS);
		if (0>nextents)
			return nextents;
		if (DEDUP_NEXTENTS > nextents) {
			rels[nextents].len=0;
			rels[nextents].fileoffset=dest_offset+len;
			nextents++;
		}
		for (int64_t relindex=0; relindex<nextents; relindex++) {
			if (current_dest_offset < rels[relindex].fileoffset) {
				uint64_t this_part_len=rels[relindex].fileoffset-current_dest_offset;
				uint64_t current_src_offset=src_offset+offset_diff;
				int64_t ret=copy_yes_overwrite(srcfd, destfd, current_src_offset, current_dest_offset, this_part_len, dest_map, type);
				if (0>ret) return ret;
				done=DEDUP_OPERATION_TODO;
			}
			current_dest_offset=rels[relindex].fileoffset+rels[relindex].len;
			offset_diff=current_dest_offset-dest_offset;
		}
	}
	return done;
}

struct link_to_srcfile_t {
	uint64_t type;
	uint64_t logical;
	uint64_t len;
	uint64_t limit;
	void *src_map;
};
static int64_t link_to_srcfile_cb(int fd, int src_fd, relextent_t* rel, uint64_t physextent, uint64_t extlen, void* private) {
	struct link_to_srcfile_t *mydata=(struct link_to_srcfile_t*)private;
	int64_t ret;
	uint64_t linktype = mydata->type;
	if (physextent+extlen > mydata->limit)
		linktype=DEDUP_LINKTYPE_COPY;
	assert(mydata->type & (DEDUP_LINKTYPE_CORONA|DEDUP_LINKTYPE_CONTENT));
	if (!(mydata->type & DEDUP_LINKTYPE_CONTENT)) {
		if (rel->extent < mydata->logical) {
			ret=copy_no_overwrite(fd, src_fd, rel->fileoffset, rel->extent, mydata->logical-rel->extent, mydata->src_map, mydata->type & DEDUP_LINKTYPE_COPY);
			if (0>ret) return ret;
		}
		if (rel->extent+rel->len > mydata->logical+mydata->len) {
			uint64_t diff=mydata->logical+mydata->len-rel->extent;
			rel->extent+=diff;
			rel->fileoffset+=diff;
			rel->len-=diff;
			ret=copy_no_overwrite(fd, src_fd, rel->fileoffset, rel->extent, rel->len, mydata->src_map, mydata->type & DEDUP_LINKTYPE_COPY);
			if (0>ret) return ret;
		}
	} else {
		if (!(mydata->type & DEDUP_LINKTYPE_CORONA)) {
			if (rel->extent >= mydata->logical+mydata->len)
				return 0;
			if (rel->extent + rel->len > mydata->logical+mydata->len) {
				rel->len=mydata->logical+mydata->len-rel->extent;
			}
			if (rel->extent < mydata->logical) {
				uint64_t diff=mydata->logical-rel->extent;
				rel->fileoffset+=diff;
				rel->len-=diff;
				rel->extent+=diff;
			}
		}
		ret=copy_no_overwrite(fd, src_fd, rel->fileoffset, rel->extent, rel->len, mydata->src_map, linktype & DEDUP_LINKTYPE_COPY);
		if (0>ret) return ret;
	}
	return 0;
}
static int link_to_srcfile(int atfd, uint64_t offset, uint64_t len, int srcfile, char *src_map ,uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen, uint64_t limit, uint64_t type) {
	struct link_to_srcfile_t mydata;
	mydata.type=type;
	mydata.src_map=src_map;
	mydata.logical=offset;
	mydata.len=len;
	mydata.limit=limit;
	int ret=iterate_extent_range(atfd, offset, len, srcfile, extsums, extoffs, extinds, metalen, link_to_srcfile_cb, &mydata);
	return ret;
}

static int link_srcfile(int atfd, uint64_t offset1, uint64_t offset2, uint64_t len, int srcfile, char* src_map, uint64_t *extsums,uint64_t *extoffs,uint64_t *extinds, uint64_t metalen) {
	DEDUP_ASSERT_LOGICAL(offset2);
	int ret;

	if (DEDUP_SPECIAL_OFFSET_ZEROES == offset1) {
		ret=link_to_srcfile(atfd, offset2, len, srcfile, src_map, extsums, extoffs, extinds, metalen, -1ULL, DEDUP_LINKTYPE_CORONA|DEDUP_LINKTYPE_COPY);

	} else {
		DEDUP_ASSERT_LOGICAL(offset1);
		if (0 >= (ret=link_to_srcfile(atfd, offset1, len, srcfile, src_map, extsums, extoffs, extinds, metalen, offset2, DEDUP_LINKTYPE_CONTENT)))
			return ret;
		if (0 > (ret=copy_no_overwrite(srcfile, srcfile, offset1, offset2, len, NULL, 0)))
			return ret;
		ret=link_to_srcfile(atfd, offset2, len, srcfile, src_map, extsums, extoffs, extinds, metalen, -1ULL, DEDUP_LINKTYPE_CONTENT|DEDUP_LINKTYPE_CORONA|DEDUP_LINKTYPE_COPY);
	}
	return ret;
}

static int64_t dedup_cb(int fd, int src_fd, relextent_t* rel, uint64_t physextent, uint64_t extlen, void* private) {
	(void)private;
	(void)physextent;
	(void)extlen;
	int64_t result;
	int64_t ret=btrfs_dedup(src_fd, rel->extent, rel->len, &fd, &(rel->fileoffset), 1, &result);
	if (0>ret) return ret;
	if (0>result) return result;
	return 0;
}

int do_dedups(int atfd, uint64_t *dedups, uint64_t deduplen, uint64_t rtable_size, uint64_t generation) {
	uint64_t *extsums;
	uint64_t *extoffs;
	uint64_t *extinds;
	int ret=rtable_init(rtable_size);
	assert(!ret);
#ifdef DEDUP_DEBUG_LINK_SRCFILE
	int tmpfd=openat(atfd, DEDUP_DEBUG_LINK_SRCFILE_NAME, O_RDWR|O_CREAT|O_EXCL, S_IRWXU);
#else
	int tmpfd=openat(atfd, ".", O_RDWR|O_TMPFILE|O_EXCL);
#endif
	assert(0<=tmpfd);

	uint64_t leftind=0;
	int64_t metalen=do_extent_search(atfd, &extsums, &extoffs, &extinds, generation);
	if (0>=metalen)
		return metalen;
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
	for (uint64_t i=0; i<deduplen*3; i+=3) {
		if (DEDUP_SPECIAL_OFFSET_ZEROES == dedups[i])
			if (0>(ret=fallocate(tmpfd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, dedups[i+1], dedups[i+2]*BLOCKSIZE)))
				return ret;;
	}
	printf("Srcfile created, %lu items to handle\n", deduplen);

	for (uint64_t j=0; DEDUP_MAX_ITERATIONS > j; j++ ) {
		leftind=0;
		metalen=do_extent_search(atfd, &extsums, &extoffs, &extinds, generation);
		printf("Extent tree cache built\n");
		assert(0 <= metalen);

		for (uint64_t i=0; i<deduplen*3; i+=3) {
			if (0>(ret=iterate_extent_range(atfd,dedups[i+1],dedups[i+2]*BLOCKSIZE,tmpfd,extsums,extoffs,extinds,metalen,dedup_cb,NULL)))
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
