#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <sais.h>
#include <sais64.h>
#include "dedup.h"

#define MAX(x,y) ((x)>(y)?(x):(y))

static int add_dedup(uint64_t **dedups, uint64_t *dedupsize, uint64_t *dedupalloc, uint64_t logical1, uint64_t logical2, uint64_t len) {
	if (*dedupsize == *dedupalloc) {
		*dedupalloc+=MEBI;
		if (!(*dedups=realloc(*dedups,*dedupalloc*3*sizeof(uint64_t))))
			return -ENOMEM;
	}
	(*dedups)[  3*(*dedupsize)  ]=logical1;
	(*dedups)[1+3*(*dedupsize)  ]=logical2;
	(*dedups)[2+3*(*dedupsize)++]=len;

	return 0;
}

int64_t do_sais(uint32_t *checksums, uint64_t *checkoffs, uint64_t *checkinds, uint64_t **dedups, uint64_t metalen, uint64_t minsumsize, uint64_t minextlen) {
	uint32_t *outmem32;
	uint64_t *outmem64;
	uint64_t unitsize=(2 > minsumsize) ? 1:2;
	uint64_t nblocks=checkinds[metalen];
	uint64_t saissize=(4 > unitsize && INT_MAX >= nblocks) ? 4 : 8;
	uint64_t ratio=(minsumsize/unitsize);
	uint64_t writeindex=0;
	uint64_t dedupalloc=30*MEBI, dedupsize=0;
	*dedups=malloc(dedupalloc*3*sizeof(uint64_t));
	int ret;

	uint64_t nsaisblocks=nblocks*(minsumsize/unitsize);

	void *minmem=malloc(nblocks*2);
	for (uint64_t i=0;i<nblocks;i++) {
		uint32_t insum = ((uint32_t*)checksums)[i];
		((uint16_t*)minmem)[i]= 0xfff & (insum ^ (insum >> 16));
	}

	void *outmem=malloc(nsaisblocks*saissize);

	
	if (4 == saissize) {
		switch (unitsize) {
			case sizeof(uint8_t):
				ret=sais_u8(minmem,  outmem, nsaisblocks, (uint64_t)0x100);
				break;
			case  sizeof(uint16_t):
				ret=sais_u16(minmem, outmem, nsaisblocks, (uint64_t)0x10000);
				break;
			default:
				fprintf(stderr, "Internal error\n");
				return 1;
				break;
		}
		assert(!ret);
		outmem32=outmem;
		for (uint64_t i = 0; i < nsaisblocks; i++) {
			if (!(outmem32[i]%ratio))
				outmem32[writeindex++]=outmem32[i]/ratio;
		}

		for (uint64_t i = 0; i < nblocks-1; i++) {
			uint64_t ind1=MIN(outmem32[i],outmem32[i+1]), ind2=MAX(outmem32[i],outmem32[i+1]), extlen=0;
			if (ind1 != 0 && checksums[ind1-1] == checksums[ind2-1]) continue;
			for (extlen=0; extlen+ind2<nblocks && checksums[ind1+extlen] == checksums[ind2+extlen]; extlen++) {
				continue;
			}
			if (minextlen <= extlen) {
				uint64_t step=ind2-ind1;
				uint64_t rounded=step*((minextlen-1)/step);
				extlen-=rounded;
				step+=rounded;
				ind2+=rounded;
				uint64_t nextstep;
				for (uint64_t j=0; j<extlen; j+=nextstep) {
					uint64_t metaind1 = getmetaindex(ind1+j, checkinds,metalen);
					uint64_t metaind2 = getmetaindex(ind2+j, checkinds,metalen);
					uint64_t stop1=checkinds[metaind1+1]-ind1-j;
					uint64_t stop2=checkinds[metaind2+1]-ind2-j;
					uint64_t nextstop=MIN(stop1, stop2);

					uint64_t zerolen, zeroind=outmem32[i], zerometaind, zerostop;
					if (zeroind==ind1) {
						zerometaind=metaind1;
						zerostop=stop1;
					} else {
						zerometaind=metaind2;
						zerostop=stop2;
					}
					nextstep=MIN((rounded?step:0)+extlen-j,zerostop);
					for (zerolen=0; zerolen<nextstep && checksums[zeroind+j+zerolen] == DEDUP_ZERO_CRC; zerolen++)
						continue;
					if (minextlen <= zerolen) {
						nextstep=zerolen;
						if (!(zeroind+j) || DEDUP_ZERO_CRC != checksums[zeroind+j-1])
							add_dedup(dedups, &dedupsize, &dedupalloc, DEDUP_SPECIAL_OFFSET_ZEROES, checkoffs[zerometaind] + BLOCKSIZE*(zeroind+j-checkinds[zerometaind]), nextstep);
						continue;
					}

					nextstep=MIN(nextstop,extlen-j);
					nextstep=MIN(step,nextstep);
					add_dedup(dedups, &dedupsize, &dedupalloc, checkoffs[metaind1] + BLOCKSIZE*(ind1+j-checkinds[metaind1]), checkoffs[metaind2] + BLOCKSIZE*(ind2+j-checkinds[metaind2]), nextstep);
				}
			}
		}
	} else {
			switch (unitsize) {
			case sizeof(uint8_t):
				ret=-1*sais64_u8(minmem,  outmem, nsaisblocks, (uint64_t)0x100);
				break;
			case  sizeof(uint16_t):
				ret=-1*sais64_u16(minmem, outmem, nsaisblocks, (uint64_t)0x10000);
				break;
			case  sizeof(uint32_t):
				ret=-1*sais64_u32(minmem, outmem, nsaisblocks, (uint64_t)0x100000000);
				break;
			default:
				fprintf(stderr, "Internal error\n");
				return 1;
				break;
		}
		assert(!ret);
		outmem64=outmem;
		for (uint64_t i = 0; i < nsaisblocks; i++) {
			if (!(outmem64[i]%ratio))
				outmem64[writeindex++]=outmem64[i]/ratio;
		}
	}

	free(minmem);
	free(outmem);
	return dedupsize;
}

int64_t find_zeros(uint32_t *checksums, uint64_t *checkoffs, uint64_t *checkinds, uint64_t **dedups, uint64_t metalen, uint64_t minextlen) {
	uint64_t dedupalloc=30*MEBI, dedupsize=0;
	int64_t ret;
	*dedups=malloc(dedupalloc*3*sizeof(uint64_t));
	for (uint64_t metaindex=0; metaindex<metalen; metaindex++) {
		uint64_t zerolen=0, allzero=1;
		for (uint64_t sumindex=checkinds[metaindex]; sumindex<checkinds[metaindex+1]; sumindex++) {
			if (checksums[sumindex] == DEDUP_ZERO_CRC) {
				zerolen++;
			} else {
				allzero=0;
				if (minextlen <= zerolen) {
					ret=add_dedup(dedups, &dedupsize, &dedupalloc, DEDUP_SPECIAL_OFFSET_ZEROES, checkoffs[metaindex]+BLOCKSIZE*(sumindex-zerolen-checkinds[metaindex]), zerolen);
					if (0>ret)
						return ret;
				}
				zerolen=0;
			}
		}
		if (allzero) {
			ret=add_dedup(dedups, &dedupsize, &dedupalloc, DEDUP_SPECIAL_OFFSET_ZEROES, checkoffs[metaindex], zerolen);
			if (0>ret)
				return ret;
		}
	}
	return dedupsize;
}
