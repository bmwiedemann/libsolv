/*
 * Copyright (c) 2026, SUSE LLC
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

/*
 * pool_snapshot.c
 *
 * EXPERIMENTAL: dump a merged pool into a single mmap-able snapshot
 * file and restore it without re-interning any ids.
 *
 * The snapshot contains the string pool, the rels, the solvables, the
 * repos' idarraydata and the repodata stores, i.e. everything
 * repo_add_solv produces.  Vertical data (filelists, descriptions,
 * checksums) stays in the original solv files; the snapshot only
 * records their paths and page tables, and the restored page store
 * demand-loads them like a freshly loaded repo would.
 *
 * pool_snapshot_map restores into a freshly created pool, so callers
 * like libzypp can keep their pool singleton with its registered
 * callbacks.  The big page-aligned sections are borrowed directly
 * from the private file mapping (registered with solv_set_borrowed,
 * so solv_realloc/solv_free migrate or ignore them); writes into
 * borrowed arrays copy single pages on write.  The mapping stays
 * alive until pool_free.  Repos can still be erased, extended and
 * the pool freed like after a normal load.
 *
 * File contract: a snapshot must only be replaced atomically via
 * rename(2), never rewritten in place or truncated.  MAP_PRIVATE
 * pages track the page cache until first write, so an in-place
 * rewrite would silently corrupt every process currently borrowing
 * from the file, and truncation would raise SIGBUS.
 *
 * The data-derived scalar pool state travels with the snapshot
 * (disttype, addedfileprovides): missing state changes query results
 * silently, see the whatprovides digest in the design doc.
 *
 * A caller-provided cookie blob is stored in the header; the caller
 * decides validity (e.g. libzypp hashes its per-repo cookie files).
 *
 * Trust model: a snapshot is trusted content, like the .solv caches it
 * is derived from, and must be protected the same way.  The header and
 * the meta region - every offset and count the restore follows - are
 * covered by a checksum, and every section extent is checked against
 * the file size, so a truncated, half-written or bit-rotted file is
 * rejected rather than followed into a wild pointer.
 *
 * The bulk sections are NOT validated: string offsets, incoredata,
 * incoreoffset, schemadata and the whatprovides index are used as
 * found.  This is weaker than repo_add_solv, which range checks every
 * id it reads, and it is the deliberate trade - checking them means
 * touching all 300+ MB, which is the very cost the mapping avoids.
 * Corrupting them is a crash, not a rejection.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "pool.h"
#include "pool_snapshot.h"

/* The implementation needs mmap and, to recover the solv file paths the
 * vertical data is demand-loaded from, /proc/self/fd. Everywhere else
 * it reports "no snapshot" rather than failing after writing a body. */
#ifndef __linux__
int
pool_snapshot_write(Pool *pool, FILE *fp, const unsigned char *cookie, unsigned int cookielen)
{
  return -2;		/* not representable here, do not retry */
}

int
pool_snapshot_map(Pool *pool, FILE *fp)
{
  return -2;		/* no snapshot here, and writing one will not help */
}

int
pool_snapshot_read_cookie(FILE *fp, unsigned char *cookie, unsigned int *cookielenp)
{
  return -1;
}

void *
pool_snapshot_mapping(Pool *pool, size_t *sizep)
{
  if (sizep)
    *sizep = 0;
  return 0;
}

#else

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#include "pool_private.h"
#include "repo.h"
#include "repodata.h"
#include "repopage.h"
#include "util.h"

#define SNAP_MAGIC "SOLVSNAP"
#define SNAP_VERSION 6
#define SNAP_ALIGN 4096
#define SNAP_COOKIE_MAX 4096
/* alignment of the items packed into the meta region */
#define SNAP_META_ALIGN 8

/* the on-disk layout of the raw-written structs depends on the ABI, and
 * neither magic nor version can express that. refuse a file from a
 * differently shaped build instead of misreading it */
#define SNAP_ABITAG ((unsigned int)(sizeof(Solvable) << 16 | sizeof(Id) << 8 | sizeof(void *)))

/* Growth block sizes of the arrays we restore. solv_extend() assumes
 * a buffer's capacity is its length rounded up to the next block
 * boundary, so restored arrays that may later be appended to must be
 * allocated block-rounded, not exact-size: an exact-size buffer makes
 * the first append write past the end (observed as a segfault in
 * stringpool_strn2id when a repo is loaded into a mapped pool).
 * Keep in sync with the private defines in the named files. */
#define SNAP_STRING_BLOCK      2047	/* strpool.c STRING_BLOCK */
#define SNAP_STRINGSPACE_BLOCK 65535	/* strpool.c STRINGSPACE_BLOCK */
#define SNAP_REL_BLOCK         1023	/* poolid.c REL_BLOCK */
#define SNAP_SOLVABLE_BLOCK    255	/* pool.c SOLVABLE_BLOCK */
#define SNAP_IDARRAY_BLOCK     4095	/* repo.c IDARRAY_BLOCK */
#define SNAP_SIDEDATA_BLOCK    63	/* repo.c REPO_SIDEDATA_BLOCK */
#define SNAP_REPODATA_BLOCK    255	/* repodata.c REPODATA_BLOCK */

/* cap on the whatprovidesdata append arena stored in the file */
#define SNAP_WPDATA_RESERVE    65536

/* block-rounded capacity in elements, as solv_extend() infers it.
 * computed in 64 bit so that the bounds checks below cannot wrap on a
 * 32 bit build */
#define SNAP_CAP(len, block) ((((unsigned long long)(len)) + (block)) & ~(unsigned long long)(block))

/* does the section [off, off + len) lie inside a file of file_size
 * bytes? written so that neither addend can overflow */
static inline int
snap_infile(unsigned long long off, unsigned long long len, unsigned long long file_size)
{
  return off <= file_size && len <= file_size - off;
}

/* FNV-1a over the header and the meta region. This is not a security
 * measure - it catches the truncated, half-written and bit-rotted
 * files that would otherwise be parsed into wild pointers */
#define SNAP_CKSUM_INIT 0xcbf29ce484222325ULL

static unsigned long long
snap_cksum(unsigned long long h, const void *data, size_t len)
{
  const unsigned char *p = data;
  for (; len; len--, p++)
    h = (h ^ *p) * 0x100000001b3ULL;
  return h;
}

/* like solv_memdup2, but with block-rounded capacity matching the
 * array's solv_extend() growth scheme */
static void *
snap_memdup_block(const void *src, size_t len, size_t size, size_t block)
{
  void *r;
  if (!len)
    return 0;
  r = solv_extend_resize(0, len, size, block);
  memcpy(r, src, len * size);
  return r;
}

typedef struct s_Snaphdr {
  char magic[8];
  unsigned int version;
  unsigned int abitag;
  unsigned int nstrings;
  unsigned int sstrings;
  unsigned int stringhashmask;
  unsigned int nrels;
  unsigned int relhashmask;
  unsigned int nsolvables;
  unsigned int nrepos;			/* number of repos with a meta entry */
  unsigned int disttype;
  unsigned int addedfileprovides;	/* data-derived pool state, not policy */
  unsigned int cookielen;
  unsigned long long stroffs_off;
  unsigned long long strspace_off;
  unsigned long long strhash_off;
  unsigned long long rels_off;
  unsigned long long relhash_off;
  unsigned long long solvables_off;
  unsigned long long meta_off;
  unsigned long long meta_size;
  unsigned int installed_repoid;
  unsigned int wp_dataoff;		/* whatprovides, all zero if not computed */
  unsigned int wp_dataleft;
  unsigned int wp_auxoff;
  unsigned int wp_auxdataoff;
  unsigned long long wp_off;
  unsigned long long wp_data_off;
  unsigned long long wp_aux_off;
  unsigned long long wp_auxdata_off;
  /* the lazy file provides state pool_createwhatprovides() leaves
   * behind. Without it a mapped pool silently loses every provider of
   * a lazy file dependency, see pool_addstdproviders() */
  unsigned int lazyq_count;		/* elements, (id, oldoffset) pairs */
  unsigned int nonstd_nids;
  unsigned long long wp_policy;		/* see snap_wp_policy() */
  unsigned long long lazyq_off;
  unsigned long long nonstd_off;
  unsigned long long file_size;
  unsigned long long cookiecksum;	/* the caller's freshness gate, so not left unchecked */
  unsigned long long cksum;		/* over the header (cksum zeroed) and the meta region */
} Snaphdr;

typedef struct s_Snaprepo {
  unsigned int repoid;
  unsigned int start;
  unsigned int end;
  unsigned int nsolvables;
  unsigned int idarraysize;
  int priority;
  int subpriority;
  unsigned int disabled;
  unsigned int has_rpmdbid;
  unsigned int aliaslen;		/* including terminating zero */
  unsigned int ndata;			/* number of repodata stores */
  unsigned long long idarray_off;
} Snaprepo;

typedef struct s_Snapdata {
  unsigned int state;
  unsigned int start;
  unsigned int end;
  unsigned int nkeys;
  unsigned int nschemata;
  unsigned int schemadatalen;
  unsigned int mainschema;
  unsigned int nmainschemaoffsets;
  unsigned int incoredatalen;
  unsigned int ndirs;
  int filelisttype;
  unsigned int have_vertical;
  unsigned int lastverticaloffset;
  unsigned int num_pages;
  unsigned long long page_file_offset;
  unsigned int pathlen;			/* solv file path for vertical paging */
  unsigned long long path_size;		/* for validating the file at map time */
  unsigned long long path_mtime;
  unsigned long long path_mtime_nsec;
  unsigned int vincorelen;
  unsigned char keybits[32];
  unsigned long long incoredata_off;	/* aligned sections */
  unsigned long long incoreoffset_off;
} Snapdata;

static int
snap_pad(FILE *fp)
{
  static const char zeros[SNAP_ALIGN];
  long long pos = ftello(fp);
  int l = pos & (SNAP_ALIGN - 1);
  if (l && fwrite(zeros, SNAP_ALIGN - l, 1, fp) != 1)
    return -1;
  return 0;
}

static long long
snap_section(FILE *fp, const void *data, size_t len)
{
  long long off;
  if (snap_pad(fp))
    return -1;
  off = ftello(fp);
  if (len && fwrite(data, len, 1, fp) != 1)
    return -1;
  return off;
}

static int
snap_zeros(FILE *fp, size_t len)
{
  static const char zeros[SNAP_ALIGN];
  while (len)
    {
      size_t n = len > SNAP_ALIGN ? SNAP_ALIGN : len;
      if (fwrite(zeros, n, 1, fp) != 1)
	return -1;
      len -= n;
    }
  return 0;
}

/* section for an array that solv_extend() may append to in place:
 * zero-pad to the block-rounded capacity solv_extend() infers from the
 * length, so that when the array is borrowed from the mapping,
 * in-slack appends stay inside the section instead of scribbling over
 * the next one. The zeros are also semantic for the whatprovides
 * index, where 0 means "compute lazily". */
static long long
snap_section_blk(FILE *fp, const void *data, size_t len, size_t size, size_t block)
{
  long long off = snap_section(fp, data, len * size);
  size_t cap = (len + block) & ~block;
  if (off < 0)
    return -1;
  if (snap_zeros(fp, (cap - len) * size))
    return -1;
  return off;
}

/* One item of the meta region, digested as it is written.
 *
 * Items are packed back to back with variable-length strings in
 * between, so each is preceded by padding to SNAP_META_ALIGN. The
 * reader skips the same padding, so it must be emitted for every item,
 * zero-length ones included. */
static int
snap_meta_write(FILE *fp, unsigned long long *h, const void *data, size_t len)
{
  static const char zeros[SNAP_META_ALIGN];
  long long pos = ftello(fp);
  int l = pos & (SNAP_META_ALIGN - 1);
  if (l)
    {
      if (fwrite(zeros, SNAP_META_ALIGN - l, 1, fp) != 1)
	return -1;
      *h = snap_cksum(*h, zeros, SNAP_META_ALIGN - l);
    }
  if (len && fwrite(data, len, 1, fp) != 1)
    return -1;
  *h = snap_cksum(*h, data, len);
  return 0;
}

/* number of keys in the main schema == length of mainschemaoffsets */
static unsigned int
snap_nmainschemaoffsets(Repodata *data)
{
  Id *keyp;
  unsigned int i;
  if (!data->mainschemaoffsets || !data->mainschema)
    return 0;
  keyp = data->schemadata + data->schemata[data->mainschema];
  for (i = 0; keyp[i]; i++)
    ;
  return i;
}

static int
snap_pagefile(Repodata *data, char *path, size_t pathmax, unsigned long long *sizep, unsigned long long *mtimep, unsigned long long *nsecp)
{
  char lnk[64];
  struct stat st;
  ssize_t l;
  if (data->store.pagefd == -1)
    return -1;
  snprintf(lnk, sizeof(lnk), "/proc/self/fd/%d", data->store.pagefd);
  l = readlink(lnk, path, pathmax - 1);
  if (l <= 0 || l >= (ssize_t)(pathmax - 1) || path[0] != '/')
    return -1;
  path[l] = 0;
  if (l > 10 && !strcmp(path + l - 10, " (deleted)"))
    return -1;
  if (fstat(data->store.pagefd, &st))
    return -1;
  *sizep = st.st_size;
  *mtimep = st.st_mtime;
  *nsecp = st.st_mtim.tv_nsec;
  return 0;
}

/* the header with its own cksum field zeroed, with the digest of the
 * meta region folded in. Both sides compute it the same way, so the
 * writer never has to read back what it just wrote */
static unsigned long long
snap_hdr_cksum(const Snaphdr *hdr, unsigned long long metahash)
{
  Snaphdr h = *hdr;
  h.cksum = 0;
  return snap_cksum(snap_cksum(SNAP_CKSUM_INIT, &h, sizeof(h)), &metahash, sizeof(metahash));
}

/* digest of the pool state the stored whatprovides index was computed
 * under but which is not part of the snapshot: pool_createwhatprovides
 * drops providers that pool_installable_whatprovides() rejects, and
 * that depends on the arch policy pool_setarch() installed. A reader
 * with a different one would silently see a fraction of the providers,
 * so make the index unusable for it. pool->considered also feeds that
 * filter, but it is a per-run decision, so a pool that has one does not
 * get its index stored at all. */
static unsigned long long
snap_wp_policy(Pool *pool)
{
  unsigned long long h = SNAP_CKSUM_INIT;
  int lastarch = pool->lastarch;
  h = snap_cksum(h, &lastarch, sizeof(lastarch));
  if (pool->id2arch)
    h = snap_cksum(h, pool->id2arch, (size_t)(lastarch + 1) * sizeof(Id));
  h = snap_cksum(h, &pool->whatprovideswithdisabled, sizeof(pool->whatprovideswithdisabled));
  return h;
}

/* everything pool_snapshot_write() cannot represent. Checked up front,
 * so that an unsupported pool is reported before the body is written */
static int
snap_supported(Pool *pool)
{
  Repo *repo;
  Repodata *data;
  int i;
  Id rdid;
  FOR_REPOS(i, repo)
    FOR_REPODATAS(repo, rdid, data)
      {
	char path[4096];
	unsigned long long size, mtime, nsec;
	if (data->state != REPODATA_AVAILABLE || data->localpool || data->attrs || data->xattrs)
	  return 0;	/* a stub, a local pool or un-internalized attributes */
	/* the vertical data stays in the solv file and is demand-loaded
	 * from it, so we must be able to name that file. A repo read from
	 * a pipe or through solv_xfopen() has no page fd at all, and dnf
	 * and OBS do read compressed solv files that way */
	if (data->store.num_pages && snap_pagefile(data, path, sizeof(path), &size, &mtime, &nsec))
	  return 0;
      }
  return 1;
}

int
pool_snapshot_write(Pool *pool, FILE *fp, const unsigned char *cookie, unsigned int cookielen)
{
  Snaphdr hdr;
  int i, j, n;
  long long off;
  Solvable buf[64];
  Repo *repo;
  Id rdid;
  Repodata *data;
  unsigned long long *dataoffs = 0;
  unsigned long long *idarrayoffs;
  unsigned long long metahash = SNAP_CKSUM_INIT;
  Id *repoidmap;
  int ndataoffs = 0;
  int ret = -1;

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, SNAP_MAGIC, 8);
  hdr.version = SNAP_VERSION;
  hdr.abitag = SNAP_ABITAG;
  hdr.nstrings = pool->ss.nstrings;
  hdr.sstrings = pool->ss.sstrings;
  hdr.stringhashmask = pool->ss.stringhashtbl ? pool->ss.stringhashmask : 0;
  hdr.nrels = pool->nrels;
  hdr.relhashmask = pool->relhashtbl ? pool->relhashmask : 0;
  hdr.nsolvables = pool->nsolvables;
  hdr.disttype = pool->disttype;
  hdr.addedfileprovides = pool->addedfileprovides;
  if (cookielen > SNAP_COOKIE_MAX || (cookielen && !cookie))
    return -2;		/* caller bug, retrying will not help */
  if (!snap_supported(pool))
    return -2;		/* nothing written, and retrying will not help */
  hdr.cookielen = cookielen;

  /* freed repos leave holes in pool->repos, but the reader wants dense
   * repoids so it can rebuild the repo table by simply creating nrepos
   * repos in order. Map the live repoids onto 1..nrepos */
  repoidmap = solv_calloc(pool->nrepos > 0 ? pool->nrepos : 1, sizeof(Id));
  FOR_REPOS(i, repo)
    repoidmap[repo->repoid] = ++hdr.nrepos;
  idarrayoffs = solv_calloc(hdr.nrepos + 1, sizeof(*idarrayoffs));

  hdr.cookiecksum = snap_cksum(SNAP_CKSUM_INIT, cookie, cookielen);
  if (fseeko(fp, sizeof(hdr), SEEK_SET))
    goto out;
  if (cookielen && fwrite(cookie, cookielen, 1, fp) != 1)
    goto out;

  if ((off = snap_section_blk(fp, pool->ss.strings, hdr.nstrings, sizeof(Offset), SNAP_STRING_BLOCK)) < 0)
    goto out;
  hdr.stroffs_off = off;
  if ((off = snap_section_blk(fp, pool->ss.stringspace, hdr.sstrings, 1, SNAP_STRINGSPACE_BLOCK)) < 0)
    goto out;
  hdr.strspace_off = off;
  if ((off = snap_section(fp, pool->ss.stringhashtbl, hdr.stringhashmask ? ((size_t)hdr.stringhashmask + 1) * sizeof(Id) : 0)) < 0)
    goto out;
  hdr.strhash_off = off;
  if ((off = snap_section_blk(fp, pool->rels, hdr.nrels, sizeof(Reldep), SNAP_REL_BLOCK)) < 0)
    goto out;
  hdr.rels_off = off;
  if ((off = snap_section(fp, pool->relhashtbl, hdr.relhashmask ? ((size_t)hdr.relhashmask + 1) * sizeof(Id) : 0)) < 0)
    goto out;
  hdr.relhash_off = off;

  /* the solvables, with the repo pointers replaced by the repoid */
  if (snap_pad(fp))
    goto out;
  hdr.solvables_off = ftello(fp);
  for (i = 0; i < pool->nsolvables; i += n)
    {
      n = pool->nsolvables - i > 64 ? 64 : pool->nsolvables - i;
      memcpy(buf, pool->solvables + i, n * sizeof(Solvable));
      for (j = 0; j < n; j++)
	buf[j].repo = (Repo *)(size_t)(buf[j].repo ? repoidmap[buf[j].repo->repoid] : 0);
      if (fwrite(buf, sizeof(Solvable), n, fp) != (size_t)n)
	goto out;
    }

  /* per-repo aligned sections: idarraydata, then per-repodata
   * incoredata and incoreoffset */
  FOR_REPOS(i, repo)
    {
      if ((off = snap_section_blk(fp, repo->idarraydata, repo->idarraysize, sizeof(Id), SNAP_IDARRAY_BLOCK)) < 0)
	goto out;
      idarrayoffs[repoidmap[repo->repoid]] = off;
      FOR_REPODATAS(repo, rdid, data)
	{
	  dataoffs = solv_realloc2(dataoffs, ndataoffs + 2, sizeof(*dataoffs));
	  if ((off = snap_section(fp, data->incoredata, data->incoredatalen)) < 0)
	    goto out;
	  dataoffs[ndataoffs++] = off;
	  if ((off = snap_section_blk(fp, data->incoreoffset, (size_t)(data->end - data->start), sizeof(Id), SNAP_REPODATA_BLOCK)) < 0)
	    goto out;
	  dataoffs[ndataoffs++] = off;
	}
    }

  /* repo meta */
  if (snap_pad(fp))
    goto out;
  hdr.meta_off = ftello(fp);
  ndataoffs = 0;
  FOR_REPOS(i, repo)
    {
      Snaprepo sr;
      memset(&sr, 0, sizeof(sr));
      sr.repoid = repoidmap[repo->repoid];
      sr.start = repo->start;
      sr.end = repo->end;
      sr.nsolvables = repo->nsolvables;
      sr.idarraysize = repo->idarraysize;
      sr.priority = repo->priority;
      sr.subpriority = repo->subpriority;
      sr.disabled = repo->disabled;
      sr.has_rpmdbid = repo->rpmdbid ? 1 : 0;
      sr.aliaslen = repo->name ? strlen(repo->name) + 1 : 0;
      sr.ndata = repo->nrepodata ? repo->nrepodata - 1 : 0;
      sr.idarray_off = idarrayoffs[sr.repoid];
      if (snap_meta_write(fp, &metahash, &sr, sizeof(sr)))
	goto out;
      if (snap_meta_write(fp, &metahash, repo->name, sr.aliaslen))
	goto out;
      if (snap_meta_write(fp, &metahash, repo->rpmdbid, sr.has_rpmdbid ? (size_t)(sr.end - sr.start) * sizeof(Id) : 0))
	goto out;
      FOR_REPODATAS(repo, rdid, data)
	{
	  Snapdata sd;
	  char path[4096];
	  memset(&sd, 0, sizeof(sd));
	  sd.state = data->state;
	  sd.start = data->start;
	  sd.end = data->end;
	  sd.nkeys = data->nkeys;
	  sd.nschemata = data->nschemata;
	  sd.schemadatalen = data->schemadatalen;
	  sd.mainschema = data->mainschema;
	  sd.nmainschemaoffsets = snap_nmainschemaoffsets(data);
	  sd.incoredatalen = data->incoredatalen;
	  sd.ndirs = data->dirpool.ndirs;
	  sd.filelisttype = data->filelisttype;
	  sd.have_vertical = data->verticaloffset ? 1 : 0;
	  sd.lastverticaloffset = data->lastverticaloffset;
	  sd.vincorelen = data->vincorelen;
	  memcpy(sd.keybits, data->keybits, sizeof(sd.keybits));
	  if (data->store.num_pages)
	    {
	      if (snap_pagefile(data, path, sizeof(path), &sd.path_size, &sd.path_mtime, &sd.path_mtime_nsec))
		goto out;		/* cannot re-find the solv file */
	      sd.num_pages = data->store.num_pages;
	      sd.page_file_offset = data->store.file_offset;
	      sd.pathlen = strlen(path) + 1;
	    }
	  sd.incoredata_off = dataoffs[ndataoffs++];
	  sd.incoreoffset_off = dataoffs[ndataoffs++];
	  /* keep this sequence in lockstep with the reader's meta parsing */
	  if (snap_meta_write(fp, &metahash, &sd, sizeof(sd))
	      || snap_meta_write(fp, &metahash, data->keys, (size_t)sd.nkeys * sizeof(Repokey))
	      || snap_meta_write(fp, &metahash, data->schemata, (size_t)sd.nschemata * sizeof(Id))
	      || snap_meta_write(fp, &metahash, data->schemadata, (size_t)sd.schemadatalen * sizeof(Id))
	      || (sd.have_vertical && snap_meta_write(fp, &metahash, data->verticaloffset, (size_t)sd.nkeys * sizeof(Id)))
	      || snap_meta_write(fp, &metahash, data->mainschemaoffsets, (size_t)sd.nmainschemaoffsets * sizeof(Id))
	      || snap_meta_write(fp, &metahash, data->dirpool.dirs, (size_t)sd.ndirs * sizeof(Id))
	      || snap_meta_write(fp, &metahash, data->store.file_pages, (size_t)sd.num_pages * sizeof(Attrblobpage))
	      || snap_meta_write(fp, &metahash, path, sd.pathlen)
	      || snap_meta_write(fp, &metahash, data->vincore, sd.vincorelen))
	    goto out;
	}
    }
  hdr.meta_size = ftello(fp) - hdr.meta_off;

  hdr.installed_repoid = pool->installed ? repoidmap[pool->installed->repoid] : 0;

  /* the file provides state pool_addfileprovides()/
   * pool_createwhatprovides() derive: nonstd_ids is needed to lazify
   * again if the restored pool recomputes whatprovides, and the
   * lazywhatprovidesq holds the pre-lazification offsets that
   * pool_addstdproviders() merges the filelist hits with */
  if (pool->nonstd_nids > 0)
    {
      hdr.nonstd_nids = pool->nonstd_nids;
      if ((off = snap_section(fp, pool->nonstd_ids, (size_t)hdr.nonstd_nids * sizeof(Id))) < 0)
	goto out;
      hdr.nonstd_off = off;
    }
  if (pool->lazywhatprovidesq.count > 0)
    {
      hdr.lazyq_count = pool->lazywhatprovidesq.count;
      if ((off = snap_section(fp, pool->lazywhatprovidesq.elements, (size_t)hdr.lazyq_count * sizeof(Id))) < 0)
	goto out;
      hdr.lazyq_off = off;
    }

  /* pool->considered filters the whatprovides index too, but unlike
   * the arch policy it is a per-run decision, so an index computed
   * under one is not worth caching */
  if (pool->whatprovides && pool->whatprovidesdataoff && !pool->considered)
    {
      hdr.wp_policy = snap_wp_policy(pool);
      /* pool->whatprovides_rel is not stored: it only caches lazily
       * computed rel providers and namespace results, which may depend
       * on the reader's configuration */
      hdr.wp_dataoff = pool->whatprovidesdataoff;
      /* the append arena for lazily computed rel providers is written
       * as zeros behind the data so a borrowed array can grow in
       * place; cap it so a huge reserve does not bloat the file (the
       * cap only makes the first overflowing append migrate to the
       * heap earlier). hdr.wp_dataleft is derived from the very bytes
       * written, keeping header and padding in sync by construction. */
      hdr.wp_dataleft = pool->whatprovidesdataleft;
      if (hdr.wp_dataleft > SNAP_WPDATA_RESERVE)
	hdr.wp_dataleft = SNAP_WPDATA_RESERVE;
      if ((off = snap_section_blk(fp, pool->whatprovides, pool->ss.nstrings, sizeof(Offset), WHATPROVIDES_BLOCK)) < 0)
	goto out;
      hdr.wp_off = off;
      if ((off = snap_section(fp, pool->whatprovidesdata, (size_t)pool->whatprovidesdataoff * sizeof(Id))) < 0)
	goto out;
      if (snap_zeros(fp, (size_t)hdr.wp_dataleft * sizeof(Id)))
	goto out;
      hdr.wp_data_off = off;
      if (pool->whatprovidesaux)
	{
	  hdr.wp_auxoff = pool->whatprovidesauxoff;
	  hdr.wp_auxdataoff = pool->whatprovidesauxdataoff;
	  if ((off = snap_section(fp, pool->whatprovidesaux, (size_t)pool->whatprovidesauxoff * sizeof(Offset))) < 0)
	    goto out;
	  hdr.wp_aux_off = off;
	  if ((off = snap_section(fp, pool->whatprovidesauxdata, (size_t)pool->whatprovidesauxdataoff * sizeof(Id))) < 0)
	    goto out;
	  hdr.wp_auxdata_off = off;
	}
    }
  hdr.file_size = ftello(fp);
  hdr.cksum = snap_hdr_cksum(&hdr, metahash);

  if (fseeko(fp, 0, SEEK_SET) || fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
    goto out;
  ret = fflush(fp);
out:
  solv_free(dataoffs);
  solv_free(idarrayoffs);
  solv_free(repoidmap);
  return ret;
}

void *
pool_snapshot_mapping(Pool *pool, size_t *sizep)
{
  if (sizep)
    *sizep = pool->snapshot_size;
  return pool->snapshot_base;
}

int
pool_snapshot_read_cookie(FILE *fp, unsigned char *cookie, unsigned int *cookielenp)
{
  Snaphdr hdr;
  if (fseeko(fp, 0, SEEK_SET) || fread(&hdr, sizeof(hdr), 1, fp) != 1)
    return -1;
  if (memcmp(hdr.magic, SNAP_MAGIC, 8) != 0 || hdr.version != SNAP_VERSION || hdr.abitag != SNAP_ABITAG)
    return -1;
  if (hdr.cookielen > SNAP_COOKIE_MAX || hdr.cookielen > *cookielenp)
    return -1;
  if (hdr.cookielen && fread(cookie, hdr.cookielen, 1, fp) != 1)
    return -1;
  if (snap_cksum(SNAP_CKSUM_INIT, cookie, hdr.cookielen) != hdr.cookiecksum)
    return -1;		/* a corrupt cookie must not pass as fresh */
  *cookielenp = hdr.cookielen;
  return 0;
}

/* parsed form of one repodata meta entry, filled in the validation
 * phase so the pool is only touched when nothing can fail anymore */
typedef struct s_Snapdatax {
  Snapdata sd;
  Repokey *keys;
  Id *schemata;
  Id *schemadata;
  Id *verticaloffset;
  Id *mainschemaoffsets;
  Id *dirs;
  Attrblobpage *file_pages;
  const char *path;
  unsigned char *vincore;
  int pagefd;
} Snapdatax;

typedef struct s_Snaprepox {
  Snaprepo sr;
  const char *alias;
  Id *rpmdbid;
  Snapdatax *datax;
} Snaprepox;

static void
snap_free_repox(Snaprepox *reposx, unsigned int nrepos)
{
  unsigned int r, d;
  if (!reposx)
    return;
  for (r = 0; r < nrepos; r++)
    if (reposx[r].datax)
      {
	for (d = 0; d < reposx[r].sr.ndata; d++)
	  if (reposx[r].datax[d].pagefd != -1)
	    close(reposx[r].datax[d].pagefd);
	solv_free(reposx[r].datax);
      }
  solv_free(reposx);
}

/* Take the next item out of the meta region. Every item is preceded by
 * padding to SNAP_META_ALIGN, emitted unconditionally by
 * snap_meta_write(), so that the fixed-size structs and the Id arrays
 * are aligned even though variable-length strings sit between them.
 * base is page aligned, so aligning relative to it aligns absolutely. */
#define SNAP_META_NEXT(dst, cnt, size) do {				\
    unsigned long long l = (unsigned long long)(cnt) * (size);		\
    size_t pad = (size_t)(-(mp - base)) & (SNAP_META_ALIGN - 1);		\
    if (pad > (size_t)(metaend - mp))					\
      goto fail;							\
    mp += pad;								\
    if (l > (unsigned long long)(metaend - mp))				\
      goto fail;							\
    (dst) = (void *)mp;							\
    mp += l;								\
  } while (0)

int
pool_snapshot_map(Pool *pool, FILE *fp)
{
  Snaphdr hdr;
  unsigned char *base, *mp, *metaend;
  struct stat st;
  int i;
  unsigned int r, d;
  Snaprepox *reposx = 0;

  /* The pool must be virgin: everything the snapshot brings replaces
   * pool state wholesale, so anything already in the pool would either
   * be dropped or, worse, keep an id that now means something else.
   * Interned strings are the one exception, see the foreign check
   * below; rels have no such check, so they must not exist yet. */
  if (pool->nrepos || pool->urepos || pool->nsolvables > 2 || pool->whatprovides)
    return -1;
  if (pool->nrels > 1)
    return -2;		/* like a foreign intern sequence, rewriting will not help */
  if (fseeko(fp, 0, SEEK_SET) || fread(&hdr, sizeof(hdr), 1, fp) != 1)
    return -1;
  if (memcmp(hdr.magic, SNAP_MAGIC, 8) != 0 || hdr.version != SNAP_VERSION || hdr.abitag != SNAP_ABITAG)
    return -1;
  if (fstat(fileno(fp), &st) || (unsigned long long)st.st_size < hdr.file_size)
    return -1;
  if (hdr.file_size > (unsigned long long)SIZE_MAX)
    return -1;		/* cannot be mapped on this build */
  if (!snap_infile(hdr.meta_off, hdr.meta_size, hdr.file_size) || hdr.cookielen > SNAP_COOKIE_MAX)
    return -1;
  /* a pool always holds at least the empty string and solvable ids 0
   * and 1, and repoids are dense from 1, so the meta region must have
   * room for nrepos entries */
  if (hdr.nstrings < 2 || hdr.nrels < 1 || hdr.nsolvables < 2
      || (unsigned long long)hdr.nrepos * sizeof(Snaprepo) > hdr.meta_size)
    return -1;
  /* borrowed sections must fit at their block-rounded capacity: the
   * in-slack appends of solv_extend() go up to there */
  if (!snap_infile(hdr.stroffs_off, SNAP_CAP(hdr.nstrings, SNAP_STRING_BLOCK) * sizeof(Offset), hdr.file_size)
      || !snap_infile(hdr.strspace_off, SNAP_CAP(hdr.sstrings, SNAP_STRINGSPACE_BLOCK), hdr.file_size)
      || !snap_infile(hdr.rels_off, SNAP_CAP(hdr.nrels, SNAP_REL_BLOCK) * sizeof(Reldep), hdr.file_size)
      || !snap_infile(hdr.solvables_off, (unsigned long long)hdr.nsolvables * sizeof(Solvable), hdr.file_size))
    return -1;
  if (hdr.stringhashmask && !snap_infile(hdr.strhash_off, ((unsigned long long)hdr.stringhashmask + 1) * sizeof(Id), hdr.file_size))
    return -1;
  if (hdr.relhashmask && !snap_infile(hdr.relhash_off, ((unsigned long long)hdr.relhashmask + 1) * sizeof(Id), hdr.file_size))
    return -1;
  if (!snap_infile(hdr.nonstd_off, (unsigned long long)hdr.nonstd_nids * sizeof(Id), hdr.file_size)
      || !snap_infile(hdr.lazyq_off, (unsigned long long)hdr.lazyq_count * sizeof(Id), hdr.file_size))
    return -1;
  if (hdr.wp_dataoff)
    {
      if (!snap_infile(hdr.wp_off, SNAP_CAP(hdr.nstrings, WHATPROVIDES_BLOCK) * sizeof(Offset), hdr.file_size))
	return -1;
      if (!snap_infile(hdr.wp_data_off, ((unsigned long long)hdr.wp_dataoff + hdr.wp_dataleft) * sizeof(Id), hdr.file_size))
	return -1;
      if (hdr.wp_auxoff
	  && (!snap_infile(hdr.wp_aux_off, (unsigned long long)hdr.wp_auxoff * sizeof(Offset), hdr.file_size)
	      || !snap_infile(hdr.wp_auxdata_off, (unsigned long long)hdr.wp_auxdataoff * sizeof(Id), hdr.file_size)))
	return -1;
    }
#ifndef MULTI_SEMANTICS
  if (hdr.disttype != (unsigned int)pool->disttype)
    return -1;		/* a snapshot of a different package system */
#endif
  /* private writable mapping: reads stay shared with the page cache,
   * written pages are copied on write */
  base = mmap(0, (size_t)hdr.file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
  if (base == MAP_FAILED)
    return -1;

  /* the header and the meta region carry every offset and count the
   * parsing below trusts, so verify them before following any of it */
  if (snap_hdr_cksum(&hdr, snap_cksum(SNAP_CKSUM_INIT, base + hdr.meta_off, (size_t)hdr.meta_size)) != hdr.cksum)
    goto fail;

  /* Ids the caller interned before mapping must keep their meaning. The
   * snapshot was written by a different process, so its string pool has to
   * start with exactly the strings this pool already has. Callers like
   * libzypp intern kind, arch and attribute names up front, and a mismatch
   * would silently turn them into unrelated strings.
   * A mismatch reports -2: the snapshot is not stale, it just belongs
   * to a client with a different pre-load intern sequence. Callers
   * should fall back without rewriting the file, or two such clients
   * would take turns clobbering each other's snapshot. */
  {
    Offset *snapstroffs = (Offset *)(base + hdr.stroffs_off);
    char *snapstrspace = (char *)(base + hdr.strspace_off);
    if (pool->ss.nstrings > hdr.nstrings)
      goto foreign;
    for (i = 1; i < (int)pool->ss.nstrings; i++)
      {
	/* the offsets come from the file, and this loop is the first
	 * thing that follows them */
	if (snapstroffs[i] >= hdr.sstrings)
	  goto fail;
	if (strcmp(pool->ss.stringspace + pool->ss.strings[i], snapstrspace + snapstroffs[i]) != 0)
	  goto foreign;
      }
  }

  /* phase 1: parse and validate all meta, open the vertical files.
   * the pool is not touched yet, any failure just unmaps */
  mp = base + hdr.meta_off;
  metaend = mp + hdr.meta_size;
  reposx = solv_calloc(hdr.nrepos ? hdr.nrepos : 1, sizeof(Snaprepox));
  for (r = 0; r < hdr.nrepos; r++)
    {
      Snaprepox *rx = reposx + r;
      void *sr;
      SNAP_META_NEXT(sr, 1, sizeof(Snaprepo));
      memcpy(&rx->sr, sr, sizeof(rx->sr));
      if (rx->sr.repoid != r + 1)
	goto fail;	/* snapshot repos are dense and ordered */
      /* the solvable range must lie in the pool the header describes */
      if (rx->sr.start > rx->sr.end || rx->sr.end > hdr.nsolvables)
	goto fail;
      SNAP_META_NEXT(rx->alias, rx->sr.aliaslen, 1);
      if (rx->sr.aliaslen && rx->alias[rx->sr.aliaslen - 1] != 0)
	goto fail;
      SNAP_META_NEXT(rx->rpmdbid, rx->sr.has_rpmdbid ? rx->sr.end - rx->sr.start : 0, sizeof(Id));
      if (!snap_infile(rx->sr.idarray_off, SNAP_CAP(rx->sr.idarraysize, SNAP_IDARRAY_BLOCK) * sizeof(Id), hdr.file_size))
	goto fail;
      /* each repodata has at least its Snapdata in the meta region */
      if ((unsigned long long)rx->sr.ndata * sizeof(Snapdata) > hdr.meta_size)
	goto fail;
      rx->datax = solv_calloc(rx->sr.ndata ? rx->sr.ndata : 1, sizeof(Snapdatax));
      for (d = 0; d < rx->sr.ndata; d++)
	rx->datax[d].pagefd = -1;
      for (d = 0; d < rx->sr.ndata; d++)
	{
	  Snapdatax *dx = rx->datax + d;
	  void *sd;
	  SNAP_META_NEXT(sd, 1, sizeof(Snapdata));
	  memcpy(&dx->sd, sd, sizeof(dx->sd));
	  if (dx->sd.state != REPODATA_AVAILABLE)
	    goto fail;
	  if (dx->sd.start > dx->sd.end || dx->sd.end > hdr.nsolvables)
	    goto fail;
	  /* the main schema is looked up in schemata[] on first use */
	  if (dx->sd.mainschema >= dx->sd.nschemata && (dx->sd.mainschema || dx->sd.nmainschemaoffsets))
	    goto fail;
	  SNAP_META_NEXT(dx->keys, dx->sd.nkeys, sizeof(Repokey));
	  SNAP_META_NEXT(dx->schemata, dx->sd.nschemata, sizeof(Id));
	  SNAP_META_NEXT(dx->schemadata, dx->sd.schemadatalen, sizeof(Id));
	  if (dx->sd.have_vertical)
	    SNAP_META_NEXT(dx->verticaloffset, dx->sd.nkeys, sizeof(Id));
	  SNAP_META_NEXT(dx->mainschemaoffsets, dx->sd.nmainschemaoffsets, sizeof(Id));
	  SNAP_META_NEXT(dx->dirs, dx->sd.ndirs, sizeof(Id));
	  SNAP_META_NEXT(dx->file_pages, dx->sd.num_pages, sizeof(Attrblobpage));
	  SNAP_META_NEXT(dx->path, dx->sd.pathlen, 1);
	  if (dx->sd.pathlen && dx->path[dx->sd.pathlen - 1] != 0)
	    goto fail;
	  SNAP_META_NEXT(dx->vincore, dx->sd.vincorelen, 1);
	  if (!snap_infile(dx->sd.incoredata_off, dx->sd.incoredatalen, hdr.file_size))
	    goto fail;
	  if (!snap_infile(dx->sd.incoreoffset_off, SNAP_CAP(dx->sd.end - dx->sd.start, SNAP_REPODATA_BLOCK) * sizeof(Id), hdr.file_size))
	    goto fail;
	  if (dx->sd.num_pages)
	    {
	      struct stat pst;
	      if (!dx->sd.pathlen)
		goto fail;
	      dx->pagefd = open(dx->path, O_RDONLY);
	      if (dx->pagefd == -1)
		goto fail;
	      solv_setcloexec(dx->pagefd, 1);
	      /* the vertical pages live in the original solv file,
	       * refuse if it changed since the snapshot was written */
	      if (fstat(dx->pagefd, &pst) || (unsigned long long)pst.st_size != dx->sd.path_size
		  || (unsigned long long)pst.st_mtime != dx->sd.path_mtime
		  || (unsigned long long)pst.st_mtim.tv_nsec != dx->sd.path_mtime_nsec)
		goto fail;
	    }
	}
    }

  /* every solvable names the repo it belongs to, and the repo table is
   * only as large as the meta region says */
  {
    const Solvable *snapsolv = (const Solvable *)(base + hdr.solvables_off);
    for (i = 0; i < (int)hdr.nsolvables; i++)
      if ((size_t)snapsolv[i].repo > hdr.nrepos)
	goto fail;
  }

  /* register the mapping as borrowed memory so solv_realloc migrates
   * and solv_free ignores pointers into it. Refused if another
   * snapshot is already mapped in this process: that is not a defect
   * of this file, so report it like a foreign one and do not make the
   * caller rewrite a perfectly good snapshot. */
  if (solv_set_borrowed(base, (size_t)hdr.file_size) != 0)
    goto foreign;

  /* phase 2: commit into the pool, nothing can fail from here on */
#ifdef MULTI_SEMANTICS
  pool_setdisttype(pool, hdr.disttype);
#endif
  pool->addedfileprovides = hdr.addedfileprovides;
  if (hdr.nonstd_nids)
    {
      solv_free(pool->nonstd_ids);
      pool->nonstd_ids = solv_memdup2(base + hdr.nonstd_off, hdr.nonstd_nids, sizeof(Id));
      pool->nonstd_nids = hdr.nonstd_nids;
    }
  if (hdr.lazyq_count)
    {
      queue_empty(&pool->lazywhatprovidesq);
      queue_insertn(&pool->lazywhatprovidesq, 0, hdr.lazyq_count, (Id *)(base + hdr.lazyq_off));
    }

  /* string pool and rels: borrowed from the mapping. New interns
   * write into the capacity slack the file reserves (CoW pages);
   * growth past a block boundary migrates the array to the heap via
   * the solv_realloc borrowed-range check. The hash tables are
   * borrowed too: they are only ever replaced wholesale, and the
   * free of the old table is a no-op for a borrowed pointer.
   *
   * Note that repo_add_solv() reserves and then shrinks through
   * solv_extend_resize(), which always reallocs, so adding even a tiny
   * repo migrates the whole string pool, its offsets and the rels to
   * the heap at once: measured 63 -> 286 MB RSS on a 321 MB snapshot.
   * The page sharing is a benefit of the read-only case, not something
   * that survives loading another repo. */
  solv_free(pool->ss.strings);
  solv_free(pool->ss.stringspace);
  solv_free(pool->ss.stringhashtbl);
  pool->ss.strings = (Offset *)(base + hdr.stroffs_off);
  pool->ss.nstrings = hdr.nstrings;
  pool->ss.stringspace = (char *)(base + hdr.strspace_off);
  pool->ss.sstrings = hdr.sstrings;
  pool->ss.stringhashtbl = 0;
  pool->ss.stringhashmask = 0;
  if (hdr.stringhashmask)
    {
      pool->ss.stringhashtbl = (Id *)(base + hdr.strhash_off);
      pool->ss.stringhashmask = hdr.stringhashmask;
    }
  solv_free(pool->rels);
  solv_free(pool->relhashtbl);
  pool->rels = (Reldep *)(base + hdr.rels_off);
  pool->nrels = hdr.nrels;
  pool->relhashtbl = 0;
  pool->relhashmask = 0;
  if (hdr.relhashmask)
    {
      pool->relhashtbl = (Id *)(base + hdr.relhash_off);
      pool->relhashmask = hdr.relhashmask;
    }

  /* solvables: heap copy. The repoid->pointer fixup below writes one
   * field in every entry, which would CoW every page of a borrowed
   * section anyway */
  solv_free(pool->solvables);
  pool->solvables = snap_memdup_block(base + hdr.solvables_off, hdr.nsolvables, sizeof(Solvable), SNAP_SOLVABLE_BLOCK);
  pool->nsolvables = hdr.nsolvables;

  for (r = 0; r < hdr.nrepos; r++)
    {
      Snaprepox *rx = reposx + r;
      Repo *repo = repo_create(pool, rx->sr.aliaslen ? rx->alias : 0);
      repo->start = rx->sr.start;
      repo->end = rx->sr.end;
      repo->nsolvables = rx->sr.nsolvables;
      repo->priority = rx->sr.priority;
      repo->subpriority = rx->sr.subpriority;
      repo->disabled = rx->sr.disabled;
      repo->idarraydata = rx->sr.idarraysize ? (Id *)(base + rx->sr.idarray_off) : 0;
      repo->idarraysize = rx->sr.idarraysize;
      if (rx->sr.has_rpmdbid)
	repo->rpmdbid = snap_memdup_block(rx->rpmdbid, rx->sr.end - rx->sr.start, sizeof(Id), SNAP_SIDEDATA_BLOCK);
      repo->nrepodata = rx->sr.ndata + 1;
      repo->repodata = solv_calloc(rx->sr.ndata + 1, sizeof(Repodata));
      for (d = 0; d < rx->sr.ndata; d++)
	{
	  Snapdatax *dx = rx->datax + d;
	  Repodata *data = repo->repodata + d + 1;
	  data->repodataid = d + 1;
	  data->repo = repo;
	  data->state = REPODATA_AVAILABLE;
	  data->start = dx->sd.start;
	  data->end = dx->sd.end;
	  data->keys = solv_memdup2(dx->keys, dx->sd.nkeys, sizeof(Repokey));
	  data->nkeys = dx->sd.nkeys;
	  memcpy(data->keybits, dx->sd.keybits, sizeof(data->keybits));
	  data->schemata = solv_memdup2(dx->schemata, dx->sd.nschemata, sizeof(Id));
	  data->nschemata = dx->sd.nschemata;
	  data->schemadata = solv_memdup2(dx->schemadata, dx->sd.schemadatalen, sizeof(Id));
	  data->schemadatalen = dx->sd.schemadatalen;
	  if (dx->sd.ndirs)
	    {
	      data->dirpool.dirs = solv_memdup2(dx->dirs, dx->sd.ndirs, sizeof(Id));
	      data->dirpool.ndirs = dx->sd.ndirs;
	    }
	  data->incoredata = dx->sd.incoredatalen ? (unsigned char *)(base + dx->sd.incoredata_off) : 0;
	  data->incoredatalen = dx->sd.incoredatalen;
	  data->incoredatafree = 0;
	  data->mainschema = dx->sd.mainschema;
	  if (dx->sd.nmainschemaoffsets)
	    data->mainschemaoffsets = solv_memdup2(dx->mainschemaoffsets, dx->sd.nmainschemaoffsets, sizeof(Id));
	  data->incoreoffset = dx->sd.end > dx->sd.start ? (Id *)(base + dx->sd.incoreoffset_off) : 0;
	  if (dx->sd.have_vertical)
	    data->verticaloffset = solv_memdup2(dx->verticaloffset, dx->sd.nkeys, sizeof(Id));
	  data->lastverticaloffset = dx->sd.lastverticaloffset;
	  data->filelisttype = dx->sd.filelisttype;
	  if (dx->sd.vincorelen)
	    {
	      data->vincore = solv_memdup2(dx->vincore, dx->sd.vincorelen, 1);
	      data->vincorelen = dx->sd.vincorelen;
	    }
	  repopagestore_init(&data->store);
	  if (dx->sd.num_pages)
	    {
	      unsigned int p;
	      data->store.pagefd = dx->pagefd;
	      dx->pagefd = -1;			/* now owned by the store */
	      data->store.file_offset = dx->sd.page_file_offset;
	      data->store.num_pages = dx->sd.num_pages;
	      data->store.file_pages = solv_memdup2(dx->file_pages, dx->sd.num_pages, sizeof(Attrblobpage));
	      data->store.mapped_at = solv_malloc2(dx->sd.num_pages, sizeof(*data->store.mapped_at));
	      for (p = 0; p < dx->sd.num_pages; p++)
		data->store.mapped_at[p] = -1;	/* not mapped yet */
	    }
	}
    }

  /* turn the stored repoids back into pointers */
  for (i = 0; i < pool->nsolvables; i++)
    {
      size_t repoid = (size_t)pool->solvables[i].repo;	/* validated above */
      pool->solvables[i].repo = repoid ? pool->repos[repoid] : 0;
    }

  if (hdr.installed_repoid && hdr.installed_repoid < (unsigned int)pool->nrepos)
    pool->installed = pool->repos[hdr.installed_repoid];

  /* The stored index only lists the providers the writer's arch policy
   * accepted, and pool->considered filters it further, so it is usable
   * only for a reader whose policy matches and who has no considered
   * map. Everything else in the snapshot is policy independent, so
   * rather than throwing the file away, compute the index instead -
   * still far cheaper than loading every repo again. That also covers
   * a snapshot written without an index at all, which must never leave
   * the caller with pool->whatprovides == 0. */
  if (hdr.wp_dataoff && !pool->considered && hdr.wp_policy == snap_wp_policy(pool))
    {
      /* borrowed; the file reserves the same growth capacity the
       * pool_createwhatprovides allocation pattern would (index padded
       * to WHATPROVIDES_BLOCK, data followed by the wp_dataleft append
       * arena, both zeroed by the writer). whatprovides_rel caches
       * reader-dependent namespace results and is never stored. */
      pool->whatprovides = (Offset *)(base + hdr.wp_off);
      pool->whatprovides_rel = solv_calloc_block(hdr.nrels, sizeof(Offset), WHATPROVIDES_BLOCK);
      pool->whatprovidesdata = (Id *)(base + hdr.wp_data_off);
      pool->whatprovidesdataoff = hdr.wp_dataoff;
      pool->whatprovidesdataleft = hdr.wp_dataleft;
      if (hdr.wp_auxoff && !pool->nowhatprovidesaux)
	{
	  pool->whatprovidesaux = (Offset *)(base + hdr.wp_aux_off);
	  pool->whatprovidesauxoff = hdr.wp_auxoff;
	  pool->whatprovidesauxdata = (Id *)(base + hdr.wp_auxdata_off);
	  pool->whatprovidesauxdataoff = hdr.wp_auxdataoff;
	}
    }
  /* the mapping stays alive until pool_free unregisters and unmaps */
  pool->snapshot_base = base;
  pool->snapshot_size = (size_t)hdr.file_size;
  snap_free_repox(reposx, hdr.nrepos);
  if (!pool->whatprovides)
    pool_createwhatprovides(pool);
  return 0;

fail:
  snap_free_repox(reposx, hdr.nrepos);
  munmap(base, (size_t)hdr.file_size);
  return -1;

foreign:
  snap_free_repox(reposx, hdr.nrepos);
  munmap(base, (size_t)hdr.file_size);
  return -2;
}

#endif /* __linux__ */
