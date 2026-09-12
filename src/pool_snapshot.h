/*
 * Copyright (c) 2026, SUSE LLC
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#ifndef LIBSOLV_POOL_SNAPSHOT_H
#define LIBSOLV_POOL_SNAPSHOT_H

#include <stddef.h>
#include <stdio.h>
#include "pooltypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EXPERIMENTAL, see pool_snapshot.c for the restrictions and the trust
 * model. The C API below is versioned like the rest of libsolv, but the
 * on-disk format is not stable: it carries a version that every reader
 * checks, so a snapshot written by another libsolv is simply rejected.
 *
 * pool_snapshot_map restores into a freshly created, still empty pool
 * and returns 0 on success; on failure the pool is untouched.
 * -1: stale, corrupt or unreadable file, callers should rewrite it
 *     after loading.
 * -2: intact file, but not usable by this caller - a different pre-load
 *     intern sequence, a different arch policy behind the stored
 *     whatprovides index, or another snapshot already mapped in this
 *     process. Fall back WITHOUT rewriting, or two such clients would
 *     take turns clobbering each other's snapshot.
 *
 * pool_snapshot_write returns 0 on success, -1 on a write error and -2
 * if the pool cannot be represented (a stub or un-internalized
 * repodata, a repo whose solv file cannot be named because it was read
 * from a pipe or a compressed stream, or no mmap on this platform);
 * -2 is decided before anything is written, and retrying will not
 * help. On success the caller still owns flushing: check fclose(), and
 * fsync() before the rename(2) the file contract requires.
 *
 * Restrictions worth knowing before calling map:
 * - the arch policy must be installed (pool_setarch) first. The stored
 *   whatprovides index depends on it; with a different one, or with a
 *   pool->considered map, the index is recomputed instead of used, so
 *   the call still succeeds but costs more.
 * - repoids come back dense in the order the snapshot stored them,
 *   which is not necessarily the order the writer created them in.
 * - repo->appdata is the application's and is not stored. */
extern int pool_snapshot_write(struct s_Pool *pool, FILE *fp, const unsigned char *cookie, unsigned int cookielen);
extern int pool_snapshot_map(struct s_Pool *pool, FILE *fp);
extern int pool_snapshot_read_cookie(FILE *fp, unsigned char *cookie, unsigned int *cookielenp);
/* the live mapping borrowed sections point into, 0 if not mapped */
extern void *pool_snapshot_mapping(struct s_Pool *pool, size_t *sizep);

#ifdef __cplusplus
}
#endif

#endif /* LIBSOLV_POOL_SNAPSHOT_H */
