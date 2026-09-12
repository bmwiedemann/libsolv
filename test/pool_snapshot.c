/*
 * Copyright (c) 2026, SUSE LLC
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

/* round trip test for pool_snapshot_write()/pool_snapshot_map():
 * build a pool in memory, snapshot it, map it into a fresh pool and
 * check that nothing an application can observe has changed */

#define LIBSOLV_INTERNAL 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pool.h"
#include "poolarch.h"
#include "pool_snapshot.h"
#include "repo.h"
#include "repodata.h"
#include "knownid.h"

static const char *snapfile;
static int failed;

static void
check(int ok, const char *what)
{
  printf("%-44s %s\n", what, ok ? "ok" : "FAILED");
  if (!ok)
    failed++;
}

static unsigned long long
hash(unsigned long long h, const void *d, size_t l)
{
  const unsigned char *p = d;
  for (; l; l--, p++)
    h = (h ^ *p) * 0x100000001b3ULL;
  return h;
}

/* everything a consumer can see: names, repos, providers, attributes */
static unsigned long long
pool_digest(Pool *pool)
{
  unsigned long long h = 0xcbf29ce484222325ULL;
  Id i, p, pp;
  for (i = 2; i < pool->nsolvables; i++)
    {
      Solvable *s = pool->solvables + i;
      const char *n;
      if (!s->repo)
	continue;
      n = pool_solvable2str(pool, s);
      h = hash(h, n, strlen(n));
      n = s->repo->name ? s->repo->name : "";
      h = hash(h, n, strlen(n));
      n = solvable_lookup_str(s, SOLVABLE_SUMMARY);
      if (n)
	h = hash(h, n, strlen(n));
      /* not the repoid: freeing a repo leaves a hole that the snapshot
       * closes again, so the numbers legitimately differ */
    }
  for (i = 1; i < pool->ss.nstrings; i++)
    {
      Id d = i;
      FOR_PROVIDES(p, pp, d)
	h = hash(h, &p, sizeof(p));
    }
  return h;
}

/* note that FOR_PROVIDES uses the identifier "pool" from its scope, so
 * queries on a pool that is not called "pool" go through here */
static int
count_providers(Pool *pool, Id d)
{
  Id p, pp;
  int n = 0;
  FOR_PROVIDES(p, pp, d)
    n++;
  return n;
}

static Solvable *
addpkg(Repo *repo, Repodata *data, const char *name, const char *evr, const char *summary)
{
  Solvable *s = pool_id2solvable(repo->pool, repo_add_solvable(repo));
  s->name = pool_str2id(repo->pool, name, 1);
  s->evr = pool_str2id(repo->pool, evr, 1);
  s->arch = pool_str2id(repo->pool, "x86_64", 1);
  s->provides = repo_addid_dep(repo, s->provides, pool_rel2id(repo->pool, s->name, s->evr, REL_EQ, 1), 0);
  repodata_set_str(data, s - repo->pool->solvables, SOLVABLE_SUMMARY, summary);
  return s;
}

/* three repos, the middle one freed again so the repoids have a hole,
 * plus one repo without a name and an installed repo */
static Pool *
build(int witharch)
{
  Pool *pool = pool_create();
  Repo *r1, *r2, *r3, *r4;
  Repodata *d;
  Solvable *s;

  if (witharch)
    pool_setarch(pool, "x86_64");
  /* so that pool_createwhatprovides leaves the id hashes in place and
   * the snapshot stores them, which is what makes a mapped pool able
   * to intern without rehashing */
  pool_set_flag(pool, POOL_FLAG_KEEPIDHASHES, 1);
  r1 = repo_create(pool, "one");
  d = repo_add_repodata(r1, 0);
  addpkg(r1, d, "aaa", "1-1", "the aaa package");
  addpkg(r1, d, "bbb", "2-1", "the bbb package");
  repodata_internalize(d);

  r2 = repo_create(pool, "doomed");
  d = repo_add_repodata(r2, 0);
  addpkg(r2, d, "ccc", "3-1", "the ccc package");
  repodata_internalize(d);

  r3 = repo_create(pool, 0);		/* nameless repo */
  d = repo_add_repodata(r3, 0);
  s = addpkg(r3, d, "ddd", "4-1", "the ddd package");
  s->requires = repo_addid_dep(r3, s->requires, pool_str2id(pool, "aaa", 1), 0);
  repodata_internalize(d);

  r4 = repo_create(pool, "@System");
  d = repo_add_repodata(r4, 0);
  s = addpkg(r4, d, "eee", "5-1", "the eee package");
  repodata_internalize(d);
  pool_set_installed(pool, r4);
  r4->rpmdbid = solv_calloc(r4->end - r4->start, sizeof(Id));
  r4->rpmdbid[(s - pool->solvables) - r4->start] = 4711;

  repo_free(r2, 1);			/* leaves a hole in pool->repos */
  pool_createwhatprovides(pool);
  return pool;
}

static int
writesnap(Pool *pool)
{
  FILE *fp = fopen(snapfile, "w");	/* write-only must be enough */
  int r;
  if (!fp)
    {
      perror(snapfile);
      exit(1);
    }
  r = pool_snapshot_write(pool, fp, (const unsigned char *)"cookie", 6);
  fclose(fp);
  return r;
}

static int
mapsnap(Pool *pool)
{
  FILE *fp = fopen(snapfile, "r");
  int r;
  if (!fp)
    return -1;
  r = pool_snapshot_map(pool, fp);
  fclose(fp);
  return r;
}

int
main(int argc, char **argv)
{
  Pool *pool, *p2;
  unsigned long long d1;
  int r;

  snapfile = argc > 1 ? argv[1] : "pool_snapshot.tmp";

  pool = build(1);
  d1 = pool_digest(pool);
  r = writesnap(pool);
  if (r == -2)
    {
      /* no mmap or no /proc here, the feature is not built in */
      printf("pool_snapshot not supported on this platform, skipping\n");
      pool_free(pool);
      unlink(snapfile);
      return 0;
    }
  check(r == 0, "write");
  pool_free(pool);

  p2 = pool_create();
  pool_setarch(p2, "x86_64");
  check(mapsnap(p2) == 0, "map");
  check(pool_digest(p2) == d1, "mapped pool has the same content");
  check(p2->nrepos == 4, "repoids are dense after a repo was freed");
  check(p2->repos[1] && p2->repos[1]->name && !strcmp(p2->repos[1]->name, "one")
      && p2->repos[2] && p2->repos[2]->name == 0, "the freed repo's id is reused");
  check(p2->installed && p2->installed->name && !strcmp(p2->installed->name, "@System"),
      "the installed repo is restored");
  {
    unsigned char cookie[16];
    unsigned int cl = sizeof(cookie);
    FILE *fp = fopen(snapfile, "r");
    check(fp && pool_snapshot_read_cookie(fp, cookie, &cl) == 0 && cl == 6
	&& !memcmp(cookie, "cookie", 6), "the cookie is readable");
    if (fp)
      fclose(fp);
  }
  check(p2->installed->rpmdbid && p2->installed->rpmdbid[0] == 4711, "rpmdbid side data is restored");
  check(p2->ss.stringhashmask != 0 && p2->relhashmask != 0, "the id hashes come from the file");
  check(pool_str2id(p2, "aaa", 0) != 0 && pool_str2id(p2, "no-such-string", 0) == 0,
      "the borrowed string hash finds and misses correctly");
  {
    /* a second mapping in the same process is refused, but as "not for
     * you" rather than "stale", so the caller does not rewrite it */
    Pool *p3 = pool_create();
    pool_setarch(p3, "x86_64");
    check(mapsnap(p3) == -2, "a second mapping is refused with -2");
    pool_free(p3);
  }
  {
    /* the hard case: appending to the borrowed arrays. Interning past
     * the capacity the file reserves has to migrate them to the heap */
    Repo *r = repo_create(p2, "added");
    Repodata *d = repo_add_repodata(r, 0);
    char name[32];
    int i;
    Id added;
    for (i = 0; i < 5000; i++)
      {
	sprintf(name, "added-%d", i);
	addpkg(r, d, name, "1-1", "an added package");
      }
    repodata_internalize(d);
    pool_createwhatprovides(p2);
    added = pool_str2id(p2, "added-4999", 0);
    check(added != 0 && count_providers(p2, added) == 1, "a repo can be added to a mapped pool");
    check(pool_str2id(p2, "aaa", 0) != 0, "the pre-snapshot ids still resolve");
  }
  pool_free(p2);

  /* a different arch interns a different set of strings before the
   * map, so the ids the caller already holds would change meaning */
  p2 = pool_create();
  pool_setarch(p2, "i586");
  check(mapsnap(p2) == -2, "a foreign intern sequence is refused with -2");
  pool_free(p2);

  /* no arch policy at all: the leading strings still match, but the
   * stored whatprovides index was computed under one. The file is
   * still good, so it maps and the index is recomputed */
  p2 = pool_create();
  check(mapsnap(p2) == 0, "a different arch policy still maps");
  check(p2->whatprovides != 0, "and never leaves the pool without an index");
  {
    Id d = pool_str2id(p2, "aaa", 0);
    check(d != 0 && count_providers(p2, d) == 1, "the recomputed index answers queries");
  }
  pool_free(p2);

  /* a pool with an interned rel would have it renumbered, and no
   * rewrite of the snapshot can change that */
  p2 = pool_create();
  pool_setarch(p2, "x86_64");
  pool_rel2id(p2, pool_str2id(p2, "aaa", 1), pool_str2id(p2, "1-1", 1), REL_EQ, 1);
  check(mapsnap(p2) == -2, "a pool with interned rels is refused with -2");
  pool_free(p2);

  /* un-internalized attributes cannot be represented, and that must be
   * decided before anything is written */
  pool = build(1);
  repo_set_str(pool->repos[1], SOLVID_META, SOLVABLE_SUMMARY, "not internalized");
  unlink(snapfile);
  check(writesnap(pool) == -2, "an un-internalized repodata is refused");
  {
    struct stat st;
    check(stat(snapfile, &st) == 0 && st.st_size == 0, "nothing was written");
  }
  pool_free(pool);

  /* a corrupt header must be rejected, not followed */
  pool = build(1);
  writesnap(pool);
  pool_free(pool);
  {
    FILE *fp = fopen(snapfile, "r+");
    unsigned char c;
    if (!fp || fseek(fp, 40, SEEK_SET) || fread(&c, 1, 1, fp) != 1)
      exit(1);
    c ^= 0x40;
    if (fseek(fp, 40, SEEK_SET) || fwrite(&c, 1, 1, fp) != 1)
      exit(1);
    fclose(fp);
    p2 = pool_create();
    pool_setarch(p2, "x86_64");
    check(mapsnap(p2) == -1, "a corrupt header is rejected as stale");
    pool_free(p2);
  }

  unlink(snapfile);
  return failed ? 1 : 0;
}
