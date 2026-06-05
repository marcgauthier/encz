/*
** 2026-06-04
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
******************************************************************************
**
** OVERVIEW
**
** This extension registers a custom VFS named "encz" that stores the
** main database file in a custom container format. SQLite still sees a
** conventional page-oriented database, but the container stores each logical
** page as an optionally compressed and encrypted record and keeps a persisted
** page-map on disk. The page-map is rewritten copy-on-write and activated by
** atomically swapping between two fixed header slots.
**
** The extension is intentionally conservative:
**
**   *  only the main database file uses the custom container,
**   *  rollback-journal modes work through SQLite's normal journal files,
**   *  WAL mode encrypts/compresses frame payloads and stores GCM metadata
**      in a sidecar file,
**   *  mmap is disabled for encrypted databases,
**   *  opening plaintext databases through this VFS is rejected.
**
** PRAGMAS
**
** The VFS handles the following PRAGMAs via SQLITE_FCNTL_PRAGMA:
**
**   PRAGMA crypto_key='passphrase';
**   PRAGMA crypto_key_hex='...64 hex chars...';
**   PRAGMA crypto_key_env='ENV_VAR';
**   PRAGMA crypto_compression='none'|'zstd'|'deflate';
**   PRAGMA crypto_compression_level=N;
**   PRAGMA crypto_status;
**
** Configuration must be supplied before the first non-configuration read or
** write against an encrypted database.
**
** BUILDING
**
**   gcc -fPIC -shared -I. ext/encz/encz.c -o encz.so \
**       -lcrypto -lzstd -lz
**
** Then:
**
**   sqlite3
**   .load ./encz
**   open 'file:test.db?vfs=encz'
**   PRAGMA crypto_key='demo';
**   PRAGMA crypto_compression='zstd';
*/
#if defined(SQLITE_AMALGAMATION) && !defined(SQLITE_CRYPTOVFS_STATIC)
# define SQLITE_CRYPTOVFS_STATIC
#endif
#ifdef SQLITE_CRYPTOVFS_STATIC
# ifndef SQLITE_CORE
#  include "sqlite3.h"
# endif
# include "sqlite3ext.h"
#else
# include "sqlite3ext.h"
  SQLITE_EXTENSION_INIT1
#endif

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <zstd.h>

typedef sqlite3_int64 i64;
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define ENCZ_VFS_NAME              "encz"
#define ENCZ_MAGIC                 "SQLITECVFS000001"
#define ENCZ_MAGIC_SZ              16
#define ENCZ_HDR_SZ                512
#define ENCZ_HDR_SLOT0             0
#define ENCZ_HDR_SLOT1             ENCZ_HDR_SZ
#define ENCZ_DATA_START            4096
#define ENCZ_HDR_VERSION           1
#define ENCZ_FLAG_COMPRESSED       0x0001
#define ENCZ_COMPRESSION_NONE      0
#define ENCZ_COMPRESSION_ZSTD      1
#define ENCZ_COMPRESSION_DEFLATE   2
#define ENCZ_CIPHER_AES_256_GCM    1
#define ENCZ_NONCE_SZ              12
#define ENCZ_TAG_SZ                16
#define ENCZ_MAP_MAGIC             0x43564d31U
#define ENCZ_MAP_ENTRY_VERSION     1
#define ENCZ_WAL_HDR_SZ            32
#define ENCZ_WAL_FRAME_HDR_SZ      24
#define ENCZ_WALMETA_MAGIC         0x43575631U
#define ENCZ_WALMETA_VERSION       1

#define ORIGVFS(p)  ((sqlite3_vfs*)((p)->pAppData))
#define ORIGFILE(p) ((sqlite3_file*)(((EnczFile*)(p))+1))

typedef struct EnczHdr EnczHdr;
typedef struct EnczMapEntry EnczMapEntry;
typedef struct EnczMapEntryDisk EnczMapEntryDisk;
typedef struct DirtyPage DirtyPage;
typedef struct WalMetaHdr WalMetaHdr;
typedef struct WalMetaEntry WalMetaEntry;
typedef struct EnczFile EnczFile;

struct EnczHdr {
  u8 magic[ENCZ_MAGIC_SZ];
  u32 version;
  u32 headerFlags;
  u32 pageSize;
  u32 pageCount;
  u32 compression;
  u32 cipher;
  u64 generation;
  u64 mapOffset;
  u64 mapSize;
  u64 dataEnd;
  u32 reserved;
  u32 crc32;
};

struct EnczMapEntry {
  u64 offset;
  u32 storedSize;
  u32 plainSize;
  u32 flags;
  u8 nonce[ENCZ_NONCE_SZ];
  u8 tag[ENCZ_TAG_SZ];
};

struct EnczMapEntryDisk {
  u64 offset;
  u32 storedSize;
  u32 plainSize;
  u32 flags;
  u8 nonce[ENCZ_NONCE_SZ];
  u8 tag[ENCZ_TAG_SZ];
  u32 crc32;
};

struct DirtyPage {
  u32 pgno;
  u8 *data;
  DirtyPage *pNext;
};

struct WalMetaHdr {
  u32 magic;
  u32 version;
  u32 pageSize;
  u32 frameCount;
  u32 crc32;
};

struct WalMetaEntry {
  u32 storedSize;
  u32 flags;
  u8 nonce[ENCZ_NONCE_SZ];
  u8 tag[ENCZ_TAG_SZ];
  u32 crc32;
};

struct EnczFile {
  sqlite3_file base;
  sqlite3_file *pSubFile;
  const char *zFName;
  int isMainDb;
  int isWal;
  int isContainer;
  int isReadonly;
  int currentHdrSlot;
  int hasKey;
  int hasCompressionSetting;
  int initialized;
  int ioStarted;
  int needsCommit;
  int pendingTruncate;
  int logicalPageSize;
  int compression;
  int compressionLevel;
  int cipher;
  int mapCap;
  int walPageSize;
  int walMetaCap;
  int walMetaDirty;
  u32 pageCount;
  u32 walFrameCount;
  u64 dataEnd;
  u64 generation;
  EnczMapEntry *aMap;
  WalMetaEntry *aWalMeta;
  DirtyPage *pDirty;
  EnczFile *pMainDb;
  sqlite3_file *pMetaFile;
  char *zMetaName;
  u8 key[32];
};

static int enczClose(sqlite3_file*);
static int enczRead(sqlite3_file*, void*, int, sqlite3_int64);
static int enczWrite(sqlite3_file*, const void*, int, sqlite3_int64);
static int enczTruncate(sqlite3_file*, sqlite3_int64);
static int enczSync(sqlite3_file*, int);
static int enczFileSize(sqlite3_file*, sqlite3_int64*);
static int enczLock(sqlite3_file*, int);
static int enczUnlock(sqlite3_file*, int);
static int enczCheckReservedLock(sqlite3_file*, int*);
static int enczFileControl(sqlite3_file*, int, void*);
static int enczSectorSize(sqlite3_file*);
static int enczDeviceCharacteristics(sqlite3_file*);
static int enczShmMap(sqlite3_file*, int, int, int, void volatile**);
static int enczShmLock(sqlite3_file*, int, int, int);
static void enczShmBarrier(sqlite3_file*);
static int enczShmUnmap(sqlite3_file*, int);
static int enczFetch(sqlite3_file*, sqlite3_int64, int, void**);
static int enczUnfetch(sqlite3_file*, sqlite3_int64, void*);
static int enczWalEnsurePageSize(EnczFile*);
static int enczRawRead(EnczFile*, void*, int, i64);
static int enczRawWrite(EnczFile*, const void*, int, i64);
static int enczEncryptPage(EnczFile*, const u8*, int, u8**, int*, u32*, u8[ENCZ_NONCE_SZ], u8[ENCZ_TAG_SZ]);
static int enczDecryptPage(EnczFile*, const EnczMapEntry*, const u8*, u8*);

static int enczOpen(sqlite3_vfs*, const char*, sqlite3_file*, int, int*);
static int enczDelete(sqlite3_vfs*, const char*, int);
static int enczAccess(sqlite3_vfs*, const char*, int, int*);
static int enczFullPathname(sqlite3_vfs*, const char*, int, char*);
static void *enczDlOpen(sqlite3_vfs*, const char*);
static void enczDlError(sqlite3_vfs*, int, char*);
static void (*enczDlSym(sqlite3_vfs*, void*, const char*))(void);
static void enczDlClose(sqlite3_vfs*, void*);
static int enczRandomness(sqlite3_vfs*, int, char*);
static int enczSleep(sqlite3_vfs*, int);
static int enczCurrentTime(sqlite3_vfs*, double*);
static int enczGetLastError(sqlite3_vfs*, int, char*);
static int enczCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);
static int enczSetSystemCall(sqlite3_vfs*, const char*, sqlite3_syscall_ptr);
static sqlite3_syscall_ptr enczGetSystemCall(sqlite3_vfs*, const char*);
static const char *enczNextSystemCall(sqlite3_vfs*, const char*);

static sqlite3_io_methods encz_io_methods = {
  3,
  enczClose,
  enczRead,
  enczWrite,
  enczTruncate,
  enczSync,
  enczFileSize,
  enczLock,
  enczUnlock,
  enczCheckReservedLock,
  enczFileControl,
  enczSectorSize,
  enczDeviceCharacteristics,
  enczShmMap,
  enczShmLock,
  enczShmBarrier,
  enczShmUnmap,
  enczFetch,
  enczUnfetch
};

static sqlite3_vfs encz_vfs = {
  3,
  0,
  0,
  0,
  ENCZ_VFS_NAME,
  0,
  enczOpen,
  enczDelete,
  enczAccess,
  enczFullPathname,
  enczDlOpen,
  enczDlError,
  enczDlSym,
  enczDlClose,
  enczRandomness,
  enczSleep,
  enczCurrentTime,
  enczGetLastError,
  enczCurrentTimeInt64,
  enczSetSystemCall,
  enczGetSystemCall,
  enczNextSystemCall
};

static u32 enczGet32(const u8 *a){
  return ((u32)a[0]) | (((u32)a[1])<<8) | (((u32)a[2])<<16) | (((u32)a[3])<<24);
}

static u64 enczGet64(const u8 *a){
  u64 v = 0;
  int i;
  for(i=7; i>=0; i--){
    v = (v<<8) | a[i];
  }
  return v;
}

static void enczPut32(u8 *a, u32 v){
  a[0] = (u8)(v & 0xff);
  a[1] = (u8)((v>>8) & 0xff);
  a[2] = (u8)((v>>16) & 0xff);
  a[3] = (u8)((v>>24) & 0xff);
}

static void enczPut64(u8 *a, u64 v){
  int i;
  for(i=0; i<8; i++, v >>= 8){
    a[i] = (u8)(v & 0xff);
  }
}

static u32 enczCrc32(const void *p, size_t n){
  return (u32)crc32(0L, (const Bytef*)p, (uInt)n);
}

static int enczIsWalPath(const char *zName){
  size_t n;
  if( zName==0 ) return 0;
  n = strlen(zName);
  return n>4 && strcmp(&zName[n-4], "-wal")==0;
}

static char *enczWalMetaPath(const char *zWalName){
  return sqlite3_mprintf("%s.cvmeta", zWalName ? zWalName : "");
}

static int enczWalMetaEnsureCap(EnczFile *p, u32 nFrame){
  WalMetaEntry *aNew;
  int nNew;
  if( (int)nFrame<=p->walMetaCap ) return SQLITE_OK;
  nNew = p->walMetaCap ? p->walMetaCap : 32;
  while( nNew<(int)nFrame ) nNew *= 2;
  aNew = sqlite3_realloc64(p->aWalMeta, (sqlite3_uint64)nNew*sizeof(WalMetaEntry));
  if( aNew==0 ) return SQLITE_NOMEM;
  memset(&aNew[p->walMetaCap], 0, (size_t)(nNew - p->walMetaCap)*sizeof(WalMetaEntry));
  p->aWalMeta = aNew;
  p->walMetaCap = nNew;
  return SQLITE_OK;
}

static void enczWalMetaClear(EnczFile *p){
  p->walFrameCount = 0;
  p->walMetaDirty = 1;
  if( p->aWalMeta && p->walMetaCap>0 ){
    memset(p->aWalMeta, 0, (size_t)p->walMetaCap*sizeof(WalMetaEntry));
  }
}

static void enczWalParseHeaderPageSize(EnczFile *p, const u8 *aHdr){
  u32 sz = enczGet32(&aHdr[8]);
  sz = (sz & 0xfe00U) + ((sz & 0x0001U)<<16);
  if( sz>=512 && sz<=65536 && (sz & (sz-1))==0 ){
    p->walPageSize = (int)sz;
  }
}

static int enczWalMetaLoad(EnczFile *p){
  sqlite3_int64 nSize = 0;
  sqlite3_int64 nWalSize = 0;
  sqlite3_int64 nMetaPayload;
  sqlite3_int64 nFrameSize;
  sqlite3_int64 nWalFrames = 0;
  u8 *aBuf = 0;
  WalMetaHdr hdr;
  u32 i;
  int rc;
  if( p->pMetaFile==0 ) return SQLITE_OK;
  rc = p->pMetaFile->pMethods->xFileSize(p->pMetaFile, &nSize);
  if( rc!=SQLITE_OK || nSize==0 ) return rc;
  if( nSize < (sqlite3_int64)sizeof(WalMetaHdr) ) return SQLITE_CORRUPT;
  aBuf = sqlite3_malloc64((sqlite3_uint64)nSize);
  if( aBuf==0 ) return SQLITE_NOMEM;
  rc = p->pMetaFile->pMethods->xRead(p->pMetaFile, aBuf, (int)nSize, 0);
  if( rc==SQLITE_IOERR_SHORT_READ ) rc = SQLITE_OK;
  if( rc!=SQLITE_OK ) goto walmeta_load_out;
  hdr.magic = enczGet32(&aBuf[0]);
  hdr.version = enczGet32(&aBuf[4]);
  hdr.pageSize = enczGet32(&aBuf[8]);
  hdr.frameCount = enczGet32(&aBuf[12]);
  hdr.crc32 = enczGet32(&aBuf[16]);
  if( hdr.magic!=ENCZ_WALMETA_MAGIC || hdr.version!=ENCZ_WALMETA_VERSION ){
    rc = SQLITE_CORRUPT;
    goto walmeta_load_out;
  }
  if( enczCrc32(&aBuf[20], (size_t)nSize - 20)!=hdr.crc32 ){
    rc = SQLITE_CORRUPT;
    goto walmeta_load_out;
  }
  nMetaPayload = nSize - 20;
  if( (nMetaPayload % (sqlite3_int64)sizeof(WalMetaEntry))!=0 ){
    rc = SQLITE_CORRUPT;
    goto walmeta_load_out;
  }
  if( hdr.frameCount > (u32)(nMetaPayload / (sqlite3_int64)sizeof(WalMetaEntry)) ){
    rc = SQLITE_CORRUPT;
    goto walmeta_load_out;
  }
  p->walPageSize = hdr.pageSize ? (int)hdr.pageSize : p->walPageSize;
  if( p->walPageSize<=0 ){
    rc = SQLITE_CORRUPT;
    goto walmeta_load_out;
  }
  rc = p->pSubFile->pMethods->xFileSize(p->pSubFile, &nWalSize);
  if( rc!=SQLITE_OK ) goto walmeta_load_out;
  nFrameSize = (sqlite3_int64)p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ;
  if( nWalSize > ENCZ_WAL_HDR_SZ ){
    nWalFrames = (nWalSize - ENCZ_WAL_HDR_SZ) / nFrameSize;
  }
  if( hdr.frameCount > (u32)nWalFrames ){
    rc = SQLITE_CORRUPT;
    goto walmeta_load_out;
  }
  rc = enczWalMetaEnsureCap(p, hdr.frameCount);
  if( rc!=SQLITE_OK ) goto walmeta_load_out;
  p->walFrameCount = hdr.frameCount;
  for(i=0; i<hdr.frameCount; i++){
    WalMetaEntry *pEntry = &((WalMetaEntry*)&aBuf[20])[i];
    u32 crc = pEntry->crc32;
    pEntry->crc32 = 0;
    if( enczCrc32(pEntry, sizeof(WalMetaEntry))!=crc ){
      pEntry->crc32 = crc;
      rc = SQLITE_CORRUPT;
      goto walmeta_load_out;
    }
    pEntry->crc32 = crc;
    memcpy(&p->aWalMeta[i], pEntry, sizeof(WalMetaEntry));
  }
  rc = SQLITE_OK;
walmeta_load_out:
  sqlite3_free(aBuf);
  return rc;
}

static int enczWalMetaSave(EnczFile *p, int syncFlags){
  WalMetaHdr hdr;
  u8 *aBuf;
  u32 i;
  int rc;
  sqlite3_int64 nSize;
  if( p->pMetaFile==0 || !p->walMetaDirty ) return SQLITE_OK;
  nSize = (sqlite3_int64)(20 + p->walFrameCount*sizeof(WalMetaEntry));
  aBuf = sqlite3_malloc64((sqlite3_uint64)nSize);
  if( aBuf==0 ) return SQLITE_NOMEM;
  memset(aBuf, 0, (size_t)nSize);
  hdr.magic = ENCZ_WALMETA_MAGIC;
  hdr.version = ENCZ_WALMETA_VERSION;
  hdr.pageSize = (u32)p->walPageSize;
  hdr.frameCount = p->walFrameCount;
  hdr.crc32 = 0;
  enczPut32(&aBuf[0], hdr.magic);
  enczPut32(&aBuf[4], hdr.version);
  enczPut32(&aBuf[8], hdr.pageSize);
  enczPut32(&aBuf[12], hdr.frameCount);
  for(i=0; i<p->walFrameCount; i++){
    WalMetaEntry *pDst = &((WalMetaEntry*)&aBuf[20])[i];
    memcpy(pDst, &p->aWalMeta[i], sizeof(WalMetaEntry));
    pDst->crc32 = 0;
    pDst->crc32 = enczCrc32(pDst, sizeof(WalMetaEntry));
  }
  enczPut32(&aBuf[16], enczCrc32(&aBuf[20], (size_t)nSize - 20));
  rc = p->pMetaFile->pMethods->xTruncate(p->pMetaFile, 0);
  if( rc==SQLITE_OK ) rc = p->pMetaFile->pMethods->xWrite(p->pMetaFile, aBuf, (int)nSize, 0);
  if( rc==SQLITE_OK ) rc = p->pMetaFile->pMethods->xSync(p->pMetaFile, syncFlags);
  if( rc==SQLITE_OK ) p->walMetaDirty = 0;
  sqlite3_free(aBuf);
  return rc;
}

static int enczWalOpenMeta(EnczFile *p){
  sqlite3_vfs *pVfs = ORIGVFS(&encz_vfs);
  int flags = p->isReadonly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE);
  int outFlags = 0;
  int rc;
  if( p->pMetaFile ) return SQLITE_OK;
  p->zMetaName = enczWalMetaPath(p->zFName);
  if( p->zMetaName==0 ) return SQLITE_NOMEM;
  p->pMetaFile = sqlite3_malloc64((sqlite3_uint64)pVfs->szOsFile);
  if( p->pMetaFile==0 ) return SQLITE_NOMEM;
  memset(p->pMetaFile, 0, (size_t)pVfs->szOsFile);
  rc = pVfs->xOpen(pVfs, p->zMetaName, p->pMetaFile, flags, &outFlags);
  if( rc!=SQLITE_OK ){
    sqlite3_free(p->pMetaFile);
    p->pMetaFile = 0;
    if( p->isReadonly ) return SQLITE_OK;
    return rc;
  }
  return enczWalMetaLoad(p);
}

static int enczWalEnsurePageSize(EnczFile *p){
  u8 aHdr[ENCZ_WAL_HDR_SZ];
  int rc;
  if( p->walPageSize>0 ) return SQLITE_OK;
  if( p->pMainDb && p->pMainDb->logicalPageSize>0 ){
    p->walPageSize = p->pMainDb->logicalPageSize;
    return SQLITE_OK;
  }
  rc = enczRawRead(p, aHdr, sizeof(aHdr), 0);
  if( rc!=SQLITE_OK ) return rc;
  enczWalParseHeaderPageSize(p, aHdr);
  return p->walPageSize>0 ? SQLITE_OK : SQLITE_CORRUPT;
}

static int enczWalFrameInfo(EnczFile *p, i64 iOfst, u32 *pFrameNo, int *pFrameOfst){
  i64 rel;
  i64 frameSize;
  int rc = enczWalEnsurePageSize(p);
  if( rc!=SQLITE_OK ) return rc;
  if( iOfst < ENCZ_WAL_HDR_SZ ) return SQLITE_ERROR;
  frameSize = (i64)p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ;
  rel = iOfst - ENCZ_WAL_HDR_SZ;
  *pFrameNo = (u32)(rel / frameSize) + 1;
  *pFrameOfst = (int)(rel % frameSize);
  return SQLITE_OK;
}

static int enczWalGetPlainPage(EnczFile *p, u32 iFrame, u8 *aPlain){
  WalMetaEntry *pMeta;
  EnczMapEntry e;
  u8 *aStored;
  int rc;
  memset(aPlain, 0, (size_t)p->walPageSize);
  if( iFrame==0 || iFrame>p->walFrameCount || p->aWalMeta==0 ) return SQLITE_OK;
  pMeta = &p->aWalMeta[iFrame-1];
  if( pMeta->storedSize==0 ) return SQLITE_OK;
  aStored = sqlite3_malloc64((sqlite3_uint64)p->walPageSize);
  if( aStored==0 ) return SQLITE_NOMEM;
  rc = enczRawRead(
    p, aStored, p->walPageSize,
    ENCZ_WAL_HDR_SZ + ((i64)(iFrame-1) * ((i64)p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ)) + ENCZ_WAL_FRAME_HDR_SZ
  );
  if( rc==SQLITE_OK ){
    memset(&e, 0, sizeof(e));
    e.storedSize = pMeta->storedSize;
    e.plainSize = (u32)p->walPageSize;
    e.flags = pMeta->flags;
    memcpy(e.nonce, pMeta->nonce, ENCZ_NONCE_SZ);
    memcpy(e.tag, pMeta->tag, ENCZ_TAG_SZ);
    rc = enczDecryptPage(p, &e, aStored, aPlain);
  }
  sqlite3_free(aStored);
  return rc;
}

static int enczWalStorePlainPage(EnczFile *p, u32 iFrame, const u8 *aPlain){
  WalMetaEntry *pMeta;
  u8 *aStored = 0;
  u8 *aDisk = 0;
  u8 nonce[ENCZ_NONCE_SZ];
  u8 tag[ENCZ_TAG_SZ];
  u32 flags = 0;
  int nStored = 0;
  int rc;
  rc = enczWalMetaEnsureCap(p, iFrame);
  if( rc!=SQLITE_OK ) return rc;
  rc = enczEncryptPage(p, aPlain, p->walPageSize, &aStored, &nStored, &flags, nonce, tag);
  if( rc!=SQLITE_OK ) return rc;
  aDisk = sqlite3_malloc64((sqlite3_uint64)p->walPageSize);
  if( aDisk==0 ){
    sqlite3_free(aStored);
    return SQLITE_NOMEM;
  }
  memset(aDisk, 0, (size_t)p->walPageSize);
  memcpy(aDisk, aStored, (size_t)nStored);
  rc = enczRawWrite(
    p, aDisk, p->walPageSize,
    ENCZ_WAL_HDR_SZ + ((i64)(iFrame-1) * ((i64)p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ)) + ENCZ_WAL_FRAME_HDR_SZ
  );
  if( rc==SQLITE_OK ){
    pMeta = &p->aWalMeta[iFrame-1];
    memset(pMeta, 0, sizeof(*pMeta));
    pMeta->storedSize = (u32)nStored;
    pMeta->flags = flags;
    memcpy(pMeta->nonce, nonce, ENCZ_NONCE_SZ);
    memcpy(pMeta->tag, tag, ENCZ_TAG_SZ);
    if( iFrame > p->walFrameCount ) p->walFrameCount = iFrame;
    p->walMetaDirty = 1;
  }
  sqlite3_free(aStored);
  sqlite3_free(aDisk);
  return rc;
}

static int enczWalReadRegion(EnczFile *p, void *pBuf, int iAmt, sqlite3_int64 iOfst){
  u8 *aOut = (u8*)pBuf;
  int rc = SQLITE_OK;
  while( iAmt>0 && rc==SQLITE_OK ){
    if( iOfst < ENCZ_WAL_HDR_SZ ){
      int n = (int)((ENCZ_WAL_HDR_SZ - iOfst) < iAmt ? (ENCZ_WAL_HDR_SZ - iOfst) : iAmt);
      rc = enczRawRead(p, aOut, n, iOfst);
      aOut += n;
      iAmt -= n;
      iOfst += n;
      continue;
    }
    else{
      u32 iFrame;
      int iFrameOfst;
      int nFrame;
      rc = enczWalFrameInfo(p, iOfst, &iFrame, &iFrameOfst);
      if( rc!=SQLITE_OK ) break;
      nFrame = (p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ) - iFrameOfst;
      if( nFrame > iAmt ) nFrame = iAmt;
      if( iFrameOfst < ENCZ_WAL_FRAME_HDR_SZ ){
        int nHdr = ENCZ_WAL_FRAME_HDR_SZ - iFrameOfst;
        if( nHdr > nFrame ) nHdr = nFrame;
        rc = enczRawRead(p, aOut, nHdr, iOfst);
        if( rc!=SQLITE_OK ) break;
        aOut += nHdr;
        iAmt -= nHdr;
        iOfst += nHdr;
        nFrame -= nHdr;
        iFrameOfst += nHdr;
      }
      if( nFrame>0 ){
        u8 *aPage = sqlite3_malloc64((sqlite3_uint64)p->walPageSize);
        int iPayloadOfst = iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ;
        if( aPage==0 ) return SQLITE_NOMEM;
        rc = enczWalGetPlainPage(p, iFrame, aPage);
        if( rc==SQLITE_OK ) memcpy(aOut, aPage + iPayloadOfst, (size_t)nFrame);
        sqlite3_free(aPage);
        if( rc!=SQLITE_OK ) break;
        aOut += nFrame;
        iAmt -= nFrame;
        iOfst += nFrame;
      }
    }
  }
  return rc;
}

static int enczWalWriteRegion(EnczFile *p, const void *pBuf, int iAmt, sqlite3_int64 iOfst){
  const u8 *aIn = (const u8*)pBuf;
  int rc = SQLITE_OK;
  if( !p->hasKey ) return SQLITE_AUTH;
  rc = enczWalOpenMeta(p);
  if( rc!=SQLITE_OK ) return rc;
  while( iAmt>0 && rc==SQLITE_OK ){
    if( iOfst==0 && iAmt>=ENCZ_WAL_HDR_SZ ){
      rc = enczRawWrite(p, aIn, ENCZ_WAL_HDR_SZ, 0);
      if( rc!=SQLITE_OK ) break;
      enczWalParseHeaderPageSize(p, aIn);
      enczWalMetaClear(p);
      aIn += ENCZ_WAL_HDR_SZ;
      iAmt -= ENCZ_WAL_HDR_SZ;
      iOfst += ENCZ_WAL_HDR_SZ;
      continue;
    }else if( iOfst < ENCZ_WAL_HDR_SZ ){
      int n = (int)((ENCZ_WAL_HDR_SZ - iOfst) < iAmt ? (ENCZ_WAL_HDR_SZ - iOfst) : iAmt);
      rc = enczRawWrite(p, aIn, n, iOfst);
      if( rc!=SQLITE_OK ) break;
      aIn += n;
      iAmt -= n;
      iOfst += n;
      continue;
    }else{
      u32 iFrame;
      int iFrameOfst;
      int nFrame;
      rc = enczWalFrameInfo(p, iOfst, &iFrame, &iFrameOfst);
      if( rc!=SQLITE_OK ) break;
      nFrame = (p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ) - iFrameOfst;
      if( nFrame > iAmt ) nFrame = iAmt;
      if( iFrameOfst < ENCZ_WAL_FRAME_HDR_SZ ){
        int nHdr = ENCZ_WAL_FRAME_HDR_SZ - iFrameOfst;
        if( nHdr > nFrame ) nHdr = nFrame;
        rc = enczRawWrite(p, aIn, nHdr, iOfst);
        if( rc!=SQLITE_OK ) break;
        aIn += nHdr;
        iAmt -= nHdr;
        iOfst += nHdr;
        nFrame -= nHdr;
        iFrameOfst += nHdr;
      }
      if( nFrame>0 ){
        u8 *aPage = sqlite3_malloc64((sqlite3_uint64)p->walPageSize);
        int iPayloadOfst = iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ;
        if( aPage==0 ) return SQLITE_NOMEM;
        rc = enczWalGetPlainPage(p, iFrame, aPage);
        if( rc==SQLITE_OK ){
          memcpy(aPage + iPayloadOfst, aIn, (size_t)nFrame);
          rc = enczWalStorePlainPage(p, iFrame, aPage);
        }
        sqlite3_free(aPage);
        if( rc!=SQLITE_OK ) break;
        aIn += nFrame;
        iAmt -= nFrame;
        iOfst += nFrame;
      }
    }
  }
  return rc;
}

static void enczFreeDirtyPages(EnczFile *p){
  DirtyPage *pCur = p->pDirty;
  while( pCur ){
    DirtyPage *pNext = pCur->pNext;
    sqlite3_free(pCur->data);
    sqlite3_free(pCur);
    pCur = pNext;
  }
  p->pDirty = 0;
}

static DirtyPage *enczFindDirtyPage(EnczFile *p, u32 pgno){
  DirtyPage *pCur;
  for(pCur=p->pDirty; pCur; pCur=pCur->pNext){
    if( pCur->pgno==pgno ) return pCur;
  }
  return 0;
}

static int enczEnsureMapCap(EnczFile *p, int nPage){
  EnczMapEntry *aNew;
  int nNew;
  if( nPage<=p->mapCap ) return SQLITE_OK;
  nNew = p->mapCap ? p->mapCap : 16;
  while( nNew<nPage ) nNew *= 2;
  aNew = sqlite3_realloc64(p->aMap, (sqlite3_uint64)nNew*sizeof(EnczMapEntry));
  if( aNew==0 ) return SQLITE_NOMEM;
  memset(&aNew[p->mapCap], 0, (size_t)(nNew - p->mapCap) * sizeof(EnczMapEntry));
  p->aMap = aNew;
  p->mapCap = nNew;
  return SQLITE_OK;
}

static void enczEncodeHeader(const EnczHdr *pHdr, u8 *aOut){
  memset(aOut, 0, ENCZ_HDR_SZ);
  memcpy(aOut, pHdr->magic, ENCZ_MAGIC_SZ);
  enczPut32(&aOut[16], pHdr->version);
  enczPut32(&aOut[20], pHdr->headerFlags);
  enczPut32(&aOut[24], pHdr->pageSize);
  enczPut32(&aOut[28], pHdr->pageCount);
  enczPut32(&aOut[32], pHdr->compression);
  enczPut32(&aOut[36], pHdr->cipher);
  enczPut64(&aOut[40], pHdr->generation);
  enczPut64(&aOut[48], pHdr->mapOffset);
  enczPut64(&aOut[56], pHdr->mapSize);
  enczPut64(&aOut[64], pHdr->dataEnd);
  enczPut32(&aOut[72], pHdr->reserved);
  enczPut32(&aOut[76], 0);
  enczPut32(&aOut[76], enczCrc32(aOut, 76));
}

static int enczDecodeHeader(const u8 *aIn, EnczHdr *pHdr){
  u32 crc;
  memset(pHdr, 0, sizeof(*pHdr));
  if( memcmp(aIn, ENCZ_MAGIC, ENCZ_MAGIC_SZ)!=0 ) return SQLITE_NOTFOUND;
  crc = enczGet32(&aIn[76]);
  if( enczCrc32(aIn, 76)!=crc ) return SQLITE_CORRUPT;
  memcpy(pHdr->magic, aIn, ENCZ_MAGIC_SZ);
  pHdr->version = enczGet32(&aIn[16]);
  pHdr->headerFlags = enczGet32(&aIn[20]);
  pHdr->pageSize = enczGet32(&aIn[24]);
  pHdr->pageCount = enczGet32(&aIn[28]);
  pHdr->compression = enczGet32(&aIn[32]);
  pHdr->cipher = enczGet32(&aIn[36]);
  pHdr->generation = enczGet64(&aIn[40]);
  pHdr->mapOffset = enczGet64(&aIn[48]);
  pHdr->mapSize = enczGet64(&aIn[56]);
  pHdr->dataEnd = enczGet64(&aIn[64]);
  pHdr->reserved = enczGet32(&aIn[72]);
  pHdr->crc32 = crc;
  if( pHdr->version!=ENCZ_HDR_VERSION ) return SQLITE_NOTFOUND;
  return SQLITE_OK;
}

static void enczMakeHeader(
  EnczFile *p,
  EnczHdr *pHdr,
  u64 mapOffset,
  u64 mapSize,
  u64 dataEnd,
  u64 generation
){
  memset(pHdr, 0, sizeof(*pHdr));
  memcpy(pHdr->magic, ENCZ_MAGIC, ENCZ_MAGIC_SZ);
  pHdr->version = ENCZ_HDR_VERSION;
  pHdr->pageSize = (u32)p->logicalPageSize;
  pHdr->pageCount = p->pageCount;
  pHdr->compression = (u32)p->compression;
  pHdr->cipher = (u32)p->cipher;
  pHdr->generation = generation;
  pHdr->mapOffset = mapOffset;
  pHdr->mapSize = mapSize;
  pHdr->dataEnd = dataEnd;
}

static int enczRawRead(EnczFile *p, void *pBuf, int nBuf, i64 iOfst){
  int rc = p->pSubFile->pMethods->xRead(p->pSubFile, pBuf, nBuf, iOfst);
  if( rc==SQLITE_IOERR_SHORT_READ ){
    memset(pBuf, 0, nBuf);
    rc = SQLITE_OK;
  }
  return rc;
}

static int enczRawWrite(EnczFile *p, const void *pBuf, int nBuf, i64 iOfst){
  return p->pSubFile->pMethods->xWrite(p->pSubFile, pBuf, nBuf, iOfst);
}

static int enczParseCompression(const char *z){
  if( z==0 ) return -1;
  if( sqlite3_stricmp(z, "none")==0 ) return ENCZ_COMPRESSION_NONE;
  if( sqlite3_stricmp(z, "zstd")==0 ) return ENCZ_COMPRESSION_ZSTD;
  if( sqlite3_stricmp(z, "deflate")==0
   || sqlite3_stricmp(z, "zip")==0
  ){
    return ENCZ_COMPRESSION_DEFLATE;
  }
  return -1;
}

static const char *enczCompressionName(int eCompression){
  switch( eCompression ){
    case ENCZ_COMPRESSION_NONE: return "none";
    case ENCZ_COMPRESSION_ZSTD: return "zstd";
    case ENCZ_COMPRESSION_DEFLATE: return "deflate";
    default: return "unknown";
  }
}

static int enczSetKeyPassphrase(EnczFile *p, const char *z){
  if( z==0 ) return SQLITE_ERROR;
  SHA256((const unsigned char*)z, strlen(z), p->key);
  p->hasKey = 1;
  return SQLITE_OK;
}

static int enczHexNibble(char c){
  if( c>='0' && c<='9' ) return c - '0';
  if( c>='a' && c<='f' ) return 10 + (c - 'a');
  if( c>='A' && c<='F' ) return 10 + (c - 'A');
  return -1;
}

static int enczSetKeyHex(EnczFile *p, const char *z){
  size_t n;
  size_t i;
  if( z==0 ) return SQLITE_ERROR;
  n = strlen(z);
  if( n!=64 ) return SQLITE_ERROR;
  for(i=0; i<32; i++){
    int hi = enczHexNibble(z[i*2]);
    int lo = enczHexNibble(z[i*2 + 1]);
    if( hi<0 || lo<0 ) return SQLITE_ERROR;
    p->key[i] = (u8)((hi<<4) | lo);
  }
  p->hasKey = 1;
  return SQLITE_OK;
}

static int enczSetKeyEnv(EnczFile *p, const char *zEnv){
  const char *zValue = zEnv ? getenv(zEnv) : 0;
  if( zValue==0 ) return SQLITE_ERROR;
  return enczSetKeyPassphrase(p, zValue);
}

static int enczEncryptPage(
  EnczFile *p,
  const u8 *aPlain,
  int nPlain,
  u8 **ppStored,
  int *pnStored,
  u32 *pFlags,
  u8 aNonce[ENCZ_NONCE_SZ],
  u8 aTag[ENCZ_TAG_SZ]
){
  u8 *aCompressed = 0;
  u8 *aCipher = 0;
  u8 *aOut = 0;
  int nCompressed = nPlain;
  int nCipher = 0;
  int nOut = 0;
  int rc = SQLITE_OK;
  int eCompression = p->compression;
  EVP_CIPHER_CTX *pCtx = 0;

  *ppStored = 0;
  *pnStored = 0;
  *pFlags = 0;

  if( eCompression==ENCZ_COMPRESSION_ZSTD ){
    size_t nBound = ZSTD_compressBound((size_t)nPlain);
    size_t nRes;
    aCompressed = sqlite3_malloc64(nBound);
    if( aCompressed==0 ) return SQLITE_NOMEM;
    nRes = ZSTD_compress(aCompressed, nBound, aPlain, (size_t)nPlain, p->compressionLevel);
    if( ZSTD_isError(nRes) ){
      sqlite3_free(aCompressed);
      return SQLITE_ERROR;
    }
    if( (int)nRes < nPlain ){
      nCompressed = (int)nRes;
      *pFlags |= ENCZ_FLAG_COMPRESSED;
    }else{
      memcpy(aCompressed, aPlain, (size_t)nPlain);
      nCompressed = nPlain;
      eCompression = ENCZ_COMPRESSION_NONE;
      *pFlags &= ~ENCZ_FLAG_COMPRESSED;
    }
  }else if( eCompression==ENCZ_COMPRESSION_DEFLATE ){
    uLongf nBound = compressBound((uLong)nPlain);
    aCompressed = sqlite3_malloc64((sqlite3_uint64)nBound);
    if( aCompressed==0 ) return SQLITE_NOMEM;
    if( compress2(aCompressed, &nBound, aPlain, (uLong)nPlain, p->compressionLevel)<0 ){
      sqlite3_free(aCompressed);
      return SQLITE_ERROR;
    }
    if( (int)nBound < nPlain ){
      nCompressed = (int)nBound;
      *pFlags |= ENCZ_FLAG_COMPRESSED;
    }else{
      memcpy(aCompressed, aPlain, (size_t)nPlain);
      nCompressed = nPlain;
      eCompression = ENCZ_COMPRESSION_NONE;
      *pFlags &= ~ENCZ_FLAG_COMPRESSED;
    }
  }else{
    aCompressed = sqlite3_malloc64((sqlite3_uint64)nPlain);
    if( aCompressed==0 ) return SQLITE_NOMEM;
    memcpy(aCompressed, aPlain, (size_t)nPlain);
    nCompressed = nPlain;
  }

  if( RAND_bytes(aNonce, ENCZ_NONCE_SZ)!=1 ){
    sqlite3_free(aCompressed);
    return SQLITE_ERROR;
  }

  aCipher = sqlite3_malloc64((sqlite3_uint64)nCompressed + 32);
  if( aCipher==0 ){
    sqlite3_free(aCompressed);
    return SQLITE_NOMEM;
  }

  pCtx = EVP_CIPHER_CTX_new();
  if( pCtx==0 ){
    rc = SQLITE_NOMEM;
    goto encrypt_out;
  }
  if( EVP_EncryptInit_ex(pCtx, EVP_aes_256_gcm(), 0, 0, 0)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, ENCZ_NONCE_SZ, 0)!=1
   || EVP_EncryptInit_ex(pCtx, 0, 0, p->key, aNonce)!=1
   || EVP_EncryptUpdate(pCtx, aCipher, &nOut, aCompressed, nCompressed)!=1
   || EVP_EncryptFinal_ex(pCtx, aCipher + nOut, &nCipher)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_GET_TAG, ENCZ_TAG_SZ, aTag)!=1
  ){
    rc = SQLITE_ERROR;
    goto encrypt_out;
  }
  nCipher += nOut;
  aOut = sqlite3_malloc64((sqlite3_uint64)nCipher);
  if( aOut==0 ){
    rc = SQLITE_NOMEM;
    goto encrypt_out;
  }
  memcpy(aOut, aCipher, (size_t)nCipher);
  *ppStored = aOut;
  *pnStored = nCipher;

encrypt_out:
  if( pCtx ) EVP_CIPHER_CTX_free(pCtx);
  sqlite3_free(aCompressed);
  sqlite3_free(aCipher);
  return rc;
}

static int enczDecryptPage(
  EnczFile *p,
  const EnczMapEntry *pEntry,
  const u8 *aStored,
  u8 *aPlain
){
  EVP_CIPHER_CTX *pCtx = 0;
  u8 *aTmp = 0;
  int rc = SQLITE_OK;
  int nOut = 0;
  int nTmp = 0;

  aTmp = sqlite3_malloc64((sqlite3_uint64)pEntry->plainSize + 64);
  if( aTmp==0 ) return SQLITE_NOMEM;

  pCtx = EVP_CIPHER_CTX_new();
  if( pCtx==0 ){
    rc = SQLITE_NOMEM;
    goto decrypt_out;
  }
  if( EVP_DecryptInit_ex(pCtx, EVP_aes_256_gcm(), 0, 0, 0)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, ENCZ_NONCE_SZ, 0)!=1
   || EVP_DecryptInit_ex(pCtx, 0, 0, p->key, pEntry->nonce)!=1
   || EVP_DecryptUpdate(pCtx, aTmp, &nOut, aStored, (int)pEntry->storedSize)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_TAG, ENCZ_TAG_SZ, (void*)pEntry->tag)!=1
  ){
    rc = SQLITE_ERROR;
    goto decrypt_out;
  }
  if( EVP_DecryptFinal_ex(pCtx, aTmp + nOut, &nTmp)!=1 ){
    rc = SQLITE_NOTADB;
    goto decrypt_out;
  }
  nTmp += nOut;

  if( (pEntry->flags & ENCZ_FLAG_COMPRESSED)!=0 ){
    if( p->compression==ENCZ_COMPRESSION_ZSTD ){
      size_t nRes = ZSTD_decompress(aPlain, (size_t)pEntry->plainSize, aTmp, (size_t)nTmp);
      if( ZSTD_isError(nRes) || (int)nRes!= (int)pEntry->plainSize ){
        rc = SQLITE_CORRUPT;
        goto decrypt_out;
      }
    }else if( p->compression==ENCZ_COMPRESSION_DEFLATE ){
      uLongf nRes = (uLongf)pEntry->plainSize;
      if( uncompress(aPlain, &nRes, aTmp, (uLong)nTmp)!=Z_OK || (int)nRes!=(int)pEntry->plainSize ){
        rc = SQLITE_CORRUPT;
        goto decrypt_out;
      }
    }else{
      rc = SQLITE_CORRUPT;
      goto decrypt_out;
    }
  }else{
    if( nTmp!=(int)pEntry->plainSize ){
      rc = SQLITE_CORRUPT;
      goto decrypt_out;
    }
    memcpy(aPlain, aTmp, (size_t)nTmp);
  }

decrypt_out:
  if( pCtx ) EVP_CIPHER_CTX_free(pCtx);
  sqlite3_free(aTmp);
  return rc;
}

static int enczLoadMap(EnczFile *p, const EnczHdr *pHdr){
  u8 *aMap = 0;
  u32 crc;
  u32 nPage;
  u32 i;
  int rc;

  if( pHdr->mapSize==0 ){
    p->pageCount = 0;
    p->dataEnd = pHdr->dataEnd ? pHdr->dataEnd : ENCZ_DATA_START;
    return SQLITE_OK;
  }
  aMap = sqlite3_malloc64((sqlite3_uint64)pHdr->mapSize);
  if( aMap==0 ) return SQLITE_NOMEM;
  rc = enczRawRead(p, aMap, (int)pHdr->mapSize, (i64)pHdr->mapOffset);
  if( rc!=SQLITE_OK ) goto load_map_out;
  if( enczGet32(&aMap[0])!=ENCZ_MAP_MAGIC
   || enczGet32(&aMap[4])!=ENCZ_MAP_ENTRY_VERSION
  ){
    rc = SQLITE_CORRUPT;
    goto load_map_out;
  }
  nPage = enczGet32(&aMap[8]);
  crc = enczGet32(&aMap[12]);
  if( enczCrc32(&aMap[16], (size_t)pHdr->mapSize - 16)!=crc ){
    rc = SQLITE_CORRUPT;
    goto load_map_out;
  }
  rc = enczEnsureMapCap(p, (int)nPage);
  if( rc!=SQLITE_OK ) goto load_map_out;
  memset(p->aMap, 0, sizeof(EnczMapEntry) * (size_t)p->mapCap);
  p->pageCount = nPage;
  for(i=0; i<nPage; i++){
    EnczMapEntryDisk *pDisk = (EnczMapEntryDisk*)(&aMap[16 + i*sizeof(EnczMapEntryDisk)]);
    u32 entryCrc = pDisk->crc32;
    u32 calc;
    pDisk->crc32 = 0;
    calc = enczCrc32(pDisk, sizeof(EnczMapEntryDisk));
    pDisk->crc32 = entryCrc;
    if( entryCrc!=calc ){
      rc = SQLITE_CORRUPT;
      goto load_map_out;
    }
    p->aMap[i].offset = pDisk->offset;
    p->aMap[i].storedSize = pDisk->storedSize;
    p->aMap[i].plainSize = pDisk->plainSize;
    p->aMap[i].flags = pDisk->flags;
    memcpy(p->aMap[i].nonce, pDisk->nonce, ENCZ_NONCE_SZ);
    memcpy(p->aMap[i].tag, pDisk->tag, ENCZ_TAG_SZ);
  }
  p->dataEnd = pHdr->dataEnd;
  if( p->dataEnd < ENCZ_DATA_START ) p->dataEnd = ENCZ_DATA_START;

load_map_out:
  sqlite3_free(aMap);
  return rc;
}

static int enczLoadHeaders(EnczFile *p){
  u8 aSlot0[ENCZ_HDR_SZ];
  u8 aSlot1[ENCZ_HDR_SZ];
  EnczHdr h0, h1;
  int rc0, rc1;
  int rc;

  rc = enczRawRead(p, aSlot0, ENCZ_HDR_SZ, ENCZ_HDR_SLOT0);
  if( rc!=SQLITE_OK ) return rc;
  rc = enczRawRead(p, aSlot1, ENCZ_HDR_SZ, ENCZ_HDR_SLOT1);
  if( rc!=SQLITE_OK ) return rc;

  rc0 = enczDecodeHeader(aSlot0, &h0);
  rc1 = enczDecodeHeader(aSlot1, &h1);
  if( rc0==SQLITE_OK || rc1==SQLITE_OK ){
    EnczHdr *pHdr = 0;
    if( rc0==SQLITE_OK && rc1==SQLITE_OK ){
      if( h0.generation >= h1.generation ){
        pHdr = &h0;
        p->currentHdrSlot = 0;
      }else{
        pHdr = &h1;
        p->currentHdrSlot = 1;
      }
    }else if( rc0==SQLITE_OK ){
      pHdr = &h0;
      p->currentHdrSlot = 0;
    }else{
      pHdr = &h1;
      p->currentHdrSlot = 1;
    }
    p->isContainer = 1;
    p->logicalPageSize = (int)pHdr->pageSize;
    p->compression = (int)pHdr->compression;
    p->cipher = (int)pHdr->cipher;
    p->pageCount = pHdr->pageCount;
    p->generation = pHdr->generation;
    p->dataEnd = pHdr->dataEnd;
    rc = enczLoadMap(p, pHdr);
    if( rc!=SQLITE_OK ) return rc;
    return SQLITE_OK;
  }
  return SQLITE_NOTFOUND;
}

static int enczInitNewContainer(EnczFile *p, int pageSize){
  EnczHdr hdr;
  u8 aHdr[ENCZ_HDR_SZ];
  int rc;
  if( !p->hasKey ) return SQLITE_AUTH;
  if( pageSize<=0 ) pageSize = 4096;
  p->logicalPageSize = pageSize;
  p->compression = p->hasCompressionSetting ? p->compression : ENCZ_COMPRESSION_NONE;
  p->cipher = ENCZ_CIPHER_AES_256_GCM;
  p->pageCount = 0;
  p->dataEnd = ENCZ_DATA_START;
  p->generation = 1;
  p->isContainer = 1;
  p->currentHdrSlot = 0;
  enczMakeHeader(p, &hdr, 0, 0, ENCZ_DATA_START, p->generation);
  enczEncodeHeader(&hdr, aHdr);
  rc = enczRawWrite(p, aHdr, ENCZ_HDR_SZ, ENCZ_HDR_SLOT0);
  if( rc!=SQLITE_OK ) return rc;
  rc = enczRawWrite(p, aHdr, ENCZ_HDR_SZ, ENCZ_HDR_SLOT1);
  if( rc!=SQLITE_OK ) return rc;
  rc = p->pSubFile->pMethods->xSync(p->pSubFile, SQLITE_SYNC_NORMAL);
  return rc;
}

static int enczEnsureReady(EnczFile *p, int pageSizeHint){
  sqlite3_int64 nSize = 0;
  int rc;
  if( !p->isMainDb ) return SQLITE_OK;
  if( p->initialized ) return SQLITE_OK;
  rc = p->pSubFile->pMethods->xFileSize(p->pSubFile, &nSize);
  if( rc!=SQLITE_OK ) return rc;
  if( nSize==0 ){
    rc = enczInitNewContainer(p, pageSizeHint);
    if( rc!=SQLITE_OK ) return rc;
  }else{
    rc = enczLoadHeaders(p);
    if( rc==SQLITE_NOTFOUND ) return SQLITE_NOTADB;
    if( rc!=SQLITE_OK ) return rc;
  }
  p->initialized = 1;
  return SQLITE_OK;
}

static int enczReadLogicalPage(EnczFile *p, u32 pgno, u8 *aPage){
  EnczMapEntry *pEntry;
  DirtyPage *pDirty;
  int rc;
  u8 *aStored;

  memset(aPage, 0, (size_t)p->logicalPageSize);
  if( pgno==0 ) return SQLITE_OK;
  if( pgno > p->pageCount ) return SQLITE_OK;

  pDirty = enczFindDirtyPage(p, pgno);
  if( pDirty ){
    memcpy(aPage, pDirty->data, (size_t)p->logicalPageSize);
    return SQLITE_OK;
  }

  pEntry = &p->aMap[pgno-1];
  if( pEntry->offset==0 || pEntry->storedSize==0 ) return SQLITE_OK;
  if( !p->hasKey ){
    if( pgno==1 ){
      memset(aPage, 0, (size_t)p->logicalPageSize);
      memcpy(aPage, "SQLite format 3", 16);
      aPage[16] = (u8)((p->logicalPageSize >> 8) & 0xff);
      aPage[17] = (u8)(p->logicalPageSize & 0xff);
      aPage[18] = 1;
      aPage[19] = 1;
      aPage[21] = 64;
      aPage[22] = 32;
      aPage[23] = 32;
      aPage[47] = 4; // Schema format = 4
      aPage[59] = 1; // Text encoding = 1 (UTF-8)
      // b-tree leaf page header at offset 100
      aPage[100] = 0x0d; // leaf table b-tree page
      aPage[105] = (u8)((p->logicalPageSize >> 8) & 0xff);
      aPage[106] = (u8)(p->logicalPageSize & 0xff);
    }else{
      memset(aPage, 0, (size_t)p->logicalPageSize);
    }
    return SQLITE_OK;
  }

  aStored = sqlite3_malloc64((sqlite3_uint64)pEntry->storedSize);
  if( aStored==0 ) return SQLITE_NOMEM;
  rc = enczRawRead(p, aStored, (int)pEntry->storedSize, (i64)pEntry->offset);
  if( rc==SQLITE_OK ){
    rc = enczDecryptPage(p, pEntry, aStored, aPage);
  }
  sqlite3_free(aStored);
  return rc;
}

static int enczStagePageWrite(
  EnczFile *p,
  const u8 *aData,
  int nData,
  i64 iOfst
){
  u32 firstPg;
  u32 lastPg;
  u32 pgno;
  int rc = SQLITE_OK;

  if( p->logicalPageSize<=0 ) return SQLITE_CORRUPT;
  firstPg = (u32)(iOfst / p->logicalPageSize) + 1;
  lastPg = (u32)((iOfst + nData - 1) / p->logicalPageSize) + 1;
  rc = enczEnsureMapCap(p, (int)lastPg);
  if( rc!=SQLITE_OK ) return rc;

  for(pgno=firstPg; pgno<=lastPg; pgno++){
    DirtyPage *pDirty = enczFindDirtyPage(p, pgno);
    u8 *aPage;
    int pageStart = (int)((pgno-1) * (u32)p->logicalPageSize);
    int copyStart = (int)(iOfst > pageStart ? iOfst - pageStart : 0);
    int srcStart = pageStart < iOfst ? 0 : pageStart - (int)iOfst;
    int copyLen = p->logicalPageSize - copyStart;
    if( srcStart + copyLen > nData ) copyLen = nData - srcStart;
    if( copyLen<0 ) copyLen = 0;

    if( !pDirty ){
      pDirty = sqlite3_malloc64(sizeof(*pDirty));
      if( pDirty==0 ) return SQLITE_NOMEM;
      memset(pDirty, 0, sizeof(*pDirty));
      pDirty->pgno = pgno;
      pDirty->data = sqlite3_malloc64((sqlite3_uint64)p->logicalPageSize);
      if( pDirty->data==0 ){
        sqlite3_free(pDirty);
        return SQLITE_NOMEM;
      }
      rc = enczReadLogicalPage(p, pgno, pDirty->data);
      if( rc!=SQLITE_OK ){
        sqlite3_free(pDirty->data);
        sqlite3_free(pDirty);
        return rc;
      }
      pDirty->pNext = p->pDirty;
      p->pDirty = pDirty;
    }
    aPage = pDirty->data;
    if( copyLen>0 ){
      memcpy(aPage + copyStart, aData + srcStart, (size_t)copyLen);
    }
  }

  if( lastPg > p->pageCount ) p->pageCount = lastPg;
  p->needsCommit = 1;
  return SQLITE_OK;
}

static int enczWriteMapSnapshot(
  EnczFile *p,
  u64 *pMapOffset,
  u64 *pMapSize,
  u64 *pDataEnd
){
  EnczMapEntryDisk *aDisk = 0;
  u8 *aBlob = 0;
  u64 mapOffset = *pDataEnd;
  u64 mapSize = 16 + (u64)p->pageCount * sizeof(EnczMapEntryDisk);
  u32 crc;
  u32 i;
  int rc;

  aBlob = sqlite3_malloc64((sqlite3_uint64)mapSize);
  if( aBlob==0 ) return SQLITE_NOMEM;
  memset(aBlob, 0, (size_t)mapSize);
  enczPut32(&aBlob[0], ENCZ_MAP_MAGIC);
  enczPut32(&aBlob[4], ENCZ_MAP_ENTRY_VERSION);
  enczPut32(&aBlob[8], p->pageCount);
  aDisk = (EnczMapEntryDisk*)(&aBlob[16]);
  for(i=0; i<p->pageCount; i++){
    aDisk[i].offset = p->aMap[i].offset;
    aDisk[i].storedSize = p->aMap[i].storedSize;
    aDisk[i].plainSize = p->aMap[i].plainSize;
    aDisk[i].flags = p->aMap[i].flags;
    memcpy(aDisk[i].nonce, p->aMap[i].nonce, ENCZ_NONCE_SZ);
    memcpy(aDisk[i].tag, p->aMap[i].tag, ENCZ_TAG_SZ);
    aDisk[i].crc32 = 0;
    aDisk[i].crc32 = enczCrc32(&aDisk[i], sizeof(EnczMapEntryDisk));
  }
  crc = enczCrc32(&aBlob[16], (size_t)mapSize - 16);
  enczPut32(&aBlob[12], crc);
  rc = enczRawWrite(p, aBlob, (int)mapSize, (i64)mapOffset);
  sqlite3_free(aBlob);
  if( rc!=SQLITE_OK ) return rc;
  *pMapOffset = mapOffset;
  *pMapSize = mapSize;
  *pDataEnd = mapOffset + mapSize;
  return SQLITE_OK;
}

static int enczCommit(EnczFile *p, int flags){
  DirtyPage *pDirty;
  u64 dataEnd = p->dataEnd;
  u64 mapOffset = 0;
  u64 mapSize = 0;
  u64 generation;
  EnczHdr hdr;
  u8 aHdr[ENCZ_HDR_SZ];
  int nextSlot;
  int rc = SQLITE_OK;

  if( !p->needsCommit ) return SQLITE_OK;
  if( !p->hasKey ) return SQLITE_AUTH;
  if( p->logicalPageSize<=0 ) return SQLITE_CORRUPT;

  for(pDirty=p->pDirty; pDirty; pDirty=pDirty->pNext){
    u8 *aStored = 0;
    int nStored = 0;
    u32 flagsPage = 0;
    u8 nonce[ENCZ_NONCE_SZ];
    u8 tag[ENCZ_TAG_SZ];
    rc = enczEncryptPage(
      p, pDirty->data, p->logicalPageSize,
      &aStored, &nStored, &flagsPage, nonce, tag
    );
    if( rc!=SQLITE_OK ) break;
    rc = enczRawWrite(p, aStored, nStored, (i64)dataEnd);
    if( rc==SQLITE_OK ){
      EnczMapEntry *pEntry = &p->aMap[pDirty->pgno - 1];
      pEntry->offset = dataEnd;
      pEntry->storedSize = (u32)nStored;
      pEntry->plainSize = (u32)p->logicalPageSize;
      pEntry->flags = flagsPage;
      memcpy(pEntry->nonce, nonce, ENCZ_NONCE_SZ);
      memcpy(pEntry->tag, tag, ENCZ_TAG_SZ);
      dataEnd += (u64)nStored;
    }
    sqlite3_free(aStored);
    if( rc!=SQLITE_OK ) break;
  }
  if( rc!=SQLITE_OK ) return rc;

  if( p->pendingTruncate>=0 && (u32)p->pendingTruncate < p->pageCount ){
    u32 i;
    for(i=(u32)p->pendingTruncate; i<p->pageCount; i++){
      memset(&p->aMap[i], 0, sizeof(EnczMapEntry));
    }
    p->pageCount = (u32)p->pendingTruncate;
  }

  rc = enczWriteMapSnapshot(p, &mapOffset, &mapSize, &dataEnd);
  if( rc!=SQLITE_OK ) return rc;
  rc = p->pSubFile->pMethods->xSync(p->pSubFile, flags);
  if( rc!=SQLITE_OK ) return rc;

  generation = p->generation + 1;
  enczMakeHeader(p, &hdr, mapOffset, mapSize, dataEnd, generation);
  enczEncodeHeader(&hdr, aHdr);
  nextSlot = p->currentHdrSlot ? 0 : 1;
  rc = enczRawWrite(
    p, aHdr, ENCZ_HDR_SZ,
    nextSlot ? ENCZ_HDR_SLOT1 : ENCZ_HDR_SLOT0
  );
  if( rc!=SQLITE_OK ) return rc;
  rc = p->pSubFile->pMethods->xSync(p->pSubFile, flags);
  if( rc!=SQLITE_OK ) return rc;

  p->generation = generation;
  p->currentHdrSlot = nextSlot;
  p->dataEnd = dataEnd;
  p->needsCommit = 0;
  p->pendingTruncate = -1;
  enczFreeDirtyPages(p);
  return SQLITE_OK;
}

static int enczClose(sqlite3_file *pFile){
  EnczFile *p = (EnczFile*)pFile;
  int rc = SQLITE_OK;
  if( p->isMainDb && p->needsCommit ){
    rc = enczCommit(p, SQLITE_SYNC_NORMAL);
  }
  if( rc==SQLITE_OK && p->isWal ) rc = enczWalMetaSave(p, SQLITE_SYNC_NORMAL);
  enczFreeDirtyPages(p);
  sqlite3_free(p->aMap);
  sqlite3_free(p->aWalMeta);
  sqlite3_free(p->zMetaName);
  if( p->pMetaFile ){
    p->pMetaFile->pMethods->xClose(p->pMetaFile);
    sqlite3_free(p->pMetaFile);
  }
  if( p->pSubFile ){
    p->pSubFile->pMethods->xClose(p->pSubFile);
  }
  return rc;
}

static int enczRead(sqlite3_file *pFile, void *pBuf, int iAmt, sqlite3_int64 iOfst){
  EnczFile *p = (EnczFile*)pFile;
  u8 *aOut = (u8*)pBuf;
  u32 firstPg;
  u32 lastPg;
  u32 pgno;
  int rc;

  if( p->isWal ){
    return enczWalReadRegion(p, pBuf, iAmt, iOfst);
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xRead(ORIGFILE(pFile), pBuf, iAmt, iOfst);
  }
  rc = enczEnsureReady(p, 0);
  if( rc!=SQLITE_OK ) return rc;

  if( p->hasKey ) p->ioStarted = 1;
  memset(aOut, 0, (size_t)iAmt);
  if( iAmt<=0 ) return SQLITE_OK;
  firstPg = (u32)(iOfst / p->logicalPageSize) + 1;
  lastPg = (u32)((iOfst + iAmt - 1) / p->logicalPageSize) + 1;
  for(pgno=firstPg; pgno<=lastPg; pgno++){
    u8 *aPage = sqlite3_malloc64((sqlite3_uint64)p->logicalPageSize);
    int pageStart = (int)((pgno-1) * (u32)p->logicalPageSize);
    int destStart = pageStart < iOfst ? 0 : pageStart - (int)iOfst;
    int srcStart = iOfst > pageStart ? (int)(iOfst - pageStart) : 0;
    int copyLen = p->logicalPageSize - srcStart;
    if( destStart + copyLen > iAmt ) copyLen = iAmt - destStart;
    if( aPage==0 ) return SQLITE_NOMEM;
    rc = enczReadLogicalPage(p, pgno, aPage);
    if( rc==SQLITE_OK && copyLen>0 ){
      memcpy(aOut + destStart, aPage + srcStart, (size_t)copyLen);
    }
    sqlite3_free(aPage);
    if( rc!=SQLITE_OK ) return rc;
  }
  return SQLITE_OK;
}

static int enczWrite(sqlite3_file *pFile, const void *pBuf, int iAmt, sqlite3_int64 iOfst){
  EnczFile *p = (EnczFile*)pFile;
  int rc;
  if( p->isWal ){
    return enczWalWriteRegion(p, pBuf, iAmt, iOfst);
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xWrite(ORIGFILE(pFile), pBuf, iAmt, iOfst);
  }
  rc = enczEnsureReady(p, iAmt>=512 ? iAmt : 0);
  if( rc!=SQLITE_OK ) return rc;
  if( !p->hasKey ) return SQLITE_AUTH;
  p->ioStarted = 1;
  return enczStagePageWrite(p, (const u8*)pBuf, iAmt, iOfst);
}

static int enczTruncate(sqlite3_file *pFile, sqlite3_int64 size){
  EnczFile *p = (EnczFile*)pFile;
  int rc;
  if( p->isWal ){
    rc = ORIGFILE(pFile)->pMethods->xTruncate(ORIGFILE(pFile), size);
    if( rc==SQLITE_OK && size <= ENCZ_WAL_HDR_SZ ){
      enczWalMetaClear(p);
    }else if( rc==SQLITE_OK && p->walPageSize>0 ){
      sqlite3_int64 frameSize = (sqlite3_int64)p->walPageSize + ENCZ_WAL_FRAME_HDR_SZ;
      u32 nFrame = size<=ENCZ_WAL_HDR_SZ ? 0 : (u32)((size - ENCZ_WAL_HDR_SZ) / frameSize);
      if( nFrame < p->walFrameCount ) p->walFrameCount = nFrame;
      p->walMetaDirty = 1;
    }
    return rc;
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xTruncate(ORIGFILE(pFile), size);
  }
  rc = enczEnsureReady(p, 0);
  if( rc!=SQLITE_OK ) return rc;
  if( size<0 ) return SQLITE_IOERR_TRUNCATE;
  p->pendingTruncate = (int)((size + p->logicalPageSize - 1) / p->logicalPageSize);
  p->needsCommit = 1;
  return SQLITE_OK;
}

static int enczSync(sqlite3_file *pFile, int flags){
  EnczFile *p = (EnczFile*)pFile;
  int rc;
  if( p->isWal ){
    rc = enczWalMetaSave(p, flags);
    if( rc!=SQLITE_OK ) return rc;
    return ORIGFILE(pFile)->pMethods->xSync(ORIGFILE(pFile), flags);
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xSync(ORIGFILE(pFile), flags);
  }
  return enczCommit(p, flags);
}

static int enczFileSize(sqlite3_file *pFile, sqlite3_int64 *pSize){
  EnczFile *p = (EnczFile*)pFile;
  int rc;
  if( p->isWal ){
    return ORIGFILE(pFile)->pMethods->xFileSize(ORIGFILE(pFile), pSize);
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xFileSize(ORIGFILE(pFile), pSize);
  }
  rc = enczEnsureReady(p, 0);
  if( rc!=SQLITE_OK ) return rc;
  *pSize = (sqlite3_int64)p->pageCount * (sqlite3_int64)p->logicalPageSize;
  if( p->pendingTruncate>=0 ){
    *pSize = (sqlite3_int64)p->pendingTruncate * (sqlite3_int64)p->logicalPageSize;
  }
  return SQLITE_OK;
}

static int enczLock(sqlite3_file *pFile, int eLock){
  return ORIGFILE(pFile)->pMethods->xLock(ORIGFILE(pFile), eLock);
}

static int enczUnlock(sqlite3_file *pFile, int eLock){
  return ORIGFILE(pFile)->pMethods->xUnlock(ORIGFILE(pFile), eLock);
}

static int enczCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  return ORIGFILE(pFile)->pMethods->xCheckReservedLock(ORIGFILE(pFile), pResOut);
}

static char *enczStatusString(EnczFile *p){
  return sqlite3_mprintf(
    "cipher=%s,key=%s,compression=%s,level=%d,pages=%u,page_size=%d,container=%d",
    p->cipher==ENCZ_CIPHER_AES_256_GCM ? "aes-256-gcm" : "unknown",
    p->hasKey ? "set" : "unset",
    enczCompressionName(p->compression),
    p->compressionLevel,
    p->pageCount,
    p->logicalPageSize,
    p->isContainer
  );
}

static int enczConfigLocked(EnczFile *p){
  if( !p->ioStarted ) return 0;
  if( p->pageCount==0 && p->pDirty==0 && !p->needsCommit ) return 0;
  return 1;
}

static int enczHandlePragma(EnczFile *p, char **azArg){
  const char *zName = azArg[1];
  const char *zValue = azArg[2];
  int rc = SQLITE_NOTFOUND;
  if( zName==0 ) return rc;

  if( sqlite3_stricmp(zName, "crypto_status")==0 ){
    azArg[0] = enczStatusString(p);
    return SQLITE_OK;
  }
  if( sqlite3_stricmp(zName, "crypto_key")==0 ){
    if( enczConfigLocked(p) ){
      azArg[0] = sqlite3_mprintf("encz pragmas must run before database IO");
      return SQLITE_ERROR;
    }
    if( zValue && enczSetKeyPassphrase(p, zValue)==SQLITE_OK ){
      azArg[0] = sqlite3_mprintf("ok");
      rc = SQLITE_OK;
    }else{
      azArg[0] = sqlite3_mprintf("invalid crypto_key");
      rc = SQLITE_ERROR;
    }
  }else if( sqlite3_stricmp(zName, "crypto_key_hex")==0 ){
    if( enczConfigLocked(p) ){
      azArg[0] = sqlite3_mprintf("encz pragmas must run before database IO");
      return SQLITE_ERROR;
    }
    if( zValue && enczSetKeyHex(p, zValue)==SQLITE_OK ){
      azArg[0] = sqlite3_mprintf("ok");
      rc = SQLITE_OK;
    }else{
      azArg[0] = sqlite3_mprintf("invalid crypto_key_hex");
      rc = SQLITE_ERROR;
    }
  }else if( sqlite3_stricmp(zName, "crypto_key_env")==0 ){
    if( enczConfigLocked(p) ){
      azArg[0] = sqlite3_mprintf("encz pragmas must run before database IO");
      return SQLITE_ERROR;
    }
    if( zValue && enczSetKeyEnv(p, zValue)==SQLITE_OK ){
      azArg[0] = sqlite3_mprintf("ok");
      rc = SQLITE_OK;
    }else{
      azArg[0] = sqlite3_mprintf("crypto_key_env not found");
      rc = SQLITE_ERROR;
    }
  }else if( sqlite3_stricmp(zName, "crypto_compression")==0 ){
    if( enczConfigLocked(p) ){
      azArg[0] = sqlite3_mprintf("encz pragmas must run before database IO");
      return SQLITE_ERROR;
    }
    int eCompression = enczParseCompression(zValue);
    if( eCompression>=0 ){
      p->compression = eCompression;
      p->hasCompressionSetting = 1;
      azArg[0] = sqlite3_mprintf("%s", enczCompressionName(eCompression));
      rc = SQLITE_OK;
    }else{
      azArg[0] = sqlite3_mprintf("invalid crypto_compression");
      rc = SQLITE_ERROR;
    }
  }else if( sqlite3_stricmp(zName, "crypto_compression_level")==0 ){
    if( enczConfigLocked(p) ){
      azArg[0] = sqlite3_mprintf("encz pragmas must run before database IO");
      return SQLITE_ERROR;
    }
    int level = zValue ? atoi(zValue) : p->compressionLevel;
    p->compressionLevel = level;
    azArg[0] = sqlite3_mprintf("%d", p->compressionLevel);
    rc = SQLITE_OK;
  }
  return rc;
}

static int enczFileControl(sqlite3_file *pFile, int op, void *pArg){
  EnczFile *p = (EnczFile*)pFile;
  int rc;
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xFileControl(ORIGFILE(pFile), op, pArg);
  }
  if( op==SQLITE_FCNTL_PRAGMA ){
    rc = enczHandlePragma(p, (char**)pArg);
    if( rc!=SQLITE_NOTFOUND ) return rc;
  }else if( op==SQLITE_FCNTL_VFSNAME ){
    *(char**)pArg = sqlite3_mprintf("%s", ENCZ_VFS_NAME);
    return SQLITE_OK;
  }else if( op==SQLITE_FCNTL_MMAP_SIZE ){
    sqlite3_int64 *pn = (sqlite3_int64*)pArg;
    if( pn ) *pn = 0;
    return SQLITE_OK;
  }else if( op==SQLITE_FCNTL_SIZE_HINT || op==SQLITE_FCNTL_CHUNK_SIZE ){
    return SQLITE_OK;
  }
  return ORIGFILE(pFile)->pMethods->xFileControl(ORIGFILE(pFile), op, pArg);
}

static int enczSectorSize(sqlite3_file *pFile){
  return ORIGFILE(pFile)->pMethods->xSectorSize(ORIGFILE(pFile));
}

static int enczDeviceCharacteristics(sqlite3_file *pFile){
  int devchar = ORIGFILE(pFile)->pMethods->xDeviceCharacteristics(ORIGFILE(pFile));
  return devchar & ~SQLITE_IOCAP_POWERSAFE_OVERWRITE;
}

static int enczShmMap(
  sqlite3_file *pFile,
  int iPg,
  int pgsz,
  int bExtend,
  void volatile **pp
){
  EnczFile *p = (EnczFile*)pFile;
  if( p->isMainDb && ORIGFILE(pFile)->pMethods->xShmMap==0 ){
    return SQLITE_IOERR_SHMMAP;
  }
  return ORIGFILE(pFile)->pMethods->xShmMap(ORIGFILE(pFile), iPg, pgsz, bExtend, pp);
}

static int enczShmLock(sqlite3_file *pFile, int offset, int n, int flags){
  return ORIGFILE(pFile)->pMethods->xShmLock(ORIGFILE(pFile), offset, n, flags);
}

static void enczShmBarrier(sqlite3_file *pFile){
  ORIGFILE(pFile)->pMethods->xShmBarrier(ORIGFILE(pFile));
}

static int enczShmUnmap(sqlite3_file *pFile, int deleteFlag){
  return ORIGFILE(pFile)->pMethods->xShmUnmap(ORIGFILE(pFile), deleteFlag);
}

static int enczFetch(sqlite3_file *pFile, sqlite3_int64 iOfst, int iAmt, void **pp){
  EnczFile *p = (EnczFile*)pFile;
  (void)iOfst;
  (void)iAmt;
  if( p->isMainDb ){
    *pp = 0;
    return SQLITE_OK;
  }
  if( ORIGFILE(pFile)->pMethods->iVersion>2 && ORIGFILE(pFile)->pMethods->xFetch ){
    return ORIGFILE(pFile)->pMethods->xFetch(ORIGFILE(pFile), iOfst, iAmt, pp);
  }
  *pp = 0;
  return SQLITE_OK;
}

static int enczUnfetch(sqlite3_file *pFile, sqlite3_int64 iOfst, void *pPage){
  if( ORIGFILE(pFile)->pMethods->iVersion>2 && ORIGFILE(pFile)->pMethods->xUnfetch ){
    return ORIGFILE(pFile)->pMethods->xUnfetch(ORIGFILE(pFile), iOfst, pPage);
  }
  return SQLITE_OK;
}

static void enczApplyUriConfig(EnczFile *p, const char *zName){
  const char *z;
  if( zName==0 ) return;
  z = sqlite3_uri_parameter(zName, "crypto_key");
  if( z ) (void)enczSetKeyPassphrase(p, z);
  z = sqlite3_uri_parameter(zName, "crypto_key_hex");
  if( z ) (void)enczSetKeyHex(p, z);
  z = sqlite3_uri_parameter(zName, "crypto_key_env");
  if( z ) (void)enczSetKeyEnv(p, z);
  z = sqlite3_uri_parameter(zName, "crypto_compression");
  if( z ){
    int eCompression = enczParseCompression(z);
    if( eCompression>=0 ){
      p->compression = eCompression;
      p->hasCompressionSetting = 1;
    }
  }
  z = sqlite3_uri_parameter(zName, "crypto_compression_level");
  if( z ) p->compressionLevel = atoi(z);
}

static int enczOpen(
  sqlite3_vfs *pVfs,
  const char *zName,
  sqlite3_file *pFile,
  int flags,
  int *pOutFlags
){
  EnczFile *p = (EnczFile*)pFile;
  sqlite3_vfs *pSubVfs = ORIGVFS(pVfs);
  sqlite3_file *pSubFile = ORIGFILE(pFile);
  int rc;
  memset(p, 0, sizeof(*p));
  p->pSubFile = pSubFile;
  p->zFName = zName;
  p->compressionLevel = 3;
  p->compression = ENCZ_COMPRESSION_NONE;
  p->cipher = ENCZ_CIPHER_AES_256_GCM;
  p->pendingTruncate = -1;
  p->isMainDb = (flags & SQLITE_OPEN_MAIN_DB)!=0;
  p->isWal = (flags & SQLITE_OPEN_WAL)!=0;
  p->isReadonly = (flags & SQLITE_OPEN_READONLY)!=0;
  if( p->isMainDb || p->isWal ){
    if( p->isMainDb ){
      enczApplyUriConfig(p, zName);
    }
    if( p->isWal && zName ){
      sqlite3_file *pDb = sqlite3_database_file_object(zName);
      if( pDb ){
        EnczFile *pDbFile = (EnczFile*)pDb;
        p->pMainDb = pDbFile;
        p->compression = pDbFile->compression;
        p->compressionLevel = pDbFile->compressionLevel;
        p->cipher = pDbFile->cipher;
        p->logicalPageSize = pDbFile->logicalPageSize;
        p->walPageSize = pDbFile->logicalPageSize;
        p->hasKey = pDbFile->hasKey;
        memcpy(p->key, pDbFile->key, sizeof(p->key));
      }
    }
    pFile->pMethods = &encz_io_methods;
    rc = pSubVfs->xOpen(pSubVfs, zName, pSubFile, flags, pOutFlags);
    if( rc!=SQLITE_OK ){
      pFile->pMethods = 0;
      return rc;
    }
    if( p->isWal ){
      rc = enczWalOpenMeta(p);
      if( rc!=SQLITE_OK ){
        pFile->pMethods = 0;
        pSubFile->pMethods->xClose(pSubFile);
        return rc;
      }
    }
    return SQLITE_OK;
  }
  return pSubVfs->xOpen(pSubVfs, zName, pFile, flags, pOutFlags);
}

static int enczDelete(sqlite3_vfs *pVfs, const char *zPath, int dirSync){
  int rc = ORIGVFS(pVfs)->xDelete(ORIGVFS(pVfs), zPath, dirSync);
  if( enczIsWalPath(zPath) ){
    char *zMeta = enczWalMetaPath(zPath);
    if( zMeta ){
      (void)ORIGVFS(pVfs)->xDelete(ORIGVFS(pVfs), zMeta, dirSync);
      sqlite3_free(zMeta);
    }
  }
  return rc;
}

static int enczAccess(sqlite3_vfs *pVfs, const char *zPath, int flags, int *pResOut){
  return ORIGVFS(pVfs)->xAccess(ORIGVFS(pVfs), zPath, flags, pResOut);
}

static int enczFullPathname(sqlite3_vfs *pVfs, const char *zPath, int nOut, char *zOut){
  return ORIGVFS(pVfs)->xFullPathname(ORIGVFS(pVfs), zPath, nOut, zOut);
}

static void *enczDlOpen(sqlite3_vfs *pVfs, const char *zPath){
  return ORIGVFS(pVfs)->xDlOpen(ORIGVFS(pVfs), zPath);
}

static void enczDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
  ORIGVFS(pVfs)->xDlError(ORIGVFS(pVfs), nByte, zErrMsg);
}

static void (*enczDlSym(sqlite3_vfs *pVfs, void *pHandle, const char *zSym))(void){
  return ORIGVFS(pVfs)->xDlSym(ORIGVFS(pVfs), pHandle, zSym);
}

static void enczDlClose(sqlite3_vfs *pVfs, void *pHandle){
  ORIGVFS(pVfs)->xDlClose(ORIGVFS(pVfs), pHandle);
}

static int enczRandomness(sqlite3_vfs *pVfs, int nByte, char *zBufOut){
  return ORIGVFS(pVfs)->xRandomness(ORIGVFS(pVfs), nByte, zBufOut);
}

static int enczSleep(sqlite3_vfs *pVfs, int nMicro){
  return ORIGVFS(pVfs)->xSleep(ORIGVFS(pVfs), nMicro);
}

static int enczCurrentTime(sqlite3_vfs *pVfs, double *pTimeOut){
  return ORIGVFS(pVfs)->xCurrentTime(ORIGVFS(pVfs), pTimeOut);
}

static int enczGetLastError(sqlite3_vfs *pVfs, int a, char *b){
  return ORIGVFS(pVfs)->xGetLastError(ORIGVFS(pVfs), a, b);
}

static int enczCurrentTimeInt64(sqlite3_vfs *pVfs, sqlite3_int64 *pNow){
  sqlite3_vfs *pOrig = ORIGVFS(pVfs);
  if( pOrig->xCurrentTimeInt64 ){
    return pOrig->xCurrentTimeInt64(pOrig, pNow);
  }else{
    double r;
    int rc = pOrig->xCurrentTime(pOrig, &r);
    *pNow = (sqlite3_int64)(r * 86400000.0);
    return rc;
  }
}

static int enczSetSystemCall(
  sqlite3_vfs *pVfs,
  const char *zName,
  sqlite3_syscall_ptr pCall
){
  return ORIGVFS(pVfs)->xSetSystemCall(ORIGVFS(pVfs), zName, pCall);
}

static sqlite3_syscall_ptr enczGetSystemCall(sqlite3_vfs *pVfs, const char *zName){
  return ORIGVFS(pVfs)->xGetSystemCall(ORIGVFS(pVfs), zName);
}

static const char *enczNextSystemCall(sqlite3_vfs *pVfs, const char *zName){
  return ORIGVFS(pVfs)->xNextSystemCall(ORIGVFS(pVfs), zName);
}

static int enczRegister(void){
  sqlite3_vfs *pOrig = sqlite3_vfs_find(0);
  if( pOrig==0 ) return SQLITE_ERROR;
  encz_vfs.iVersion = pOrig->iVersion;
  encz_vfs.mxPathname = pOrig->mxPathname;
  encz_vfs.szOsFile = pOrig->szOsFile + sizeof(EnczFile);
  encz_vfs.pAppData = pOrig;
  return sqlite3_vfs_register(&encz_vfs, 0);
}

#if defined(SQLITE_CRYPTOVFS_STATIC)
int sqlite3_register_encz(const char *NotUsed){
  (void)NotUsed;
  return enczRegister();
}
#endif

#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_encz_init(
  sqlite3 *db,
  char **pzErrMsg,
  const sqlite3_api_routines *pApi
){
  int rc;
  (void)db;
  (void)pzErrMsg;
  SQLITE_EXTENSION_INIT2(pApi);
  OpenSSL_add_all_algorithms();
  rc = enczRegister();
  if( rc==SQLITE_OK ) rc = SQLITE_OK_LOAD_PERMANENTLY;
  return rc;
}
