/*
** 2026-06-06
**
** Custom SQLite VFS that encrypts and decrypts flat database file pages
** in-place using Go-provided AEAD ciphers, utilizing SQLite's reserved bytes.
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
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
# include <windows.h>
#endif


typedef sqlite3_int64 i64;
typedef unsigned char u8;
typedef unsigned int u32;

#define ENCZ_VFS_NAME              "encz"
#define ENCZ_CIPHER_AES_256_GCM           1
#define ENCZ_CIPHER_CHACHA20_POLY1305     2
#define ENCZ_CIPHER_XCHACHA20_POLY1305    3

#define ENCZ_WAL_HDR_SZ            32
#define ENCZ_WAL_FRAME_HDR_SZ      24
#define ENCZ_RESERVED_SZ           48
#define ENCZ_CIPHER_SHIFT           25
#define ENCZ_CIPHER_MASK            0x0e000000U
#define ENCZ_FLAG_HEADER_AAD       0x01000000U

#define ORIGVFS(p)  ((sqlite3_vfs*)((p)->pAppData))
#define ORIGFILE(p) ((sqlite3_file*)(((EnczFile*)(p))+1))

typedef struct EnczFile EnczFile;

struct EnczFile {
  sqlite3_file base;
  sqlite3_file *pSubFile;
  const char *zFName;
  int isMainDb;
  int isWal;
  int isReadonly;
  int hasKey;
  int initialized;
  int ioStarted;
  int logicalPageSize;
  int walPageSize;
  int cipher;
  u8 key[32];
  sqlite3_uint64 registryHandle;
  int hasReservedBytes;
  int allowBootstrapJournal;
  EnczFile *pMainDb;
  u8 *readBuf;
  int readBufCap;
  u8 *sealedBuf;
  int sealedBufCap;
  u8 *walPlainBuf;
  int walPlainBufCap;
  int statsEnabled;
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

static int enczDecryptAndReadPage(EnczFile*, u8*, u32, i64);
static int enczEncryptAndWritePageAtOffset(EnczFile*, const u8*, u32, i64);
static void enczInitPlainPage(u8*, int, u32);

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

static void enczPut32(u8 *a, u32 v){
  a[0] = (u8)(v & 0xff);
  a[1] = (u8)((v>>8) & 0xff);
  a[2] = (u8)((v>>16) & 0xff);
  a[3] = (u8)((v>>24) & 0xff);
}

static void enczWalParseHeaderPageSize(EnczFile *p, const u8 *aHdr){
  u32 sz = enczGet32(&aHdr[8]);
  sz = (sz & 0xfe00U) + ((sz & 0x0001U)<<16);
  if( sz>=512 && sz<=65536 && (sz & (sz-1))==0 ){
    p->walPageSize = (int)sz;
  }
}

static int enczWalEnsurePageSize(EnczFile *p){
  u8 aHdr[ENCZ_WAL_HDR_SZ];
  int rc;
  if( p->walPageSize>0 ) return SQLITE_OK;
  if( p->pMainDb && p->pMainDb->logicalPageSize>0 ){
    p->walPageSize = p->pMainDb->logicalPageSize;
    return SQLITE_OK;
  }
  rc = p->pSubFile->pMethods->xRead(p->pSubFile, aHdr, sizeof(aHdr), 0);
  if( rc==SQLITE_IOERR_SHORT_READ ){
    memset(aHdr, 0, sizeof(aHdr));
    rc = SQLITE_OK;
  }
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

static u32 enczGetWalPgno(EnczFile *p, i64 pageStartOfst) {
  u8 aPgno[4];
  int rc = p->pSubFile->pMethods->xRead(p->pSubFile, aPgno, 4, pageStartOfst - 24);
  if (rc == SQLITE_OK) {
    return ((u32)aPgno[0] << 24) | ((u32)aPgno[1] << 16) | ((u32)aPgno[2] << 8) | aPgno[3];
  }
  return 0;
}

static int enczIsValidPageSize(int sz){
  return sz>=512 && sz<=65536 && (sz & (sz-1))==0;
}

extern void enczGoLog(const char *zMsg);
extern int enczGoFillKey(unsigned long long handle, unsigned int keyId, unsigned char *aOut);
extern int enczGoFillActiveKey(unsigned long long handle, unsigned int *pKeyId, unsigned char *aOut);
extern int enczGoFillDBUUID(unsigned long long handle, unsigned char *aOut);
extern int enczGoRandomBytes(unsigned char *out, int n);
extern int enczGoAEADSeal(unsigned int cipher, unsigned char *key, unsigned char *nonce, unsigned char *out, unsigned char *tag, unsigned char *plain, unsigned char *aad, int plainLen, int aadLen);
extern int enczGoAEADOpen(unsigned int cipher, unsigned char *key, unsigned char *nonce, unsigned char *tag, unsigned char *out, unsigned char *ciphertext, unsigned char *aad, int ciphertextLen, int aadLen);
extern int enczGoAEADOpenCached(unsigned long long handle, unsigned int keyId, unsigned char *nonce, unsigned char *sealed, unsigned char *out, unsigned char *aad, int sealedLen, int plainLen, int aadLen);
extern int enczGoPageCacheCandidate(unsigned long long handle, int isWal, unsigned int pgno, long long offset, unsigned int pageSize, unsigned char *pageOut, unsigned char *tokenOut, int tokenCap, int *tokenLen);
extern int enczGoPageCacheConfirm(unsigned long long handle, int isWal, unsigned int pgno, long long offset, unsigned int pageSize, unsigned char *expected, unsigned char *actual, int tokenLen);
extern void enczGoPageCachePut(unsigned long long handle, int isWal, unsigned int pgno, long long offset, unsigned int pageSize, unsigned char *page, unsigned char *token, int tokenLen);
extern void enczGoPageCacheInvalidate(unsigned long long handle, int isWal, unsigned int pgno, long long offset, unsigned int pageSize);
extern void enczGoPageCacheClear(unsigned long long handle, int isWal);
extern int enczGoReadStatsEnabled(unsigned long long handle);
extern void enczGoRecordReadIO(unsigned long long handle, unsigned long long reads, unsigned long long bytesRead, unsigned long long nanos, unsigned long long scratchAllocs, unsigned long long copyBytes);

static sqlite3_uint64 enczNowNanos(void){
#ifdef _WIN32
  LARGE_INTEGER freq, now;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&now);
  return (sqlite3_uint64)((now.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
  struct timespec ts;
  if( clock_gettime(CLOCK_MONOTONIC, &ts)!=0 ) return 0;
  return (sqlite3_uint64)ts.tv_sec * 1000000000ULL + (sqlite3_uint64)ts.tv_nsec;
#endif
}

static int enczEnsureBuffer(u8 **pp, int *pCap, int n){
  u8 *pNew;
  if( *pCap>=n ) return 0;
  pNew = sqlite3_malloc64((sqlite3_uint64)n);
  if( pNew==0 ) return -1;
  if( *pp ){ memset(*pp, 0, (size_t)*pCap); sqlite3_free(*pp); }
  *pp = pNew;
  *pCap = n;
  return 1;
}

static int enczPageToken(const u8 *aBuf, int P, u32 pgno, u8 *aToken){
  int n = 0;
  if( pgno==1 ){ memcpy(aToken, aBuf, 100); n = 100; }
  memcpy(aToken+n, aBuf+P-ENCZ_RESERVED_SZ, ENCZ_RESERVED_SZ);
  return n + ENCZ_RESERVED_SZ;
}

static int enczFillKeyForPage(EnczFile *p, u32 keyId, u8 *aKeyOut){
  if( p->registryHandle ){
    if( enczGoFillKey((unsigned long long)p->registryHandle, keyId, aKeyOut) ) return SQLITE_OK;
    return SQLITE_ERROR;
  }
  if( p->hasKey && keyId==0 ){
    memcpy(aKeyOut, p->key, 32);
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

static int enczFillActiveKey(EnczFile *p, u32 *pKeyId, u8 *aKeyOut){
  if( p->registryHandle ){
    unsigned int keyId = 0;
    if( enczGoFillActiveKey((unsigned long long)p->registryHandle, &keyId, aKeyOut) ){
      *pKeyId = (u32)keyId;
      return SQLITE_OK;
    }
    return SQLITE_ERROR;
  }
  if( p->hasKey ){
    *pKeyId = 0;
    memcpy(aKeyOut, p->key, 32);
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

static void enczInitPlainPage(u8 *aPlain, int P, u32 pgno){
  memset(aPlain, 0, P);
  if( pgno!=1 ) return;
  memcpy(aPlain, "SQLite format 3", 16);
  aPlain[16] = (u8)((P >> 8) & 0xff);
  aPlain[17] = (u8)(P & 0xff);
  aPlain[18] = 1;
  aPlain[19] = 1;
  aPlain[20] = ENCZ_RESERVED_SZ;
  aPlain[21] = 64;
  aPlain[22] = 32;
  aPlain[23] = 32;
  aPlain[47] = 4;
  aPlain[59] = 1;
  aPlain[100] = 0x0d;
  aPlain[105] = (u8)(((P - ENCZ_RESERVED_SZ) >> 8) & 0xff);
  aPlain[106] = (u8)((P - ENCZ_RESERVED_SZ) & 0xff);
}

static int enczInitNewDatabase(EnczFile *p) {
  int P = 4096;
  u8 *aPlain = sqlite3_malloc64(P);
  if( aPlain==0 ) return SQLITE_NOMEM;
  enczInitPlainPage(aPlain, P, 1);
  
  p->logicalPageSize = P;
  p->hasReservedBytes = ENCZ_RESERVED_SZ;
  p->initialized = 1;
  
  int rc = enczEncryptAndWritePageAtOffset(p, aPlain, 1, 0);
  sqlite3_free(aPlain);
  if( rc!=SQLITE_OK ){
    p->initialized = 0;
  }
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
    if( enczIsValidPageSize(pageSizeHint) ){
      p->logicalPageSize = pageSizeHint;
    }else{
      p->logicalPageSize = 4096;
    }
    p->hasReservedBytes = ENCZ_RESERVED_SZ;
    p->initialized = 1;
  }else{
    u8 aHdr[100];
    rc = p->pSubFile->pMethods->xRead(p->pSubFile, aHdr, 100, 0);
    if( rc!=SQLITE_OK && rc!=SQLITE_IOERR_SHORT_READ ) return rc;
    if( memcmp(aHdr, "SQLite format 3", 15)!=0 ){
      return SQLITE_NOTADB;
    }
    u32 sz = ((u32)aHdr[16] << 8) | aHdr[17];
    if( sz == 1 ) sz = 65536;
    if( sz>=512 && sz<=65536 && (sz & (sz-1))==0 ){
      p->logicalPageSize = (int)sz;
    }else{
      p->logicalPageSize = 4096;
    }
    p->hasReservedBytes = aHdr[20];
    if( p->hasReservedBytes == 0 ){
      p->hasReservedBytes = ENCZ_RESERVED_SZ;
    }
    p->initialized = 1;
  }
  return SQLITE_OK;
}

static void enczLog(const char *zFormat, ...){
  va_list ap;
  char *zMsg;
  va_start(ap, zFormat);
  zMsg = sqlite3_vmprintf(zFormat, ap);
  va_end(ap);
  if( zMsg ){
    enczGoLog(zMsg);
    sqlite3_free(zMsg);
  }
}

static int enczDecryptAndReadPage(EnczFile *p, u8 *aPlain, u32 pgno, i64 iOfst) {
  int P = p->isWal ? p->walPageSize : p->logicalPageSize;
  int H = (pgno == 1) ? 100 : 0;
  int nPlain = P - H - ENCZ_RESERVED_SZ;
  int rc = SQLITE_OK, scratchAllocs = 0;
  sqlite3_uint64 ioStart, ioNanos = 0;
  unsigned long long ioReads = 0, ioBytes = 0, copyBytes = 0;
  u8 expectedToken[148], actualToken[148], pageToken[148];
  int tokenLen = 0;

  if( p->registryHandle && enczGoPageCacheCandidate((unsigned long long)p->registryHandle, p->isWal, pgno, (long long)iOfst, (unsigned int)P, aPlain, expectedToken, (int)sizeof(expectedToken), &tokenLen) ){
    if( p->statsEnabled ) ioStart = enczNowNanos();
    if( tokenLen==148 ){
      rc = p->pSubFile->pMethods->xRead(p->pSubFile, actualToken, 100, iOfst);
      ioReads++; ioBytes += 100;
      if( rc==SQLITE_OK ){
        rc = p->pSubFile->pMethods->xRead(p->pSubFile, actualToken+100, ENCZ_RESERVED_SZ, iOfst+P-ENCZ_RESERVED_SZ);
        ioReads++; ioBytes += ENCZ_RESERVED_SZ;
      }
    }else{
      rc = p->pSubFile->pMethods->xRead(p->pSubFile, actualToken, ENCZ_RESERVED_SZ, iOfst+P-ENCZ_RESERVED_SZ);
      ioReads++; ioBytes += ENCZ_RESERVED_SZ;
    }
    if( p->statsEnabled ) ioNanos += enczNowNanos() - ioStart;
    if( rc!=SQLITE_OK ) return rc;
    if( enczGoPageCacheConfirm((unsigned long long)p->registryHandle, p->isWal, pgno, (long long)iOfst, (unsigned int)P, expectedToken, actualToken, tokenLen) ){
      if( p->statsEnabled ) enczGoRecordReadIO((unsigned long long)p->registryHandle, ioReads, ioBytes, ioNanos, 0, (unsigned long long)P);
      return SQLITE_OK;
    }
  }

  rc = enczEnsureBuffer(&p->readBuf, &p->readBufCap, P);
  if( rc<0 ) return SQLITE_NOMEM;
  scratchAllocs += rc;
  rc = enczEnsureBuffer(&p->sealedBuf, &p->sealedBufCap, nPlain+16);
  if( rc<0 ) return SQLITE_NOMEM;
  scratchAllocs += rc;
  if( p->statsEnabled ) ioStart = enczNowNanos();
  rc = p->pSubFile->pMethods->xRead(p->pSubFile, p->readBuf, P, iOfst);
  if( p->statsEnabled ) ioNanos += enczNowNanos() - ioStart;
  ioReads++; ioBytes += (unsigned long long)P;
  if( rc!=SQLITE_OK ){
    if( pgno == 1 && rc == SQLITE_IOERR_SHORT_READ ){ enczInitPlainPage(aPlain, P, pgno); rc = SQLITE_OK; }
    else enczLog("[SQLiteSeal] READ xRead failed, rc=%d\n", rc);
    if( p->statsEnabled ) enczGoRecordReadIO((unsigned long long)p->registryHandle, ioReads, ioBytes, ioNanos, scratchAllocs, 0);
    return rc;
  }
  if( !p->hasKey && !p->registryHandle ){ enczInitPlainPage(aPlain, P, pgno); return SQLITE_OK; }

  u32 flags = enczGet32(p->readBuf + P - ENCZ_RESERVED_SZ);
  u8 aNonce[24], aTag[16];
  u32 keyId = enczGet32(p->readBuf + P - 44);
  u32 nCipher = flags & 0x00ffffff;
  memcpy(aNonce, p->readBuf + P - 40, 24);
  memcpy(aTag, p->readBuf + P - 16, 16);
  if( nCipher != (u32)nPlain || ((flags & ENCZ_CIPHER_MASK) >> ENCZ_CIPHER_SHIFT) != (u32)p->cipher ) return SQLITE_CORRUPT;

  u8 aDbUuid[16], aAAD[132];
  size_t nAAD = 32;
  memset(aDbUuid, 0, sizeof(aDbUuid));
  if( p->registryHandle ) enczGoFillDBUUID((unsigned long long)p->registryHandle, aDbUuid);
  memcpy(aAAD, aDbUuid, 16);
  enczPut32(aAAD + 16, pgno);
  aAAD[20] = (u8)(iOfst & 0xff); aAAD[21] = (u8)((iOfst >> 8) & 0xff);
  aAAD[22] = (u8)((iOfst >> 16) & 0xff); aAAD[23] = (u8)((iOfst >> 24) & 0xff);
  aAAD[24] = (u8)((iOfst >> 32) & 0xff); aAAD[25] = (u8)((iOfst >> 40) & 0xff);
  aAAD[26] = (u8)((iOfst >> 48) & 0xff); aAAD[27] = (u8)((iOfst >> 56) & 0xff);
  aAAD[28] = p->isWal ? 1 : 0; aAAD[29] = (u8)p->cipher; memset(aAAD + 30, 0, 2);
  if( pgno==1 && (flags & ENCZ_FLAG_HEADER_AAD)!=0 ){ memcpy(aAAD + nAAD, p->readBuf, 100); nAAD += 100; }

  memcpy(p->sealedBuf, p->readBuf + H, nCipher);
  memcpy(p->sealedBuf + nCipher, aTag, 16);
  copyBytes += nCipher + 16;
  if( pgno==1 ) memcpy(aPlain, p->readBuf, 100);
  memset(aPlain + P - ENCZ_RESERVED_SZ, 0, ENCZ_RESERVED_SZ);
  if( p->registryHandle ){
    if( !enczGoAEADOpenCached((unsigned long long)p->registryHandle, keyId, aNonce, p->sealedBuf, aPlain+H, aAAD, nCipher+16, nPlain, (int)nAAD) ) rc = SQLITE_CORRUPT;
  }else{
    u8 aKey[32];
    if( enczFillKeyForPage(p, keyId, aKey)!=SQLITE_OK || !enczGoAEADOpen((unsigned int)p->cipher, aKey, aNonce, aTag, aPlain+H, p->readBuf+H, aAAD, (int)nCipher, (int)nAAD) ) rc = SQLITE_CORRUPT;
    memset(aKey, 0, sizeof(aKey));
  }
  if( rc!=SQLITE_OK ){ memset(aPlain, 0, P); enczLog("[SQLiteSeal] READ DecryptFinal (MAC check failed) for pgno=%u\n", pgno); }
  else if( p->registryHandle ){
    tokenLen = enczPageToken(p->readBuf, P, pgno, pageToken);
    enczGoPageCachePut((unsigned long long)p->registryHandle, p->isWal, pgno, (long long)iOfst, (unsigned int)P, aPlain, pageToken, tokenLen);
  }
  if( p->statsEnabled ) enczGoRecordReadIO((unsigned long long)p->registryHandle, ioReads, ioBytes, ioNanos, scratchAllocs, copyBytes);
  return rc;
}

static int enczEncryptAndWritePageAtOffset(EnczFile *p, const u8 *aPlain, u32 pgno, i64 iOfst) {
  int P = p->isWal ? p->walPageSize : p->logicalPageSize;
  if( p->registryHandle ) enczGoPageCacheInvalidate((unsigned long long)p->registryHandle, p->isWal, pgno, (long long)iOfst, (unsigned int)P);
  int rc = SQLITE_OK;
  int H = (pgno == 1) ? 100 : 0;
  int nPlain = P - H - ENCZ_RESERVED_SZ;
  
  u8 *aBuf = sqlite3_malloc64(P);
  if( aBuf==0 ) return SQLITE_NOMEM;
  memcpy(aBuf, aPlain, P);
  
  if (pgno == 1) {
    aBuf[20] = ENCZ_RESERVED_SZ; // Ensure reserved bytes is set to 48
  }
  
  u8 *aCipher = sqlite3_malloc64(nPlain + 32);
  u32 flags = (u32)nPlain | ENCZ_FLAG_HEADER_AAD | ((u32)p->cipher << ENCZ_CIPHER_SHIFT);
  u32 keyId = 0;
  u8 aKey[32];
  if( aCipher==0 ){
    sqlite3_free(aBuf);
    return SQLITE_NOMEM;
  }
  
  u8 aNonce[24];
  u8 aTag[16];
  if( enczFillActiveKey(p, &keyId, aKey)!=SQLITE_OK ){
    sqlite3_free(aBuf);
    sqlite3_free(aCipher);
    return SQLITE_AUTH;
  }

  if( !enczGoRandomBytes(aNonce, p->cipher==ENCZ_CIPHER_XCHACHA20_POLY1305 ? 24 : 12) ){
    memset(aKey, 0, sizeof(aKey));
    sqlite3_free(aBuf);
    sqlite3_free(aCipher);
    return SQLITE_IOERR;
  }
  
  u8 aDbUuid[16];
  memset(aDbUuid, 0, 16);
  if( p->registryHandle ){
    enczGoFillDBUUID((unsigned long long)p->registryHandle, aDbUuid);
  }
  
  u8 aAAD[132];
  size_t nAAD = 32;
  memcpy(aAAD, aDbUuid, 16);
  enczPut32(aAAD + 16, pgno);
  aAAD[20] = (u8)(iOfst & 0xff);
  aAAD[21] = (u8)((iOfst >> 8) & 0xff);
  aAAD[22] = (u8)((iOfst >> 16) & 0xff);
  aAAD[23] = (u8)((iOfst >> 24) & 0xff);
  aAAD[24] = (u8)((iOfst >> 32) & 0xff);
  aAAD[25] = (u8)((iOfst >> 40) & 0xff);
  aAAD[26] = (u8)((iOfst >> 48) & 0xff);
  aAAD[27] = (u8)((iOfst >> 56) & 0xff);
  aAAD[28] = p->isWal ? 1 : 0;
  aAAD[29] = (u8)p->cipher;
  memset(aAAD + 30, 0, 2);
  if( pgno==1 ){
    memcpy(aAAD + nAAD, aBuf, 100);
    nAAD += 100;
  }

  if( !enczGoAEADSeal((unsigned int)p->cipher, aKey, aNonce, aCipher, aTag, (unsigned char*)(aPlain + H), aAAD, nPlain, (int)nAAD) ){
    memset(aKey, 0, sizeof(aKey));
    sqlite3_free(aBuf);
    sqlite3_free(aCipher);
    return SQLITE_ERROR;
  }
  memset(aKey, 0, sizeof(aKey));
  
  int final_cipher_len = nPlain;
  memcpy(aBuf + H, aCipher, final_cipher_len);
  memset(aBuf + H + final_cipher_len, 0, P - ENCZ_RESERVED_SZ - H - final_cipher_len);
  enczPut32(aBuf + P - ENCZ_RESERVED_SZ, flags);
  enczPut32(aBuf + P - 44, keyId);
  memset(aBuf + P - 40, 0, 24);
  memcpy(aBuf + P - 40, aNonce, p->cipher==ENCZ_CIPHER_XCHACHA20_POLY1305 ? 24 : 12);
  memcpy(aBuf + P - 16, aTag, 16);
  
  rc = p->pSubFile->pMethods->xWrite(p->pSubFile, aBuf, P, iOfst);
  if( rc!=SQLITE_OK ){
    enczLog("[SQLiteSeal] WRITE xWrite failed, rc=%d\n", rc);
  }
  sqlite3_free(aBuf);
  sqlite3_free(aCipher);
  return rc;
}

static int enczWalReadRegion(EnczFile *p, void *pBuf, int iAmt, sqlite3_int64 iOfst){
  u8 *aOut = (u8*)pBuf;
  int rc = SQLITE_OK;
  int P = p->walPageSize;
  if (P <= 0) {
    rc = enczWalEnsurePageSize(p);
    if (rc != SQLITE_OK) return rc;
    P = p->walPageSize;
  }
  
  while( iAmt>0 && rc==SQLITE_OK ){
    if( iOfst < ENCZ_WAL_HDR_SZ ){
      int n = (int)((ENCZ_WAL_HDR_SZ - iOfst) < iAmt ? (ENCZ_WAL_HDR_SZ - iOfst) : iAmt);
      rc = p->pSubFile->pMethods->xRead(p->pSubFile, aOut, n, iOfst);
      aOut += n;
      iAmt -= n;
      iOfst += n;
    }else{
      u32 iFrame;
      int iFrameOfst;
      rc = enczWalFrameInfo(p, iOfst, &iFrame, &iFrameOfst);
      if( rc!=SQLITE_OK ) break;
      int nFrame = (P + ENCZ_WAL_FRAME_HDR_SZ) - iFrameOfst;
      if( nFrame > iAmt ) nFrame = iAmt;
      
      if( iFrameOfst < ENCZ_WAL_FRAME_HDR_SZ ){
        int nHdr = ENCZ_WAL_FRAME_HDR_SZ - iFrameOfst;
        if( nHdr > nFrame ) nHdr = nFrame;
        rc = p->pSubFile->pMethods->xRead(p->pSubFile, aOut, nHdr, iOfst);
        if( rc!=SQLITE_OK ) break;
        aOut += nHdr;
        iAmt -= nHdr;
        iOfst += nHdr;
        nFrame -= nHdr;
        iFrameOfst += nHdr;
      }
      if( nFrame>0 ){
        i64 pageStartOfst = iOfst - (iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ);
        int pageAlloc = enczEnsureBuffer(&p->walPlainBuf, &p->walPlainBufCap, P);
        u8 *aPage = p->walPlainBuf;
        if( pageAlloc<0 ) return SQLITE_NOMEM;
        if( pageAlloc>0 && p->statsEnabled ) enczGoRecordReadIO((unsigned long long)p->registryHandle, 0, 0, 0, 1, 0);
        
        u32 dbPgno = enczGetWalPgno(p, pageStartOfst);
        rc = enczDecryptAndReadPage(p, aPage, dbPgno, pageStartOfst);
        if( rc==SQLITE_OK ){
          int iPayloadOfst = iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ;
          memcpy(aOut, aPage + iPayloadOfst, (size_t)nFrame);
        }
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
  int P = p->walPageSize;
  if (P <= 0) {
    rc = enczWalEnsurePageSize(p);
    if (rc != SQLITE_OK) return rc;
    P = p->walPageSize;
  }
  
  while( iAmt>0 && rc==SQLITE_OK ){
    if( iOfst < ENCZ_WAL_HDR_SZ ){
      int n = (int)((ENCZ_WAL_HDR_SZ - iOfst) < iAmt ? (ENCZ_WAL_HDR_SZ - iOfst) : iAmt);
      if( p->registryHandle ) enczGoPageCacheClear((unsigned long long)p->registryHandle, 1);
      rc = p->pSubFile->pMethods->xWrite(p->pSubFile, aIn, n, iOfst);
      aIn += n;
      iAmt -= n;
      iOfst += n;
    }else{
      u32 iFrame;
      int iFrameOfst;
      rc = enczWalFrameInfo(p, iOfst, &iFrame, &iFrameOfst);
      if( rc!=SQLITE_OK ) break;
      int nFrame = (P + ENCZ_WAL_FRAME_HDR_SZ) - iFrameOfst;
      if( nFrame > iAmt ) nFrame = iAmt;
      
      if( iFrameOfst < ENCZ_WAL_FRAME_HDR_SZ ){
        int nHdr = ENCZ_WAL_FRAME_HDR_SZ - iFrameOfst;
        if( nHdr > nFrame ) nHdr = nFrame;
        rc = p->pSubFile->pMethods->xWrite(p->pSubFile, aIn, nHdr, iOfst);
        if( rc!=SQLITE_OK ) break;
        aIn += nHdr;
        iAmt -= nHdr;
        iOfst += nHdr;
        nFrame -= nHdr;
        iFrameOfst += nHdr;
      }
      if( nFrame>0 ){
        sqlite3_int64 walSize = 0;
        i64 pageStartOfst = iOfst - (iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ);
        int pageAlloc = enczEnsureBuffer(&p->walPlainBuf, &p->walPlainBufCap, P);
        u8 *aPage = p->walPlainBuf;
        if( pageAlloc<0 ) return SQLITE_NOMEM;
        if( pageAlloc>0 && p->statsEnabled ) enczGoRecordReadIO((unsigned long long)p->registryHandle, 0, 0, 0, 1, 0);
        
        int iPayloadOfst = iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ;
        u32 dbPgno = enczGetWalPgno(p, pageStartOfst);
        enczInitPlainPage(aPage, P, dbPgno);
        if( nFrame < P ){
          rc = p->pSubFile->pMethods->xFileSize(p->pSubFile, &walSize);
          if( rc!=SQLITE_OK ){
            break;
          }
          rc = enczDecryptAndReadPage(p, aPage, dbPgno, pageStartOfst);
          if( rc==SQLITE_IOERR_SHORT_READ ){
            if( walSize >= pageStartOfst + P ){
              break;
            }
            rc = SQLITE_OK;
          }else if( rc!=SQLITE_OK ){
            break;
          }
        }
        
        memcpy(aPage + iPayloadOfst, aIn, (size_t)nFrame);
        rc = enczEncryptAndWritePageAtOffset(p, aPage, dbPgno, pageStartOfst);
        if( rc!=SQLITE_OK ) break;
        aIn += nFrame;
        iAmt -= nFrame;
        iOfst += nFrame;
      }
    }
  }
  return rc;
}

static int enczClose(sqlite3_file *pFile){
  EnczFile *p = (EnczFile*)pFile;
  if( p->readBuf ){ memset(p->readBuf, 0, (size_t)p->readBufCap); sqlite3_free(p->readBuf); }
  if( p->sealedBuf ){ memset(p->sealedBuf, 0, (size_t)p->sealedBufCap); sqlite3_free(p->sealedBuf); }
  if( p->walPlainBuf ){ memset(p->walPlainBuf, 0, (size_t)p->walPlainBufCap); sqlite3_free(p->walPlainBuf); }
  memset(p->key, 0, sizeof(p->key));
  p->hasKey = 0;
  p->registryHandle = 0;
  if( p->pSubFile ){
    p->pSubFile->pMethods->xClose(p->pSubFile);
  }
  return SQLITE_OK;
}

static int enczRead(sqlite3_file *pFile, void *pBuf, int iAmt, sqlite3_int64 iOfst){
  EnczFile *p = (EnczFile*)pFile;
  if( p->isWal ){
    return enczWalReadRegion(p, pBuf, iAmt, iOfst);
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xRead(ORIGFILE(pFile), pBuf, iAmt, iOfst);
  }
  
  int rc = enczEnsureReady(p, 0);
  if( rc!=SQLITE_OK ) return rc;
  if( p->hasKey ) p->ioStarted = 1;
  
  int P = p->logicalPageSize;
  if( iAmt == P && (iOfst % P) == 0 ){
    return enczDecryptAndReadPage(p, pBuf, (u32)(iOfst / P) + 1, iOfst);
  }
  
  rc = ORIGFILE(pFile)->pMethods->xRead(ORIGFILE(pFile), pBuf, iAmt, iOfst);
  if( rc == SQLITE_IOERR_SHORT_READ && iOfst == 0 && iAmt == 100 ){
    u8 *aBuf = (u8*)pBuf;
    memset(aBuf, 0, iAmt);
    memcpy(aBuf, "SQLite format 3", 16);
    aBuf[16] = 0x10; // 4096 page size
    aBuf[17] = 0x00;
    aBuf[18] = 1;
    aBuf[19] = 1;
    aBuf[20] = ENCZ_RESERVED_SZ;   // 48 reserved bytes
    aBuf[21] = 64;
    aBuf[22] = 32;
    aBuf[23] = 32;
    aBuf[47] = 4;
    aBuf[59] = 1;
    return SQLITE_OK;
  }
  return rc;
}

static int enczWrite(sqlite3_file *pFile, const void *pBuf, int iAmt, sqlite3_int64 iOfst){
  EnczFile *p = (EnczFile*)pFile;
  if( p->isWal ){
    return enczWalWriteRegion(p, pBuf, iAmt, iOfst);
  }
  if( !p->isMainDb ){
    return ORIGFILE(pFile)->pMethods->xWrite(ORIGFILE(pFile), pBuf, iAmt, iOfst);
  }
  
  int rc = enczEnsureReady(p, iAmt);
  if( rc!=SQLITE_OK ) return rc;
  if( !p->hasKey && !p->registryHandle ) return SQLITE_AUTH;
  p->ioStarted = 1;
  
  int P = p->logicalPageSize;
  if( iOfst == 0 && enczIsValidPageSize(iAmt) ){
    p->logicalPageSize = iAmt;
    P = iAmt;
  }
  
  if( iAmt == P && (iOfst % P) == 0 ){
    rc = enczEncryptAndWritePageAtOffset(p, pBuf, (u32)(iOfst / P) + 1, iOfst);
  }else{
    if( p->registryHandle ) enczGoPageCacheClear((unsigned long long)p->registryHandle, 0);
    rc = ORIGFILE(pFile)->pMethods->xWrite(ORIGFILE(pFile), pBuf, iAmt, iOfst);
  }
  if( rc==SQLITE_OK ) p->allowBootstrapJournal = 0;
  return rc;
}

static int enczTruncate(sqlite3_file *pFile, sqlite3_int64 size){
  EnczFile *p = (EnczFile*)pFile;
  if( p->registryHandle ) enczGoPageCacheClear((unsigned long long)p->registryHandle, p->isWal);
  return ORIGFILE(pFile)->pMethods->xTruncate(ORIGFILE(pFile), size);
}

static int enczSync(sqlite3_file *pFile, int flags){
  return ORIGFILE(pFile)->pMethods->xSync(ORIGFILE(pFile), flags);
}

static int enczFileSize(sqlite3_file *pFile, sqlite3_int64 *pSize){
  return ORIGFILE(pFile)->pMethods->xFileSize(ORIGFILE(pFile), pSize);
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
  sqlite3_int64 nSize = 0;
  if( p->pSubFile && p->pSubFile->pMethods ){
    (void)p->pSubFile->pMethods->xFileSize(p->pSubFile, &nSize);
  }
  u32 pageCount = p->logicalPageSize > 0 ? (u32)(nSize / p->logicalPageSize) : 0;
  return sqlite3_mprintf(
    "cipher=%s,key=%s,pages=%u,page_size=%d,container=%d",
    p->cipher==ENCZ_CIPHER_AES_256_GCM ? "aes-256-gcm" : (p->cipher==ENCZ_CIPHER_CHACHA20_POLY1305 ? "chacha20-poly1305" : "xchacha20-poly1305"),
    (p->hasKey || p->registryHandle) ? "set" : "unset",
    pageCount,
    p->logicalPageSize,
    0
  );
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
  if( sqlite3_stricmp(zName, "crypto_key")==0 ||
      sqlite3_stricmp(zName, "crypto_key_hex")==0 ||
      sqlite3_stricmp(zName, "crypto_key_env")==0 ){
    (void)zValue;
    azArg[0] = sqlite3_mprintf("SQLiteSeal direct-key pragmas are disabled");
    rc = SQLITE_ERROR;
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
  if( p->isMainDb || p->isWal ){
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
  z = sqlite3_uri_parameter(zName, "encz_registry");
  if( z ){
    p->registryHandle = (sqlite3_uint64)strtoull(z, 0, 10);
    if( p->registryHandle ) p->hasKey = 1;
    if( p->registryHandle ) p->statsEnabled = enczGoReadStatsEnabled((unsigned long long)p->registryHandle);
  }
  z = sqlite3_uri_parameter(zName, "encz_cipher");
  if( z ){
    unsigned long cipher = strtoul(z, 0, 10);
    if( cipher>=ENCZ_CIPHER_AES_256_GCM && cipher<=ENCZ_CIPHER_XCHACHA20_POLY1305 ) p->cipher = (int)cipher;
  }
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
  p->cipher = ENCZ_CIPHER_AES_256_GCM;
  p->isMainDb = (flags & SQLITE_OPEN_MAIN_DB)!=0;
  p->isWal = (flags & SQLITE_OPEN_WAL)!=0;
  p->isReadonly = (flags & SQLITE_OPEN_READONLY)!=0;

  /*
  ** Rollback journals and disk-backed temporary databases contain plaintext
  ** page images. SQLiteSeal supports encrypted WAL and in-memory journals only.
  ** Refuse any fallback that could persist plaintext through this VFS.
  */
  if( flags & SQLITE_OPEN_MAIN_JOURNAL ){
    sqlite3_file *pDb = zName ? sqlite3_database_file_object(zName) : 0;
    if( pDb==0 || !((EnczFile*)pDb)->allowBootstrapJournal ){
      return SQLITE_CANTOPEN;
    }
    return pSubVfs->xOpen(pSubVfs, zName, pFile, flags, pOutFlags);
  }
  if( flags & (SQLITE_OPEN_TEMP_JOURNAL |
               SQLITE_OPEN_SUBJOURNAL |
               SQLITE_OPEN_TEMP_DB |
               SQLITE_OPEN_TRANSIENT_DB) ){
    return SQLITE_CANTOPEN;
  }
  if( p->isMainDb || p->isWal ){
    if( p->isMainDb ){
      enczApplyUriConfig(p, zName);
    }
    if( p->isWal && zName ){
      sqlite3_file *pDb = sqlite3_database_file_object(zName);
      if( pDb ){
        EnczFile *pDbFile = (EnczFile*)pDb;
        p->pMainDb = pDbFile;
        p->cipher = pDbFile->cipher;
        p->logicalPageSize = pDbFile->logicalPageSize;
        p->walPageSize = pDbFile->logicalPageSize;
        p->hasKey = pDbFile->hasKey;
        p->registryHandle = pDbFile->registryHandle;
        p->statsEnabled = pDbFile->statsEnabled;
        memcpy(p->key, pDbFile->key, sizeof(p->key));
      }
    }
    pFile->pMethods = &encz_io_methods;
    rc = pSubVfs->xOpen(pSubVfs, zName, pSubFile, flags, pOutFlags);
    if( rc!=SQLITE_OK ){
      pFile->pMethods = 0;
      return rc;
    }
    if( p->isMainDb && !p->isReadonly ){
      sqlite3_int64 nSize = 0;
      if( pSubFile->pMethods->xFileSize(pSubFile, &nSize)==SQLITE_OK && nSize==0 ){
        p->allowBootstrapJournal = 1;
      }
    }
    return SQLITE_OK;
  }
  return pSubVfs->xOpen(pSubVfs, zName, pFile, flags, pOutFlags);
}

static int enczDelete(sqlite3_vfs *pVfs, const char *zPath, int dirSync){
  return ORIGVFS(pVfs)->xDelete(ORIGVFS(pVfs), zPath, dirSync);
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
  rc = enczRegister();
  if( rc==SQLITE_OK ) rc = SQLITE_OK_LOAD_PERMANENTLY;
  return rc;
}
