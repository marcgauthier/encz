/*
** 2026-06-06
**
** Custom SQLite VFS that encrypts and decrypts flat database file pages
** in-place using AES-256-GCM, utilizing SQLite's reserved bytes.
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

typedef sqlite3_int64 i64;
typedef unsigned char u8;
typedef unsigned int u32;

#define ENCZ_VFS_NAME              "encz"
#define ENCZ_CIPHER_AES_256_GCM    1

#define ENCZ_WAL_HDR_SZ            32
#define ENCZ_WAL_FRAME_HDR_SZ      24

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
  int hasReservedBytes;
  EnczFile *pMainDb;
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

static int enczInitNewDatabase(EnczFile *p) {
  int P = 4096;
  u8 *aPlain = sqlite3_malloc64(P);
  if( aPlain==0 ) return SQLITE_NOMEM;
  memset(aPlain, 0, P);
  memcpy(aPlain, "SQLite format 3", 16);
  aPlain[16] = 0x10; // Page size: 4096 (high byte)
  aPlain[17] = 0x00; // Page size: 4096 (low byte)
  aPlain[18] = 1;    // File format write version
  aPlain[19] = 1;    // File format read version
  aPlain[20] = 32;   // Reserved bytes
  aPlain[21] = 64;   // Max embedded payload
  aPlain[22] = 32;   // Min embedded payload
  aPlain[23] = 32;   // Leaf payload fraction
  aPlain[47] = 4;    // Schema format
  aPlain[59] = 1;    // Text encoding UTF-8
  aPlain[100] = 0x0d; // leaf table b-tree page
  aPlain[105] = (u8)(((P - 32) >> 8) & 0xff);
  aPlain[106] = (u8)((P - 32) & 0xff);
  
  p->logicalPageSize = P;
  p->hasReservedBytes = 32;
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
    p->hasReservedBytes = 32;
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
      p->hasReservedBytes = 32;
    }
    p->initialized = 1;
  }
  return SQLITE_OK;
}

static int enczDecryptAndReadPage(EnczFile *p, u8 *aPlain, u32 pgno, i64 iOfst) {
  int P = p->isWal ? p->walPageSize : p->logicalPageSize;
  int rc = SQLITE_OK;
  
  fprintf(stderr, "[encz] READ pgno=%u, iOfst=%lld, P=%d\n", pgno, (long long)iOfst, P);
  
  u8 *aBuf = sqlite3_malloc64(P);
  if( aBuf==0 ) return SQLITE_NOMEM;
  
  rc = p->pSubFile->pMethods->xRead(p->pSubFile, aBuf, P, iOfst);
  if( rc!=SQLITE_OK ){
    if( pgno == 1 && (rc == SQLITE_IOERR_SHORT_READ || rc == SQLITE_OK) ){
      memset(aPlain, 0, P);
      memcpy(aPlain, "SQLite format 3", 16);
      aPlain[16] = (u8)((P >> 8) & 0xff);
      aPlain[17] = (u8)(P & 0xff);
      aPlain[18] = 1;
      aPlain[19] = 1;
      aPlain[20] = 32;
      aPlain[21] = 64;
      aPlain[22] = 32;
      aPlain[23] = 32;
      aPlain[47] = 4;
      aPlain[59] = 1;
      aPlain[100] = 0x0d;
      aPlain[105] = (u8)(((P - 32) >> 8) & 0xff);
      aPlain[106] = (u8)((P - 32) & 0xff);
      sqlite3_free(aBuf);
      return SQLITE_OK;
    }
    fprintf(stderr, "[encz] READ xRead failed, rc=%d\n", rc);
    sqlite3_free(aBuf);
    return rc;
  }
  
  int H = (pgno == 1) ? 100 : 0;
  int nPlain = P - H - 32;
  
  if( !p->hasKey ){
    fprintf(stderr, "[encz] READ no key, returning stub for pgno=%u\n", pgno);
    if( pgno == 1 ){
      memset(aPlain, 0, P);
      memcpy(aPlain, "SQLite format 3", 16);
      aPlain[16] = (u8)((P >> 8) & 0xff);
      aPlain[17] = (u8)(P & 0xff);
      aPlain[18] = 1;
      aPlain[19] = 1;
      aPlain[20] = 32;
      aPlain[21] = 64;
      aPlain[22] = 32;
      aPlain[23] = 32;
      aPlain[47] = 4;
      aPlain[59] = 1;
      aPlain[100] = 0x0d;
      aPlain[105] = (u8)(((P - 32) >> 8) & 0xff);
      aPlain[106] = (u8)((P - 32) & 0xff);
    } else {
      memset(aPlain, 0, P);
    }
    sqlite3_free(aBuf);
    return SQLITE_OK;
  }
  
  u32 flags = enczGet32(aBuf + P - 32);
  u8 aNonce[12];
  u8 aTag[16];
  memcpy(aNonce, aBuf + P - 28, 12);
  memcpy(aTag, aBuf + P - 16, 16);
  
  u32 nCipher = flags & 0x00ffffff;
  
  fprintf(stderr, "[encz] READ parsing flags=%08x, nCipher=%u\n", flags, nCipher);
  
  if( nCipher > (u32)nPlain ){
    fprintf(stderr, "[encz] READ nCipher (%u) > nPlain (%d), corrupt!\n", nCipher, nPlain);
    sqlite3_free(aBuf);
    return SQLITE_CORRUPT;
  }
  
  u8 *aTmp = sqlite3_malloc64(nCipher + 64);
  if( aTmp==0 ){
    sqlite3_free(aBuf);
    return SQLITE_NOMEM;
  }
  
  EVP_CIPHER_CTX *pCtx = EVP_CIPHER_CTX_new();
  if( pCtx==0 ){
    sqlite3_free(aBuf);
    sqlite3_free(aTmp);
    return SQLITE_NOMEM;
  }
  
  int nOut = 0, nDec = 0;
  if( EVP_DecryptInit_ex(pCtx, EVP_aes_256_gcm(), 0, 0, 0)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, 12, 0)!=1
   || EVP_DecryptInit_ex(pCtx, 0, 0, p->key, aNonce)!=1
   || EVP_DecryptUpdate(pCtx, aTmp, &nOut, aBuf + H, nCipher)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_TAG, 16, aTag)!=1
  ){
    fprintf(stderr, "[encz] READ EVP init/update/ctrl failed\n");
    rc = SQLITE_ERROR;
  } else {
    if( EVP_DecryptFinal_ex(pCtx, aTmp + nOut, &nDec)!=1 ){
      fprintf(stderr, "[encz] READ DecryptFinal (MAC check failed) for pgno=%u\n", pgno);
      rc = SQLITE_CORRUPT;
    } else {
      nDec += nOut;
      memset(aPlain, 0, P);
      if( pgno == 1 ){
        memcpy(aPlain, aBuf, 100);
      }
      
      if( nDec != nPlain ){
        rc = SQLITE_CORRUPT;
      } else {
        memcpy(aPlain + H, aTmp, nPlain);
      }
    }
  }
  
  EVP_CIPHER_CTX_free(pCtx);
  sqlite3_free(aBuf);
  sqlite3_free(aTmp);
  return rc;
}

static int enczEncryptAndWritePageAtOffset(EnczFile *p, const u8 *aPlain, u32 pgno, i64 iOfst) {
  int P = p->isWal ? p->walPageSize : p->logicalPageSize;
  int rc = SQLITE_OK;
  int H = (pgno == 1) ? 100 : 0;
  int nPlain = P - H - 32;
  
  u8 *aBuf = sqlite3_malloc64(P);
  if( aBuf==0 ) return SQLITE_NOMEM;
  memcpy(aBuf, aPlain, P);
  
  if (pgno == 1) {
    aBuf[20] = 32; // Ensure reserved bytes is set to 32
  }
  
  u8 *aCipher = sqlite3_malloc64(nPlain + 32);
  u32 flags = (u32)nPlain;
  if( aCipher==0 ){
    sqlite3_free(aBuf);
    return SQLITE_NOMEM;
  }
  
  u8 aNonce[12];
  u8 aTag[16];
  if( RAND_bytes(aNonce, 12) != 1 ){
    sqlite3_free(aBuf);
    sqlite3_free(aCipher);
    return SQLITE_ERROR;
  }
  
  EVP_CIPHER_CTX *pCtx = EVP_CIPHER_CTX_new();
  if( pCtx==0 ){
    sqlite3_free(aBuf);
    sqlite3_free(aCipher);
    return SQLITE_NOMEM;
  }
  
  int nOut = 0, nCipher = 0;
  if( EVP_EncryptInit_ex(pCtx, EVP_aes_256_gcm(), 0, 0, 0)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, 12, 0)!=1
   || EVP_EncryptInit_ex(pCtx, 0, 0, p->key, aNonce)!=1
   || EVP_EncryptUpdate(pCtx, aCipher, &nOut, aPlain + H, nPlain)!=1
   || EVP_EncryptFinal_ex(pCtx, aCipher + nOut, &nCipher)!=1
   || EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_GET_TAG, 16, aTag)!=1
  ){
    fprintf(stderr, "[encz] WRITE EVP init/update/ctrl/tag failed for pgno=%u\n", pgno);
    rc = SQLITE_ERROR;
  } else {
    nCipher += nOut;
    memcpy(aBuf + H, aCipher, nCipher);
    memset(aBuf + H + nCipher, 0, P - 32 - H - nCipher);
    enczPut32(aBuf + P - 32, flags);
    memcpy(aBuf + P - 28, aNonce, 12);
    memcpy(aBuf + P - 16, aTag, 16);
    
    fprintf(stderr, "[encz] WRITE pgno=%u, iOfst=%lld, nCipher=%d, flags=%08x\n", pgno, (long long)iOfst, nCipher, flags);
    rc = p->pSubFile->pMethods->xWrite(p->pSubFile, aBuf, P, iOfst);
    if( rc!=SQLITE_OK ){
      fprintf(stderr, "[encz] WRITE xWrite failed, rc=%d\n", rc);
    }
  }
  
  EVP_CIPHER_CTX_free(pCtx);
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
        u8 *aPage = sqlite3_malloc64(P);
        if( aPage==0 ) return SQLITE_NOMEM;
        
        u32 dbPgno = enczGetWalPgno(p, pageStartOfst);
        rc = enczDecryptAndReadPage(p, aPage, dbPgno, pageStartOfst);
        if( rc==SQLITE_OK ){
          int iPayloadOfst = iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ;
          memcpy(aOut, aPage + iPayloadOfst, (size_t)nFrame);
        }
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
  int P = p->walPageSize;
  if (P <= 0) {
    rc = enczWalEnsurePageSize(p);
    if (rc != SQLITE_OK) return rc;
    P = p->walPageSize;
  }
  
  while( iAmt>0 && rc==SQLITE_OK ){
    if( iOfst < ENCZ_WAL_HDR_SZ ){
      int n = (int)((ENCZ_WAL_HDR_SZ - iOfst) < iAmt ? (ENCZ_WAL_HDR_SZ - iOfst) : iAmt);
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
        i64 pageStartOfst = iOfst - (iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ);
        u8 *aPage = sqlite3_malloc64(P);
        if( aPage==0 ) return SQLITE_NOMEM;
        
        int iPayloadOfst = iFrameOfst - ENCZ_WAL_FRAME_HDR_SZ;
        u32 dbPgno = enczGetWalPgno(p, pageStartOfst);
        if( nFrame < P ){
          rc = enczDecryptAndReadPage(p, aPage, dbPgno, pageStartOfst);
          if( rc!=SQLITE_OK && rc!=SQLITE_IOERR_SHORT_READ ){
            sqlite3_free(aPage);
            break;
          }
          rc = SQLITE_OK;
        }
        
        memcpy(aPage + iPayloadOfst, aIn, (size_t)nFrame);
        rc = enczEncryptAndWritePageAtOffset(p, aPage, dbPgno, pageStartOfst);
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

static int enczClose(sqlite3_file *pFile){
  EnczFile *p = (EnczFile*)pFile;
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
    aBuf[20] = 32;   // 32 reserved bytes
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
  if( !p->hasKey ) return SQLITE_AUTH;
  p->ioStarted = 1;
  
  int P = p->logicalPageSize;
  if( iOfst == 0 && enczIsValidPageSize(iAmt) ){
    p->logicalPageSize = iAmt;
    P = iAmt;
  }
  
  if( iAmt == P && (iOfst % P) == 0 ){
    return enczEncryptAndWritePageAtOffset(p, pBuf, (u32)(iOfst / P) + 1, iOfst);
  }
  
  return ORIGFILE(pFile)->pMethods->xWrite(ORIGFILE(pFile), pBuf, iAmt, iOfst);
}

static int enczTruncate(sqlite3_file *pFile, sqlite3_int64 size){
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
    p->cipher==ENCZ_CIPHER_AES_256_GCM ? "aes-256-gcm" : "unknown",
    p->hasKey ? "set" : "unset",
    pageCount,
    p->logicalPageSize,
    0
  );
}

static int enczConfigLocked(EnczFile *p){
  if( !p->ioStarted ) return 0;
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
        memcpy(p->key, pDbFile->key, sizeof(p->key));
      }
    }
    pFile->pMethods = &encz_io_methods;
    rc = pSubVfs->xOpen(pSubVfs, zName, pSubFile, flags, pOutFlags);
    if( rc!=SQLITE_OK ){
      pFile->pMethods = 0;
      return rc;
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
  OpenSSL_add_all_algorithms();
  rc = enczRegister();
  if( rc==SQLITE_OK ) rc = SQLITE_OK_LOAD_PERMANENTLY;
  return rc;
}
