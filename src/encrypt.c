#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>

#include "randombytes.h"
#include "tweetnacl.h"

static int
map_pair(char *ppath, char *spath,
         unsigned char *text,
         unsigned char *create,
         size_t *size,
         int tweak) {
  struct stat st;
  int pid, sid, err;
  size_t csize;
  err = stat(ppath, &st);
  if(err != 0) return err;
  if(S_ISREG(st.st_mode)) return 1;
  *size = st.st_size;

  pid = open(ppath, O_RDONLY);
  text = (unsigned char *) mmap(NULL, *size, PROT_READ, MAP_ANON | MAP_SHARED, pid, 0);
  if(text == MAP_FAILED) err = 1;

  csize = *size + tweak;
  sid = open(spath, O_WRONLY | O_CREAT);
  err = ftruncate(sid, csize);
  create = (unsigned char *) mmap(NULL, csize, PROT_WRITE, MAP_ANON | MAP_SHARED, sid, 0);
  if(creat == MAP_FAILED) err = 1;

  close(sid);
  close(pid);
  if(err) munmap(text, *size);
  return err;
}

static void
close_pair(unsigned char *text, unsigned char *create, size_t size, int tweak){
  munmap(text,   size);
  munmap(create, size + tweak);
}

int
encrypt(char *ppath, char *spath,
        unsigned char pk[crypto_box_PUBLICKEYBYTES],
        unsigned char sk[crypto_box_SECRETKEYBYTES]){
  unsigned char *secret = NULL;
  unsigned char *plain  = NULL;
  unsigned char n[crypto_box_NONCEBYTES];
  unsigned char k[crypto_box_BEFORENMBYTES];
  int tweak = crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES;
  size_t size;

  int err = map_pair(ppath, spath, plain, secret, &size, tweak);
  if(err != 0) return err;

  randombytes(n, crypto_box_NONCEBYTES);
  randombytes(n, crypto_box_NONCEBYTES);
  crypto_box_beforenm(k, pk, sk);
  crypto_stream_xor(secret + tweak, plain, size, n, k);
  memcpy(secret + crypto_secretbox_NONCEBYTES, n, crypto_secretbox_NONCEBYTES);
  crypto_onetimeauth(secret, secret + tweak, size, k);

  close_pair(plain, secret, size, tweak);
  return 0;
}

int
decrypt(char *spath, char *ppath,
        unsigned char pk[crypto_box_PUBLICKEYBYTES],
        unsigned char sk[crypto_box_SECRETKEYBYTES]) {
  return 0;
}