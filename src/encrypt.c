#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>

#include "randombytes.h"
#include "tweetnacl.h"
#include "encrypt.h"

static const int padding = crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES;

static int
map_pair(const char *ppath, char const *spath,
         unsigned char **text,
         unsigned char **create,
         size_t *size,
         int tweak) {
  struct stat st;
  int pid, sid, err;
  size_t csize;
  err = stat(ppath, &st);
  if(err != 0) return err;
  if(!S_ISREG(st.st_mode)) return 1;
  *size = st.st_size;

  pid = open(ppath, O_RDONLY);
  *text = (unsigned char *) mmap(NULL, *size, PROT_READ, MAP_SHARED, pid, 0);
  if(*text == MAP_FAILED) err = 1;

  csize = *size + tweak;
  sid = open(spath, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR);
  err = ftruncate(sid, csize);
  *create = (unsigned char *) mmap(NULL, csize, PROT_READ | PROT_WRITE, MAP_SHARED, sid, 0);
  if(*create == MAP_FAILED) err = 1;

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

void
brainkey(unsigned char pk[crypto_box_PUBLICKEYBYTES],
         unsigned char sk[crypto_box_SECRETKEYBYTES],
         const char *key, const int klen){
  unsigned char h[crypto_hash_BYTES];
  crypto_hash(h, (unsigned char *) key, klen);

  // stretch the key a bit, we could go further, but this might just be a
  // cargocult anyhow
  for(int i = 0; i < 50000; i++)
    crypto_hash(h, h, crypto_hash_BYTES);

  memcpy(sk, h, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(pk, sk);
  memset(h, 0, crypto_hash_BYTES);
}

int
encryptf(const char *ppath, const char *spath,
        const unsigned char pk[crypto_box_PUBLICKEYBYTES],
        const unsigned char sk[crypto_box_SECRETKEYBYTES]){
  unsigned char *secret = NULL;
  unsigned char *plain  = NULL;
  unsigned char n[crypto_box_NONCEBYTES];
  unsigned char k[crypto_box_BEFORENMBYTES];
  size_t size;

  int err = map_pair(ppath, spath, &plain, &secret, &size, padding);
  if(err != 0) return err;

  randombytes(n, crypto_box_NONCEBYTES);
  crypto_box_beforenm(k, pk, sk);
  crypto_stream_xor(secret + padding, plain, size, n, k);
  memcpy(secret, n, crypto_secretbox_NONCEBYTES);
  crypto_onetimeauth(secret + crypto_secretbox_NONCEBYTES, secret + padding, size, k);
  memset(k, 0, crypto_box_BEFORENMBYTES);
  close_pair(plain, secret, size, padding);

  return 0;
}

int
decryptf(const char *spath, const char *ppath,
         const unsigned char pk[crypto_box_PUBLICKEYBYTES],
         const unsigned char sk[crypto_box_SECRETKEYBYTES]) {
  unsigned char *secret = NULL;
  unsigned char *plain  = NULL;
  unsigned char k[crypto_box_BEFORENMBYTES];
  size_t size;

  int err = map_pair(spath, ppath, &secret, &plain, &size, -1 * padding);
  if(err != 0) return err;

  crypto_box_beforenm(k, pk, sk);
  err = crypto_onetimeauth_verify(secret + crypto_secretbox_NONCEBYTES, secret + padding, size - padding, k);
  if(err == 0) {
    unsigned char n[crypto_box_NONCEBYTES];
    memcpy(n, secret, crypto_secretbox_NONCEBYTES);
    crypto_stream_xor(plain, secret + padding, size - padding, n ,k);
  }

  memset(k, 0, crypto_box_BEFORENMBYTES);
  close_pair(secret, plain, size, -1 * padding);
  return err;
}
