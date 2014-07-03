#include <sys/mman.h>
#include <sys/stat.h>

#include "randombytes.h"
#include "tweetnacl.h"


int
encrypt(char *ppath, char *spath, char key[32]){
  struct stat st;
  int err = stat(ppath, &st);
  if(err != 0) return err;
  if(S_ISREG(st->st_mode)) return EINVAL;
  size_t size = st->st_size;

  int pid = open(ppath, O_RDONLY);
  void *plain = mmap(NULL, size, PROT_READ, MAP_SHARED, pid, 0);
  if(plain == MAP_FAILED) return 1;

  size_t csize = size + crypto_secretbox_NONCEBYTES + crypto_secretbox_BOXZEROBYTES;
  int sid = open(spath, O_WRONLY | O_CREAT);
  err = ftruncate(sid, csize);
  if(err != 0) {
    munmap(plain, size);
    return err;
  }

  void *secret = mmap(NULL, csize, MAP_SHARED, sid, 0);
  if(secret == MAP_FAILED) {
    munmap(plain, size);
    return 1;
  }



  return 0;
}

int
decrypt(char *spath, char *ppath) {

}