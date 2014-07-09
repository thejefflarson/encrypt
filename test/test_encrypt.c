#include "tap.h"
#include "encrypt.h"
#include <sys/stat.h>
#include <fcntl.h>

int
main(){
  int err = encrypt("encrypt.in", "encrypt.out");
  ok(err == 0, "encrypted the file");
  err = decrypt("encrypt.out", "decrypt.out");
  ok(err == 0, "decrypted the file");
  struct stat st;
  // test that everything works out.

  ok(ret, "files are identical");
  return 0;
}