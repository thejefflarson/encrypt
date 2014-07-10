#include "tap.h"
#include "encrypt.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int
main(){
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  memset(pk, 0, crypto_box_PUBLICKEYBYTES);
  memset(sk, 0, crypto_box_SECRETKEYBYTES);

  char *t = "estllo";
  brainkey(pk, sk, t, 5);

  for(int i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
    printf("%0x", (unsigned int)pk[i]);
  puts("");

  for(int i = 0; i < crypto_box_SECRETKEYBYTES; i++)
    printf("%0x", (unsigned int)sk[i]);
  puts("");


  int err = encryptf("test/encrypt.in", "test/encrypt.out", pk, sk);
  if(err != 0) printf("%s\n", strerror(errno));
  ok(err == 0, "encrypted the file");
  err = decryptf("test/encrypt.out", "test/decrypt.out", pk, sk);
  if(err != 0) printf("%s\n", strerror(errno));
  ok(err == 0, "decrypted the file");



  return 0;
}