#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "tweetnacl.h"

void
brainkey(unsigned char pk[crypto_box_PUBLICKEYBYTES],
         unsigned char sk[crypto_box_SECRETKEYBYTES],
         const char *key, const int klen);

int
encryptf(const char *ppath, const char *spath,
         const unsigned char pk[crypto_box_PUBLICKEYBYTES],
         const unsigned char sk[crypto_box_SECRETKEYBYTES]);

int
decryptf(const char *spath, const char *ppath,
         const unsigned char pk[crypto_box_PUBLICKEYBYTES],
         const unsigned char sk[crypto_box_SECRETKEYBYTES]);

#endif
