#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "tweetnacl.h"

int
encrypt(const char *ppath, const char *spath,
        const unsigned char pk[crypto_box_PUBLICKEYBYTES],
        const unsigned char sk[crypto_box_SECRETKEYBYTES]);

int
decrypt(const char *spath, const char *ppath,
        const unsigned char pk[crypto_box_PUBLICKEYBYTES],
        const unsigned char sk[crypto_box_SECRETKEYBYTES]);

#endif