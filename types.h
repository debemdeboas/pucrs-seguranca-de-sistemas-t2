#ifndef TYPES_H
#define TYPES_H

#include <openssl/bn.h>
#include <stdlib.h>

typedef struct RSASecretKey {
    BIGNUM *d;
    BIGNUM *n;
} RSASecretKey;

typedef struct RSAPublicKey {
    BIGNUM *e;
    BIGNUM *n;
} RSAPublicKey;

typedef struct RSAKeyPair {
    RSASecretKey *sk;
    RSAPublicKey *pk;
} RSAKeyPair;

typedef struct MessageStream {
    BIGNUM *sig;

    unsigned char iv[16];
    size_t c_len;
    unsigned char *c;
} MessageStream;

#endif