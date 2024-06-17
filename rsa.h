#ifndef RSA_H
#define RSA_H

#include <openssl/bn.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_BITS 1024

typedef struct SecretKey {
    BIGNUM * d;
    BIGNUM * n;
} SecretKey;

typedef struct RSAPublicKey {
    BIGNUM * e;
    BIGNUM * n;
} RSAPublicKey;

typedef struct RSAKeyPair {
    SecretKey * sk;
    RSAPublicKey * pk;
} RSAKeyPair;

BIGNUM * bignum_from_file(FILE * file);
void bignum_to_file(BIGNUM const * bn, FILE * file);

RSAPublicKey * pk_load_from_file(char const * filename);

RSAKeyPair * keypair_load_from_file(char const * filename);
RSAKeyPair * keypair_generate(void);
void keypair_save_to_file(RSAKeyPair const * kp, char const * filename);
void keypair_free(RSAKeyPair * kp);

#endif