#ifndef TYPES_H
#define TYPES_H

#include <openssl/bn.h>
#include <stdlib.h>

/// @brief Secret key `sk=(d, N)`
typedef struct RSASecretKey {
    BIGNUM *d;
    BIGNUM *n;
} RSASecretKey;

/// @brief Public key `pk=(e, N)`
typedef struct RSAPublicKey {
    BIGNUM *e;
    BIGNUM *n;
} RSAPublicKey;

/// @brief Key pair `(sk, pk)`
typedef struct RSAKeyPair {
    RSASecretKey *sk;
    RSAPublicKey *pk;
} RSAKeyPair;

/// @brief Signed message `sig + \\n + iv + c`
typedef struct MessageStream {
    BIGNUM *sig;

    unsigned char iv[16];
    size_t c_len;
    unsigned char *c;
} MessageStream;

#endif