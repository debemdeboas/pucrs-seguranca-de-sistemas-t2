#ifndef RSA_H
#define RSA_H

#include "bn.h"
#include "types.h"
#include <limits.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_BITS 1024

/// @brief Load a public key from a file in the format `e + \\n + N`
/// @param filename File to load the key from
/// @return Public key struct (must be freed with `RSAPKey_free`)
RSAPublicKey *RSAPKey_load_from_file(char const *filename);

/// @brief Destroy a public key
/// @param pk Public key to destroy
void RSAPKey_free(RSAPublicKey *pk);

/// @brief Load a key pair from a file in the format `d + \\n + N + \\n + e + \\n + N`
/// @param filename File to load the key pair from
/// @return Key pair struct (must be freed with `RSAKP_free`)
RSAKeyPair *RSAKP_load_from_file(char const *filename);

/// @brief Generate a key pair from two random primes using OpenSSL
/// @return Key pair struct (must be freed with `RSAKP_free`)
RSAKeyPair *RSAKP_generate(void);

/// @brief Save a key pair to file in the format `d + \\n + N + \\n + e + \\n + N`
/// @param kp Key pair to save
/// @param filename File to save the key pair to
void RSAKP_to_file(RSAKeyPair const *kp, char const *filename);

/// @brief Destroy a key pair
/// @param kp Key pair to destroy
void RSAKP_free(RSAKeyPair *kp);

#endif