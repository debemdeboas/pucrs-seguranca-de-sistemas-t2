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

RSAPublicKey *RSAPKey_load_from_file(char const *filename);

RSAKeyPair *RSAKP_load_from_file(char const *filename);
RSAKeyPair *RSAKP_generate(void);
void RSAKP_to_file(RSAKeyPair const *kp, char const *filename);
void RSAKP_free(RSAKeyPair *kp);

#endif