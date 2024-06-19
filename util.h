#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

BIGNUM *BN_from_file(FILE *file);
BIGNUM *BN_one_from_file(char const *filename);
void BN_to_file(BIGNUM const *bn, FILE *file);

unsigned char *invert_array(unsigned char const *const arr, size_t const len);

#endif