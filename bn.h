#ifndef BN_H
#define BN_H

#include "util.h"
#include <limits.h>
#include <openssl/bn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LINE_MAX
#define LINE_MAX 2048
#endif

BIGNUM *BN_from_file(FILE *file);
BIGNUM *BN_one_from_file(char const *filename);
void BN_to_file(BIGNUM const *bn, FILE *file);

#endif