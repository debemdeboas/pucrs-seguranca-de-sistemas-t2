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

/// @brief Load a BIGNUM from a file line by line in hex format (e.g. "ABC1234")
/// @param file File to read from
/// @return BIGNUM pointer (must be freed by the caller)
BIGNUM *BN_from_file(FILE *file);

/// @brief Open a file and load a BIGNUM from it
/// @param filename File to open
/// @return BIGNUM pointer (must be freed by the caller)
BIGNUM *BN_one_from_file(char const *filename);

/// @brief Save a BIGNUM to a file in hex format
/// @param bn BIGNUM to save
/// @param file File to write to
void BN_to_file(BIGNUM const *bn, FILE *file);

#endif