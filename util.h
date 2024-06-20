#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LINE_MAX
#define LINE_MAX 2048
#endif

#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"
#define SIG_FILE "sig.txt"

BIGNUM *BN_from_file(FILE *file);
BIGNUM *BN_one_from_file(char const *filename);
void BN_to_file(BIGNUM const *bn, FILE *file);

unsigned char *invert_array(unsigned char const *const arr, size_t const len);
void write_string_to_file(char const *const filename, char const *const str);

#endif