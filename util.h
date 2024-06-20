#ifndef UTIL_H
#define UTIL_H

#include "verify.h"
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"
#define SIG_FILE "sig.txt"

BIGNUM *BN_from_file(FILE *file);
BIGNUM *BN_one_from_file(char const *filename);
void BN_to_file(BIGNUM const *bn, FILE *file);

unsigned char *invert_array(unsigned char const *const arr, size_t const len);

MessageStream *encrypt_and_sign(unsigned char const *const message, int const message_len);
unsigned char *decrypt_file(char const *const filename, int *message_len);

#endif