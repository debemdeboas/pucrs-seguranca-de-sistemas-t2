#ifndef UTIL_H
#define UTIL_H

#include "bn.h"
#include "cipher.h"
#include "rsa.h"
#include "types.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"
#define SIG_FILE "sig.txt"

unsigned char *invert_array(unsigned char const *const arr, size_t const len);
void write_string_to_file(char const *const filename, char const *const str);

bool RSA_verify_signature(MessageStream const *ms, RSAPublicKey const *bob_pk, BN_CTX *bn_ctx);
void RSA_sign_message(MessageStream *ms, RSAKeyPair const *alice_kp, BN_CTX *bn_ctx);

MessageStream *encrypt_and_sign(unsigned char const *const message, int const message_len);
unsigned char *decrypt_file(char const *const filename, int *message_len);

#endif