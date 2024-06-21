#ifndef VERIFY_H
#define VERIFY_H

#include "bn.h"
#include "rsa.h"
#include "types.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EVP_CIPHER_CHOICE "AES-128-CBC"
#define DIGEST_ALGORITHM "sha256"

MessageStream *MS_load_from_file(char const *filename);
void MS_save_to_file(MessageStream const *ms, char const *filename);
void MS_calc_digest(unsigned char **res, unsigned int *len, MessageStream const *ms, char const *digest);
void MS_destroy(MessageStream *ms);

unsigned char *CIPHER_load_key_from_file(const char *filename);
unsigned char *CIPHER_decrypt_message(MessageStream const *msg, unsigned char const *aes_key_s, int *cipher_final_len);
void CIPHER_encrypt_message(MessageStream *msg, unsigned char const *aes_key_s, unsigned char const *plaintext,
                            int plaintext_len);

#endif