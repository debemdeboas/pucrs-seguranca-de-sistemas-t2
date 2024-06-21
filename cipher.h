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

/// @brief Load a message stream from a file in the format:
/// Signature (hex encoded) + \\n + IV (16 bytes) + message (hex encoded)
/// @param filename File to read from
/// @return MessageStream pointer (must be freed by the caller)
MessageStream *MS_load_from_file(char const *filename);

/// @brief Save a message stream to a file in the format:
/// Signature (hex encoded) + \\n + IV (16 bytes) + message (hex encoded)
/// @param ms MessageStream to save
/// @param filename File to write to
void MS_save_to_file(MessageStream const *ms, char const *filename);

/// @brief Calculate the digest of a message stream and store it in `res`
/// @param res Output buffer for the digest
/// @param len Length of the digest
/// @param ms MessageStream to calculate the digest of
/// @param digest Digest algorithm to use (e.g. "AES-128-CBC")
void MS_calc_digest(unsigned char **res, unsigned int *len, MessageStream const *ms, char const *digest);

/// @brief Free a MessageStream
/// @param ms MessageStream to free
void MS_destroy(MessageStream *ms);

/// @brief Load a cipher key from a file in hex format (e.g. "ABC1234")
/// @note The key is shifted by one byte if the first byte is >= 0x9 and pad it with 0x00. This is only needed because
/// we know the other side (Bob) uses Java.
/// @param filename File to read from
/// @return Cipher key (must be freed by the caller)
unsigned char *CIPHER_load_key_from_file(const char *filename);

/// @brief Decrypt a message stream using CIPHER and return the decrypted buffer
/// @param ms MessageStream to decrypt
/// @param cipher_key_s Cipher key to use
/// @param decrypted_len Length of the decrypted message
/// @return Decrypted message buffer (must be freed by the caller)
unsigned char *CIPHER_decrypt_message(MessageStream const *ms, unsigned char const *cipher_key_s, int *decrypted_len);

/// @brief Encrypt a message using CIPHER and store the result in `ms->c`
/// @param ms MessageStream to store the encrypted message and new IV
/// @param cipher_key_s Cipher key to use
/// @param data Message to encrypt
/// @param data_len Length of the message
void CIPHER_encrypt_message(MessageStream *ms, unsigned char const *cipher_key_s, unsigned char const *data,
                            int data_len);

#endif