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

/// @brief Invert the order of the elements in an array and return the inverted array.
/// @note UTF-8 characters are inverted incorrectly.
/// @param arr Array to invert
/// @param len Length of the array
/// @return Null-terminated inverted array. Must be freed by the caller.
unsigned char *invert_array(unsigned char const *const arr, size_t const len);

/// @brief Write data to a file.
/// @param filename File to write to
/// @param data Data to write
/// @param data_len Length of the data
/// @param mode File mode (e.g., "w" for write, "wb" for write binary)
void write_to_file(char const *const filename, unsigned char const *const data, size_t const data_len,
                   char const *const mode);

/// @brief Write a string (null-terminated) to a file.
/// @param filename File to write to
/// @param str String to write
void write_string_to_file(char const *const filename, char const *const str);

/// @brief Open a file for reading or writing.
/// @param filename File to open
/// @param mode File mode (e.g., "r" for read, "w" for write)
/// @return File pointer to the opened file
FILE *open_file(char const *const filename, char const *const mode);

/// @brief Verify Bob's signature on a message by checking if the hash of the message is equal to the signature raised
/// to Bob's public exponent modulo Bob's public N.
/// @param ms MessageStream containing the message and signature
/// @param pk Bob's public key
/// @param bn_ctx BN_CTX to use for calculations
/// @return True if the signature is verified, false otherwise
bool RSA_verify_signature(MessageStream const *ms, RSAPublicKey const *pk, BN_CTX *bn_ctx);

/// @brief Sign a message by calculating the digest of the message and raising it to the private exponent modulo the
/// private N. The signature is stored in the message `ms->sig`.
/// @param ms MessageStream containing the message to sign. Needs `msg->iv` and `msg->c` to calculate the digest.
/// Message signature is stored in `msg->sig`.
/// @param kp RSAKeyPair containing the private key to sign the message
/// @param bn_ctx BN_CTX to use for calculations. If NULL, a new BN_CTX will be created and freed after the operation.
void RSA_sign_message(MessageStream *ms, RSAKeyPair const *kp, BN_CTX *bn_ctx);

/// @brief Load Alice's key pair from file, load CIPHER key from `SIG_FILE`, encrypt the message using CIPHER, and sign
/// the message with RSA.
/// @param message Message to encrypt and sign
/// @param message_len Length of the message
/// @return MessageStream containing the encrypted and signed message
MessageStream *encrypt_and_sign(unsigned char const *const message, int const message_len);

/// @brief Decrypt a message from a file using CIPHER (CIPHER key is loaded from `SIG_FILE`)
/// @param filename File to read the message from
/// @param message_len Length of the decrypted message (output)
/// @return Decrypted message (must be freed by the caller)
unsigned char *decrypt_file(char const *const filename, int *message_len);

#endif