#include "rsa.h"
#include "util.h"
#include "verify.h"
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define __STDC_WANT_LIB_EXT1__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void help(char const *const name);
void gen(void);
void sign(void);
bool verify(char const *const filename);

int main(int argc, char **argv) {
    if (argc < 2) {
        help(argv[0]);
        exit(1);
    }

    char const *const mode = argv[1];

    // Setup OpenSSL random generator
    RAND_poll();

    // Basic modes
    if (strcmp(mode, "gen") == 0) {
        gen();
        exit(0);
    } else if (strcmp(mode, "sign") == 0) {
        sign();
        exit(0);
    }

    // File-related modes
    // Every subsequent mode verifies the message and signature, so we're using
    // early returns and cascades (e.g. decrypt is actually verify and then decrypt)
    if (argc < 3) {
        fprintf(stderr, "No file specified\n");
        help(argv[0]);
        exit(1);
    }

    if (verify(argv[2])) {
        printf("Signature is valid\n");
    } else {
        fprintf(stderr, "Signature is invalid\n");
        exit(1);
    }

    if (strcmp(mode, "verify") == 0) {
        exit(0);
    }

    // Decryption is used by both encrypt_inv and decrypt.
    // The encrypt mode doesn't use the decrypted message, so we branch here.

    int alice_message_len;
    unsigned char *alice_message;

    if (strcmp(mode, "encrypt") == 0) {
        if (argc < 4) {
            fprintf(stderr, "No message specified\n");
            help(argv[0]);
            exit(1);
        }

        alice_message = malloc(strlen(argv[3]) + 1);
        strcpy((char *)alice_message, argv[3]);
        alice_message_len = (int)strlen((char *)alice_message) + 1;

        printf("Message to encrypt: %s\n", alice_message);
    } else if (strcmp(mode, "encrypt_inv") == 0 || strcmp(mode, "decrypt") == 0) {
        int message_len;
        unsigned char *message = decrypt_file(argv[2], &message_len);
        printf("Message: %s\n", message);

        // Save the decrypted message to a file
        char *decrypt_filename = malloc(strlen(argv[2]) + 9);
        strcpy(decrypt_filename, argv[2]);
        strcat(decrypt_filename, ".decrypt");
        FILE *out_file = fopen(decrypt_filename, "w");
        if (out_file == NULL) {
            fprintf(stderr, "Error opening file %s\n", decrypt_filename);
            exit(1);
        }

        // Since we can't be sure that the message is null-terminated, we use fwrite
        fwrite(message, sizeof(unsigned char), message_len, out_file);
        fclose(out_file);
        free(decrypt_filename);

        if (strcmp(mode, "decrypt") == 0) {
            free(message);
            exit(0);
        }

        // I'm aware that this is a bit of a waste of memory (i.e. we could've
        // used alice_message_len from the start), but it's easier to read and
        // understand the code this way.
        alice_message_len = message_len;

        // Invert the message
        alice_message = invert_array(message, message_len);
        printf("Inverted message: %s\n", alice_message);
        free(message);
    } else {
        fprintf(stderr, "Invalid mode\n");
        help(argv[0]);
        exit(1);
    }

    MessageStream *msg_alice = encrypt_and_sign(alice_message, alice_message_len);

    char *out_filename = malloc(strlen(argv[2]) + 8);
    strcpy(out_filename, argv[2]);
    strcat(out_filename, ".alice");
    MS_save_to_file(msg_alice, out_filename);

    free(alice_message);
    free(out_filename);
    MS_destroy(msg_alice);

    return 0;
}

void gen(void) {
    if (access(ALICE_KP_FILE, F_OK) == F_OK) {
        fprintf(stderr, "Error: Alice's key pair already exists\n");
        exit(1);
    }

    RSAKeyPair *alice_kp = RSAKP_generate();
    RSAKP_to_file(alice_kp, ALICE_KP_FILE);
    printf("Saved Alice's keypair to file %s\n", ALICE_KP_FILE);

    RSAKP_free(alice_kp);
}

void sign(void) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair *alice_kp = RSAKP_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey *bob_pk = RSAPKey_load_from_file(BOB_PK_N_FILE);

    if (access(SIG_FILE, F_OK) == F_OK) {
        fprintf(stderr, "Error: Signature information already exists\n");
        exit(1);
    }

    BIGNUM *aes_key = BN_new();
    BN_rand(aes_key, 128, 0, 0);

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *x = BN_new(); // x = AES_key^eb mod nb
    BN_mod_exp(x, aes_key, bob_pk->e, bob_pk->n, ctx);

    BIGNUM *sig = BN_new(); // sig = x^da mod na
    BN_mod_exp(sig, x, alice_kp->sk->d, alice_kp->sk->n, ctx);

    FILE *file = fopen(SIG_FILE, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    BN_to_file(aes_key, file);
    BN_to_file(x, file);
    BN_to_file(sig, file);
    BN_to_file(alice_kp->pk->e, file);
    BN_to_file(alice_kp->pk->n, file);

    fclose(file);

    BN_free(sig);
    BN_free(x);
    BN_free(aes_key);
    BN_free(bob_pk->e);
    BN_free(bob_pk->n);
    free(bob_pk);
    RSAKP_free(alice_kp);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

bool verify(char const *const filename) {
    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey *const bob_pk = RSAPKey_load_from_file(BOB_PK_N_FILE);

    MessageStream *msg_bob = MS_load_from_file(filename);

    BN_CTX *bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);

    bool verified = RSA_verify_signature(msg_bob, bob_pk, bn_ctx);

    // Cleanup

    MS_destroy(msg_bob);

    BN_free(bob_pk->e);
    BN_free(bob_pk->n);
    free(bob_pk);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return verified;
}

void help(char const *const name) {
    fprintf(stderr, "Usage: %s <mode>\n", name);
    fprintf(stderr, "\nBasic modes:\n");
    fprintf(stderr, "\tgen     Generate a key pair and write it to " ALICE_KP_FILE "\n");
    fprintf(stderr, "\tsign    Generate a symmetric key using AES-128, enciphers the key, signs it and write "
                    "everything to " SIG_FILE "\n");

    fprintf(stderr, "\nFile-related modes:\n");
    fprintf(stderr, "\tverify <file>               Verify <file>'s signature using Bob's key from " BOB_PK_N_FILE "\n");
    fprintf(stderr, "\tdecrypt <file>              Decrypt <file> and print to stdout\n");
    fprintf(stderr, "\tencrypt_inv <file>          Decrypt <file> and create a new encrypted and signed message "
                    "inverting <file>'s contents\n");
    fprintf(
        stderr,
        "\tencrypt <file> <message>    Decrypt <file>, verify its signature, and write <message> to <file>.alice\n");
}
