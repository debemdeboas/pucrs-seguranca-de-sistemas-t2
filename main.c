#include "rsa.h"
#include "util.h"
#include "verify.h"
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"
#define SIG_FILE "sig.txt"

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

MessageStream *encrypt_and_sign(unsigned char const *const message, int const message_len) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair *const alice_kp = RSAKP_load_from_file(ALICE_KP_FILE);

    unsigned char *aes_key_s = CIPHER_load_key_from_file(SIG_FILE);

    // MessageStream for the inverted message
    MessageStream *msg_alice = malloc(sizeof(MessageStream));

    CIPHER_encrypt_message(msg_alice, aes_key_s, message, message_len + 1);
    RSA_sign_message(msg_alice, alice_kp, NULL);

    // Cleanup

    RSAKP_free(alice_kp);
    free(aes_key_s);

    return msg_alice;
}

void verify_ex(char const *const filename) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair *const alice_kp = RSAKP_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey *const bob_pk = RSAPKey_load_from_file(BOB_PK_N_FILE);

    MessageStream *msg_bob = MS_load_from_file(filename);

    BN_CTX *bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);

    if (RSA_verify_signature(msg_bob, bob_pk, bn_ctx)) {
        printf("Signature is valid\n");
    } else {
        fprintf(stderr, "Signature is invalid\n");
        exit(1);
    }

    // Decrypt message c with AES (key s, CBC, PKCS) where m=AES^{-1}(c, s)
    unsigned char *aes_key_s = CIPHER_load_key_from_file(SIG_FILE);
    int decrypted_c_len;
    unsigned char *decrypted_c = CIPHER_decrypt_message(msg_bob, aes_key_s, &decrypted_c_len);
    printf("Message: %s\n", decrypted_c);

    // Invert the message
    unsigned char *inverted_message = invert_array(decrypted_c, decrypted_c_len);
    printf("Inverted message: %s\n", inverted_message);

    // MessageStream for the inverted message
    MessageStream *msg_alice = malloc(sizeof(MessageStream));

    CIPHER_encrypt_message(msg_alice, aes_key_s, inverted_message, decrypted_c_len + 1);
    RSA_sign_message(msg_alice, alice_kp, bn_ctx);

    // Save (c_inv, sig_hinv) to file
    FILE *out_file = fopen("message_inv.txt", "w");
    if (out_file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // Save IV
    for (int i = 0; i < 16; i++) {
        fprintf(out_file, "%02X", msg_alice->iv[i]);
    }
    // Save message
    for (int i = 0; i < (int)msg_alice->c_len; i++) {
        fprintf(out_file, "%02X", msg_alice->c[i]);
    }
    fprintf(out_file, "\n");

    // Save signature
    BN_to_file(msg_alice->sig, out_file);

    fclose(out_file);

    // Cleanup

    MS_destroy(msg_bob);
    MS_destroy(msg_alice);
    BN_free(bob_pk->e);
    BN_free(bob_pk->n);
    free(bob_pk);
    RSAKP_free(alice_kp);
    free(aes_key_s);
    free(inverted_message);
    free(decrypted_c);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
}

unsigned char *decrypt(char const *const filename, int *message_len) {
    MessageStream *msg_bob = MS_load_from_file(filename);

    // Decrypt message c with AES (key s, CBC, PKCS) where m=AES^{-1}(c, s)
    unsigned char *aes_key_s = CIPHER_load_key_from_file(SIG_FILE);
    unsigned char *decrypted_message = CIPHER_decrypt_message(msg_bob, aes_key_s, message_len);

    // Cleanup
    MS_destroy(msg_bob);
    free(aes_key_s);

    return decrypted_message;
}

int main(int argc, char **argv) {
    // Possible argv values:
    // gen
    // sign
    // verify <file>
    // decrypt <file>
    // encrypt <file>

    if (argc < 2) {
        help(argv[0]);
        exit(1);
    }

    char const *const mode = argv[1];

    // Setup OpenSSL random generator
    RAND_poll();

    if (strcmp(mode, "gen") == 0) {
        gen();
        exit(0);
    } else if (strcmp(mode, "sign") == 0) {
        sign();
        exit(0);
    }

    // Every subsequent mode verifies the message and signature, so we do it here

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

    int message_len;
    unsigned char *message = decrypt(argv[2], &message_len);
    printf("Message: %s\n", message);

    if (strcmp(mode, "decrypt") == 0) {
        free(message);
        exit(0);
    }

    unsigned char *alice_message;
    if (strcmp(mode, "inv") == 0) {
        // Invert the message
        alice_message = invert_array(message, message_len);
        printf("Inverted message: %s\n", alice_message);
    } else if (strcmp(mode, "encrypt") == 0) {
        if (argc < 4) {
            fprintf(stderr, "No message specified\n");
            help(argv[0]);
            exit(1);
        }

        alice_message = malloc(strlen(argv[3]) + 1);
        strcpy((char *)alice_message, argv[3]);
    } else {
        fprintf(stderr, "Invalid mode\n");
        help(argv[0]);
        exit(1);
    }

    MessageStream *msg_alice = encrypt_and_sign(alice_message, message_len);

    char *out_filename = malloc(strlen(argv[2]) + 8);
    strcpy(out_filename, argv[2]);
    strcat(out_filename, ".alice");
    MS_save_to_file(msg_alice, out_filename);

    free(message);
    free(alice_message);
    free(out_filename);
    MS_destroy(msg_alice);

    return 0;
}