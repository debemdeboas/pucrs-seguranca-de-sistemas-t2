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
    fprintf(stderr, "Usage: %s [gen|sign|verify]\n", name);
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

void verify(void) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair *const alice_kp = RSAKP_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey *const bob_pk = RSAPKey_load_from_file(BOB_PK_N_FILE);

    MessageStream *msg_bob = MS_load_from_file("message.txt");

    BN_CTX *bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);

    if (verify_signature(msg_bob, bob_pk, bn_ctx)) {
        printf("Signature is valid\n");
    } else {
        fprintf(stderr, "Signature is invalid\n");
        exit(1);
    }

    // Decrypt message c with AES (key s, CBC, PKCS) where m=AES^{-1}(c, s)
    unsigned char *aes_key_s = AES_load_key_from_file(SIG_FILE);
    int decrypted_c_len;
    unsigned char *decrypted_c = AES_decrypt_message(msg_bob, aes_key_s, &decrypted_c_len);
    printf("Message: %s\n", decrypted_c);

    // Invert the message
    unsigned char *inverted_message = invert_array(decrypted_c, decrypted_c_len);
    printf("Inverted message: %s\n", inverted_message);

    // MessageStream for the inverted message
    MessageStream *msg_alice = malloc(sizeof(MessageStream));

    AES_encrypt_message(msg_alice, aes_key_s, inverted_message, decrypted_c_len + 1);
    sign_message(msg_alice, alice_kp, bn_ctx);

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

int main(int argc, char **argv) {
    // Possible argv values:
    // gen
    // sign
    // verify

    if (argc < 2) {
        help(argv[0]);
        exit(1);
    }

    char const *const mode = argv[1];

    // Setup OpenSSL random generator
    RAND_poll();

    if (strcmp(mode, "gen") == 0) {
        gen();
    } else if (strcmp(mode, "sign") == 0) {
        sign();
    } else if (strcmp(mode, "verify") == 0) {
        verify();
    } else {
        help(argv[0]);
        exit(1);
    }

    return 0;
}