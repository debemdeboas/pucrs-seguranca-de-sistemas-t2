#include "rsa.h"
#include <ctype.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"
#define SIG_FILE "sig.txt"

void help(char const * const name) {
    fprintf(stderr, "Usage: %s [gen|sign|verify]\n", name);
}

void gen(void) {
    if (access(ALICE_KP_FILE, F_OK) == F_OK) {
        fprintf(stderr, "Error: Alice's key pair already exists\n");
        exit(1);
    }

    RSAKeyPair * alice_kp = keypair_generate();
    keypair_save_to_file(alice_kp, ALICE_KP_FILE);
    printf("Saved Alice's keypair to file %s\n", ALICE_KP_FILE);

    keypair_free(alice_kp);
}

void sign(void) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair * alice_kp = keypair_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey * bob_pk = pk_load_from_file(BOB_PK_N_FILE);

    if (access(SIG_FILE, F_OK) == F_OK) {
        fprintf(stderr, "Error: Signature information already exists\n");
        exit(1);
    }

    BIGNUM * aes_key = BN_new();
    BN_rand(aes_key, 128, 0, 0);

    BN_CTX * ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM * x = BN_new(); // x = AES_key^eb mod nb
    BN_mod_exp(x, aes_key, bob_pk->e, bob_pk->n, ctx);

    BIGNUM * sig = BN_new(); // sig = x^da mod na
    BN_mod_exp(sig, x, alice_kp->sk->d, alice_kp->sk->n, ctx);

    FILE * file = fopen(SIG_FILE, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    bignum_to_file(aes_key, file);
    bignum_to_file(x, file);
    bignum_to_file(sig, file);
    bignum_to_file(alice_kp->pk->e, file);
    bignum_to_file(alice_kp->pk->n, file);

    fclose(file);

    BN_free(sig);
    BN_free(x);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(aes_key);
    BN_free(bob_pk->e);
    BN_free(bob_pk->n);
    free(bob_pk);
    keypair_free(alice_kp);
}

void verify(void) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair * alice_kp = keypair_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey * bob_pk = pk_load_from_file(BOB_PK_N_FILE);

    FILE * file = fopen(SIG_FILE, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    BN_CTX * ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM * aes_key = bignum_from_file(file);
    BIGNUM * x = bignum_from_file(file);
    BIGNUM * sig = bignum_from_file(file);
    fclose(file);

    // Read message c from file
    FILE * file = fopen("message.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // First line is sig_c
    BIGNUM * sig_c = bignum_from_file(file);

    // First 16 bytes of message are the IV
    unsigned char iv[16];
    fread(iv, 1, 16, file);

    // Read the rest of the message
    BIGNUM * c = bignum_from_file(file);

    fclose(file);

    // Calculate SHA256(c)
    unsigned char const * sha256sum = SHA256(BN_bn2hex(c), BN_num_bytes(c), NULL);

    // Check if hash = sig_{c^{ep}} mod N_b
    BIGNUM * hash = BN_new();
    BN_hex2bn(&hash, sha256sum);
    BN_mod(sig_c, sig_c, bob_pk->n, ctx);
    BN_cmp(hash, sig_c) == 0 ? printf("Signature verified\n") : printf("Signature not verified\n");

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

int main(int argc, char ** argv) {
    // Possible argv values:
    // gen
    // sign
    // verify

    if (argc < 2) {
        help(argv[0]);
        exit(1);
    }

    char const * const mode = argv[1];

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