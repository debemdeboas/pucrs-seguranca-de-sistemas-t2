#include "rsa.h"
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"
#define SIG_FILE "sig.txt"

void
help(char const *const name) {
    fprintf(stderr, "Usage: %s [gen|sign|verify]\n", name);
}

void
gen(void) {
    if (access(ALICE_KP_FILE, F_OK) == F_OK) {
        fprintf(stderr, "Error: Alice's key pair already exists\n");
        exit(1);
    }

    RSAKeyPair *alice_kp = keypair_generate();
    keypair_save_to_file(alice_kp, ALICE_KP_FILE);
    printf("Saved Alice's keypair to file %s\n", ALICE_KP_FILE);

    keypair_free(alice_kp);
}

void
sign(void) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair *alice_kp = keypair_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey *bob_pk = pk_load_from_file(BOB_PK_N_FILE);

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

void
verify(void) {
    printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
    RSAKeyPair *alice_kp = keypair_load_from_file(ALICE_KP_FILE);

    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    RSAPublicKey *bob_pk = pk_load_from_file(BOB_PK_N_FILE);

    FILE *file = fopen(SIG_FILE, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *aes_key = bignum_from_file(file);
    BIGNUM *x = bignum_from_file(file);
    BIGNUM *sig = bignum_from_file(file);
    fclose(file);

    // Read message c from file
    file = fopen("message.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // Read signature from file
    char line[LINE_MAX];
    if (fgets(line, LINE_MAX, file) == NULL) {
        fprintf(stderr, "Error: Could not read line from file\n");
        exit(1);
    }
    size_t line_len = strlen(line) / 2;
    unsigned char *sig_c = malloc(sizeof(unsigned char) * line_len);
    for (size_t i = 0, j = 0; i < line_len; i++, j += 2) {
        sscanf(&line[j], "%02hhx", &sig_c[i]);
    }

    BIGNUM *bn_sig_c = BN_new();
    BN_bin2bn(sig_c, (int)line_len, bn_sig_c);

    // First 16 bytes of message are the IV
    unsigned char iv[16];
    for (int i = 0; i < 16; i++) {
        if (fscanf(file, "%02hhx", &iv[i]) != 1) {
            fprintf(stderr, "Error reading IV\n");
            exit(1);
        }
    }

    long file_cur = ftell(file);
    fseek(file, 0, SEEK_END);
    long c_len = (ftell(file) - file_cur) / 2;
    unsigned char *c = malloc(sizeof(unsigned char) * c_len);
    fseek(file, file_cur, SEEK_SET);
    for (int i = 0; i < c_len; i++) {
        if (fscanf(file, "%02hhx", &c[i]) != 1) {
            fprintf(stderr, "Error reading message\n");
            exit(1);
        }
    }

    fclose(file);

    OpenSSL_add_all_algorithms();
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_create();

    const EVP_MD *md = EVP_get_digestbyname("sha256");
    if (!md) {
        fprintf(stderr, "Error getting digest\n");
        exit(1);
    }

    unsigned char md_res[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit_ex(evp_ctx, md, NULL);
    EVP_DigestUpdate(evp_ctx, iv, 16);
    EVP_DigestUpdate(evp_ctx, c, c_len);
    EVP_DigestFinal_ex(evp_ctx, md_res, &md_len);
    EVP_MD_CTX_destroy(evp_ctx);

    // Check if hash = $sig_{c}^{e_b} mod N_b$
    BIGNUM *hash = BN_new();
    BN_bin2bn(md_res, md_len, hash);

    BN_mod_exp(bn_sig_c, bn_sig_c, bob_pk->e, bob_pk->n, ctx);
    BN_cmp(hash, bn_sig_c) == 0 ? printf("Signature verified\n")
                                : printf("Signature not verified\n");

    EVP_cleanup();
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    free(c);
}

int
main(int argc, char **argv) {
    // Possible argv values:
    // gen
    // sign
    // verify

    if (argc < 2) {
        help(argv[0]);
        exit(1);
    }

    char const *const mode = argv[1];

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