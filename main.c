#include "stdio.h"
#include <openssl/bn.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_BITS 1024
#define ALICE_KP_FILE "alice.kp"
#define BOB_PK_N_FILE "bob.pk"

BIGNUM *bignum_from_file(FILE* file) {
    char *line = NULL;
    ssize_t read;
    size_t len = 0;

    read = getline(&line, &len, file);
    if (line[read - 1] == '\n') { // Check for newline and remove if present
        line[read - 1] = '\0';
    }

    BIGNUM *bn = BN_new();
    BN_hex2bn(&bn, line);

    free(line);
    return bn;
}

void bignum_to_file(const BIGNUM *bn, FILE* file) {
    char *hex = BN_bn2hex(bn);
    fprintf(file, "%s\n", hex);
}

typedef struct SecretKey {
    BIGNUM *d;
    BIGNUM *n;
} SecretKey;

typedef struct RSAPublicKey {
    BIGNUM *e;
    BIGNUM *n;
} RSAPublicKey;

typedef struct RSAKeyPair {
    SecretKey *sk;
    RSAPublicKey *pk;
} RSAKeyPair;

RSAPublicKey *loadPublicKeyFromFile(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    RSAPublicKey *pk = malloc(sizeof(RSAPublicKey));
    pk->e = BN_new();
    pk->n = BN_new();

    char *line = NULL;
    ssize_t read;
    size_t len = 0;

    read = getline(&line, &len, file);
    line[read - 1] = '\0'; // remove newline
    BN_hex2bn(&pk->e, line);

    read = getline(&line, &len, file);
    if (line[read - 1] == '\n') { // Check for newline and remove if present
        line[read - 1] = '\0';
    }
    BN_hex2bn(&pk->n, line);

    free(line);
    fclose(file);
    return pk;
}

RSAKeyPair *keypair_load_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    RSAKeyPair *kp = malloc(sizeof(RSAKeyPair));
    kp->sk = malloc(sizeof(SecretKey));
    kp->pk = malloc(sizeof(RSAPublicKey));

    kp->sk->d = bignum_from_file(file);
    kp->sk->n = bignum_from_file(file);
    kp->pk->e = bignum_from_file(file);
    kp->pk->n = bignum_from_file(file);

    fclose(file);
    return kp;
}

void keypair_save_to_file(const RSAKeyPair *kp, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    bignum_to_file(kp->sk->d, file);
    bignum_to_file(kp->sk->n, file);
    bignum_to_file(kp->pk->e, file);
    bignum_to_file(kp->pk->n, file);

    fclose(file);
}

RSAKeyPair *keypair_generate() {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    BN_generate_prime_ex(p, NUM_BITS, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, NUM_BITS, 0, NULL, NULL, NULL);

    BIGNUM *N = BN_new();
    BN_mul(N, p, q, ctx);

    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_one = BN_dup(p);
    BIGNUM *q_minus_one = BN_dup(q);
    BN_sub(p_minus_one, p_minus_one, BN_value_one());
    BN_sub(q_minus_one, q_minus_one, BN_value_one());
    BN_mul(phi, p_minus_one, q_minus_one, ctx);
    BN_free(p_minus_one);
    BN_free(q_minus_one);

    BIGNUM *e = BN_new();
    BIGNUM *gcd = BN_new();
    do {
        BN_generate_prime_ex(e, 1024, 0, NULL, NULL, NULL);
        BN_gcd(gcd, e, phi, ctx);
    } while (!BN_is_one(gcd));
    BN_free(gcd);

    BIGNUM *d = BN_new();
    BN_mod_inverse(d, e, phi, ctx);

    RSAKeyPair *kp = malloc(sizeof(RSAKeyPair));
    kp->sk = malloc(sizeof(SecretKey));
    kp->pk = malloc(sizeof(RSAPublicKey));

    kp->sk->d = d;
    kp->sk->n = N;

    kp->pk->e = e;
    kp->pk->n = N;

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return kp;
}

void keypair_free(RSAKeyPair *kp) {
    BN_clear_free(kp->sk->d);
    BN_clear_free(kp->sk->n);
    BN_clear_free(kp->pk->e);
    // no need to call BN_clear_free(kp->pk->n); // n is already freed by sk->n

    free(kp->sk);
    free(kp->pk);
    free(kp);
}

int main() {
    printf("Loading Bob's public key from file %s\n", BOB_PK_N_FILE);
    const RSAPublicKey *bob_pk = loadPublicKeyFromFile(BOB_PK_N_FILE);

    RSAKeyPair *alice_kp;
    if (access(ALICE_KP_FILE, F_OK) == F_OK) {
        printf("Loading Alice's key pair from file %s\n", ALICE_KP_FILE);
        alice_kp = keypair_load_from_file(ALICE_KP_FILE);
    } else {
        printf("Generating Alice's key pair\n");
        alice_kp = keypair_generate();
        keypair_save_to_file(alice_kp, ALICE_KP_FILE);
        printf("Saved Alice's keypair to file %s\n", ALICE_KP_FILE);
    }

    if (access("sig.txt", F_OK) == F_OK) {
        printf("Signature information already exists\n");
    } else {
        BIGNUM *aes_key = BN_new();
        BN_rand(aes_key, 128, 0, 0);

        BN_CTX *ctx = BN_CTX_new();
        BN_CTX_start(ctx);

        BIGNUM *x = BN_new(); // x = AES_key^eb mod nb
        BN_mod_exp(x, aes_key, bob_pk->e, bob_pk->n, ctx);

        BIGNUM *sig = BN_new(); // sig = x^da mod na
        BN_mod_exp(sig, x, alice_kp->sk->d, alice_kp->sk->n, ctx);

        FILE *file = fopen("sig.txt", "w");
        bignum_to_file(aes_key, file);
        bignum_to_file(x, file);
        bignum_to_file(sig, file);
        fclose(file);

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    keypair_free(alice_kp);
    return 0;
}