#include "rsa.h"
#include <limits.h>

BIGNUM * bignum_from_file(FILE * file) {
    char line[LINE_MAX];
    if (fgets(line, LINE_MAX, file) == NULL) {
        fprintf(stderr, "Error: Could not read line from file\n");
        exit(1);
    }

    BIGNUM * bn = BN_new();
    BN_hex2bn(&bn, line);

    return bn;
}

void bignum_to_file(BIGNUM const * bn, FILE * file) {
    char * hex = BN_bn2hex(bn);
    fprintf(file, "%s\n", hex);
    free(hex);
}

RSAPublicKey * pk_load_from_file(char const * filename) {
    FILE * file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    RSAPublicKey * pk = malloc(sizeof(RSAPublicKey));
    pk->e = bignum_from_file(file);
    pk->n = bignum_from_file(file);

    fclose(file);
    return pk;
}

RSAKeyPair * keypair_load_from_file(char const * filename) {
    FILE * file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    RSAKeyPair * kp = malloc(sizeof(RSAKeyPair));
    kp->sk = malloc(sizeof(SecretKey));
    kp->pk = malloc(sizeof(RSAPublicKey));

    kp->sk->d = bignum_from_file(file);
    kp->sk->n = bignum_from_file(file);
    kp->pk->e = bignum_from_file(file);
    kp->pk->n = bignum_from_file(file);

    fclose(file);
    return kp;
}

RSAKeyPair * keypair_generate(void) {
    BN_CTX * ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM * p = BN_new();
    BIGNUM * q = BN_new();

    BN_generate_prime_ex(p, NUM_BITS, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, NUM_BITS, 0, NULL, NULL, NULL);

    BIGNUM * N = BN_new();
    BN_mul(N, p, q, ctx);

    BIGNUM * phi = BN_new();
    BN_sub(p, p, BN_value_one());
    BN_sub(q, q, BN_value_one());
    BN_mul(phi, p, q, ctx);

    BIGNUM * e = BN_new();
    BIGNUM * gcd = BN_new();
    do {
        BN_generate_prime_ex(e, 128, 0, NULL, NULL, NULL);
        BN_gcd(gcd, e, phi, ctx);
    } while (!BN_is_one(gcd));

    BIGNUM * d = BN_new();
    BN_mod_inverse(d, e, phi, ctx);

    RSAKeyPair * kp = malloc(sizeof(RSAKeyPair));
    kp->sk = malloc(sizeof(SecretKey));
    kp->pk = malloc(sizeof(RSAPublicKey));

    kp->sk->d = d;
    kp->sk->n = N;

    kp->pk->e = e;
    kp->pk->n = N;

    BN_free(gcd);
    BN_free(phi);
    BN_free(q);
    BN_free(p);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return kp;
}

void keypair_save_to_file(RSAKeyPair const * kp, char const * filename) {
    FILE * file = fopen(filename, "w");
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

void keypair_free(RSAKeyPair * kp) {
    BN_clear_free(kp->sk->d);
    BN_clear_free(kp->sk->n);
    BN_clear_free(kp->pk->e);
    // no need to call BN_clear_free(kp->pk->n); // n is already freed by sk->n

    free(kp->sk);
    free(kp->pk);
    free(kp);
}