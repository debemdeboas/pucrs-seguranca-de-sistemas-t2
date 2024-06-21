#include "rsa.h"

RSAPublicKey *RSAPKey_load_from_file(char const *filename) {
    FILE *file = open_file(filename, "r");

    RSAPublicKey *pk = malloc(sizeof(RSAPublicKey));
    pk->e = BN_from_file(file);
    pk->n = BN_from_file(file);

    fclose(file);
    return pk;
}

void RSAPKey_free(RSAPublicKey *pk) {
    BN_free(pk->e);
    BN_free(pk->n);
    free(pk);
}

RSAKeyPair *RSAKP_load_from_file(char const *filename) {
    FILE *file = open_file(filename, "r");

    RSAKeyPair *kp = malloc(sizeof(RSAKeyPair));
    kp->sk = malloc(sizeof(RSASecretKey));
    kp->pk = malloc(sizeof(RSAPublicKey));

    kp->sk->d = BN_from_file(file);
    kp->sk->n = BN_from_file(file);
    kp->pk->e = BN_from_file(file);
    kp->pk->n = BN_from_file(file);

    fclose(file);
    return kp;
}

RSAKeyPair *RSAKP_generate(void) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    BN_generate_prime_ex(p, NUM_BITS, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, NUM_BITS, 0, NULL, NULL, NULL);

    BIGNUM *N = BN_new();
    BN_mul(N, p, q, ctx);

    BIGNUM *phi = BN_new();
    BN_sub(p, p, BN_value_one());
    BN_sub(q, q, BN_value_one());
    BN_mul(phi, p, q, ctx);

    BIGNUM *e = BN_new();
    BIGNUM *gcd = BN_new();
    do {
        BN_generate_prime_ex(e, 128, 0, NULL, NULL, NULL);
        BN_gcd(gcd, e, phi, ctx);
    } while (!BN_is_one(gcd));

    BIGNUM *d = BN_new();
    BN_mod_inverse(d, e, phi, ctx);

    RSAKeyPair *kp = malloc(sizeof(RSAKeyPair));
    kp->sk = malloc(sizeof(RSASecretKey));
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

void RSAKP_to_file(RSAKeyPair const *kp, char const *filename) {
    FILE *file = open_file(filename, "w");

    BN_to_file(kp->sk->d, file);
    BN_to_file(kp->sk->n, file);
    BN_to_file(kp->pk->e, file);
    BN_to_file(kp->pk->n, file);

    fclose(file);
}

void RSAKP_free(RSAKeyPair *kp) {
    BN_clear_free(kp->sk->d);
    BN_clear_free(kp->sk->n);
    BN_clear_free(kp->pk->e);
    BN_clear_free(kp->pk->n);

    free(kp->sk);
    free(kp->pk);
    free(kp);
}
