#include "util.h"

unsigned char *invert_array(unsigned char const *const arr, size_t const len) {
    unsigned char *inv = malloc(sizeof(unsigned char) * (len + 1));
    for (size_t i = 0; i < len; i++) {
        inv[i] = arr[len - i - 1];
    }
    inv[len] = '\0';
    return inv;
}

void write_string_to_file(char const *const filename, char const *const str) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }
    fprintf(file, "%s", str);
    fclose(file);
}

bool RSA_verify_signature(MessageStream const *ms, RSAPublicKey const *bob_pk, BN_CTX *bn_ctx) {
    // Calculate digest of the message
    unsigned char *digest;
    unsigned int digest_len;
    MS_calc_digest(&digest, &digest_len, ms, DIGEST_ALGORITHM);

    // Check if hash = $sig_{c}^{e_b} mod N_b$
    BIGNUM *hash = BN_new();
    BN_bin2bn(digest, digest_len, hash);

    BN_mod_exp(ms->sig, ms->sig, bob_pk->e, bob_pk->n, bn_ctx);
    bool verified = BN_cmp(hash, ms->sig) == 0;

    free(digest);
    BN_free(hash);

    return verified;
}

void RSA_sign_message(MessageStream *ms, RSAKeyPair const *kp, BN_CTX *bn_ctx) {
    bool should_free_ctx = false;
    if (bn_ctx == NULL) {
        bn_ctx = BN_CTX_new();
        BN_CTX_start(bn_ctx);
        should_free_ctx = true;
    }

    // Calculate digest of the message
    unsigned char *digest;
    unsigned int digest_len;
    MS_calc_digest(&digest, &digest_len, ms, DIGEST_ALGORITHM);

    // Sign the message
    ms->sig = BN_new();
    BN_bin2bn(digest, digest_len, ms->sig);
    BN_mod_exp(ms->sig, ms->sig, kp->sk->d, kp->sk->n, bn_ctx);

    free(digest);

    if (should_free_ctx) {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }
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

unsigned char *decrypt_file(char const *const filename, int *message_len) {
    MessageStream *msg_bob = MS_load_from_file(filename);

    // Decrypt message c with AES (key s, CBC, PKCS) where m=AES^{-1}(c, s)
    unsigned char *aes_key_s = CIPHER_load_key_from_file(SIG_FILE);
    unsigned char *decrypted_message = CIPHER_decrypt_message(msg_bob, aes_key_s, message_len);

    // Cleanup
    MS_destroy(msg_bob);
    free(aes_key_s);

    return decrypted_message;
}
