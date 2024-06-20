#include "verify.h"

MessageStream *MS_load_from_file(char const *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    MessageStream *ms = malloc(sizeof(MessageStream));
    ms->sig = BN_from_file(file);

    // First 16 bytes of message are the IV
    for (int i = 0; i < 16; i++) {
        if (fscanf(file, "%02hhx", &ms->iv[i]) != 1) {
            fprintf(stderr, "Error reading IV\n");
            exit(1);
        }
    }

    // Read message c from file
    long file_cur = ftell(file);
    fseek(file, 0, SEEK_END);
    ms->c_len = (ftell(file) - file_cur) / 2;
    ms->c = malloc(sizeof(unsigned char) * ms->c_len);
    fseek(file, file_cur, SEEK_SET);
    for (size_t i = 0; i < ms->c_len; i++) {
        if (fscanf(file, "%02hhx", &ms->c[i]) != 1) {
            fprintf(stderr, "Error reading message\n");
            exit(1);
        }
    }

    fclose(file);

    return ms;
}

void MS_save_to_file(MessageStream const *ms, char const *filename) {
    // Save (c_inv, sig_hinv) to file
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }

    // Save IV
    for (int i = 0; i < 16; i++) {
        fprintf(file, "%02X", ms->iv[i]);
    }

    // Save message (same line as IV)
    for (int i = 0; i < (int)ms->c_len; i++) {
        fprintf(file, "%02X", ms->c[i]);
    }

    fprintf(file, "\n");

    // Save signature
    BN_to_file(ms->sig, file);

    fclose(file);
}

void MS_destroy(MessageStream *ms) {
    BN_free(ms->sig);
    free(ms->c);
    free(ms);
}

void MS_calc_digest(unsigned char **res, unsigned int *len, MessageStream const *ms, char const *digest) {
    OpenSSL_add_all_algorithms();
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_create();

    const EVP_MD *md = EVP_get_digestbyname(digest);
    if (!md) {
        fprintf(stderr, "Error getting digest %s\n", digest);
        exit(1);
    }

    *res = malloc(sizeof(unsigned char) * EVP_MAX_MD_SIZE);

    EVP_DigestInit_ex(evp_ctx, md, NULL);
    EVP_DigestUpdate(evp_ctx, ms->iv, sizeof(ms->iv));
    EVP_DigestUpdate(evp_ctx, ms->c, ms->c_len);
    EVP_DigestFinal_ex(evp_ctx, *res, len);
    EVP_MD_CTX_destroy(evp_ctx);
    EVP_cleanup();
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


unsigned char *CIPHER_load_key_from_file(const char *filename) {
    BIGNUM *bn_aes_key_s = BN_one_from_file(filename);

    size_t aes_key_s_len = BN_num_bytes(bn_aes_key_s);
    unsigned char *aes_key_s = malloc(sizeof(unsigned char) * aes_key_s_len);
    BN_bn2bin(bn_aes_key_s, aes_key_s);

    // Shift the key by one byte, pad with 0x00 and discard the last byte
    if (aes_key_s[0] >= 0x9) {
        memmove(aes_key_s + 1, aes_key_s, aes_key_s_len - 1);
        aes_key_s[0] = 0;
    }

    BN_free(bn_aes_key_s);
    return aes_key_s;
}

unsigned char *CIPHER_decrypt_message(MessageStream const *ms, unsigned char const *aes_key_s, int *decrypted_len) {
    EVP_CIPHER_CTX *evp_cip_ctx_d = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cip = EVP_CIPHER_fetch(NULL, EVP_CIPHER_CHOICE, NULL);

    unsigned char *decrypted = malloc(sizeof(unsigned char) * (ms->c_len + EVP_CIPHER_block_size(cip)));
    int cipher_out_len;
    *decrypted_len = 0;

    EVP_CIPHER_CTX_init(evp_cip_ctx_d);
    EVP_DecryptInit_ex(evp_cip_ctx_d, cip, NULL, aes_key_s, ms->iv);
    EVP_DecryptUpdate(evp_cip_ctx_d, decrypted, &cipher_out_len, ms->c, (int)ms->c_len);
    *decrypted_len += cipher_out_len;
    EVP_DecryptFinal_ex(evp_cip_ctx_d, decrypted + cipher_out_len, &cipher_out_len);
    *decrypted_len += cipher_out_len;
    *(decrypted + *decrypted_len) = '\0'; // Null terminate the message

    EVP_CIPHER_CTX_cleanup(evp_cip_ctx_d);
    EVP_CIPHER_CTX_free(evp_cip_ctx_d);
    EVP_CIPHER_free(cip);

    return decrypted;
}

void CIPHER_encrypt_message(MessageStream *ms, unsigned char const *aes_key_s, unsigned char const *plaintext,
                            int plaintext_len) {
    // Generate IV
    RAND_bytes(ms->iv, 16);

    // Encrypt the message
    EVP_CIPHER_CTX *evp_cip_ctx_e = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cip = EVP_CIPHER_fetch(NULL, EVP_CIPHER_CHOICE, NULL);

    ms->c = malloc(sizeof(unsigned char) * (plaintext_len + EVP_CIPHER_block_size(cip)));

    int cipher_out_len;

    EVP_CIPHER_CTX_init(evp_cip_ctx_e);
    EVP_EncryptInit_ex(evp_cip_ctx_e, cip, NULL, aes_key_s, ms->iv);
    EVP_EncryptUpdate(evp_cip_ctx_e, ms->c, &cipher_out_len, plaintext, plaintext_len);
    ms->c_len = cipher_out_len;
    EVP_EncryptFinal_ex(evp_cip_ctx_e, ms->c + plaintext_len, &cipher_out_len);
    ms->c_len += cipher_out_len;

    EVP_CIPHER_CTX_cleanup(evp_cip_ctx_e);
    EVP_CIPHER_CTX_free(evp_cip_ctx_e);
    EVP_CIPHER_free(cip);
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
