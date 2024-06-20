#include "util.h"
#include <limits.h>

BIGNUM *BN_from_file(FILE *file) {
    char line[LINE_MAX];
    if (fgets(line, LINE_MAX, file) == NULL) {
        fprintf(stderr, "Error: Could not read line from file\n");
        exit(1);
    }

    BIGNUM *bn = BN_new();
    BN_hex2bn(&bn, line);

    return bn;
}

BIGNUM *BN_one_from_file(char const *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }
    BIGNUM *ret = BN_from_file(file);
    fclose(file);
    return ret;
}

void BN_to_file(BIGNUM const *bn, FILE *file) {
    char *hex = BN_bn2hex(bn);
    fprintf(file, "%s\n", hex);
    free(hex);
}

unsigned char *invert_array(unsigned char const *const arr, size_t const len) {
    unsigned char *inv = malloc(sizeof(unsigned char) * (len + 1));
    for (size_t i = 0; i < len; i++) {
        inv[i] = arr[len - i - 1];
    }
    inv[len] = '\0';
    return inv;
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