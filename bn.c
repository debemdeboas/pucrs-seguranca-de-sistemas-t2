#include "bn.h"

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
