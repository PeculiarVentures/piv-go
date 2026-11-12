/* OpenSSL's pkeyutl CLI cannot allocate a zero-byte one-shot input buffer.
 * Exercise the same OpenSSL EVP verifier directly for an empty message. */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *public_file = fopen(argv[1], "rb");
    if (!public_file) return 2;
    EVP_PKEY *key = PEM_read_PUBKEY(public_file, NULL, NULL, NULL);
    fclose(public_file);
    if (!key) { ERR_print_errors_fp(stderr); return 2; }
    FILE *signature_file = fopen(argv[2], "rb");
    if (!signature_file) { EVP_PKEY_free(key); return 2; }
    if (fseek(signature_file, 0, SEEK_END) != 0) return 2;
    long size = ftell(signature_file);
    if (size <= 0 || size > 16384 || fseek(signature_file, 0, SEEK_SET) != 0) return 2;
    unsigned char *signature = malloc((size_t)size);
    if (!signature || fread(signature, 1, (size_t)size, signature_file) != (size_t)size) return 2;
    fclose(signature_file);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const unsigned char empty = 0;
    int valid = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(ctx, signature, (size_t)size, &empty, 0) == 1;
    if (!valid) ERR_print_errors_fp(stderr);
    if (valid) puts(OpenSSL_version(OPENSSL_VERSION));
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(signature);
    return valid ? 0 : 1;
}
