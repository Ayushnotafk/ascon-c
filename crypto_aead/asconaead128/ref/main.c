
#include <stdio.h>
#include <string.h>
#include "api.h"

int main(void) {
    /* 128-bit secret key: 16 bytes */
    unsigned char key[CRYPTO_KEYBYTES] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    /* 128-bit nonce: 16 bytes */
    unsigned char nonce[CRYPTO_NPUBBYTES] = {
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F
    };

    unsigned char plaintext[] = "Hello IoT Security";
    unsigned char ad[] = "Device_ID=101";

    unsigned long long mlen = sizeof(plaintext) - 1;
    unsigned long long adlen = sizeof(ad) - 1;
    unsigned long long clen = 0, recovered_len = 0;

    unsigned char ciphertext[
        sizeof(plaintext) - 1 + CRYPTO_ABYTES
    ];
    unsigned char recovered[sizeof(plaintext)];

    /* Encrypt */
    int result = crypto_aead_encrypt(
        ciphertext, &clen,
        plaintext, mlen,
        ad, adlen,
        NULL, nonce, key
    );

    if (result != 0) {
        printf("Encryption failed!\n");
        return 1;
    }

    size_t cipher_len = (size_t)clen - CRYPTO_ABYTES;

    printf("Original plaintext: %s\n", plaintext);
    printf("Associated data: %s\n", ad);

    printf("Ciphertext: ");
    for (size_t i = 0; i < cipher_len; i++)
        printf("%02X", ciphertext[i]);
    printf("\n");

    printf("Authentication tag: ");
    for (size_t i = cipher_len; i < (size_t)clen; i++)
        printf("%02X", ciphertext[i]);
    printf("\n");

    /* Decrypt and verify */
    result = crypto_aead_decrypt(
        recovered, &recovered_len,
        NULL, ciphertext, clen,
        ad, adlen, nonce, key
    );

    if (result == 0 &&
        recovered_len == mlen &&
        memcmp(recovered, plaintext, mlen) == 0) {

        recovered[recovered_len] = '\0';
        printf("\nDecryption successful!\n");
        printf("Recovered plaintext: %s\n", recovered);
        printf("Messages match: YES\n");
    } else {
        printf("Decryption/authentication failed!\n");
        return 1;
    }

    /* Modify one ciphertext byte */
    ciphertext[0] ^= 0x01;

    printf("\nTampering with ciphertext...\n");

    result = crypto_aead_decrypt(
        recovered, &recovered_len,
        NULL, ciphertext, clen,
        ad, adlen, nonce, key
    );

    if (result != 0) {
        printf("Authentication failed!\n");
        printf("Tampered ciphertext rejected.\n");
    } else {
        printf("ERROR: Tampered ciphertext accepted!\n");
        return 1;
    }

    return 0;
}
