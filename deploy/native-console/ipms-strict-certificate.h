/* IPMS native-console adaptation. Copyright Alvestrasza Corporation.
 * This file is compiled into the separately attributed Apache Guacamole RDP
 * adapter. It is intentionally independent of CA stores and known_hosts.
 */
#ifndef IPMS_STRICT_CERTIFICATE_H
#define IPMS_STRICT_CERTIFICATE_H

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stddef.h>
#include <string.h>

static int ipms_hex_nibble(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

/* Exactly one SHA-256 pin. No wildcards, extra algorithms, lists or whitespace. */
static int ipms_parse_sha256_pin(const char* pin, unsigned char output[32]) {
    if (!pin) return 0;
    const size_t length = strnlen(pin, 104);
    if ((length != 71 && length != 102) || strncmp(pin, "sha256:", 7)) return 0;
    const int separated = length == 102;
    for (size_t index = 0; index < 32; ++index) {
        const size_t offset = 7 + index * (separated ? 3 : 2);
        const int high = ipms_hex_nibble((unsigned char) pin[offset]);
        const int low = ipms_hex_nibble((unsigned char) pin[offset + 1]);
        if (high < 0 || low < 0) return 0;
        if (separated && index < 31 && pin[offset + 2] != ':') return 0;
        output[index] = (unsigned char) ((high << 4) | low);
    }
    return 1;
}

/* FreeRDP ExternalCertificateManagement supplies the peer leaf certificate in
 * PEM format. A result of 2 accepts only this connection and never persists
 * trust in FreeRDP. The callback must be invoked for EVERY certificate, even
 * certificates accepted by the platform CA store or a previous connection.
 */
static int ipms_verify_native_certificate(const char* pin,
        const unsigned char* pem, size_t length, unsigned long flags) {
    unsigned char expected[32];
    unsigned char observed[EVP_MAX_MD_SIZE];
    unsigned int observed_length = 0;
    if (flags || !pem || !length || length > 65536 ||
            !ipms_parse_sha256_pin(pin, expected)) return 0;
    BIO* input = BIO_new_mem_buf(pem, (int) length);
    if (!input) return 0;
    X509* certificate = PEM_read_bio_X509(input, NULL, NULL, NULL);
    BIO_free(input);
    if (!certificate) return 0;
    const int accepted =
        X509_cmp_current_time(X509_get0_notBefore(certificate)) < 0 &&
        X509_cmp_current_time(X509_get0_notAfter(certificate)) > 0 &&
        X509_digest(certificate, EVP_sha256(), observed, &observed_length) &&
        observed_length == sizeof(expected) &&
        CRYPTO_memcmp(expected, observed, sizeof(expected)) == 0;
    X509_free(certificate);
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(observed, sizeof(observed));
    return accepted ? 2 : 0;
}

#endif
