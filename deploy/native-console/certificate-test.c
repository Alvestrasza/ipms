/* Synthetic regression harness. Never used by the deployed service. */
#include "ipms-strict-certificate.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    unsigned char pem[65537];
    FILE* input = fopen(argv[2], "rb");
    if (!input) return 2;
    size_t length = fread(pem, 1, sizeof(pem), input);
    fclose(input);
    int accepted = ipms_verify_native_certificate(argv[1], pem, length,
            strtoul(argv[3], NULL, 10));
    printf("%d\n", accepted);
    return 0;
}
