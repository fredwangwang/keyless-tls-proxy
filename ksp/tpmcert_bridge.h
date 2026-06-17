#ifndef TPMCERT_BRIDGE_H
#define TPMCERT_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TPMCERT_OK        0
#define TPMCERT_ERR      -1
#define TPMCERT_NO_MORE  -2
#define TPMCERT_NOT_FOUND -3
#define TPMCERT_BUFFER_TOO_SMALL -4

typedef struct {
    char thumbprint[64];
    char subject[512];
    char key_algorithm[32];
    int32_t key_size;
    uint8_t* cert_der;
    size_t cert_der_len;
    uint8_t* rsa_public_blob;
    size_t rsa_public_blob_len;
} tpmcert_key_info;

int tpmcert_init(const char* config_path);
void tpmcert_shutdown(void);
int tpmcert_reload_manifest(void);
int tpmcert_installed_count(void);
int tpmcert_get_installed(int index, tpmcert_key_info* out);
int tpmcert_find_installed(const char* thumbprint, tpmcert_key_info* out);
void tpmcert_free_key_info(tpmcert_key_info* info);
int tpmcert_sign_hash(
    const char* thumbprint,
    const uint8_t* digest,
    size_t digest_len,
    int hash_alg,
    int rsa_padding,
    uint8_t* sig_out,
    size_t* sig_len);

#ifdef __cplusplus
}
#endif

#endif
