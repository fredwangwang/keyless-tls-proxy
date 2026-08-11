/*
 * ksp11.c — minimal PKCS#11 v2.40 software token module for testing
 * keyless-tls-proxy signing with OpenSSL's pkcs11-provider.
 *
 * The token holds a SINGLE private key (RSA or EC) loaded from a PEM file
 * at C_Initialize time. The key file is taken from the KSP11_KEY_PATH
 * environment variable and defaults to ./test-key.pem.
 *
 * Implemented:
 *   - slot/token/session management (one slot, RO sessions, no PIN)
 *   - object enumeration (one private + one public key object)
 *   - attribute retrieval (CKA_MODULUS/CKA_PUBLIC_EXPONENT for RSA,
 *     CKA_EC_PARAMS/CKA_EC_POINT for EC; private components are sensitive)
 *   - signing: CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA{256,384,512}_RSA_PKCS[_PSS],
 *     CKM_ECDSA, CKM_ECDSA_SHA{256,384,512}, single- and multi-part
 *   - random generation
 *
 * Everything else returns CKR_FUNCTION_NOT_SUPPORTED.
 *
 * Build:  gcc -shared -fPIC -I/usr/include/p11-kit-1 -o ksp11.so ksp11.c -lcrypto
 * Test:   ./test-sign.sh   (or see README.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <p11-kit/pkcs11.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

/* ---------------- token configuration ---------------- */

#define TOKEN_LABEL    "ksp11-token"
#define OBJECT_LABEL   "test-key"
#define OBJECT_ID      "\x01"
#define OBJECT_ID_LEN  1

/* Debug logging: set KSP11_DEBUG=1 to trace provider calls. */
static int dbg_enabled(void) {
    static int v = -1;
    if (v < 0) {
        v = getenv("KSP11_DEBUG") ? atoi(getenv("KSP11_DEBUG")) : 0;
    }
    return v;
}
#define DBG(...) do { if (dbg_enabled()) { fprintf(stderr, "ksp11: " __VA_ARGS__); } } while (0)

/* ---------------- global state ---------------- */

static int g_initialized = 0;
static EVP_PKEY *g_key = NULL;
static CK_KEY_TYPE g_key_type = 0; /* CKK_RSA or CKK_EC */

/* public components, derived at C_Initialize */
static CK_BYTE g_modulus[1024];
static CK_ULONG g_modulus_len = 0;
static CK_BYTE g_pubexp[8];
static CK_ULONG g_pubexp_len = 0;
static CK_BYTE g_ecparams[64];
static CK_ULONG g_ecparams_len = 0;
static CK_BYTE g_ecpoint[512];
static CK_ULONG g_ecpoint_len = 0;

/* ---------------- sessions ---------------- */

#define MAX_SESSIONS 16

typedef struct {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    int open;
} ksp_session;

static ksp_session g_sessions[MAX_SESSIONS];
static CK_SESSION_HANDLE g_next_handle = 1;

static ksp_session *find_session(CK_SESSION_HANDLE h) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].open && g_sessions[i].handle == h) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

/* ---------------- signing state (per session) ---------------- */

typedef struct {
    int active;
    int digest_mech;      /* mechanism hashes input internally */
    int pss;              /* RSA-PSS padding */
    const EVP_MD *md;     /* digest for digest mechanisms */
    int saltlen;          /* PSS salt length (0 => md size) */
    EVP_PKEY_CTX *raw_ctx; /* one-shot context (raw mechanisms) */
    EVP_MD_CTX *md_ctx;    /* multi-part context (digest mechanisms) */
    CK_BYTE *buf;          /* accumulated input for raw multi-part */
    CK_ULONG buflen, bufcap;
} ksp_sign;

static ksp_sign g_sign[MAX_SESSIONS];

static void sign_reset(ksp_sign *st) {
    if (st->raw_ctx) {
        EVP_PKEY_CTX_free(st->raw_ctx);
        st->raw_ctx = NULL;
    }
    if (st->md_ctx) {
        EVP_MD_CTX_free(st->md_ctx);
        st->md_ctx = NULL;
    }
    free(st->buf);
    st->buf = NULL;
    st->buflen = st->bufcap = 0;
    st->active = 0;
}

/* ---------------- mechanisms ---------------- */

typedef struct {
    CK_MECHANISM_TYPE type;
    int digest_mech;
    const EVP_MD *(*md)(void);
    int pss;
} ksp_mech;

static const ksp_mech ksp_mechs[] = {
    { CKM_RSA_PKCS,            0, NULL,       0 },
    { CKM_SHA256_RSA_PKCS,     1, EVP_sha256, 0 },
    { CKM_SHA384_RSA_PKCS,     1, EVP_sha384, 0 },
    { CKM_SHA512_RSA_PKCS,     1, EVP_sha512, 0 },
    { CKM_RSA_PKCS_PSS,        0, NULL,       1 },
    { CKM_SHA256_RSA_PKCS_PSS, 1, EVP_sha256, 1 },
    { CKM_SHA384_RSA_PKCS_PSS, 1, EVP_sha384, 1 },
    { CKM_SHA512_RSA_PKCS_PSS, 1, EVP_sha512, 1 },
    { CKM_ECDSA,               0, NULL,       0 },
    { CKM_ECDSA_SHA256,        1, EVP_sha256, 0 },
    { CKM_ECDSA_SHA384,        1, EVP_sha384, 0 },
    { CKM_ECDSA_SHA512,        1, EVP_sha512, 0 },
};
#define N_MECHS (sizeof(ksp_mechs) / sizeof(ksp_mechs[0]))

static const ksp_mech *find_mech(CK_MECHANISM_TYPE t) {
    for (size_t i = 0; i < N_MECHS; i++) {
        if (ksp_mechs[i].type == t) {
            return &ksp_mechs[i];
        }
    }
    return NULL;
}

static int mech_for_key(CK_MECHANISM_TYPE t) {
    const ksp_mech *m = find_mech(t);
    if (!m) {
        return 0;
    }
    if (g_key_type == CKK_RSA) {
        return t == CKM_RSA_PKCS || t == CKM_RSA_PKCS_PSS ||
               t == CKM_SHA256_RSA_PKCS || t == CKM_SHA384_RSA_PKCS || t == CKM_SHA512_RSA_PKCS ||
               t == CKM_SHA256_RSA_PKCS_PSS || t == CKM_SHA384_RSA_PKCS_PSS || t == CKM_SHA512_RSA_PKCS_PSS;
    }
    return t == CKM_ECDSA || t == CKM_ECDSA_SHA256 || t == CKM_ECDSA_SHA384 || t == CKM_ECDSA_SHA512;
}

/* ---------------- objects ---------------- */

#define PRIV_HANDLE 1
#define PUB_HANDLE  2

static CK_OBJECT_CLASS object_class(CK_OBJECT_HANDLE h) {
    switch (h) {
    case PRIV_HANDLE:
        return CKO_PRIVATE_KEY;
    case PUB_HANDLE:
        return CKO_PUBLIC_KEY;
    default:
        return 0;
    }
}

/* ---------------- find state ---------------- */

static CK_OBJECT_HANDLE g_find_handles[2];
static CK_ULONG g_find_n = 0, g_find_pos = 0;
static int g_find_active = 0;

/* ---------------- key loading ---------------- */

static CK_RV load_key(void) {
    const char *path = getenv("KSP11_KEY_PATH");
    if (!path || !*path) {
        path = "./test-key.pem";
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "ksp11: cannot open key file %s (set KSP11_KEY_PATH)\n", path);
        return CKR_DEVICE_ERROR;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!key) {
        fprintf(stderr, "ksp11: cannot parse key file %s\n", path);
        ERR_print_errors_fp(stderr);
        return CKR_DEVICE_ERROR;
    }

    g_key = key;
    int base = EVP_PKEY_base_id(key);
    if (base == EVP_PKEY_RSA) {
        g_key_type = CKK_RSA;
    } else if (base == EVP_PKEY_EC) {
        g_key_type = CKK_EC;
    } else {
        fprintf(stderr, "ksp11: unsupported key type %d (RSA or EC only)\n", base);
        EVP_PKEY_free(g_key);
        g_key = NULL;
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    return CKR_OK;
}

static CK_RV derive_attrs(void) {
    if (g_key_type == CKK_RSA) {
        BIGNUM *n = NULL, *e = NULL;
        if (!EVP_PKEY_get_bn_param(g_key, OSSL_PKEY_PARAM_RSA_N, &n) ||
            !EVP_PKEY_get_bn_param(g_key, OSSL_PKEY_PARAM_RSA_E, &e)) {
            BN_free(n);
            BN_free(e);
            return CKR_DEVICE_ERROR;
        }
        g_modulus_len = BN_bn2bin(n, g_modulus);
        g_pubexp_len = BN_bn2bin(e, g_pubexp);
        BN_free(n);
        BN_free(e);
        return CKR_OK;
    }

    /* EC: CKA_EC_PARAMS = DER of curve OID, CKA_EC_POINT = DER OCTET STRING
     * wrapping the ANSI X9.62 uncompressed point. */
    char curve[64] = {0};
    if (!EVP_PKEY_get_utf8_string_param(g_key, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve, sizeof(curve), NULL)) {
        return CKR_DEVICE_ERROR;
    }
    int nid = OBJ_txt2nid(curve);
    if (nid == NID_undef) {
        return CKR_DEVICE_ERROR;
    }
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    g_ecparams_len = i2d_ASN1_OBJECT(obj, NULL);
    if (g_ecparams_len > sizeof(g_ecparams)) {
        return CKR_DEVICE_ERROR;
    }
    unsigned char *p = g_ecparams;
    i2d_ASN1_OBJECT(obj, &p);

    CK_BYTE raw[256];
    size_t rawlen = 0;
    if (!EVP_PKEY_get_octet_string_param(g_key, OSSL_PKEY_PARAM_PUB_KEY,
                                         raw, sizeof(raw), &rawlen)) {
        return CKR_DEVICE_ERROR;
    }
    if (rawlen < 128) {
        g_ecpoint[0] = 0x04; /* OCTET STRING */
        g_ecpoint[1] = (CK_BYTE)rawlen;
        memcpy(g_ecpoint + 2, raw, rawlen);
        g_ecpoint_len = rawlen + 2;
    } else {
        g_ecpoint[0] = 0x04; /* OCTET STRING, long-form length */
        g_ecpoint[1] = 0x81;
        g_ecpoint[2] = (CK_BYTE)rawlen;
        memcpy(g_ecpoint + 3, raw, rawlen);
        g_ecpoint_len = rawlen + 3;
    }
    return CKR_OK;
}

/* ---------------- attribute helpers ---------------- */

/* Returns the size of the attribute value, 0 when unknown/invalid.
 * Sets *sensitive=1 for private key material that must not be disclosed. */
static CK_ULONG attr_size(CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type, int *sensitive) {
    CK_OBJECT_CLASS cls = object_class(h);
    switch (type) {
    case CKA_CLASS:
        return sizeof(CK_OBJECT_CLASS);
    case CKA_KEY_TYPE:
        return sizeof(CK_KEY_TYPE);
    case CKA_KEY_GEN_MECHANISM:
        return sizeof(CK_MECHANISM_TYPE);
    case CKA_ID:
        return OBJECT_ID_LEN;
    case CKA_LABEL:
        return sizeof(OBJECT_LABEL) - 1;
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_DESTROYABLE:
    case CKA_LOCAL:
    case CKA_SIGN:
    case CKA_VERIFY:
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_WRAP:
    case CKA_UNWRAP:
    case CKA_SENSITIVE:
    case CKA_EXTRACTABLE:
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_NEVER_EXTRACTABLE:
        return sizeof(CK_BBOOL);
    case CKA_MODULUS:
        return (g_key_type == CKK_RSA) ? g_modulus_len : 0;
    case CKA_PUBLIC_EXPONENT:
        return (g_key_type == CKK_RSA) ? g_pubexp_len : 0;
    case CKA_EC_PARAMS:
        return (g_key_type == CKK_EC) ? g_ecparams_len : 0;
    case CKA_EC_POINT:
        return (g_key_type == CKK_EC) ? g_ecpoint_len : 0;
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
    case CKA_VALUE:
        if (cls == CKO_PRIVATE_KEY) {
            *sensitive = 1;
        }
        return 0;
    default:
        return 0;
    }
}

static CK_BBOOL bool_attr(CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type) {
    switch (type) {
    case CKA_TOKEN:
    case CKA_DESTROYABLE:
    case CKA_COPYABLE:
    case CKA_SIGN:
    case CKA_VERIFY:
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_NEVER_EXTRACTABLE:
        return CK_TRUE;
    case CKA_SENSITIVE:
        return object_class(h) == CKO_PRIVATE_KEY ? CK_TRUE : CK_FALSE;
    default:
        return CK_FALSE;
    }
}

/* ---------------- CK_FUNCTION_LIST entry points ---------------- */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    if (g_initialized) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    if (pInitArgs) {
        CK_C_INITIALIZE_ARGS *args = (CK_C_INITIALIZE_ARGS *)pInitArgs;
        if (args->pReserved) {
            return CKR_ARGUMENTS_BAD;
        }
    }

    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_sign, 0, sizeof(g_sign));

    CK_RV rv = load_key();
    if (rv != CKR_OK) {
        return rv;
    }
    rv = derive_attrs();
    if (rv != CKR_OK) {
        EVP_PKEY_free(g_key);
        g_key = NULL;
        return rv;
    }
    g_initialized = 1;
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (pReserved) {
        return CKR_ARGUMENTS_BAD;
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sign_reset(&g_sign[i]);
        g_sessions[i].open = 0;
    }
    if (g_key) {
        EVP_PKEY_free(g_key);
        g_key = NULL;
    }
    g_initialized = 0;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    memcpy(pInfo->manufacturerID, "ksp11", 5);
    memcpy(pInfo->libraryDescription, "ksp11 minimal software token", 29);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    if (!pulCount) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    (void)tokenPresent; /* our single slot always has the token present */
    if (pSlotList == NULL) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    pSlotList[0] = 0;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    memcpy(pInfo->slotDescription, "ksp11 slot 0", 12);
    memcpy(pInfo->manufacturerID, "ksp11", 5);
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 1;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    memset(pInfo, ' ', sizeof(*pInfo));
    memcpy(pInfo->label, TOKEN_LABEL, sizeof(TOKEN_LABEL) - 1);
    memcpy(pInfo->manufacturerID, "ksp11", 5);
    memcpy(pInfo->model, "ksp11", 5);
    memcpy(pInfo->serialNumber, "00000001", 8);
    pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = 0;
    pInfo->ulMaxRwSessionCount = 0;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 8;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 1;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    memcpy(pInfo->utcTime, "0000000000000000", 16);
    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (!pulCount) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_ULONG n = 0;
    for (size_t i = 0; i < N_MECHS; i++) {
        if (mech_for_key(ksp_mechs[i].type)) {
            n++;
        }
    }
    if (pMechanismList == NULL) {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    CK_ULONG j = 0;
    for (size_t i = 0; i < N_MECHS; i++) {
        if (mech_for_key(ksp_mechs[i].type)) {
            pMechanismList[j++] = ksp_mechs[i].type;
        }
    }
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!mech_for_key(type)) {
        return CKR_MECHANISM_INVALID;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_SIGN | CKF_VERIFY;
    if (g_key_type == CKK_RSA) {
        pInfo->ulMinKeySize = 1024;
        pInfo->ulMaxKeySize = 8192;
    } else {
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 521;
    }
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (!phSession) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (flags & CKF_RW_SESSION) {
        return CKR_SESSION_READ_ONLY;
    }
    (void)pApplication;
    (void)Notify; /* application callbacks are not supported; ignored */

    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].open) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        return CKR_SESSION_COUNT;
    }
    g_sessions[slot].open = 1;
    g_sessions[slot].handle = g_next_handle++;
    g_sessions[slot].slot = slotID;
    *phSession = g_sessions[slot].handle;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ksp_session *s = find_session(hSession);
    if (!s) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    sign_reset(&g_sign[s - g_sessions]);
    s->open = 0;
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].open) {
            sign_reset(&g_sign[i]);
            g_sessions[i].open = 0;
        }
    }
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ksp_session *s = find_session(hSession);
    if (!s) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->slotID = s->slot;
    pInfo->state = CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (userType != CKU_USER) {
        return CKR_USER_TYPE_INVALID;
    }
    (void)pPin;
    (void)ulPinLen; /* token has no PIN; login always succeeds */
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (g_find_active) {
        return CKR_OPERATION_ACTIVE;
    }

    g_find_n = 0;
    for (int i = 0; i < 2; i++) {
        CK_OBJECT_HANDLE h = (i == 0) ? PRIV_HANDLE : PUB_HANDLE;
        int match = 1;
        for (CK_ULONG j = 0; j < ulCount && match; j++) {
            CK_ATTRIBUTE *a = &pTemplate[j];
            switch (a->type) {
            case CKA_CLASS: {
                if (a->ulValueLen != sizeof(CK_OBJECT_CLASS)) {
                    match = 0;
                    break;
                }
                CK_OBJECT_CLASS cls;
                memcpy(&cls, a->pValue, sizeof(cls));
                if (cls != object_class(h)) {
                    match = 0;
                }
                break;
            }
            case CKA_KEY_TYPE: {
                if (a->ulValueLen != sizeof(CK_KEY_TYPE)) {
                    match = 0;
                    break;
                }
                CK_KEY_TYPE kt;
                memcpy(&kt, a->pValue, sizeof(kt));
                if (kt != g_key_type) {
                    match = 0;
                }
                break;
            }
            case CKA_LABEL: {
                if (a->ulValueLen != sizeof(OBJECT_LABEL) - 1 ||
                    memcmp(a->pValue, OBJECT_LABEL, a->ulValueLen) != 0) {
                    match = 0;
                }
                break;
            }
            case CKA_ID: {
                if (a->ulValueLen != OBJECT_ID_LEN ||
                    memcmp(a->pValue, OBJECT_ID, a->ulValueLen) != 0) {
                    match = 0;
                }
                break;
            }
            default:
                match = 0; /* unsupported filter attribute */
            }
        }
        if (match) {
            g_find_handles[g_find_n++] = h;
        }
    }
    g_find_pos = 0;
    g_find_active = 1;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!g_find_active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!phObject || !pulObjectCount) {
        return CKR_ARGUMENTS_BAD;
    }
    CK_ULONG n = 0;
    while (g_find_pos < g_find_n && n < ulMaxObjectCount) {
        phObject[n++] = g_find_handles[g_find_pos++];
    }
    *pulObjectCount = n;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    g_find_active = 0;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (object_class(hObject) == 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (!pTemplate && ulCount > 0) {
        return CKR_ARGUMENTS_BAD;
    }

    CK_RV ret = CKR_OK;
    int any_sensitive = 0, any_invalid = 0, any_small = 0;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        int sensitive = 0;
        CK_ULONG size = attr_size(hObject, a->type, &sensitive);

        if (sensitive) {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            any_sensitive = 1;
            continue;
        }
        if (size == 0) {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            any_invalid = 1;
            continue;
        }
        if (a->pValue == NULL) {
            a->ulValueLen = size;
            continue;
        }
        if (a->ulValueLen < size) {
            a->ulValueLen = size;
            any_small = 1;
            continue;
        }

        CK_BYTE tmp[1024];
        CK_BYTE *p = tmp;
        CK_BBOOL b;
        switch (a->type) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS v = object_class(hObject);
            memcpy(p, &v, sizeof(v));
            break;
        }
        case CKA_KEY_TYPE:
            memcpy(p, &g_key_type, sizeof(g_key_type));
            break;
        case CKA_KEY_GEN_MECHANISM: {
            CK_MECHANISM_TYPE v = CKM_RSA_PKCS_KEY_PAIR_GEN;
            memcpy(p, &v, sizeof(v));
            break;
        }
        case CKA_ID:
            memcpy(p, OBJECT_ID, OBJECT_ID_LEN);
            break;
        case CKA_LABEL:
            memcpy(p, OBJECT_LABEL, sizeof(OBJECT_LABEL) - 1);
            break;
        case CKA_TOKEN:
        case CKA_DESTROYABLE:
        case CKA_COPYABLE:
        case CKA_SIGN:
        case CKA_VERIFY:
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
        case CKA_NEVER_EXTRACTABLE:
        case CKA_PRIVATE:
        case CKA_MODIFIABLE:
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_EXTRACTABLE:
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_LOCAL:
        case CKA_SENSITIVE:
            b = bool_attr(hObject, a->type);
            memcpy(p, &b, sizeof(b));
            break;
        case CKA_MODULUS:
            memcpy(p, g_modulus, g_modulus_len);
            break;
        case CKA_PUBLIC_EXPONENT:
            memcpy(p, g_pubexp, g_pubexp_len);
            break;
        case CKA_EC_PARAMS:
            memcpy(p, g_ecparams, g_ecparams_len);
            break;
        case CKA_EC_POINT:
            memcpy(p, g_ecpoint, g_ecpoint_len);
            break;
        default:
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            any_invalid = 1;
            continue;
        }
        a->ulValueLen = size;
        memcpy(a->pValue, p, size);
    }

    if (any_sensitive) {
        ret = CKR_ATTRIBUTE_SENSITIVE;
    } else if (any_invalid) {
        ret = CKR_ATTRIBUTE_TYPE_INVALID;
    } else if (any_small) {
        ret = CKR_BUFFER_TOO_SMALL;
    }
    return ret;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG_PTR pulSize) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (object_class(hObject) == 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (!pulSize) {
        return CKR_ARGUMENTS_BAD;
    }
    *pulSize = 0; /* unknown */
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ksp_session *s = find_session(hSession);
    if (!s) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (hKey != PRIV_HANDLE) {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    ksp_sign *st = &g_sign[s - g_sessions];
    if (st->active) {
        return CKR_OPERATION_ACTIVE;
    }

    const ksp_mech *m = find_mech(pMechanism->mechanism);
    if (!m || !mech_for_key(pMechanism->mechanism)) {
        return CKR_MECHANISM_INVALID;
    }
    DBG("C_SignInit mech=0x%lx key_type=%lu\n",
        (unsigned long)pMechanism->mechanism, (unsigned long)g_key_type);

    sign_reset(st);
    st->active = 1;
    st->digest_mech = m->digest_mech;
    st->pss = m->pss;
    st->md = m->md ? m->md() : NULL;
    st->saltlen = 0;

    if (m->pss && pMechanism->pParameter &&
        pMechanism->ulParameterLen >= sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
        CK_RSA_PKCS_PSS_PARAMS *par = (CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
        if (par->sLen != CK_UNAVAILABLE_INFORMATION) {
            st->saltlen = (int)par->sLen;
        }
    }

    if (m->digest_mech) {
        st->md_ctx = EVP_MD_CTX_new();
        if (!st->md_ctx) {
            st->active = 0;
            return CKR_HOST_MEMORY;
        }
        if (EVP_DigestSignInit(st->md_ctx, NULL, st->md, NULL, g_key) <= 0) {
            fprintf(stderr, "ksp11: DigestSignInit failed\n");
            sign_reset(st);
            return CKR_FUNCTION_FAILED;
        }
        if (m->pss) {
            EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(st->md_ctx);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                st->saltlen ? st->saltlen : EVP_MD_size(st->md));
        }
    } else {
        st->raw_ctx = EVP_PKEY_CTX_new(g_key, NULL);
        if (!st->raw_ctx) {
            st->active = 0;
            return CKR_HOST_MEMORY;
        }
        if (EVP_PKEY_sign_init(st->raw_ctx) <= 0) {
            fprintf(stderr, "ksp11: PKEY_sign_init failed\n");
            sign_reset(st);
            return CKR_FUNCTION_FAILED;
        }
        if (m->pss) {
            EVP_PKEY_CTX_set_rsa_padding(st->raw_ctx, RSA_PKCS1_PSS_PADDING);
            const EVP_MD *md = st->md ? st->md : EVP_sha256();
            EVP_PKEY_CTX_set_rsa_pss_saltlen(st->raw_ctx,
                st->saltlen ? st->saltlen : EVP_MD_size(md));
        } else if (g_key_type == CKK_RSA) {
            EVP_PKEY_CTX_set_rsa_padding(st->raw_ctx, RSA_PKCS1_PADDING);
        }
    }
    return CKR_OK;
}

/* pkcs11-provider expects ECDSA signatures as raw r||s (padded to the field
 * size), NOT DER-encoded (see p11prov_ecdsa_sign -> convert_ecdsa_raw_to_der
 * in latchset/pkcs11-provider src/sig/ecdsa.c). Convert the DER signature
 * produced by OpenSSL into the raw form. */
static int ecdsa_der_to_raw(const unsigned char *der, size_t derlen,
                            unsigned char **out, size_t *outlen) {
    const unsigned char *p = der;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long)derlen);
    if (!s) {
        return 0;
    }
    const BIGNUM *r = NULL, *ss = NULL;
    ECDSA_SIG_get0(s, &r, &ss);
    int field = (EVP_PKEY_get_bits(g_key) + 7) / 8;
    unsigned char *raw = malloc(2 * field);
    if (!raw) {
        ECDSA_SIG_free(s);
        return 0;
    }
    if (BN_bn2binpad(r, raw, field) < 0 || BN_bn2binpad(ss, raw + field, field) < 0) {
        free(raw);
        ECDSA_SIG_free(s);
        return 0;
    }
    ECDSA_SIG_free(s);
    *out = raw;
    *outlen = 2 * (size_t)field;
    return 1;
}

/* Buffer dance shared by C_Sign and C_SignFinal: copy sig into the caller's
 * buffer, handling the NULL / too-small conventions, then complete the op. */
static CK_RV sign_emit(ksp_sign *st, CK_BYTE *sig, CK_ULONG siglen,
                       CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    DBG("sign_emit siglen=%lu pSignature=%s *pulSignatureLen=%lu\n",
        (unsigned long)siglen, pSignature ? "set" : "NULL",
        pSignature ? (unsigned long)*pulSignatureLen : 0);
    if (pSignature == NULL) {
        *pulSignatureLen = siglen;
        sign_reset(st);
        return CKR_OK;
    }
    if (*pulSignatureLen < siglen) {
        *pulSignatureLen = siglen;
        sign_reset(st);
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pSignature, sig, siglen);
    *pulSignatureLen = siglen;
    sign_reset(st);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ksp_session *s = find_session(hSession);
    if (!s) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    ksp_sign *st = &g_sign[s - g_sessions];
    if (!st->active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!pulSignatureLen) {
        return CKR_ARGUMENTS_BAD;
    }
    DBG("C_Sign data_len=%lu\n", (unsigned long)ulDataLen);

    CK_BYTE *sig = NULL;
    CK_ULONG siglen = 0;
    int ok = 0;

    if (st->digest_mech) {
        if (EVP_DigestSignUpdate(st->md_ctx, pData, ulDataLen) <= 0 ||
            EVP_DigestSignFinal(st->md_ctx, NULL, &siglen) <= 0) {
            goto fail;
        }
        sig = malloc(siglen);
        if (!sig) {
            sign_reset(st);
            return CKR_HOST_MEMORY;
        }
        if (EVP_DigestSignFinal(st->md_ctx, sig, &siglen) <= 0) {
            goto fail;
        }
        ok = 1;
    } else {
        size_t len = 0;
        if (EVP_PKEY_sign(st->raw_ctx, NULL, &len, pData, ulDataLen) <= 0) {
            goto fail;
        }
        sig = malloc(len);
        if (!sig) {
            sign_reset(st);
            return CKR_HOST_MEMORY;
        }
        if (EVP_PKEY_sign(st->raw_ctx, sig, &len, pData, ulDataLen) <= 0) {
            goto fail;
        }
        siglen = len;
        ok = 1;
    }

    if (ok && g_key_type == CKK_EC) {
        unsigned char *raw = NULL;
        size_t rawlen = 0;
        if (!ecdsa_der_to_raw(sig, siglen, &raw, &rawlen)) {
            free(sig);
            ok = 0;
            goto fail;
        }
        free(sig);
        sig = raw;
        siglen = rawlen;
    }

    if (ok) {
        CK_RV rv = sign_emit(st, sig, siglen, pSignature, pulSignatureLen);
        free(sig);
        return rv;
    }

fail:
    free(sig);
    fprintf(stderr, "ksp11: signing failed\n");
    ERR_print_errors_fp(stderr);
    sign_reset(st);
    return CKR_FUNCTION_FAILED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ksp_session *s = find_session(hSession);
    if (!s) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    ksp_sign *st = &g_sign[s - g_sessions];
    if (!st->active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    DBG("C_SignUpdate len=%lu\n", (unsigned long)ulPartLen);
    if (st->digest_mech) {
        if (EVP_DigestSignUpdate(st->md_ctx, pPart, ulPartLen) <= 0) {
            return CKR_FUNCTION_FAILED;
        }
        return CKR_OK;
    }
    if (st->buflen + ulPartLen > st->bufcap) {
        CK_ULONG cap = st->bufcap ? st->bufcap * 2 : 256;
        while (cap < st->buflen + ulPartLen) {
            cap *= 2;
        }
        CK_BYTE *nb = realloc(st->buf, cap);
        if (!nb) {
            return CKR_HOST_MEMORY;
        }
        st->buf = nb;
        st->bufcap = cap;
    }
    memcpy(st->buf + st->buflen, pPart, ulPartLen);
    st->buflen += ulPartLen;
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ksp_session *s = find_session(hSession);
    if (!s) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    ksp_sign *st = &g_sign[s - g_sessions];
    if (!st->active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!pulSignatureLen) {
        return CKR_ARGUMENTS_BAD;
    }
    DBG("C_SignFinal buflen=%lu\n", (unsigned long)st->buflen);

    CK_BYTE *sig = NULL;
    CK_ULONG siglen = 0;

    if (st->digest_mech) {
        if (EVP_DigestSignFinal(st->md_ctx, NULL, &siglen) <= 0) {
            goto fail;
        }
        DBG("C_SignFinal size-call returned %lu\n", (unsigned long)siglen);
        sig = malloc(siglen);
        if (!sig) {
            sign_reset(st);
            return CKR_HOST_MEMORY;
        }
        if (EVP_DigestSignFinal(st->md_ctx, sig, &siglen) <= 0) {
            goto fail;
        }
        DBG("C_SignFinal sig-call returned %lu, first bytes: %02x %02x %02x %02x %02x\n",
            (unsigned long)siglen, sig[0], sig[1], sig[2], sig[3], sig[4]);
    } else {
        size_t len = 0;
        if (EVP_PKEY_sign(st->raw_ctx, NULL, &len, st->buf, st->buflen) <= 0) {
            goto fail;
        }
        sig = malloc(len);
        if (!sig) {
            sign_reset(st);
            return CKR_HOST_MEMORY;
        }
        if (EVP_PKEY_sign(st->raw_ctx, sig, &len, st->buf, st->buflen) <= 0) {
            goto fail;
        }
        siglen = len;
    }

    if (g_key_type == CKK_EC) {
        unsigned char *raw = NULL;
        size_t rawlen = 0;
        if (!ecdsa_der_to_raw(sig, siglen, &raw, &rawlen)) {
            free(sig);
            goto fail;
        }
        free(sig);
        sig = raw;
        siglen = rawlen;
    }

    {
        CK_RV rv = sign_emit(st, sig, siglen, pSignature, pulSignatureLen);
        free(sig);
        return rv;
    }

fail:
    free(sig);
    fprintf(stderr, "ksp11: signing failed\n");
    ERR_print_errors_fp(stderr);
    sign_reset(st);
    return CKR_FUNCTION_FAILED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    if (!g_initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!find_session(hSession)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!pRandomData && ulRandomLen > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    if (ulRandomLen > 0 && RAND_bytes(pRandomData, (int)ulRandomLen) != 1) {
        return CKR_RANDOM_NO_RNG;
    }
    return CKR_OK;
}

/* ---------------- unsupported entry points ---------------- */

static CK_RV ksp_not_supported(void) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) { return ksp_not_supported(); }
CK_RV C_InitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_SetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) { return ksp_not_supported(); }
CK_RV C_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) { return ksp_not_supported(); }
CK_RV C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_EncryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DecryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DigestInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR) { return ksp_not_supported(); }
CK_RV C_Digest(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_DigestFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_SignRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_Verify(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_VerifyFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) { return ksp_not_supported(); }
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) { return ksp_not_supported(); }
CK_RV C_VerifyRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) { return ksp_not_supported(); }
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR) { return ksp_not_supported(); }
CK_RV C_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) { return ksp_not_supported(); }
CK_RV C_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) { return ksp_not_supported(); }
CK_RV C_DeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) { return ksp_not_supported(); }
CK_RV C_SeedRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) { return CKR_RANDOM_SEED_NOT_SUPPORTED; }
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE) { return CKR_FUNCTION_NOT_PARALLEL; }
CK_RV C_CancelFunction(CK_SESSION_HANDLE) { return CKR_FUNCTION_NOT_PARALLEL; }
CK_RV C_WaitForSlotEvent(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) { return CKR_NO_EVENT; }

/* ---------------- function list ---------------- */

static CK_FUNCTION_LIST ksp11_functions;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!ppFunctionList) {
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = (CK_FUNCTION_LIST_PTR)&ksp11_functions;
    return CKR_OK;
}

static CK_FUNCTION_LIST ksp11_functions = {
    { 2, 40 },
    C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList,
    C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
    C_InitToken, C_InitPIN, C_SetPIN,
    C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo,
    C_GetOperationState, C_SetOperationState,
    C_Login, C_Logout,
    C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
    C_GetAttributeValue, C_SetAttributeValue,
    C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,
    C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal,
    C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal,
    C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal,
    C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
    C_SignRecoverInit, C_SignRecover,
    C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal,
    C_VerifyRecoverInit, C_VerifyRecover,
    C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate,
    C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey,
    C_SeedRandom, C_GenerateRandom, C_GetFunctionStatus, C_CancelFunction, C_WaitForSlotEvent
};
