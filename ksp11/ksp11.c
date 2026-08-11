/*
 * ksp11.c — keyless PKCS#11 v2.40 software token module for Linux.
 *
 * The module holds NO private keys locally. Certificates and keys live on the
 * keyless-tls-proxy cert-server; every signing request is forwarded over gRPC
 * (mTLS) through the cgo tpmcert bridge that is statically linked into this
 * .so, and the signature is returned to the caller (e.g. OpenSSL's
 * pkcs11-provider). This mirrors the Windows KSP DLL (ksp/ksp.c) architecture:
 *
 *   openssl ──PKCS#11──> ksp11.so ──tpmcert_*──> [cgo bridge] ──gRPC──> cert-server
 *
 * Configuration (read by the bridge at C_Initialize):
 *   env  : KSP11_ADDR, KSP11_CA, KSP11_CERT, KSP11_KEY
 *   file : JSON config {"addr","ca","cert","key"} at $KSP11_CONFIG, or
 *          $XDG_CONFIG_HOME/fredprx-ksp/config.json
 *
 * Implemented:
 *   - slot/token/session management (one slot, RO sessions, no PIN)
 *   - one private-key object per remote certificate (CKA_ID = thumbprint,
 *     CKA_LABEL = subject; RSA modulus/exponent or EC params/point parsed from
 *     the certificate)
 *   - signing, single- and multi-part: CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
 *     CKM_SHA{256,384,512}_RSA_PKCS[_PSS], CKM_ECDSA,
 *     CKM_ECDSA_SHA{256,384,512} — digests are hashed locally, then signed by
 *     the server via tpmcert_sign_hash
 *   - C_GenerateRandom
 *
 * Build (see Makefile): cgo bridge is compiled with
 *   go build -buildmode=c-archive ./internal/kspbridge
 * then linked together with gcc -shared.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <p11-kit/pkcs11.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "../ksp/tpmcert_bridge.h"

/* ---------------- cgo bridge loading (dlopen) ---------------- */

/* The Go gRPC bridge lives in libtpmcertclient.so next to this module; the Go
 * runtime must be loaded in c-shared mode (not c-archive) to run safely inside
 * a foreign process. Resolve the bridge functions once at C_Initialize. */
static void *g_bridge = NULL;

static int (*bridge_init)(const char *);
static void (*bridge_shutdown)(void);
static int (*bridge_reload_manifest)(void);
static int (*bridge_installed_count)(void);
static int (*bridge_get_installed)(int, tpmcert_key_info *);
static int (*bridge_find_installed)(const char *, tpmcert_key_info *);
static void (*bridge_free_key_info)(tpmcert_key_info *);
static int (*bridge_sign_hash)(const char *, const uint8_t *, size_t, int, int, uint8_t *, size_t *);

#define BRIDGE_SO_NAME "libtpmcertclient.so"

static int bridge_load(void) {
    Dl_info info;
    if (!dladdr((void *)C_Initialize, &info) || !info.dli_fname) {
        fprintf(stderr, "ksp11: cannot locate module path\n");
        return 0;
    }
    char path[PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s", info.dli_fname);
    char *slash = strrchr(path, '/');
    if (slash) {
        *slash = '\0';
    } else {
        strcpy(path, ".");
    }
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "/%s", BRIDGE_SO_NAME);

    g_bridge = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!g_bridge) {
        fprintf(stderr, "ksp11: dlopen %s: %s\n", path, dlerror());
        return 0;
    }
#define KSP11_LOAD(sym)                                                         \
    do {                                                                        \
        *(void **)(&bridge_##sym) = dlsym(g_bridge, "tpmcert_" #sym);          \
        if (!bridge_##sym) {                                                    \
            fprintf(stderr, "ksp11: dlsym tpmcert_" #sym " failed: %s\n",       \
                    dlerror());                                                 \
            return 0;                                                           \
        }                                                                       \
    } while (0)
    KSP11_LOAD(init);
    KSP11_LOAD(shutdown);
    KSP11_LOAD(reload_manifest);
    KSP11_LOAD(installed_count);
    KSP11_LOAD(get_installed);
    KSP11_LOAD(find_installed);
    KSP11_LOAD(free_key_info);
    KSP11_LOAD(sign_hash);
#undef KSP11_LOAD
    return 1;
}

/* ---------------- token configuration ---------------- */

#define TOKEN_LABEL  "ksp11-token"

/* Debug logging: set KSP11_DEBUG=1 to trace calls. */
static int dbg_enabled(void) {
    static int v = -1;
    if (v < 0) {
        v = getenv("KSP11_DEBUG") ? atoi(getenv("KSP11_DEBUG")) : 0;
    }
    return v;
}
#define DBG(...) do { if (dbg_enabled()) { fprintf(stderr, "ksp11: " __VA_ARGS__); } } while (0)

/* ---------------- objects (one per remote certificate) ---------------- */

typedef struct {
    CK_OBJECT_HANDLE handle;
    CK_KEY_TYPE ktype;          /* CKK_RSA or CKK_EC */
    int key_size;               /* bits */
    char thumbprint[64];
    char label[512];
    CK_BYTE id[20];
    CK_ULONG id_len;
    CK_BYTE modulus[512];
    CK_ULONG modulus_len;
    CK_BYTE pubexp[8];
    CK_ULONG pubexp_len;
    CK_BYTE ec_params[64];
    CK_ULONG ec_params_len;
    CK_BYTE ec_point[512];
    CK_ULONG ec_point_len;
} ksp_object;

static ksp_object *g_objects = NULL;
static CK_ULONG g_object_count = 0;

/* ---------------- global state ---------------- */

static int g_initialized = 0;

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
    int obj_index;            /* index into g_objects */
    int digest_mech;          /* mechanism hashes input internally */
    int pss;                  /* RSA-PSS padding */
    const EVP_MD *md;         /* digest for digest mechanisms */
    int hash_alg;             /* 1=sha256 2=sha384 3=sha512, 0 = derive */
    CK_BYTE *buf;             /* accumulated input */
    CK_ULONG buflen, bufcap;
    CK_BYTE *cached;          /* signature cached for the size-query call */
    CK_ULONG cached_len;
} ksp_sign;

static ksp_sign g_sign[MAX_SESSIONS];

static void sign_reset(ksp_sign *st) {
    free(st->buf);
    free(st->cached);
    memset(st, 0, sizeof(*st));
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

static int mech_ok_for_type(CK_MECHANISM_TYPE t, CK_KEY_TYPE ktype) {
    if (ktype == CKK_RSA) {
        return t == CKM_RSA_PKCS || t == CKM_RSA_PKCS_PSS ||
               t == CKM_SHA256_RSA_PKCS || t == CKM_SHA384_RSA_PKCS || t == CKM_SHA512_RSA_PKCS ||
               t == CKM_SHA256_RSA_PKCS_PSS || t == CKM_SHA384_RSA_PKCS_PSS || t == CKM_SHA512_RSA_PKCS_PSS;
    }
    return t == CKM_ECDSA || t == CKM_ECDSA_SHA256 || t == CKM_ECDSA_SHA384 || t == CKM_ECDSA_SHA512;
}

/* ---------------- helpers ---------------- */

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static CK_ULONG hex_decode(const char *hex, CK_BYTE *out, CK_ULONG outcap) {
    size_t len = strlen(hex);
    CK_ULONG n = 0;
    for (size_t i = 0; i + 1 < len && n < outcap; i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            break;
        }
        out[n++] = (CK_BYTE)((hi << 4) | lo);
    }
    return n;
}

/* Parse the certificate's public key into CKA_MODULUS / CKA_PUBLIC_EXPONENT
 * (RSA) or CKA_EC_PARAMS / CKA_EC_POINT (EC). */
static void parse_cert_pubkey(const uint8_t *der, size_t derlen, ksp_object *o) {
    const unsigned char *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)derlen);
    if (!x) {
        return;
    }
    EVP_PKEY *pk = X509_get_pubkey(x);
    if (pk) {
        int base = EVP_PKEY_base_id(pk);
        if (base == EVP_PKEY_RSA) {
            o->ktype = CKK_RSA;
            BIGNUM *n = NULL, *e = NULL;
            if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &n) &&
                EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &e)) {
                o->modulus_len = BN_bn2bin(n, o->modulus);
                o->pubexp_len = BN_bn2bin(e, o->pubexp);
            }
            BN_free(n);
            BN_free(e);
        } else if (base == EVP_PKEY_EC) {
            o->ktype = CKK_EC;
            char curve[64] = {0};
            if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                                               curve, sizeof(curve), NULL)) {
                int nid = OBJ_txt2nid(curve);
                if (nid != NID_undef) {
                    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
                    o->ec_params_len = i2d_ASN1_OBJECT(obj, NULL);
                    if (o->ec_params_len <= sizeof(o->ec_params)) {
                        unsigned char *q = o->ec_params;
                        i2d_ASN1_OBJECT(obj, &q);
                    }
                }
            }
            CK_BYTE raw[256];
            size_t rawlen = 0;
            if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                                                raw, sizeof(raw), &rawlen) &&
                rawlen <= 254) {
                o->ec_point[0] = 0x04; /* DER OCTET STRING wrap */
                o->ec_point[1] = (CK_BYTE)rawlen;
                memcpy(o->ec_point + 2, raw, rawlen);
                o->ec_point_len = rawlen + 2;
            }
        }
        EVP_PKEY_free(pk);
    }
    X509_free(x);
}

/* DigestInfo prefixes for raw CKM_RSA_PKCS input parsing. */
static const unsigned char DI_PREFIX_SHA256[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
static const unsigned char DI_PREFIX_SHA384[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
static const unsigned char DI_PREFIX_SHA512[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

static int hash_alg_from_len(CK_ULONG len) {
    switch (len) {
    case 48:
        return 2;
    case 64:
        return 3;
    default:
        return 1;
    }
}

/* Extract the raw digest (+ hash algorithm) from raw RSA PKCS#1 input, which
 * is either a DER DigestInfo (with prefix) or a bare digest. */
static int parse_digest_info(const CK_BYTE *data, CK_ULONG len,
                             CK_BYTE *digest, CK_ULONG *digest_len, int *hash_alg) {
    if (len == 32 || len == 48 || len == 64) {
        memcpy(digest, data, len);
        *digest_len = len;
        *hash_alg = hash_alg_from_len(len);
        return 1;
    }
    const struct {
        const unsigned char *prefix;
        int hash_alg;
        CK_ULONG digest_len;
    } tbl[] = {
        { DI_PREFIX_SHA256, 1, 32 },
        { DI_PREFIX_SHA384, 2, 48 },
        { DI_PREFIX_SHA512, 3, 64 },
    };
    for (int i = 0; i < 3; i++) {
        if (len == 19 + tbl[i].digest_len &&
            memcmp(data, tbl[i].prefix, 19) == 0) {
            memcpy(digest, data + 19, tbl[i].digest_len);
            *digest_len = tbl[i].digest_len;
            *hash_alg = tbl[i].hash_alg;
            return 1;
        }
    }
    return 0;
}

/* pkcs11-provider expects ECDSA signatures as raw r||s (not DER), so convert
 * the DER signature returned by the server. */
static int ecdsa_der_to_raw(const unsigned char *der, size_t derlen, int field,
                            CK_BYTE **out, CK_ULONG *outlen) {
    const unsigned char *p = der;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long)derlen);
    if (!s) {
        return 0;
    }
    const BIGNUM *r = NULL, *ss = NULL;
    ECDSA_SIG_get0(s, &r, &ss);
    CK_BYTE *raw = malloc(2 * field);
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
    *outlen = (CK_ULONG)(2 * field);
    return 1;
}

/* ---------------- attribute helpers ---------------- */

static ksp_object *object_by_handle(CK_OBJECT_HANDLE h) {
    for (CK_ULONG i = 0; i < g_object_count; i++) {
        if (g_objects[i].handle == h) {
            return &g_objects[i];
        }
    }
    return NULL;
}

static CK_ULONG attr_size(CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type, int *sensitive) {
    ksp_object *o = object_by_handle(h);
    if (!o) {
        return 0;
    }
    switch (type) {
    case CKA_CLASS:
        return sizeof(CK_OBJECT_CLASS);
    case CKA_KEY_TYPE:
        return sizeof(CK_KEY_TYPE);
    case CKA_ID:
        return o->id_len;
    case CKA_LABEL:
        return strlen(o->label);
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
        return o->modulus_len;
    case CKA_PUBLIC_EXPONENT:
        return o->pubexp_len;
    case CKA_EC_PARAMS:
        return o->ec_params_len;
    case CKA_EC_POINT:
        return o->ec_point_len;
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
    case CKA_VALUE:
        *sensitive = 1;
        return 0;
    default:
        return 0;
    }
}

static CK_BBOOL bool_attr(CK_ATTRIBUTE_TYPE type) {
    switch (type) {
    case CKA_TOKEN:
    case CKA_DESTROYABLE:
    case CKA_COPYABLE:
    case CKA_SIGN:
    case CKA_VERIFY:
    case CKA_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
        return CK_TRUE;
    default:
        return CK_FALSE;
    }
}

/* ---------------- CK_FUNCTION_LIST entry points ---------------- */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    DBG("C_Initialize pInitArgs=%p\n", pInitArgs);
    if (g_initialized) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    if (pInitArgs) {
        CK_C_INITIALIZE_ARGS *args = (CK_C_INITIALIZE_ARGS *)pInitArgs;
        DBG("C_Initialize flags=0x%lx pReserved=%p\n",
            (unsigned long)args->flags, args->pReserved);
        if (args->pReserved) {
            return CKR_ARGUMENTS_BAD;
        }
    }

    /* Load the cgo gRPC bridge and connect to the cert-server. */
    if (!bridge_load()) {
        return CKR_DEVICE_ERROR;
    }
    const char *cfg = getenv("KSP11_CONFIG");
    if (bridge_init(cfg) != TPMCERT_OK) {
        fprintf(stderr, "ksp11: bridge init failed (cert-server unreachable or config missing)\n");
        return CKR_DEVICE_ERROR;
    }

    /* Enumerate remote certificates into token objects. */
    int n = bridge_installed_count();
    if (n > 0) {
        g_objects = calloc((size_t)n, sizeof(ksp_object));
        if (!g_objects) {
            bridge_shutdown();
            return CKR_HOST_MEMORY;
        }
        for (int i = 0; i < n; i++) {
            tpmcert_key_info info;
            memset(&info, 0, sizeof(info));
            if (bridge_get_installed(i, &info) != TPMCERT_OK) {
                continue;
            }
            ksp_object *o = &g_objects[g_object_count];
            o->handle = (CK_OBJECT_HANDLE)(g_object_count + 1);
            o->key_size = info.key_size;
            o->ktype = CKK_RSA; /* default; corrected by cert parse */
            o->id_len = hex_decode(info.thumbprint, o->id, sizeof(o->id));
            snprintf(o->thumbprint, sizeof(o->thumbprint), "%s", info.thumbprint);
            snprintf(o->label, sizeof(o->label), "%s", info.subject);
            if (info.cert_der != NULL && info.cert_der_len > 0) {
                parse_cert_pubkey(info.cert_der, info.cert_der_len, o);
            }
            DBG("object %lu: %s type=%lu size=%d\n",
                (unsigned long)o->handle, o->label,
                (unsigned long)o->ktype, o->key_size);
            g_object_count++;
            bridge_free_key_info(&info);
        }
    }

    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_sign, 0, sizeof(g_sign));
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
    free(g_objects);
    g_objects = NULL;
    g_object_count = 0;
    bridge_shutdown();
    if (g_bridge) {
        dlclose(g_bridge);
        g_bridge = NULL;
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
    memcpy(pInfo->libraryDescription, "ksp11 keyless PKCS#11 (gRPC)", 29);
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
    (void)tokenPresent;
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
    if (pMechanismList == NULL) {
        *pulCount = N_MECHS;
        return CKR_OK;
    }
    if (*pulCount < N_MECHS) {
        *pulCount = N_MECHS;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < N_MECHS; i++) {
        pMechanismList[i] = ksp_mechs[i].type;
    }
    *pulCount = N_MECHS;
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
    if (!find_mech(type)) {
        return CKR_MECHANISM_INVALID;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_SIGN | CKF_VERIFY;
    if (type == CKM_RSA_PKCS || type == CKM_RSA_PKCS_PSS ||
        type == CKM_SHA256_RSA_PKCS || type == CKM_SHA384_RSA_PKCS || type == CKM_SHA512_RSA_PKCS ||
        type == CKM_SHA256_RSA_PKCS_PSS || type == CKM_SHA384_RSA_PKCS_PSS || type == CKM_SHA512_RSA_PKCS_PSS) {
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
    (void)Notify;
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
    (void)ulPinLen;
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

/* ---------------- find state ---------------- */

static CK_OBJECT_HANDLE *g_find_handles = NULL;
static CK_ULONG g_find_n = 0, g_find_pos = 0;
static int g_find_active = 0;

static int object_matches(CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR tmpl, CK_ULONG n) {
    ksp_object *o = object_by_handle(h);
    if (!o) {
        return 0;
    }
    for (CK_ULONG i = 0; i < n; i++) {
        CK_ATTRIBUTE *a = &tmpl[i];
        switch (a->type) {
        case CKA_CLASS: {
            if (a->ulValueLen != sizeof(CK_OBJECT_CLASS)) {
                return 0;
            }
            CK_OBJECT_CLASS cls;
            memcpy(&cls, a->pValue, sizeof(cls));
            if (cls != CKO_PRIVATE_KEY) {
                return 0;
            }
            break;
        }
        case CKA_KEY_TYPE: {
            if (a->ulValueLen != sizeof(CK_KEY_TYPE)) {
                return 0;
            }
            CK_KEY_TYPE kt;
            memcpy(&kt, a->pValue, sizeof(kt));
            if (kt != o->ktype) {
                return 0;
            }
            break;
        }
        case CKA_LABEL: {
            if (a->ulValueLen != strlen(o->label) ||
                memcmp(a->pValue, o->label, a->ulValueLen) != 0) {
                return 0;
            }
            break;
        }
        case CKA_ID: {
            if (a->ulValueLen != o->id_len ||
                memcmp(a->pValue, o->id, a->ulValueLen) != 0) {
                return 0;
            }
            break;
        }
        default:
            return 0;
        }
    }
    return 1;
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
    free(g_find_handles);
    g_find_handles = NULL;
    g_find_n = 0;
    g_find_pos = 0;

    if (g_object_count > 0) {
        g_find_handles = malloc(g_object_count * sizeof(CK_OBJECT_HANDLE));
        if (!g_find_handles) {
            return CKR_HOST_MEMORY;
        }
        for (CK_ULONG i = 0; i < g_object_count; i++) {
            if (object_matches(g_objects[i].handle, pTemplate, ulCount)) {
                g_find_handles[g_find_n++] = g_objects[i].handle;
            }
        }
    }
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
    free(g_find_handles);
    g_find_handles = NULL;
    g_find_n = 0;
    g_find_pos = 0;
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
    ksp_object *o = object_by_handle(hObject);
    if (!o) {
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
        CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
        switch (a->type) {
        case CKA_CLASS:
            memcpy(p, &cls, sizeof(cls));
            break;
        case CKA_KEY_TYPE:
            memcpy(p, &o->ktype, sizeof(o->ktype));
            break;
        case CKA_ID:
            memcpy(p, o->id, o->id_len);
            break;
        case CKA_LABEL:
            memcpy(p, o->label, strlen(o->label));
            break;
        case CKA_TOKEN:
        case CKA_DESTROYABLE:
        case CKA_COPYABLE:
        case CKA_SIGN:
        case CKA_VERIFY:
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_PRIVATE:
        case CKA_MODIFIABLE:
        case CKA_EXTRACTABLE:
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_LOCAL:
        case CKA_SENSITIVE:
        case CKA_NEVER_EXTRACTABLE:
            b = bool_attr(a->type);
            memcpy(p, &b, sizeof(b));
            break;
        case CKA_MODULUS:
            memcpy(p, o->modulus, o->modulus_len);
            break;
        case CKA_PUBLIC_EXPONENT:
            memcpy(p, o->pubexp, o->pubexp_len);
            break;
        case CKA_EC_PARAMS:
            memcpy(p, o->ec_params, o->ec_params_len);
            break;
        case CKA_EC_POINT:
            memcpy(p, o->ec_point, o->ec_point_len);
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
    if (!object_by_handle(hObject)) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (!pulSize) {
        return CKR_ARGUMENTS_BAD;
    }
    *pulSize = 0;
    return CKR_OK;
}

/* ---------------- signing ---------------- */

static CK_RV do_sign(ksp_sign *st, const CK_BYTE *data, CK_ULONG len,
                     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!st->active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!pulSignatureLen) {
        return CKR_ARGUMENTS_BAD;
    }
    ksp_object *o = &g_objects[st->obj_index];
    DBG("sign obj=%s hash_alg=%d pss=%d digest_mech=%d len=%lu\n",
        o->thumbprint, st->hash_alg, st->pss, st->digest_mech, (unsigned long)len);

    /* Use a signature cached by a previous size-query call. */
    if (st->cached) {
        CK_BYTE *sig = st->cached;
        CK_ULONG sig_len = st->cached_len;
        st->cached = NULL;
        st->cached_len = 0;
        if (pSignature == NULL) {
            st->cached = sig;
            st->cached_len = sig_len;
            *pulSignatureLen = sig_len;
            return CKR_OK;
        }
        if (*pulSignatureLen < sig_len) {
            *pulSignatureLen = sig_len;
            free(sig);
            sign_reset(st);
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(pSignature, sig, sig_len);
        *pulSignatureLen = sig_len;
        free(sig);
        sign_reset(st);
        return CKR_OK;
    }

    /* Build the digest to send to the server. */
    CK_BYTE digest[64];
    CK_ULONG digest_len = 0;
    int hash_alg = st->hash_alg;

    if (st->digest_mech) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        unsigned int dlen = 0;
        int ok = mdctx != NULL &&
                 EVP_DigestInit_ex(mdctx, st->md, NULL) == 1 &&
                 EVP_DigestUpdate(mdctx, data, len) == 1 &&
                 EVP_DigestFinal_ex(mdctx, digest, &dlen) == 1;
        EVP_MD_CTX_free(mdctx);
        if (!ok) {
            sign_reset(st);
            return CKR_FUNCTION_FAILED;
        }
        digest_len = dlen;
    } else if (st->pss) {
        /* input is the digest itself */
        if (len > sizeof(digest)) {
            sign_reset(st);
            return CKR_DATA_INVALID;
        }
        memcpy(digest, data, len);
        digest_len = len;
        if (hash_alg == 0) {
            hash_alg = hash_alg_from_len(len);
        }
    } else if (o->ktype == CKK_EC) {
        /* input is the digest itself */
        if (len > sizeof(digest)) {
            sign_reset(st);
            return CKR_DATA_INVALID;
        }
        memcpy(digest, data, len);
        digest_len = len;
        hash_alg = hash_alg_from_len(len);
    } else {
        /* RSA PKCS1: input is a DER DigestInfo (or a bare digest) */
        if (!parse_digest_info(data, len, digest, &digest_len, &hash_alg)) {
            sign_reset(st);
            return CKR_DATA_INVALID;
        }
    }

    int padding = st->pss ? 2 : 1;

    size_t sig_len = 0;
    if (bridge_sign_hash(o->thumbprint, digest, digest_len, hash_alg,
                         padding, NULL, &sig_len) != TPMCERT_OK) {
        DBG("sign RPC (size) failed\n");
        sign_reset(st);
        return CKR_FUNCTION_FAILED;
    }
    if (sig_len == 0 || sig_len > 1024 * 1024) {
        sign_reset(st);
        return CKR_FUNCTION_FAILED;
    }
    /* ECDSA signatures are randomized: the follow-up call can produce a
     * slightly longer signature than the size query, so add slack. */
    CK_ULONG sig_cap = sig_len + 64;
    CK_BYTE *sig = malloc(sig_cap);
    if (!sig) {
        sign_reset(st);
        return CKR_HOST_MEMORY;
    }
    size_t actual = sig_cap;
    if (bridge_sign_hash(o->thumbprint, digest, digest_len, hash_alg,
                         padding, sig, &actual) != TPMCERT_OK) {
        DBG("sign RPC (data) failed\n");
        free(sig);
        sign_reset(st);
        return CKR_FUNCTION_FAILED;
    }
    sig_len = actual;

    /* pkcs11-provider expects ECDSA signatures as raw r||s. */
    if (o->ktype == CKK_EC) {
        int field = (o->key_size + 7) / 8;
        if (field <= 0 || field > 128) {
            free(sig);
            sign_reset(st);
            return CKR_FUNCTION_FAILED;
        }
        CK_BYTE *raw = NULL;
        CK_ULONG rawlen = 0;
        if (!ecdsa_der_to_raw(sig, sig_len, field, &raw, &rawlen)) {
            free(sig);
            sign_reset(st);
            return CKR_FUNCTION_FAILED;
        }
        free(sig);
        sig = raw;
        sig_len = rawlen;
    }

    if (pSignature == NULL) {
        /* Size query: cache the signature for the follow-up call. */
        st->cached = sig;
        st->cached_len = sig_len;
        *pulSignatureLen = sig_len;
        return CKR_OK;
    }
    if (*pulSignatureLen < sig_len) {
        *pulSignatureLen = sig_len;
        free(sig);
        sign_reset(st);
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pSignature, sig, sig_len);
    *pulSignatureLen = sig_len;
    free(sig);
    sign_reset(st);
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
    ksp_object *o = object_by_handle(hKey);
    if (!o) {
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
    if (!m || !mech_ok_for_type(pMechanism->mechanism, o->ktype)) {
        return CKR_MECHANISM_INVALID;
    }

    sign_reset(st);
    st->active = 1;
    st->obj_index = (int)(o - g_objects);
    st->digest_mech = m->digest_mech;
    st->pss = m->pss;
    st->md = m->md ? m->md() : NULL;
    st->hash_alg = 0;

    if (st->digest_mech) {
        if (st->md == EVP_sha384()) {
            st->hash_alg = 2;
        } else if (st->md == EVP_sha512()) {
            st->hash_alg = 3;
        } else {
            st->hash_alg = 1;
        }
    } else if (m->pss && pMechanism->pParameter &&
               pMechanism->ulParameterLen >= sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
        CK_RSA_PKCS_PSS_PARAMS *par = (CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
        switch (par->hashAlg) {
        case CKM_SHA384:
            st->hash_alg = 2;
            break;
        case CKM_SHA512:
            st->hash_alg = 3;
            break;
        case CKM_SHA256:
        default:
            st->hash_alg = 1;
            break;
        }
    }

    DBG("C_SignInit mech=0x%lx obj=%s hash_alg=%d\n",
        (unsigned long)pMechanism->mechanism, o->thumbprint, st->hash_alg);
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
    return do_sign(st, pData, ulDataLen, pSignature, pulSignatureLen);
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
    return do_sign(st, st->buf, st->buflen, pSignature, pulSignatureLen);
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
