#ifndef TPMCERT_KSP_H
#define TPMCERT_KSP_H

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include "win_ncrypt_provider.h"
#include "tpmcert_bridge.h"

#define KSP_INTERFACE_VERSION BCRYPT_MAKE_INTERFACE_VERSION(1, 0)
#define KSP_PROVIDER_MAGIC 0x54504D43 /* TPMC */
#define KSP_KEY_MAGIC      0x54504D4B /* TPMK */

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#define TPMCERT_KSP_PROVIDER_NAME L"TPM Certificate Key Storage Provider"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _KSP_PROVIDER {
    DWORD cbLength;
    DWORD dwMagic;
    LPWSTR pszName;
} KSP_PROVIDER;

typedef struct _KSP_KEY {
    DWORD cbLength;
    DWORD dwMagic;
    LPWSTR pszKeyName;
    DWORD dwAlgID;
    DWORD dwKeyBitLength;
    DWORD dwExportPolicy;
    DWORD dwKeyUsagePolicy;
    BOOL fFinished;
    LPWSTR pszKeyBlobType;
    PBYTE pbPubKeyInfo;
    DWORD cbPubKeyInfo;
} KSP_KEY;

typedef struct _KSP_ENUM_STATE {
    DWORD dwIndex;
    DWORD dwCount;
} KSP_ENUM_STATE;

SECURITY_STATUS WINAPI KSPOpenProvider(NCRYPT_PROV_HANDLE* phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE hProvider);
SECURITY_STATUS WINAPI KSPOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPCreatePersistedKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPGetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPGetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFinalizeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDeleteKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey);
SECURITY_STATUS WINAPI KSPFreeBuffer(PVOID pvInput);
SECURITY_STATUS WINAPI KSPEncrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDecrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPIsAlgSupported(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPEnumAlgorithms(NCRYPT_PROV_HANDLE hProvider, DWORD dwAlgOperations, DWORD* pdwAlgCount, NCryptAlgorithmName** ppAlgList, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPEnumKeys(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszScope, NCryptKeyName** ppKeyName, PVOID* ppEnumState, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPImportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, NCryptBufferDesc* pParameterList, NCRYPT_KEY_HANDLE* phKey, PBYTE pbData, DWORD cbData, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPExportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc* pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSignHash(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPVerifySignature(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPPromptUser(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszOperation, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPNotifyChangeKey(NCRYPT_PROV_HANDLE hProvider, HANDLE* phEvent, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSecretAgreement(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hPrivKey, NCRYPT_KEY_HANDLE hPubKey, NCRYPT_SECRET_HANDLE* phAgreedSecret, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDeriveKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF, NCryptBufferDesc* pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD* pcbResult, ULONG dwFlags);
SECURITY_STATUS WINAPI KSPFreeSecret(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret);

KSP_PROVIDER* KspValidateProvHandle(NCRYPT_PROV_HANDLE hProvider);
KSP_KEY* KspValidateKeyHandle(NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS CreateNewKeyObject(LPCWSTR pszKeyName, KSP_KEY** ppKey);
SECURITY_STATUS DeleteKeyObject(KSP_KEY* pKey);

SECURITY_STATUS StorageInit(void);
void StorageShutdown(void);
SECURITY_STATUS StorageEnumKeysBegin(PVOID* ppEnumState, NCryptKeyName** ppKeyName);
SECURITY_STATUS StorageEnumKeysNext(PVOID pEnumState, NCryptKeyName** ppKeyName);
void StorageEnumKeysEnd(PVOID pEnumState);
SECURITY_STATUS StorageOpenKey(LPCWSTR pszKeyName, KSP_KEY** ppKey);

NTSTATUS WINAPI GetKeyStorageInterface(
    LPCWSTR pszProviderName,
    NCRYPT_KEY_STORAGE_FUNCTION_TABLE** ppFunctionTable,
    DWORD dwFlags);

#endif
