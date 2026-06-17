#include "ksp.h"
#include <stdlib.h>
#include <string.h>

static BOOL g_bridgeReady = FALSE;

static SECURITY_STATUS EnsureBridge(void) {
    if (g_bridgeReady) {
        return ERROR_SUCCESS;
    }
    if (tpmcert_init(NULL) != TPMCERT_OK) {
        return NTE_INTERNAL_ERROR;
    }
    g_bridgeReady = TRUE;
    return ERROR_SUCCESS;
}

KSP_PROVIDER* KspValidateProvHandle(NCRYPT_PROV_HANDLE hProvider) {
    KSP_PROVIDER* p = (KSP_PROVIDER*)hProvider;
    if (p == NULL || p->cbLength != sizeof(KSP_PROVIDER) || p->dwMagic != KSP_PROVIDER_MAGIC) {
        return NULL;
    }
    return p;
}

KSP_KEY* KspValidateKeyHandle(NCRYPT_KEY_HANDLE hKey) {
    KSP_KEY* p = (KSP_KEY*)hKey;
    if (p == NULL || p->cbLength != sizeof(KSP_KEY) || p->dwMagic != KSP_KEY_MAGIC) {
        return NULL;
    }
    return p;
}

SECURITY_STATUS CreateNewKeyObject(LPCWSTR pszKeyName, KSP_KEY** ppKey) {
    KSP_KEY* pKey;
    size_t nameLen;
    if (ppKey == NULL || pszKeyName == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    pKey = (KSP_KEY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KSP_KEY));
    if (pKey == NULL) {
        return NTE_NO_MEMORY;
    }
    nameLen = (wcslen(pszKeyName) + 1) * sizeof(WCHAR);
    pKey->pszKeyName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, nameLen);
    if (pKey->pszKeyName == NULL) {
        HeapFree(GetProcessHeap(), 0, pKey);
        return NTE_NO_MEMORY;
    }
    CopyMemory(pKey->pszKeyName, pszKeyName, nameLen);
    pKey->cbLength = sizeof(KSP_KEY);
    pKey->dwMagic = KSP_KEY_MAGIC;
    pKey->dwAlgID = 1;
    pKey->dwExportPolicy = NCRYPT_ALLOW_EXPORT_FLAG;
    pKey->dwKeyUsagePolicy = NCRYPT_ALLOW_SIGNING_FLAG;
    *ppKey = pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS DeleteKeyObject(KSP_KEY* pKey) {
    if (pKey == NULL) {
        return ERROR_SUCCESS;
    }
    if (pKey->pbPubKeyInfo) {
        HeapFree(GetProcessHeap(), 0, pKey->pbPubKeyInfo);
    }
    if (pKey->pszKeyName) {
        HeapFree(GetProcessHeap(), 0, pKey->pszKeyName);
    }
    if (pKey->pszKeyBlobType) {
        HeapFree(GetProcessHeap(), 0, pKey->pszKeyBlobType);
    }
    HeapFree(GetProcessHeap(), 0, pKey);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS CopyWideProperty(LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, LPCWSTR value) {
    DWORD cb = (DWORD)((wcslen(value) + 1) * sizeof(WCHAR));
    if (pcbResult == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    *pcbResult = cb;
    if (pbOutput == NULL) {
        return ERROR_SUCCESS;
    }
    if (cbOutput < cb) {
        return NTE_BUFFER_TOO_SMALL;
    }
    CopyMemory(pbOutput, value, cb);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS CopyDwordProperty(PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD value) {
    if (pcbResult == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    *pcbResult = sizeof(DWORD);
    if (pbOutput == NULL) {
        return ERROR_SUCCESS;
    }
    if (cbOutput < sizeof(DWORD)) {
        return NTE_BUFFER_TOO_SMALL;
    }
    CopyMemory(pbOutput, &value, sizeof(DWORD));
    return ERROR_SUCCESS;
}

static NCRYPT_KEY_STORAGE_FUNCTION_TABLE KSPFunctionTable = {
    KSP_INTERFACE_VERSION,
    KSPOpenProvider,
    KSPOpenKey,
    KSPCreatePersistedKey,
    KSPGetProviderProperty,
    KSPGetKeyProperty,
    KSPSetProviderProperty,
    KSPSetKeyProperty,
    KSPFinalizeKey,
    KSPDeleteKey,
    KSPFreeProvider,
    KSPFreeKey,
    KSPFreeBuffer,
    KSPEncrypt,
    KSPDecrypt,
    KSPIsAlgSupported,
    KSPEnumAlgorithms,
    KSPEnumKeys,
    KSPImportKey,
    KSPExportKey,
    KSPSignHash,
    KSPVerifySignature,
    KSPPromptUser,
    KSPNotifyChangeKey,
    KSPSecretAgreement,
    KSPDeriveKey,
    KSPFreeSecret
};

NTSTATUS WINAPI GetKeyStorageInterface(
    LPCWSTR pszProviderName,
    NCRYPT_KEY_STORAGE_FUNCTION_TABLE** ppFunctionTable,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);
    if (ppFunctionTable == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ppFunctionTable = &KSPFunctionTable;
    return STATUS_SUCCESS;
}

SECURITY_STATUS WINAPI KSPOpenProvider(NCRYPT_PROV_HANDLE* phProvider, LPCWSTR pszProviderName, DWORD dwFlags) {
    KSP_PROVIDER* pProvider;
    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);
    if (phProvider == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    if (EnsureBridge() != ERROR_SUCCESS) {
        return NTE_INTERNAL_ERROR;
    }
    pProvider = (KSP_PROVIDER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KSP_PROVIDER));
    if (pProvider == NULL) {
        return NTE_NO_MEMORY;
    }
    pProvider->cbLength = sizeof(KSP_PROVIDER);
    pProvider->dwMagic = KSP_PROVIDER_MAGIC;
    pProvider->pszName = (LPWSTR)TPMCERT_KSP_PROVIDER_NAME;
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE hProvider) {
    KSP_PROVIDER* pProvider = KspValidateProvHandle(hProvider);
    if (pProvider == NULL) {
        return NTE_INVALID_HANDLE;
    }
    HeapFree(GetProcessHeap(), 0, pProvider);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPOpenKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE* phKey,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags) {
    KSP_PROVIDER* pProvider;
    SECURITY_STATUS status;
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    UNREFERENCED_PARAMETER(dwFlags);
    pProvider = KspValidateProvHandle(hProvider);
    if (pProvider == NULL) {
        return NTE_INVALID_HANDLE;
    }
    if (phKey == NULL || pszKeyName == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    status = StorageOpenKey(pszKeyName, (KSP_KEY**)phKey);
    return status;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE* phKey,
    LPCWSTR pszAlgId,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phKey);
    UNREFERENCED_PARAMETER(pszAlgId);
    UNREFERENCED_PARAMETER(pszKeyName);
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszProperty,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD* pcbResult,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwFlags);
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        return CopyWideProperty(pszProperty, pbOutput, cbOutput, pcbResult, TPMCERT_KSP_PROVIDER_NAME);
    }
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        return CopyDwordProperty(pbOutput, cbOutput, pcbResult, NCRYPT_IMPL_SOFTWARE_FLAG);
    }
    if (wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0) {
        return CopyDwordProperty(pbOutput, cbOutput, pcbResult, 0x00010000);
    }
    return NTE_INVALID_PARAMETER;
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszProperty,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD* pcbResult,
    DWORD dwFlags) {
    KSP_KEY* pKey;
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwFlags);
    pKey = KspValidateKeyHandle(hKey);
    if (pKey == NULL) {
        return NTE_INVALID_HANDLE;
    }
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        return CopyWideProperty(pszProperty, pbOutput, cbOutput, pcbResult, pKey->pszKeyName);
    }
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        return CopyWideProperty(pszProperty, pbOutput, cbOutput, pcbResult, BCRYPT_RSA_ALGORITHM);
    }
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0) {
        return CopyWideProperty(pszProperty, pbOutput, cbOutput, pcbResult, BCRYPT_RSA_ALGORITHM);
    }
    if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        return CopyDwordProperty(pbOutput, cbOutput, pcbResult, pKey->dwKeyBitLength);
    }
    if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        return CopyDwordProperty(pbOutput, cbOutput, pcbResult, pKey->dwKeyUsagePolicy);
    }
    if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) {
        return CopyDwordProperty(pbOutput, cbOutput, pcbResult, pKey->dwExportPolicy);
    }
    return NTE_INVALID_PARAMETER;
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszProperty,
    PBYTE pbInput,
    DWORD cbInput,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszProperty,
    PBYTE pbInput,
    DWORD cbInput,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFinalizeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeleteKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey) {
    KSP_KEY* pKey;
    UNREFERENCED_PARAMETER(hProvider);
    pKey = KspValidateKeyHandle(hKey);
    if (pKey == NULL) {
        return NTE_INVALID_HANDLE;
    }
    return DeleteKeyObject(pKey);
}

SECURITY_STATUS WINAPI KSPFreeBuffer(PVOID pvInput) {
    if (pvInput) {
        HeapFree(GetProcessHeap(), 0, pvInput);
    }
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPEncrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
    DWORD cbInput,
    VOID* pPaddingInfo,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD* pcbResult,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDecrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
    DWORD cbInput,
    VOID* pPaddingInfo,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD* pcbResult,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPIsAlgSupported(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId, DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwFlags);
    if (wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0) {
        return ERROR_SUCCESS;
    }
    return NTE_BAD_ALGID;
}

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    NCRYPT_PROV_HANDLE hProvider,
    DWORD dwAlgOperations,
    DWORD* pdwAlgCount,
    NCryptAlgorithmName** ppAlgList,
    DWORD dwFlags) {
    NCryptAlgorithmName* pList;
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwAlgOperations);
    UNREFERENCED_PARAMETER(dwFlags);
    if (pdwAlgCount == NULL || ppAlgList == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    pList = (NCryptAlgorithmName*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptAlgorithmName));
    if (pList == NULL) {
        return NTE_NO_MEMORY;
    }
    pList->pszName = (LPWSTR)BCRYPT_RSA_ALGORITHM;
    pList->dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
    pList->dwFlags = 0;
    *pdwAlgCount = 1;
    *ppAlgList = pList;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPEnumKeys(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszScope,
    NCryptKeyName** ppKeyName,
    PVOID* ppEnumState,
    DWORD dwFlags) {
    SECURITY_STATUS status;
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(pszScope);
    UNREFERENCED_PARAMETER(dwFlags);
    if (ppKeyName == NULL || ppEnumState == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    tpmcert_reload_manifest();
    if (*ppEnumState == NULL) {
        status = StorageEnumKeysBegin(ppEnumState, ppKeyName);
    } else {
        status = StorageEnumKeysNext(*ppEnumState, ppKeyName);
    }
    return status;
}

SECURITY_STATUS WINAPI KSPImportKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType,
    NCryptBufferDesc* pParameterList,
    NCRYPT_KEY_HANDLE* phKey,
    PBYTE pbData,
    DWORD cbData,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hImportKey);
    UNREFERENCED_PARAMETER(pszBlobType);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(phKey);
    UNREFERENCED_PARAMETER(pbData);
    UNREFERENCED_PARAMETER(cbData);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPExportKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    NCRYPT_KEY_HANDLE hExportKey,
    LPCWSTR pszBlobType,
    NCryptBufferDesc* pParameterList,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD* pcbResult,
    DWORD dwFlags) {
    KSP_KEY* pKey;
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hExportKey);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(dwFlags);
    pKey = KspValidateKeyHandle(hKey);
    if (pKey == NULL) {
        return NTE_INVALID_HANDLE;
    }
    if (pcbResult == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    if (wcscmp(pszBlobType, BCRYPT_PUBLIC_KEY_BLOB) != 0 &&
        wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) != 0) {
        return NTE_NOT_SUPPORTED;
    }
    *pcbResult = pKey->cbPubKeyInfo;
    if (pbOutput == NULL) {
        return ERROR_SUCCESS;
    }
    if (cbOutput < pKey->cbPubKeyInfo) {
        return NTE_BUFFER_TOO_SMALL;
    }
    CopyMemory(pbOutput, pKey->pbPubKeyInfo, pKey->cbPubKeyInfo);
    return ERROR_SUCCESS;
}

static int HashAlgFromPadding(BCRYPT_PKCS1_PADDING_INFO* pad, DWORD cbHash) {
    if (pad != NULL && pad->pszAlgId != NULL) {
        if (wcscmp(pad->pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0) return 1;
        if (wcscmp(pad->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) return 2;
        if (wcscmp(pad->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) return 3;
    }
    if (cbHash == 32) return 1;
    if (cbHash == 48) return 2;
    if (cbHash == 64) return 3;
    return 1;
}

SECURITY_STATUS WINAPI KSPSignHash(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    VOID* pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD* pcbResult,
    DWORD dwFlags) {
    KSP_KEY* pKey;
    char thumbprint[64];
    int hashAlg;
    int padding;
    size_t sigLen;
    int rc;
    UNREFERENCED_PARAMETER(hProvider);

    pKey = KspValidateKeyHandle(hKey);
    if (pKey == NULL) {
        return NTE_INVALID_HANDLE;
    }
    if (!pKey->fFinished) {
        return NTE_BAD_KEY_STATE;
    }
    if (pbHashValue == NULL || cbHashValue == 0 || pcbResult == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    if ((pKey->dwKeyUsagePolicy & NCRYPT_ALLOW_SIGNING_FLAG) == 0) {
        return NTE_PERM;
    }

    padding = 1;
    hashAlg = HashAlgFromPadding((BCRYPT_PKCS1_PADDING_INFO*)pPaddingInfo, cbHashValue);
    if (dwFlags & BCRYPT_PAD_PSS) {
        padding = 2;
    }

    WideCharToMultiByte(CP_UTF8, 0, pKey->pszKeyName, -1, thumbprint, sizeof(thumbprint), NULL, NULL);

    sigLen = cbSignature;
    rc = tpmcert_sign_hash(thumbprint, pbHashValue, cbHashValue, hashAlg, padding, pbSignature, &sigLen);
    if (rc == TPMCERT_BUFFER_TOO_SMALL) {
        *pcbResult = (DWORD)sigLen;
        return NTE_BUFFER_TOO_SMALL;
    }
    if (rc != TPMCERT_OK) {
        return NTE_INTERNAL_ERROR;
    }
    if (pbSignature == NULL) {
        *pcbResult = (DWORD)sigLen;
        return ERROR_SUCCESS;
    }
    *pcbResult = (DWORD)sigLen;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPVerifySignature(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    VOID* pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD dwFlags) {
    KSP_KEY* pKey;
    BCRYPT_ALG_HANDLE hRSA = NULL;
    BCRYPT_KEY_HANDLE hPub = NULL;
    NTSTATUS status;
    DWORD padFlags = 0;
    UNREFERENCED_PARAMETER(hProvider);

    pKey = KspValidateKeyHandle(hKey);
    if (pKey == NULL || pKey->pbPubKeyInfo == NULL) {
        return NTE_INVALID_HANDLE;
    }
    if (dwFlags & BCRYPT_PAD_PKCS1) {
        padFlags = BCRYPT_PAD_PKCS1;
    } else if (dwFlags & BCRYPT_PAD_PSS) {
        padFlags = BCRYPT_PAD_PSS;
    }
    status = BCryptOpenAlgorithmProvider(&hRSA, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        return NTE_INTERNAL_ERROR;
    }
    status = BCryptImportKeyPair(hRSA, NULL, BCRYPT_RSAPUBLIC_BLOB, &hPub, pKey->pbPubKeyInfo, pKey->cbPubKeyInfo, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hRSA, 0);
        return NTE_INTERNAL_ERROR;
    }
    status = BCryptVerifySignature(hPub, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, padFlags);
    BCryptDestroyKey(hPub);
    BCryptCloseAlgorithmProvider(hRSA, 0);
    if (!NT_SUCCESS(status)) {
        return NTE_BAD_SIGNATURE;
    }
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPPromptUser(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszOperation, DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPNotifyChangeKey(NCRYPT_PROV_HANDLE hProvider, HANDLE* phEvent, DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phEvent);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSecretAgreement(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hPrivKey,
    NCRYPT_KEY_HANDLE hPubKey,
    NCRYPT_SECRET_HANDLE* phAgreedSecret,
    DWORD dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hPrivKey);
    UNREFERENCED_PARAMETER(hPubKey);
    UNREFERENCED_PARAMETER(phAgreedSecret);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeriveKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret,
    LPCWSTR pwszKDF,
    NCryptBufferDesc* pParameterList,
    PUCHAR pbDerivedKey,
    DWORD cbDerivedKey,
    DWORD* pcbResult,
    ULONG dwFlags) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    UNREFERENCED_PARAMETER(pwszKDF);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(pbDerivedKey);
    UNREFERENCED_PARAMETER(cbDerivedKey);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeSecret(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret) {
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    return NTE_NOT_SUPPORTED;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved) {
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);
    if (dwReason == DLL_PROCESS_DETACH && g_bridgeReady) {
        tpmcert_shutdown();
        g_bridgeReady = FALSE;
    }
    return TRUE;
}
