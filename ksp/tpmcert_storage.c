#include "ksp.h"
#include <stdlib.h>
#include <string.h>

static NCryptKeyName* AllocKeyNameFromInfo(const tpmcert_key_info* info) {
    NCryptKeyName* pName;
    WCHAR wideName[64];
    WCHAR wideSubject[512];
    size_t nameLen;
    LPWSTR pszAlias;

    MultiByteToWideChar(CP_UTF8, 0, info->thumbprint, -1, wideName, 64);
    MultiByteToWideChar(CP_UTF8, 0, info->subject, -1, wideSubject, 512);

    nameLen = (wcslen(wideName) + 1) * sizeof(WCHAR);

    pName = (NCryptKeyName*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptKeyName) + nameLen);
    if (pName == NULL) {
        return NULL;
    }
    pName->pszName = (LPWSTR)((PBYTE)pName + sizeof(NCryptKeyName));
    pName->pszAlgid = (LPWSTR)BCRYPT_RSA_ALGORITHM;
    pName->dwLegacyKeySpec = AT_SIGNATURE;
    pName->dwFlags = 0;
    CopyMemory(pName->pszName, wideName, nameLen);
    pszAlias = wideSubject;
    if (wcslen(pszAlias) > 0) {
        pName->dwFlags = 0;
    }
    return pName;
}

static NCryptKeyName* BuildKeyName(int index) {
    tpmcert_key_info info;
    NCryptKeyName* pName;
    ZeroMemory(&info, sizeof(info));
    if (tpmcert_get_installed(index, &info) != TPMCERT_OK) {
        return NULL;
    }
    pName = AllocKeyNameFromInfo(&info);
    tpmcert_free_key_info(&info);
    return pName;
}

SECURITY_STATUS StorageInit(void) {
    if (tpmcert_init(NULL) != TPMCERT_OK) {
        return NTE_INTERNAL_ERROR;
    }
    return ERROR_SUCCESS;
}

void StorageShutdown(void) {
    tpmcert_shutdown();
}

SECURITY_STATUS StorageEnumKeysBegin(PVOID* ppEnumState, NCryptKeyName** ppKeyName) {
    KSP_ENUM_STATE* state;
    int count;

    if (ppEnumState == NULL || ppKeyName == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    count = tpmcert_installed_count();
    if (count == 0) {
        return NTE_NO_MORE_ITEMS;
    }
    state = (KSP_ENUM_STATE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KSP_ENUM_STATE));
    if (state == NULL) {
        return NTE_NO_MEMORY;
    }
    state->dwCount = (DWORD)count;
    state->dwIndex = 0;
    *ppEnumState = state;
    *ppKeyName = BuildKeyName(0);
    if (*ppKeyName == NULL) {
        HeapFree(GetProcessHeap(), 0, state);
        *ppEnumState = NULL;
        return NTE_INTERNAL_ERROR;
    }
    state->dwIndex = 1;
    return ERROR_SUCCESS;
}

SECURITY_STATUS StorageEnumKeysNext(PVOID pEnumState, NCryptKeyName** ppKeyName) {
    KSP_ENUM_STATE* state = (KSP_ENUM_STATE*)pEnumState;
    if (state == NULL || ppKeyName == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    if (state->dwIndex >= state->dwCount) {
        return NTE_NO_MORE_ITEMS;
    }
    *ppKeyName = BuildKeyName((int)state->dwIndex);
    if (*ppKeyName == NULL) {
        return NTE_INTERNAL_ERROR;
    }
    state->dwIndex++;
    return ERROR_SUCCESS;
}

void StorageEnumKeysEnd(PVOID pEnumState) {
    if (pEnumState) {
        HeapFree(GetProcessHeap(), 0, pEnumState);
    }
}

SECURITY_STATUS StorageOpenKey(LPCWSTR pszKeyName, KSP_KEY** ppKey) {
    tpmcert_key_info info;
    char thumbprint[64];
    KSP_KEY* pKey;
    SECURITY_STATUS status;

    if (pszKeyName == NULL || ppKey == NULL) {
        return NTE_INVALID_PARAMETER;
    }
    WideCharToMultiByte(CP_UTF8, 0, pszKeyName, -1, thumbprint, sizeof(thumbprint), NULL, NULL);
    ZeroMemory(&info, sizeof(info));
    if (tpmcert_find_installed(thumbprint, &info) != TPMCERT_OK) {
        return NTE_BAD_KEYSET;
    }

    status = CreateNewKeyObject(pszKeyName, &pKey);
    if (status != ERROR_SUCCESS) {
        tpmcert_free_key_info(&info);
        return status;
    }

    pKey->dwKeyBitLength = (DWORD)info.key_size;
    pKey->fFinished = TRUE;
    if (info.rsa_public_blob_len > 0) {
        pKey->pbPubKeyInfo = (PBYTE)HeapAlloc(GetProcessHeap(), 0, info.rsa_public_blob_len);
        if (pKey->pbPubKeyInfo == NULL) {
            DeleteKeyObject(pKey);
            tpmcert_free_key_info(&info);
            return NTE_NO_MEMORY;
        }
        CopyMemory(pKey->pbPubKeyInfo, info.rsa_public_blob, info.rsa_public_blob_len);
        pKey->cbPubKeyInfo = (DWORD)info.rsa_public_blob_len;
    }
    tpmcert_free_key_info(&info);
    *ppKey = pKey;
    return ERROR_SUCCESS;
}
