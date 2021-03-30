#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>

#include <openssl/bn.h>

#include <shamir_scheme.h>

#pragma comment(lib, "crypt32.lib")

#define AES_BLOCK_SIZE 16
#define ENCRYPT_AES_CBC_BLOCK_SIZE(len) (len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE
#define HANDLER(func, message, body) if(func) {\
            printf("%i ",__LINE__);\
            printf(message);\
            printf(" %i\n",GetLastError());\
            body;\
            if(_getch())\
                exit(1);}


VOID acquireContext(HCRYPTPROV* phProv, LPCWSTR szContainer) {
    HANDLER(!CryptAcquireContext(phProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT|CRYPT_NEWKEYSET), "",
        {
            HANDLER(GetLastError() == NTE_BAD_KEYSET, 
                "A cryptographic service handle could not be acquired.");
            HANDLER(!CryptAcquireContext(phProv, szContainer, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET), 
                "Could not create a new key container." )
        });
}


VOID releaseCtx(HCRYPTPROV phProv)
{
    HANDLER(!CryptReleaseContext(phProv, 0), "The handle could not be released.");
}

VOID genKey(HCRYPTPROV phProv, HCRYPTKEY* hKey) 
{
    HANDLER(!CryptGenKey(phProv, CALG_AES_256, CRYPT_EXPORTABLE, hKey), "Error during CryptGenKey.");
}

VOID destroyKey(HCRYPTPROV hKey) 
{
    HANDLER(!CryptDestroyKey(hKey), "Error during CryptDestroyKey.");
}

VOID encMessage(HCRYPTKEY hKey, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen)
{
    HANDLER(!CryptEncrypt(hKey, 0, TRUE, 0, pbData, pdwDataLen, dwBufLen), "Getting EncryptedBlob size failed.");
}

VOID decMessage(HCRYPTKEY hKey, BYTE* pbData, DWORD* pdwDataLen) 
{
    HANDLER(!CryptDecrypt(hKey, 0, TRUE, NULL, pbData, pdwDataLen), "Error getting decrypted message size.");
}

VOID exportKey(HCRYPTKEY hKey, HCRYPTKEY hExportKey, DWORD dwBlobType, LPBYTE* ppbKeyBlob, LPDWORD pdwBlobLen)
{
    DWORD dwBlobLength;
    *ppbKeyBlob = NULL;
    *pdwBlobLen = 0;

    HANDLER(!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLength), "Error computing BLOB length.");
    HANDLER(!(*ppbKeyBlob = (LPBYTE)malloc(dwBlobLength)), "Out of memory. \n");
    HANDLER(!CryptExportKey(hKey, hExportKey, dwBlobType, 0, *ppbKeyBlob, &dwBlobLength), 
        "Error exporting key.", 
        { free(*ppbKeyBlob);
        *ppbKeyBlob = NULL; });

    *pdwBlobLen = dwBlobLength;
}

VOID importKey(HCRYPTPROV hProv, LPBYTE pbKeyBlob, DWORD dwBlobLen, HCRYPTKEY* hKey)
{
    HCRYPTHASH hHash;

    HANDLER(!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash), "Error during CryptCreateHash!");
    HANDLER(!CryptHashData(hHash, pbKeyBlob, dwBlobLen, 0),   "Error during CryptHashData!");
    HANDLER(!CryptDeriveKey(hProv, CALG_AES_256, hHash, NULL, hKey), "Error during CryptDeriveKey!");
    if (hHash)
        HANDLER(!CryptDestroyHash(hHash), "Error during CryptDestroyHash");
}

VOID partsInit(part_t parts[_N])
{
    for (int i = 0; i < _N; i++) {
        parts[i].shadow = BN_secure_new();
        parts[i].id = BN_secure_new();
    }
}


int main(int argc, char* argv[])
{
    //1 Gen K
    HCRYPTPROV hProv;
    LPCWSTR    szContainer = L"Container";
    acquireContext(&hProv, szContainer);

    HCRYPTKEY hKey;
    genKey(hProv, &hKey);

    //2 Gen MK
    const BIGNUM* mod = BN_get0_nist_prime_256();
    polynom_t pol;
    construct_polynom(&pol, mod);

    DWORD len = BN_num_bytes(pol.coeffs[0]);
    LPBYTE masterKeyBlob = (LPBYTE)malloc(len);
    BIGNUM* secret = BN_new();
    BN_copy(secret, pol.coeffs[0]);
    BN_bn2bin(secret, masterKeyBlob);

    HCRYPTKEY hMasterKey;
    importKey(hProv, masterKeyBlob, len, &hMasterKey);
    free(masterKeyBlob);

    //3 MK -> part[1] ... part[5]
    part_t parts[_N];
    partsInit(parts);
    share_secret(parts, &pol, mod);
    destruct_polynom(&pol);

    //4 E(MK,K)
    HCRYPTKEY derKey;
    LPBYTE    keyBlob;
    DWORD     keyLen;
    exportKey(hKey, 0, PLAINTEXTKEYBLOB, &keyBlob, &keyLen);
    importKey(hProv, keyBlob, keyLen, &derKey);
    encMessage(hMasterKey, keyBlob, &keyLen, 48);
    destroyKey(hMasterKey);

    //5 M
    const char* text = "text";
    BYTE* message = (BYTE*)malloc(AES_BLOCK_SIZE);
    memcpy(message, text, strlen(text));
    
    //6 C = E(K,M)
    DWORD encMessageLen = strlen(text);
    encMessage(derKey, message, &encMessageLen, ENCRYPT_AES_CBC_BLOCK_SIZE(encMessageLen));
    destroyKey(derKey);

    //7 Rec(3 of 5 parts)
    BIGNUM* recMasterKey = BN_new();
    restore_secret(recMasterKey, &parts[0], &parts[2], &parts[4], mod);

    DWORD  recMasterKeyLength = BN_num_bytes(recMasterKey);
    LPBYTE recMasterKeyBlob = (LPBYTE)malloc(recMasterKeyLength);
    BN_bn2bin(recMasterKey, recMasterKeyBlob);

    HCRYPTKEY hRecMasterKey;
    importKey(hProv, recMasterKeyBlob, recMasterKeyLength, &hRecMasterKey);
    free(recMasterKeyBlob);

    //8 D(MK,K)
    HCRYPTKEY hRecKey;
    decMessage(hRecMasterKey, keyBlob, &keyLen);
    importKey (hProv, keyBlob, keyLen, &hRecKey);
    encMessage(hRecMasterKey, keyBlob, &keyLen, ENCRYPT_AES_CBC_BLOCK_SIZE(keyLen));
    destroyKey(hRecMasterKey);

    //9 D(K,C)
    DWORD blockSize = AES_BLOCK_SIZE;
    decMessage(hRecKey, message, &blockSize);
    destroyKey(hRecKey);

    //10 CMP
    if (!memcmp(message, text, blockSize))
        printf("SUCCESS!");

    releaseCtx(hProv);

    free(message);

    _getch();
}
