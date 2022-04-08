#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf_driver.h"
#include "skf_dl.h"

typedef ULONG (DEVAPI *V_ECCPrvKeyDecrypt)(HCONTAINER hContainer, ULONG ulKeySpec, ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText, ULONG *pulPlainTextLen);
typedef ULONG (DEVAPI *V_RSAPrvKeyDecrypt)(HCONTAINER hContainer,BYTE *pbCipherText,ULONG ulCipherTextLen,BYTE *pbPlainText,ULONG *pulPlainTextLen);

static struct {
    BOOL                bInit;
    V_ECCPrvKeyDecrypt  ECCDecrypt;
    V_RSAPrvKeyDecrypt  RSADecrypt;
} SKF_CCORE = {
    FALSE,
    NULL,
    NULL
};

static ULONG
InitDriver(HANDLE hDLL)
{
    if (SKF_CCORE.bInit) {
        return SAR_OK;
    }

    /* load ECCDecrypt */
    SKF_CCORE.ECCDecrypt = (V_ECCPrvKeyDecrypt)skf_dlsym(hDLL,
        "V_ECCPrvKeyDecrypt");
    if (NULL == SKF_CCORE.ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }

    /* load RSADecrypt */
    SKF_CCORE.RSADecrypt = (V_RSAPrvKeyDecrypt)skf_dlsym(hDLL,
        "V_RSAPrvKeyDecrypt");
    if (NULL == SKF_CCORE.RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }

    /* flag */
    SKF_CCORE.bInit = TRUE;

    return SAR_OK;
}

static ULONG
ExitDriver(void)
{
    memset(&SKF_CCORE, 0, sizeof(SKF_CCORE));
    return SAR_OK;
}

static ULONG DEVAPI
AuthDev(DEVHANDLE hDev)
{
    int               iRet = SAR_FAIL;
    DEVINFO           devInfo;
    BYTE              authRand[16] = {0};
    ULONG             authRandLen = 8;
    BYTE              authKey[16] = {0};
    HANDLE            hKey = NULL;
    BLOCKCIPHERPARAM  encParam = {{0}, 0, 0, 0};
    BYTE              authData[16] = {0};
    ULONG             authDataLen = sizeof(authData);
    const LPSTR       ccoreKeyList[] = { (LPSTR)"1234567812345678", (LPSTR)"C*CORE SYS @ SZ " };
    size_t            i = 0;

    for (i = 0; i < sizeof(ccoreKeyList)/sizeof(LPSTR); i++) {
        /* set auth key */
        if (strlen((const char *)ccoreKeyList[i]) > sizeof(authKey)) {
            continue;
        }
        memcpy(authKey, ccoreKeyList[i], strlen((const char *)ccoreKeyList[i]));

        /* auth */
        memset(&devInfo, 0, sizeof(devInfo));

        if (SAR_OK != (iRet = SKF_GetDevInfo(hDev, &devInfo))
            || SAR_OK != (iRet = SKF_UnlockDev(hDev))
            || SAR_OK != (iRet = SKF_GenRandom(hDev, authRand, authRandLen))
            || SAR_OK != (iRet = SKF_SetSymmKey(hDev, authKey, devInfo.DevAuthAlgId, &hKey))
            || SAR_OK != (iRet = SKF_EncryptInit(hKey, encParam))
            || SAR_OK != (iRet = SKF_Encrypt(hKey, authRand, sizeof(authRand), authData, &authDataLen))
            || SAR_OK != (iRet = SKF_DevAuth(hDev, authData, authDataLen))
        ) {
            if (SAR_OK == iRet) {
                iRet = SAR_FAIL;
            }
            continue;
        }

        /* success */
        break;
    }
    if (hKey) {
        SKF_CloseHandle(hKey);
    }
    return iRet;
}

static ULONG DEVAPI
ECCDecrypt(HCONTAINER hContainer, BOOL bSignFlag,
    ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF_CCORE.ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    /* ulKeySpec: 1-encrypt usage, 2-sign usage */
    return SKF_CCORE.ECCDecrypt(hContainer, bSignFlag?2:1,
        pCipherBlob, pbPlainText, pulPlainTextLen);
}

static ULONG DEVAPI
RSADecrypt(HCONTAINER hContainer, BYTE *pbCipherText,
    ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF_CCORE.RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF_CCORE.RSADecrypt(hContainer, pbCipherText,
        ulCipherTextLen, pbPlainText, pulPlainTextLen);
}

/* CCORE */
const SKF_Driver_t SKF_Driver_CCORE = {
    (LPSTR)"C*Core",
    InitDriver,
    ExitDriver,
    AuthDev,
    ECCDecrypt,
    RSADecrypt
};

