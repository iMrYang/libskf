#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf_driver.h"
#include "skf_dl.h"

typedef ULONG (DEVAPI *SKF_ECCPrvKeyDecrypt)(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText, ULONG *pulPlainTextLen);
typedef ULONG (DEVAPI *SKF_RSAPrvKeyDecrypt)(HCONTAINER hContainer, BYTE *pbCipherText, ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen);

static struct {
    BOOL                  bInit;
    SKF_ECCPrvKeyDecrypt  ECCDecrypt;
    SKF_RSAPrvKeyDecrypt  RSADecrypt;
} SKF_LONGMAI = {
    FALSE,
    NULL,
    NULL
};

static ULONG
InitDriver(HANDLE hDLL)
{
    if (SKF_LONGMAI.bInit) {
        return SAR_OK;
    }

    /* load ECCDecrypt */
    SKF_LONGMAI.ECCDecrypt = (SKF_ECCPrvKeyDecrypt)skf_dlsym(hDLL,
        "SKF_ECCPrvKeyDecrypt");
    if (NULL == SKF_LONGMAI.ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }

    /* load RSADecrypt */
    SKF_LONGMAI.RSADecrypt = (SKF_RSAPrvKeyDecrypt)skf_dlsym(hDLL,
        "SKF_RSAPrvKeyDecrypt");
    if (NULL == SKF_LONGMAI.RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }

    /* flag */
    SKF_LONGMAI.bInit = TRUE;

    return SAR_OK;
}

static ULONG
ExitDriver(void)
{
    memset(&SKF_LONGMAI, 0, sizeof(SKF_LONGMAI));
    return SAR_OK;
}

static ULONG DEVAPI
AuthDev(DEVHANDLE hDev)
{
    /* TODO: add LONGMAI default device auth */
    (void)hDev;
    return SAR_NOTSUPPORTYETERR;
}

static ULONG DEVAPI
ECCDecrypt(HCONTAINER hContainer, BOOL bSignFlag,
    ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF_LONGMAI.ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    if (TRUE == bSignFlag) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF_LONGMAI.ECCDecrypt(hContainer,
        pCipherBlob, pbPlainText, pulPlainTextLen);
}

static ULONG DEVAPI
RSADecrypt(HCONTAINER hContainer, BYTE *pbCipherText,
    ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF_LONGMAI.RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF_LONGMAI.RSADecrypt(hContainer, pbCipherText,
        ulCipherTextLen, pbPlainText, pulPlainTextLen);
}

/* LONGMAI */
const SKF_Driver_t SKF_Driver_LONGMAI = {
    (LPSTR)"Longmai",
    InitDriver,
    ExitDriver,
    AuthDev,
    ECCDecrypt,
    RSADecrypt
};

