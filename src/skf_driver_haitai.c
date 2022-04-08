#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf_driver.h"
#include "skf_dl.h"

typedef ULONG (DEVAPI *HAITAI_SKF_ECCDecrypt)(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText, ULONG *pulPlainTextLen);
typedef ULONG (DEVAPI *HAITAI_SKF_RSADecrypt)(HCONTAINER hContainer, BYTE *pbCipherText, ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen);

static struct {
    BOOL                   bInit;
    HAITAI_SKF_ECCDecrypt  ECCDecrypt;
    HAITAI_SKF_RSADecrypt  RSADecrypt;
} SKF_HAITAI = {
    FALSE,
    NULL,
    NULL
};

static ULONG
InitDriver(HANDLE hDLL)
{
    if (SKF_HAITAI.bInit) {
        return SAR_OK;
    }

    /* load ECCDecrypt */
    SKF_HAITAI.ECCDecrypt = (HAITAI_SKF_ECCDecrypt)skf_dlsym(hDLL,
        "SKF_ECCDecrypt");
    if (NULL == SKF_HAITAI.ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }

    /* load RSADecrypt */
    SKF_HAITAI.RSADecrypt = (HAITAI_SKF_RSADecrypt)skf_dlsym(hDLL,
        "SKF_RSADecrypt");
    if (NULL == SKF_HAITAI.RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }

    /* flag */
    SKF_HAITAI.bInit = TRUE;

    return SAR_OK;
}

static ULONG
ExitDriver(void)
{
    memset(&SKF_HAITAI, 0, sizeof(SKF_HAITAI));
    return SAR_OK;
}

static ULONG DEVAPI
AuthDev(DEVHANDLE hDev)
{
    /* TODO: add haitai default device auth */
    (void)hDev;
    return SAR_NOTSUPPORTYETERR;
}

static ULONG DEVAPI
ECCDecrypt(HCONTAINER hContainer, BOOL bSignFlag,
    ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF_HAITAI.ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    if (TRUE == bSignFlag) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF_HAITAI.ECCDecrypt(hContainer,
        pCipherBlob, pbPlainText, pulPlainTextLen);
}

static ULONG DEVAPI
RSADecrypt(HCONTAINER hContainer, BYTE *pbCipherText,
    ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF_HAITAI.RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF_HAITAI.RSADecrypt(hContainer, pbCipherText,
        ulCipherTextLen, pbPlainText, pulPlainTextLen);
}

/* HAITAI */
const SKF_Driver_t SKF_Driver_HAITAI = {
    (LPSTR)"Haitai",
    InitDriver,
    ExitDriver,
    AuthDev,
    ECCDecrypt,
    RSADecrypt
};

