#include <stdio.h>
#include <string.h>
#include "skf_ext.h"

#define PRINT_HEX(arr,len,fmt,...)   do { \
        int i; \
        unsigned char *p = (unsigned char *)(arr); \
        printf(fmt "\n",##__VA_ARGS__); \
        for (i = 0; p && i < (int)(len); i++) { \
            printf("0x%02x, ", p[i]); \
            if ((i + 1) % 16 == 0) {  \
                printf("\n"); \
            } \
        } \
        printf("\n"); \
    } while (0)

/* global config */
struct {
    const char *lib;
    const char *app_name;
    const char *admin_pin;
    const char *ctnr_name;
    const char *user_pin;
} skf;

static int skf_main(void);
static int skf_sm2_test_sign(DEVHANDLE hDev, HCONTAINER hCtnr);
static int skf_sm2_test_encrypt(DEVHANDLE hDev, HCONTAINER hCtnr);

int main(int argc, char *argv[])
{
    ULONG iRet = SAR_FAIL;
    ULONG iRv  = iRet;

    if (argc != 6) {
        printf("SKF - SKF Test tool\n");
        printf("\n");
        printf("Usage: %s [skf_lib] [app_name] [admin_pin] [ctnr_name] [user_pin]\n", argv[0]);
        printf("\n");
        return -1;
    }
    memset(&skf, 0, sizeof(skf));
    skf.lib       = argv[1];
    skf.app_name  = argv[2];
    skf.admin_pin = argv[3];
    skf.ctnr_name = argv[4];
    skf.user_pin  = argv[5];

    if (SAR_OK != (iRet = SKF_GlobalInit((LPSTR)skf.lib))) {
        fprintf(stderr, "SKF_GlobalInit return 0x%08x, lib: %s\n", iRet, skf.lib);
        return -1;
    }

    iRv = skf_main();

    if (SAR_OK != (iRet = SKF_GlobalCleanup())) {
        fprintf(stderr, "SKF_GlobalCleanup return 0x%08x\n", iRet);
        return -1;
    }

    return (SAR_OK == iRv) ? 0 : -1;
}

static int skf_main(void)
{
    ULONG         iRet = SAR_FAIL;
    DEVHANDLE     hDev = NULL;
    DEVINFO       DevInfo;
    HAPPLICATION  hApp = NULL;
    HCONTAINER    hCtnr = NULL;
    LPSTR         szAppName = (LPSTR)skf.app_name;
    LPSTR         szAdminPin = (LPSTR)skf.admin_pin;
    ULONG         ulRetryCount = 0;
    LPSTR         szContainerName = (LPSTR)skf.ctnr_name;
    LPSTR         szUserPin = (LPSTR)skf.user_pin;

    if (SAR_OK != (iRet = SKF_AuthConnectDev(NULL, &hDev))) {
        fprintf(stderr, "SKF_AuthConnectDev return 0x%08x:%s\n", iRet, SKF_StrError(iRet));
        return iRet;
    }

    /* get device info */
    memset(&DevInfo, 0, sizeof(DevInfo));
    if (SAR_OK != (iRet = SKF_GetDevInfo(hDev, &DevInfo))) {
        fprintf(stderr, "SKF_GetDevInfo return 0x%08x:%s\n", iRet, SKF_StrError(iRet));
        goto end;
    }

    /* print */
    printf("--------------------------------------------------------------------------------\n");
    printf("Version        : %d.%d\n", DevInfo.Version.major, DevInfo.Version.minor);
    printf("Manufacturer   : %.*s\n", (int)sizeof(DevInfo.Manufacturer), DevInfo.Manufacturer);
    printf("Issuer         : %.*s\n", (int)sizeof(DevInfo.Issuer), DevInfo.Issuer);
    printf("Label          : %.*s\n", (int)sizeof(DevInfo.Label), DevInfo.Label);
    printf("SerialNumber   : %.*s\n", (int)sizeof(DevInfo.SerialNumber), DevInfo.SerialNumber);
    printf("HWVersion      : %d.%d\n", DevInfo.HWVersion.major, DevInfo.HWVersion.minor);
    printf("FirmwareVersion: %d.%d\n", DevInfo.FirmwareVersion.major, DevInfo.FirmwareVersion.minor);
    printf("--------------------------------------------------------------------------------\n");

    /* open application */
    iRet = SKF_OpenApplication(hDev, szAppName, &hApp);
    if (SAR_OK != iRet) {
        fprintf(stderr, "open application %s return 0x%08x:%s\n", skf.app_name, iRet, SKF_StrError(iRet));
        goto end;
    }

    /* verify admin pin */
    if (SAR_OK != (iRet = SKF_VerifyPIN(hApp, ADMIN_TYPE, szAdminPin, &ulRetryCount))) {
        fprintf(stderr, "verify admin pin %s return 0x%08x:%s\n", skf.admin_pin, iRet, SKF_StrError(iRet));
        goto end;
    }

    /* open container */
    iRet = SKF_OpenContainer(hApp, szContainerName, &hCtnr);
    if (SAR_OK != iRet) {
        fprintf(stderr, "open container %s return 0x%08x:%s\n", skf.ctnr_name, iRet, SKF_StrError(iRet));
        goto end;
    }

    /* verify user pin */
    if (SAR_OK != (iRet = SKF_VerifyPIN(hApp, USER_TYPE, szUserPin, &ulRetryCount))) {
        fprintf(stderr, "verify user pin %s return 0x%08x:%s\n", skf.user_pin, iRet, SKF_StrError(iRet));
        goto end;
    }

    /* sm2 test */
    skf_sm2_test_sign(hDev, hCtnr);
    skf_sm2_test_encrypt(hDev, hCtnr);

    /* rsa test */

    /* success */
    iRet = SAR_OK;
end:
    SKF_CloseContainer(hCtnr);
    SKF_CloseApplication(hApp);
    SKF_DisConnectDev(hDev); hDev = NULL;

    return iRet;
}

static int skf_sm2_test_sign(DEVHANDLE hDev, HCONTAINER hCtnr)
{
    ULONG              iRet = SAR_FAIL;
    /* public key */
    BYTE               bSigPub[512] = {0};
    ULONG              ulSigPubLen = 0;
    /* digest */
    BYTE               bDigest[32];
    ULONG              ulDigestLen = sizeof(bDigest);
    /* sign */
    ECCSIGNATUREBLOB   Sig;
    ECCPUBLICKEYBLOB  *pSigECCPub = (ECCPUBLICKEYBLOB*)bSigPub;

    /* debug */
    PRINT_HEX(NULL, 0, "!!! Test Sign:");

    /* export sign usage public key */
    ulSigPubLen = sizeof(bSigPub);

    iRet = SKF_ExportPublicKey(hCtnr, TRUE, bSigPub, &ulSigPubLen);
    if (iRet != SAR_OK) {
        fprintf(stderr, "Error, export sign usage public key return 0x%08x\n", iRet);
        goto end;
    }
    PRINT_HEX(pSigECCPub->XCoordinate, sizeof(pSigECCPub->XCoordinate), "[SIG PUBLIC KEY-X]:");
    PRINT_HEX(pSigECCPub->YCoordinate, sizeof(pSigECCPub->YCoordinate), "[SIG PUBLIC KEY-Y]:");

    /* sign */
    memset(&Sig, 0, sizeof(Sig));

    iRet = SKF_ECCSignData(hCtnr, bDigest, ulDigestLen, &Sig);
    if (iRet != SAR_OK) {
        fprintf(stderr, "Error, do sign return 0x%08x\n", iRet);
        goto end;
    }

    /* verify */
    iRet = SKF_ExtECCVerify(hDev, pSigECCPub, bDigest, ulDigestLen, &Sig);
    if (iRet != SAR_OK) {
        fprintf(stderr, "Error, do verify return 0x%08x\n", iRet);
        goto end;
    }

    /* success */
    PRINT_HEX(NULL, 0, "Success");
    iRet = SAR_OK;
end:
    return iRet;
}

static int skf_sm2_test_encrypt(DEVHANDLE hDev, HCONTAINER hCtnr)
{
    ULONG              iRet = SAR_FAIL;
    /* public key */
    BYTE               bEncPub[512] = {0};
    ULONG              ulEncPubLen = 0;
    /* data */
    BYTE               bData[16];
    ULONG              ulDataLen = 0;
    /* cipher */
    BYTE               bCipher[sizeof(bEncPub)] = {0};
    /* plain */
    BYTE               bPlain[sizeof(bData)] = {0};
    ULONG              ulPlainLen = 0;
    ECCPUBLICKEYBLOB  *pEncECCPub = (ECCPUBLICKEYBLOB*)bEncPub;
    ECCCIPHERBLOB     *pECCCipher = (PECCCIPHERBLOB)bCipher;

    /* debug */
    PRINT_HEX(NULL, 0, "!!! Test Encrypt:");

    /* export encrypt usage public key */
    ulEncPubLen = sizeof(bEncPub);

    iRet = SKF_ExportPublicKey(hCtnr, FALSE, bEncPub, &ulEncPubLen);
    if (iRet != SAR_OK) {
        fprintf(stderr, "Error, export encrypt usage public key return 0x%08x\n", iRet);
        goto end;
    }
    PRINT_HEX(pEncECCPub->XCoordinate, sizeof(pEncECCPub->XCoordinate), "[ENC PUBLIC KEY-X]:");
    PRINT_HEX(pEncECCPub->YCoordinate, sizeof(pEncECCPub->YCoordinate), "[ENC PUBLIC KEY-Y]:");

    /* encrypt */
    ulDataLen = (ULONG)sizeof(bData);

    PRINT_HEX(bData, ulDataLen, "[DATA]:");

    iRet = SKF_ExtECCEncrypt(hDev, pEncECCPub, bData, ulDataLen, pECCCipher);
    if (iRet != SAR_OK) {
        fprintf(stderr, "Error, SM2 encrypt return 0x%08x\n", iRet);
        goto end;
    }
    PRINT_HEX(pECCCipher->XCoordinate, sizeof(pECCCipher->XCoordinate), "[CIPHER-X]:");
    PRINT_HEX(pECCCipher->YCoordinate, sizeof(pECCCipher->YCoordinate), "[CIPHER-Y]:");
    PRINT_HEX(pECCCipher->HASH, sizeof(pECCCipher->HASH), "[CIPHER-HASH]:");
    PRINT_HEX(pECCCipher->Cipher, pECCCipher->CipherLen, "[CIPHER-Cipher]:");

    /* decrypt */
    ulPlainLen = sizeof(bPlain);

    iRet = SKF_ECCDecrypt(hCtnr, FALSE, pECCCipher, bPlain, &ulPlainLen);
    if (iRet != SAR_OK) {
        fprintf(stderr, "Error, SM2 decrypt return 0x%08x\n", iRet);
        goto end;
    }
    PRINT_HEX(bPlain, ulPlainLen, "[Plain]:");

    /* success */
    PRINT_HEX(NULL, 0, "Success");
    iRet = SAR_OK;
end:
    return iRet;
}

