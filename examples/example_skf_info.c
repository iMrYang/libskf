#include <stdio.h>
#include <string.h>
#include "skf_ext.h"

/* global config */
struct {
    const char *lib;
} skf;

static int skf_main(void);
int main(int argc, char *argv[])
{
    ULONG iRet = SAR_FAIL;
    ULONG iRv  = iRet;

    if (argc != 2) {
        printf("SKF - SKF Test tool\n");
        printf("\n");
        printf("Usage: %s [skf_lib]\n", argv[0]);
        printf("\n");
        return -1;
    }
    memset(&skf, 0, sizeof(skf));
    skf.lib       = argv[1];

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
    CHAR          szAppList[1024] = {0};
    ULONG         ulAppListSize = sizeof(szAppList);
    CHAR         *pszAppName = NULL;

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

    /* enum device */
    if (SAR_OK != (iRet = SKF_EnumApplication(hDev, szAppList, &ulAppListSize))) {
        fprintf(stderr, "SKF_EnumApplication return 0x%08x:%s\n", iRet, SKF_StrError(iRet));
        goto end;
    }

    /* enum application */
    for (pszAppName = szAppList; *pszAppName; pszAppName = pszAppName + strlen((const char *)pszAppName) + 1) {
        HAPPLICATION  hApp = NULL;
        CHAR          szCtnrList[10240] = {0};
        ULONG         ulCtnrListSize = sizeof(szCtnrList);
        CHAR         *pszCtnrName = NULL;

        printf("Application: \"%s\"\n", (char *)pszAppName);

        /* open application */
        if (SAR_OK != (iRet = SKF_OpenApplication(hDev, pszAppName, &hApp))) {
            fprintf(stderr, "SKF_OpenApplication(%s) return 0x%08x:%s\n", (char *)pszAppName, iRet, SKF_StrError(iRet));
            continue;
        }

        /* enum container */
        if (SAR_OK != (iRet = SKF_EnumContainer(hApp, szCtnrList, &ulCtnrListSize))) {
            fprintf(stderr, "SKF_EnumContainer return 0x%08x:%s\n", iRet, SKF_StrError(iRet));
            SKF_CloseApplication(hApp);
            continue;
        }

        for (pszCtnrName = szCtnrList; *pszCtnrName; pszCtnrName = pszCtnrName + strlen((const char *)pszCtnrName) + 1) {
            printf("    Container: \"%s\"\n", (char *)pszCtnrName);
        }
        printf("\n");

        SKF_CloseApplication(hApp);
    }

    /* success */
    iRet = SAR_OK;
end:
    SKF_DisConnectDev(hDev); hDev = NULL;

    return iRet;
}
