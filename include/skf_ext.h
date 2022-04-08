#ifndef __SKF_EXT_H
#define __SKF_EXT_H

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#include "skf.h"

/**
 * @brief Global init
 *
 * @param szLibPath   [in] SKF device library path
 * @return ULONG SAR_OK - success, else - failed
 */
ULONG DEVAPI SKF_GlobalInit(LPSTR szLibPath);

/**
 * @brief Global clean
 *
 * @return ULONG SAR_OK - success, else - failed
 */
ULONG DEVAPI SKF_GlobalCleanup(void);

/**
 * @brief Error string
 *
 * @param iRet
 * @return LPSTR
 */
LPSTR DEVAPI SKF_StrError(ULONG iRet);

/**
 * @brief Authenticate device
 *
 * @param hDev [in] device handle
 * @return ULONG SAR_OK - success, else - failed
 */
ULONG DEVAPI SKF_AuthDev(DEVHANDLE hDev);

/**
 * @brief ECC Decrypt
 *
 * @param hContainer        [in] container handle
 * @param bSignFlag         [in] choose sign/encrypt keypair to decrypt
 * @param pCipherBlob       [in] cipher blob
 * @param pbPlainText       [out] plain data
 * @param pulPlainTextLen   [out] plain length
 * @return ULONG
 */
ULONG DEVAPI SKF_ECCDecrypt(HCONTAINER hContainer, BOOL bSignFlag,
    ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText, ULONG *pulPlainTextLen);

/**
 * @brief RSA Decrypt
 *
 * @param hContainer        [in] container handle
 * @param pbCipherText      [in] cipher data
 * @param ulCipherTextLen   [in] cipher length
 * @param pbPlainText       [out] plain data
 * @param pulPlainTextLen   [out] plain length
 * @return ULONG
 */
ULONG DEVAPI SKF_RSADecrypt(HCONTAINER hContainer, BYTE *pbCipherText,
    ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen);

#if 1
/**
 * @brief Authenticate and connect device
 *
 * @param pszName  [in] device name, NULL will choose the first
 * @param phDev    [out] device handle
 * @return ULONG
 */
ULONG DEVAPI SKF_AuthConnectDev(LPSTR pszName, DEVHANDLE *phDev);

/**
 * @brief Open or create application
 *
 * @param hDev           [in] device handle
 * @param szAppName      [in] application name
 * @param szAdminPin     [in] admin pin
 * @param szUserPin      [in] user pin
 * @param phApplication  [out] application handle
 * @return ULONG
 */
ULONG DEVAPI SKF_OpenOrCreateApp(DEVHANDLE hDev, LPSTR szAppName,
    LPSTR szAdminPin, LPSTR szUserPin, HAPPLICATION *phApplication);

/**
 * @brief Open or create container
 *
 * @param hApplication     [in] application handle
 * @param szContainerName  [in] container name
 * @param szUserPin        [in] user pin
 * @param phContainer      [out] container handle
 * @return ULONG
 */
ULONG DEVAPI SKF_OpenOrCreateCtnr(HAPPLICATION hApplication, LPSTR szContainerName,
    LPSTR szUserPin, HCONTAINER *phContainer);

#endif

#ifdef __cplusplus
}
#endif  /* __cplusplus */
#endif  /* __SKF_EXT_H */

