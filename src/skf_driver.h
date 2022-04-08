#ifndef __SKF_DRIVER_H
#define __SKF_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#include "skf_ext.h"

/**
 * @brief SKF Function
 *
 */
# define SKF_FUNC_PTR(name)             SKF_##name##_PTR
# define SKF_FUNC_PTR_DEF(name,args)    typedef ULONG (DEVAPI *SKF_##name##_PTR) args

/**
 * @brief Default Config
 *
 */
#define SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT   10
#define SKF_DEFAULT_USER_PIN_RETRY_COUNT    10
#define SKF_DEFAULT_FILE_RIGHTS             0

/* SKF Standard API */
SKF_FUNC_PTR_DEF(WaitForDevEvent, (LPSTR szDevName,ULONG *pulDevNameLen,ULONG *pulEvent));
SKF_FUNC_PTR_DEF(CancelWaitForDevEvent, (void));
SKF_FUNC_PTR_DEF(EnumDev, (BOOL bPresent,LPSTR szNameList,ULONG *pulSize));
SKF_FUNC_PTR_DEF(ConnectDev, (LPSTR szName,DEVHANDLE *phDev));
SKF_FUNC_PTR_DEF(DisConnectDev, (DEVHANDLE hDev));
SKF_FUNC_PTR_DEF(GetDevState, (LPSTR szDevName,ULONG *pulDevState));
SKF_FUNC_PTR_DEF(SetLabel, (DEVHANDLE hDev,LPSTR szLabel));
SKF_FUNC_PTR_DEF(GetDevInfo, (DEVHANDLE hDev,DEVINFO *pDevInfo));
SKF_FUNC_PTR_DEF(LockDev, (DEVHANDLE hDev,ULONG ulTimeOut));
SKF_FUNC_PTR_DEF(UnlockDev, (DEVHANDLE hDev));
SKF_FUNC_PTR_DEF(Transmit, (DEVHANDLE hDev,BYTE *pbCommand,ULONG ulCommandLen,BYTE *pbData,ULONG *pulDataLen));
SKF_FUNC_PTR_DEF(ChangeDevAuthKey, (DEVHANDLE hDev,BYTE *pbKeyValue,ULONG ulKeyLen));
SKF_FUNC_PTR_DEF(DevAuth, (DEVHANDLE hDev,BYTE *pbAuthData,ULONG ulLen));
SKF_FUNC_PTR_DEF(ChangePIN, (HAPPLICATION hApplication,ULONG ulPINType,LPSTR szOldPin,LPSTR szNewPin,ULONG *pulRetryCount));
SKF_FUNC_PTR_DEF(GetPINInfo, (HAPPLICATION hApplication,ULONG ulPINType,ULONG *pulMaxRetryCount,ULONG *pulRemainRetryCount,BOOL *pbDefaultPin));
SKF_FUNC_PTR_DEF(VerifyPIN, (HAPPLICATION hApplication,ULONG ulPINType,LPSTR szPIN,ULONG *pulRetryCount));
SKF_FUNC_PTR_DEF(UnblockPIN, (HAPPLICATION hApplication,LPSTR szAdminPIN,LPSTR szNewUserPIN,ULONG *pulRetryCount));
SKF_FUNC_PTR_DEF(ClearSecureState, (HAPPLICATION hApplication));
SKF_FUNC_PTR_DEF(CreateApplication, (DEVHANDLE hDev,LPSTR szAppName,LPSTR szAdminPin,DWORD dwAdminPinRetryCount,LPSTR szUserPin,DWORD dwUserPinRetryCount,DWORD dwCreateFileRights,HAPPLICATION *phApplication));
SKF_FUNC_PTR_DEF(EnumApplication, (DEVHANDLE hDev,LPSTR szAppName,ULONG *pulSize));
SKF_FUNC_PTR_DEF(DeleteApplication, (DEVHANDLE hDev,LPSTR szAppName));
SKF_FUNC_PTR_DEF(OpenApplication, (DEVHANDLE hDev,LPSTR szAppName,HAPPLICATION *phApplication));
SKF_FUNC_PTR_DEF(CloseApplication, (HAPPLICATION hApplication));
SKF_FUNC_PTR_DEF(CreateFile, (HAPPLICATION hApplication,LPSTR szFileName,ULONG ulFileSize,ULONG ulReadRights,ULONG ulWriteRights));
SKF_FUNC_PTR_DEF(DeleteFile, (HAPPLICATION hApplication,LPSTR szFileName));
SKF_FUNC_PTR_DEF(EnumFiles, (HAPPLICATION hApplication,LPSTR szFileList,ULONG *pulSize));
SKF_FUNC_PTR_DEF(GetFileInfo, (HAPPLICATION hApplication,LPSTR szFileName,FILEATTRIBUTE *pFileInfo));
SKF_FUNC_PTR_DEF(ReadFile, (HAPPLICATION hApplication,LPSTR szFileName,ULONG ulOffset,ULONG ulSize,BYTE *pbOutData,ULONG *pulOutLen));
SKF_FUNC_PTR_DEF(WriteFile, (HAPPLICATION hApplication,LPSTR szFileName,ULONG ulOffset,BYTE *pbData,ULONG ulSize));
SKF_FUNC_PTR_DEF(CreateContainer, (HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer));
SKF_FUNC_PTR_DEF(DeleteContainer, (HAPPLICATION hApplication,LPSTR szContainerName));
SKF_FUNC_PTR_DEF(OpenContainer, (HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer));
SKF_FUNC_PTR_DEF(CloseContainer, (HCONTAINER hContainer));
SKF_FUNC_PTR_DEF(EnumContainer, (HAPPLICATION hApplication,LPSTR szContainerName,ULONG *pulSize));
SKF_FUNC_PTR_DEF(GetContainerType, (HCONTAINER hContainer,ULONG *pulContainerType));
SKF_FUNC_PTR_DEF(ImportCertificate, (HCONTAINER hContainer,BOOL bExportSignKey,BYTE *pbCert,ULONG ulCertLen));
SKF_FUNC_PTR_DEF(ExportCertificate, (HCONTAINER hContainer,BOOL bSignFlag,BYTE *pbCert,ULONG *pulCertLen));
SKF_FUNC_PTR_DEF(GenRandom, (DEVHANDLE hDev,BYTE *pbRandom,ULONG ulRandomLen));
SKF_FUNC_PTR_DEF(GenExtRSAKey, (DEVHANDLE hDev,ULONG ulBitsLen,RSAPRIVATEKEYBLOB *pBlob));
SKF_FUNC_PTR_DEF(GenRSAKeyPair, (HCONTAINER hContainer,ULONG ulBitsLen,RSAPUBLICKEYBLOB *pBlob));
SKF_FUNC_PTR_DEF(ImportRSAKeyPair, (HCONTAINER hContainer,ULONG ulSymAlgId,BYTE *pbWrappedKey,ULONG ulWrappedKeyLen,BYTE *pbEncryptedData,ULONG ulEncryptedDataLen));
SKF_FUNC_PTR_DEF(RSASignData, (HCONTAINER hContainer,BYTE *pbData,ULONG ulDataLen,BYTE *pbSignature,ULONG *pulSignLen));
SKF_FUNC_PTR_DEF(RSAVerify, (DEVHANDLE hDev,RSAPUBLICKEYBLOB *pRSAPubKeyBlob,BYTE *pbData,ULONG ulDataLen,BYTE *pbSignature,ULONG ulSignLen));
SKF_FUNC_PTR_DEF(RSAExportSessionKey, (HCONTAINER hContainer,ULONG ulAlgId,RSAPUBLICKEYBLOB *pPubKey,BYTE *pbData,ULONG *pulDataLen,HANDLE *phSessionKey));
SKF_FUNC_PTR_DEF(ExtRSAPubKeyOperation, (DEVHANDLE hDev,RSAPUBLICKEYBLOB *pRSAPubKeyBlob,BYTE *pbInput,ULONG ulInputLen,BYTE *pbOutput,ULONG *pulOutputLen));
SKF_FUNC_PTR_DEF(ExtRSAPriKeyOperation, (DEVHANDLE hDev,RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,BYTE *pbInput,ULONG ulInputLen,BYTE *pbOutput,ULONG *pulOutputLen));
SKF_FUNC_PTR_DEF(GenECCKeyPair, (HCONTAINER hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pBlob));
SKF_FUNC_PTR_DEF(ImportECCKeyPair, (HCONTAINER hContainer,ENVELOPEDKEYBLOB *pEnvelopedKeyBlob));
SKF_FUNC_PTR_DEF(ECCSignData, (HCONTAINER hContainer,BYTE *pbDigest,ULONG ulDigestLen,ECCSIGNATUREBLOB *pSignature));
SKF_FUNC_PTR_DEF(ECCVerify, (DEVHANDLE hDev,ECCPUBLICKEYBLOB *pECCPubKeyBlob,BYTE *pbData,ULONG ulDataLen,ECCSIGNATUREBLOB *pSignature));
SKF_FUNC_PTR_DEF(ECCExportSessionKey, (HCONTAINER hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pPubKey,ECCCIPHERBLOB *pData,HANDLE *phSessionKey));
SKF_FUNC_PTR_DEF(ExtECCEncrypt, (DEVHANDLE hDev,ECCPUBLICKEYBLOB *pECCPubKeyBlob,BYTE *pbPlainText,ULONG ulPlainTextLen,ECCCIPHERBLOB *pCipherText));
SKF_FUNC_PTR_DEF(ExtECCDecrypt, (DEVHANDLE hDev,ECCPRIVATEKEYBLOB *pECCPriKeyBlob,ECCCIPHERBLOB *pCipherText,BYTE *pbPlainText,ULONG *pulPlainTextLen));
SKF_FUNC_PTR_DEF(ExtECCSign, (DEVHANDLE hDev,ECCPRIVATEKEYBLOB *pECCPriKeyBlob,BYTE *pbData,ULONG ulDataLen,ECCSIGNATUREBLOB *pSignature));
SKF_FUNC_PTR_DEF(ExtECCVerify, (DEVHANDLE hDev,ECCPUBLICKEYBLOB *pECCPubKeyBlob,BYTE *pbData,ULONG ulDataLen,ECCSIGNATUREBLOB *pSignature));
SKF_FUNC_PTR_DEF(GenerateAgreementDataWithECC, (HCONTAINER hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,BYTE *pbID,ULONG ulIDLen,HANDLE *phAgreementHandle));
SKF_FUNC_PTR_DEF(GenerateAgreementDataAndKeyWithECC, (HANDLE hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,BYTE *pbID,ULONG ulIDLen,BYTE *pbSponsorID,ULONG ulSponsorIDLen,HANDLE *phKeyHandle));
SKF_FUNC_PTR_DEF(GenerateKeyWithECC, (HANDLE hAgreementHandle,ECCPUBLICKEYBLOB *pECCPubKeyBlob,ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,BYTE *pbID,ULONG ulIDLen,HANDLE *phKeyHandle));
SKF_FUNC_PTR_DEF(ExportPublicKey, (HCONTAINER hContainer,BOOL bSignFlag,BYTE *pbBlob,ULONG *pulBlobLen));
SKF_FUNC_PTR_DEF(ImportSessionKey, (HCONTAINER hContainer,ULONG ulAlgId,BYTE *pbWrapedData,ULONG ulWrapedLen,HANDLE *phKey));
SKF_FUNC_PTR_DEF(SetSymmKey, (DEVHANDLE hDev,BYTE *pbKey,ULONG ulAlgID,HANDLE *phKey));
SKF_FUNC_PTR_DEF(EncryptInit, (HANDLE hKey,BLOCKCIPHERPARAM EncryptParam));
SKF_FUNC_PTR_DEF(Encrypt, (HANDLE hKey,BYTE *pbData,ULONG ulDataLen,BYTE *pbEncryptedData,ULONG *pulEncryptedLen));
SKF_FUNC_PTR_DEF(EncryptUpdate, (HANDLE hKey,BYTE *pbData,ULONG ulDataLen,BYTE *pbEncryptedData,ULONG *pulEncryptedLen));
SKF_FUNC_PTR_DEF(EncryptFinal, (HANDLE hKey,BYTE *pbEncryptedData,ULONG *pulEncryptedDataLen));
SKF_FUNC_PTR_DEF(DecryptInit, (HANDLE hKey,BLOCKCIPHERPARAM DecryptParam));
SKF_FUNC_PTR_DEF(Decrypt, (HANDLE hKey,BYTE *pbEncryptedData,ULONG ulEncryptedLen,BYTE *pbData,ULONG *pulDataLen));
SKF_FUNC_PTR_DEF(DecryptUpdate, (HANDLE hKey,BYTE *pbEncryptedData,ULONG ulEncryptedLen,BYTE *pbData,ULONG *pulDataLen));
SKF_FUNC_PTR_DEF(DecryptFinal, (HANDLE hKey,BYTE *pbDecryptedData,ULONG *pulDecryptedDataLen));
SKF_FUNC_PTR_DEF(DigestInit, (DEVHANDLE hDev,ULONG ulAlgID,ECCPUBLICKEYBLOB *pPubKey,BYTE *pbID,ULONG ulIDLen,HANDLE *phHash));
SKF_FUNC_PTR_DEF(Digest, (HANDLE hHash,BYTE *pbData,ULONG ulDataLen,BYTE *pbHashData,ULONG *pulHashLen));
SKF_FUNC_PTR_DEF(DigestUpdate, (HANDLE hHash,BYTE *pbData,ULONG ulDataLen));
SKF_FUNC_PTR_DEF(DigestFinal, (HANDLE hHash,BYTE *pHashData,ULONG *pulHashLen));
SKF_FUNC_PTR_DEF(MacInit, (HANDLE hKey,BLOCKCIPHERPARAM *pMacParam,HANDLE *phMac));
SKF_FUNC_PTR_DEF(Mac, (HANDLE hMac,BYTE *pbData,ULONG ulDataLen,BYTE *pbMacData,ULONG *pulMacLen));
SKF_FUNC_PTR_DEF(MacUpdate, (HANDLE hMac,BYTE *pbData,ULONG ulDataLen));
SKF_FUNC_PTR_DEF(MacFinal, (HANDLE hMac,BYTE *pbMacData,ULONG *pulMacDataLen));
SKF_FUNC_PTR_DEF(CloseHandle, (HANDLE hHandle));

/* SKF Extention API */
SKF_FUNC_PTR_DEF(AuthDev, (DEVHANDLE hDev));
SKF_FUNC_PTR_DEF(ECCDecrypt, (HCONTAINER hContainer,BOOL bSignFlag,ECCCIPHERBLOB *pCipherBlob,BYTE *pbPlainText,ULONG *pulPlainTextLen));
SKF_FUNC_PTR_DEF(RSADecrypt, (HCONTAINER hContainer,BYTE *pbCipherText,ULONG ulCipherTextLen,BYTE *pbPlainText,ULONG *pulPlainTextLen));

/**
 * @brief SKF extension
 *
 */
typedef struct {
    LPSTR                     szName;
    ULONG                   (*InitDriver)(HANDLE hDLL);
    ULONG                   (*ExitDriver)(void);
    SKF_FUNC_PTR(AuthDev)     AuthDev;
    SKF_FUNC_PTR(ECCDecrypt)  ECCDecrypt;
    SKF_FUNC_PTR(RSADecrypt)  RSADecrypt;
} SKF_Driver_t;

#ifdef __cplusplus
}
#endif  /* __cplusplus */
#endif  /* __SKF_DRIVER_H */

