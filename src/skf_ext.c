#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf_driver.h"
#include "skf_dl.h"

/**
 * @brief SKF struct
 *
 */
typedef struct SKF_s {
    /* hDLL */
    HANDLE                                           hDLL;
    /* Flags */
    BOOL                                             bInit;
    /* Standard SKF API */
    SKF_FUNC_PTR(WaitForDevEvent)                    WaitForDevEvent;
    SKF_FUNC_PTR(CancelWaitForDevEvent)              CancelWaitForDevEvent;
    SKF_FUNC_PTR(EnumDev)                            EnumDev;
    SKF_FUNC_PTR(ConnectDev)                         ConnectDev;
    SKF_FUNC_PTR(DisConnectDev)                      DisConnectDev;
    SKF_FUNC_PTR(GetDevState)                        GetDevState;
    SKF_FUNC_PTR(SetLabel)                           SetLabel;
    SKF_FUNC_PTR(GetDevInfo)                         GetDevInfo;
    SKF_FUNC_PTR(LockDev)                            LockDev;
    SKF_FUNC_PTR(UnlockDev)                          UnlockDev;
    SKF_FUNC_PTR(Transmit)                           Transmit;
    SKF_FUNC_PTR(ChangeDevAuthKey)                   ChangeDevAuthKey;
    SKF_FUNC_PTR(DevAuth)                            DevAuth;
    SKF_FUNC_PTR(ChangePIN)                          ChangePIN;
    SKF_FUNC_PTR(GetPINInfo)                         GetPINInfo;
    SKF_FUNC_PTR(VerifyPIN)                          VerifyPIN;
    SKF_FUNC_PTR(UnblockPIN)                         UnblockPIN;
    SKF_FUNC_PTR(ClearSecureState)                   ClearSecureState;
    SKF_FUNC_PTR(CreateApplication)                  CreateApplication;
    SKF_FUNC_PTR(EnumApplication)                    EnumApplication;
    SKF_FUNC_PTR(DeleteApplication)                  DeleteApplication;
    SKF_FUNC_PTR(OpenApplication)                    OpenApplication;
    SKF_FUNC_PTR(CloseApplication)                   CloseApplication;
    SKF_FUNC_PTR(CreateFile)                         CreateFile;
    SKF_FUNC_PTR(DeleteFile)                         DeleteFile;
    SKF_FUNC_PTR(EnumFiles)                          EnumFiles;
    SKF_FUNC_PTR(GetFileInfo)                        GetFileInfo;
    SKF_FUNC_PTR(ReadFile)                           ReadFile;
    SKF_FUNC_PTR(WriteFile)                          WriteFile;
    SKF_FUNC_PTR(CreateContainer)                    CreateContainer;
    SKF_FUNC_PTR(DeleteContainer)                    DeleteContainer;
    SKF_FUNC_PTR(OpenContainer)                      OpenContainer;
    SKF_FUNC_PTR(CloseContainer)                     CloseContainer;
    SKF_FUNC_PTR(EnumContainer)                      EnumContainer;
    SKF_FUNC_PTR(GetContainerType)                   GetContainerType;
    SKF_FUNC_PTR(ImportCertificate)                  ImportCertificate;
    SKF_FUNC_PTR(ExportCertificate)                  ExportCertificate;
    SKF_FUNC_PTR(GenRandom)                          GenRandom;
    SKF_FUNC_PTR(GenExtRSAKey)                       GenExtRSAKey;
    SKF_FUNC_PTR(GenRSAKeyPair)                      GenRSAKeyPair;
    SKF_FUNC_PTR(ImportRSAKeyPair)                   ImportRSAKeyPair;
    SKF_FUNC_PTR(RSASignData)                        RSASignData;
    SKF_FUNC_PTR(RSAVerify)                          RSAVerify;
    SKF_FUNC_PTR(RSAExportSessionKey)                RSAExportSessionKey;
    SKF_FUNC_PTR(ExtRSAPubKeyOperation)              ExtRSAPubKeyOperation;
    SKF_FUNC_PTR(ExtRSAPriKeyOperation)              ExtRSAPriKeyOperation;
    SKF_FUNC_PTR(GenECCKeyPair)                      GenECCKeyPair;
    SKF_FUNC_PTR(ImportECCKeyPair)                   ImportECCKeyPair;
    SKF_FUNC_PTR(ECCSignData)                        ECCSignData;
    SKF_FUNC_PTR(ECCVerify)                          ECCVerify;
    SKF_FUNC_PTR(ECCExportSessionKey)                ECCExportSessionKey;
    SKF_FUNC_PTR(ExtECCEncrypt)                      ExtECCEncrypt;
    SKF_FUNC_PTR(ExtECCDecrypt)                      ExtECCDecrypt;
    SKF_FUNC_PTR(ExtECCSign)                         ExtECCSign;
    SKF_FUNC_PTR(ExtECCVerify)                       ExtECCVerify;
    SKF_FUNC_PTR(GenerateAgreementDataWithECC)       GenerateAgreementDataWithECC;
    SKF_FUNC_PTR(GenerateAgreementDataAndKeyWithECC) GenerateAgreementDataAndKeyWithECC;
    SKF_FUNC_PTR(GenerateKeyWithECC)                 GenerateKeyWithECC;
    SKF_FUNC_PTR(ExportPublicKey)                    ExportPublicKey;
    SKF_FUNC_PTR(ImportSessionKey)                   ImportSessionKey;
    SKF_FUNC_PTR(SetSymmKey)                         SetSymmKey;
    SKF_FUNC_PTR(EncryptInit)                        EncryptInit;
    SKF_FUNC_PTR(Encrypt)                            Encrypt;
    SKF_FUNC_PTR(EncryptUpdate)                      EncryptUpdate;
    SKF_FUNC_PTR(EncryptFinal)                       EncryptFinal;
    SKF_FUNC_PTR(DecryptInit)                        DecryptInit;
    SKF_FUNC_PTR(Decrypt)                            Decrypt;
    SKF_FUNC_PTR(DecryptUpdate)                      DecryptUpdate;
    SKF_FUNC_PTR(DecryptFinal)                       DecryptFinal;
    SKF_FUNC_PTR(DigestInit)                         DigestInit;
    SKF_FUNC_PTR(Digest)                             Digest;
    SKF_FUNC_PTR(DigestUpdate)                       DigestUpdate;
    SKF_FUNC_PTR(DigestFinal)                        DigestFinal;
    SKF_FUNC_PTR(MacInit)                            MacInit;
    SKF_FUNC_PTR(Mac)                                Mac;
    SKF_FUNC_PTR(MacUpdate)                          MacUpdate;
    SKF_FUNC_PTR(MacFinal)                           MacFinal;
    SKF_FUNC_PTR(CloseHandle)                        CloseHandle;
    /* Private SKF API */
    const SKF_Driver_t                              *Driver;
} SKF_t;

/**
 * @brief SKF build-in extension
 *
 */
extern const SKF_Driver_t SKF_Driver_CCORE;
extern const SKF_Driver_t SKF_Driver_HAITAI;
extern const SKF_Driver_t SKF_Driver_LONGMAI;

/**
 * @brief SKF
 *
 */
static SKF_t                SKF = {0};
static const SKF_Driver_t  *SKF_Drivers[] = {
    &SKF_Driver_CCORE,
    &SKF_Driver_HAITAI,
    &SKF_Driver_LONGMAI,
    NULL
};

/**
 * @brief SKF standard function
 *
 */
#define SKF_FUNC_DEF(name,args,params) \
    ULONG DEVAPI SKF_##name args \
    {\
        if (NULL == SKF.hDLL) { \
            return SAR_NOTINITIALIZEERR; \
        } \
        if (NULL == SKF.name) { \
            return SAR_NOTSUPPORTYETERR; \
        } \
        return SKF.name params; \
    }

#ifdef SKF_FUNC_DEF
SKF_FUNC_DEF(WaitForDevEvent, (LPSTR szDevName,ULONG *pulDevNameLen,ULONG *pulEvent),
    (szDevName,pulDevNameLen,pulEvent));
SKF_FUNC_DEF(CancelWaitForDevEvent, (void),
    ());
SKF_FUNC_DEF(EnumDev, (BOOL bPresent,LPSTR szNameList,ULONG *pulSize),
    (bPresent,szNameList,pulSize));
SKF_FUNC_DEF(ConnectDev, (LPSTR szName,DEVHANDLE *phDev),
    (szName,phDev));
SKF_FUNC_DEF(DisConnectDev, (DEVHANDLE hDev),
    (hDev));
SKF_FUNC_DEF(GetDevState, (LPSTR szDevName,ULONG *pulDevState),
    (szDevName,pulDevState));
SKF_FUNC_DEF(SetLabel, (DEVHANDLE hDev,LPSTR szLabel),
    (hDev,szLabel));
SKF_FUNC_DEF(GetDevInfo, (DEVHANDLE hDev,DEVINFO *pDevInfo),
    (hDev,pDevInfo));
SKF_FUNC_DEF(LockDev, (DEVHANDLE hDev,ULONG ulTimeOut),
    (hDev,ulTimeOut));
SKF_FUNC_DEF(UnlockDev, (DEVHANDLE hDev),
    (hDev));
SKF_FUNC_DEF(Transmit, (DEVHANDLE hDev,BYTE *pbCommand,ULONG ulCommandLen,BYTE *pbData,ULONG *pulDataLen),
    (hDev,pbCommand,ulCommandLen,pbData,pulDataLen));
SKF_FUNC_DEF(ChangeDevAuthKey, (DEVHANDLE hDev,BYTE *pbKeyValue,ULONG ulKeyLen),
    (hDev,pbKeyValue,ulKeyLen));
SKF_FUNC_DEF(DevAuth, (DEVHANDLE hDev,BYTE *pbAuthData,ULONG ulLen),
    (hDev,pbAuthData,ulLen));
SKF_FUNC_DEF(ChangePIN, (HAPPLICATION hApplication,ULONG ulPINType,LPSTR szOldPin,LPSTR szNewPin,ULONG *pulRetryCount),
    (hApplication,ulPINType,szOldPin,szNewPin,pulRetryCount));
SKF_FUNC_DEF(GetPINInfo, (HAPPLICATION hApplication,ULONG ulPINType,ULONG *pulMaxRetryCount,ULONG *pulRemainRetryCount,BOOL *pbDefaultPin),
    (hApplication,ulPINType,pulMaxRetryCount,pulRemainRetryCount,pbDefaultPin));
SKF_FUNC_DEF(VerifyPIN, (HAPPLICATION hApplication,ULONG ulPINType,LPSTR szPIN,ULONG *pulRetryCount),
    (hApplication,ulPINType,szPIN,pulRetryCount));
SKF_FUNC_DEF(UnblockPIN, (HAPPLICATION hApplication,LPSTR szAdminPIN,LPSTR szNewUserPIN,ULONG *pulRetryCount),
    (hApplication,szAdminPIN,szNewUserPIN,pulRetryCount));
SKF_FUNC_DEF(ClearSecureState, (HAPPLICATION hApplication),
    (hApplication));
SKF_FUNC_DEF(CreateApplication, (DEVHANDLE hDev,LPSTR szAppName,LPSTR szAdminPin,DWORD dwAdminPinRetryCount,LPSTR szUserPin,DWORD dwUserPinRetryCount,DWORD dwCreateFileRights,HAPPLICATION *phApplication),
    (hDev,szAppName,szAdminPin,dwAdminPinRetryCount,szUserPin,dwUserPinRetryCount,dwCreateFileRights,phApplication));
SKF_FUNC_DEF(EnumApplication, (DEVHANDLE hDev,LPSTR szAppName,ULONG *pulSize),
    (hDev,szAppName,pulSize));
SKF_FUNC_DEF(DeleteApplication, (DEVHANDLE hDev,LPSTR szAppName),
    (hDev,szAppName));
SKF_FUNC_DEF(OpenApplication, (DEVHANDLE hDev,LPSTR szAppName,HAPPLICATION *phApplication),
    (hDev,szAppName,phApplication));
SKF_FUNC_DEF(CloseApplication, (HAPPLICATION hApplication),
    (hApplication));
SKF_FUNC_DEF(CreateFile, (HAPPLICATION hApplication,LPSTR szFileName,ULONG ulFileSize,ULONG ulReadRights,ULONG ulWriteRights),
    (hApplication,szFileName,ulFileSize,ulReadRights,ulWriteRights));
SKF_FUNC_DEF(DeleteFile, (HAPPLICATION hApplication,LPSTR szFileName),
    (hApplication,szFileName));
SKF_FUNC_DEF(EnumFiles, (HAPPLICATION hApplication,LPSTR szFileList,ULONG *pulSize),
    (hApplication,szFileList,pulSize));
SKF_FUNC_DEF(GetFileInfo, (HAPPLICATION hApplication,LPSTR szFileName,FILEATTRIBUTE *pFileInfo),
    (hApplication,szFileName,pFileInfo));
SKF_FUNC_DEF(ReadFile, (HAPPLICATION hApplication,LPSTR szFileName,ULONG ulOffset,ULONG ulSize,BYTE *pbOutData,ULONG *pulOutLen),
    (hApplication,szFileName,ulOffset,ulSize,pbOutData,pulOutLen));
SKF_FUNC_DEF(WriteFile, (HAPPLICATION hApplication,LPSTR szFileName,ULONG ulOffset,BYTE *pbData,ULONG ulSize),
    (hApplication,szFileName,ulOffset,pbData,ulSize));
SKF_FUNC_DEF(CreateContainer, (HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer),
    (hApplication,szContainerName,phContainer));
SKF_FUNC_DEF(DeleteContainer, (HAPPLICATION hApplication,LPSTR szContainerName),
    (hApplication,szContainerName));
SKF_FUNC_DEF(OpenContainer, (HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer),
    (hApplication,szContainerName,phContainer));
SKF_FUNC_DEF(CloseContainer, (HCONTAINER hContainer),
    (hContainer));
SKF_FUNC_DEF(EnumContainer, (HAPPLICATION hApplication,LPSTR szContainerName,ULONG *pulSize),
    (hApplication,szContainerName,pulSize));
SKF_FUNC_DEF(GetContainerType, (HCONTAINER hContainer,ULONG *pulContainerType),
    (hContainer,pulContainerType));
SKF_FUNC_DEF(ImportCertificate, (HCONTAINER hContainer,BOOL bSignFlag,BYTE *pbCert,ULONG ulCertLen),
    (hContainer,bSignFlag,pbCert,ulCertLen));
SKF_FUNC_DEF(ExportCertificate, (HCONTAINER hContainer,BOOL bSignFlag,BYTE *pbCert,ULONG *pulCertLen),
    (hContainer,bSignFlag,pbCert,pulCertLen));
SKF_FUNC_DEF(GenRandom, (DEVHANDLE hDev,BYTE *pbRandom,ULONG ulRandomLen),
    (hDev,pbRandom,ulRandomLen));
SKF_FUNC_DEF(GenExtRSAKey, (DEVHANDLE hDev,ULONG ulBitsLen,RSAPRIVATEKEYBLOB *pBlob),
    (hDev,ulBitsLen,pBlob));
SKF_FUNC_DEF(GenRSAKeyPair, (HCONTAINER hContainer,ULONG ulBitsLen,RSAPUBLICKEYBLOB *pBlob),
    (hContainer,ulBitsLen,pBlob));
SKF_FUNC_DEF(ImportRSAKeyPair, (HCONTAINER hContainer,ULONG ulSymAlgId,BYTE *pbWrappedKey,ULONG ulWrappedKeyLen,BYTE *pbEncryptedData,ULONG ulEncryptedDataLen),
    (hContainer,ulSymAlgId,pbWrappedKey,ulWrappedKeyLen,pbEncryptedData,ulEncryptedDataLen));
SKF_FUNC_DEF(RSASignData, (HCONTAINER hContainer,BYTE *pbData,ULONG ulDataLen,BYTE *pbSignature,ULONG *pulSignLen),
    (hContainer,pbData,ulDataLen,pbSignature,pulSignLen));
SKF_FUNC_DEF(RSAVerify, (DEVHANDLE hDev,RSAPUBLICKEYBLOB *pRSAPubKeyBlob,BYTE *pbData,ULONG ulDataLen,BYTE *pbSignature,ULONG ulSignLen),
    (hDev,pRSAPubKeyBlob,pbData,ulDataLen,pbSignature,ulSignLen));
SKF_FUNC_DEF(RSAExportSessionKey, (HCONTAINER hContainer,ULONG ulAlgId,RSAPUBLICKEYBLOB *pPubKey,BYTE *pbData,ULONG *pulDataLen,HANDLE *phSessionKey),
    (hContainer,ulAlgId,pPubKey,pbData,pulDataLen,phSessionKey));
SKF_FUNC_DEF(ExtRSAPubKeyOperation, (DEVHANDLE hDev,RSAPUBLICKEYBLOB *pRSAPubKeyBlob,BYTE *pbInput,ULONG ulInputLen,BYTE *pbOutput,ULONG *pulOutputLen),
    (hDev,pRSAPubKeyBlob,pbInput,ulInputLen,pbOutput,pulOutputLen));
SKF_FUNC_DEF(ExtRSAPriKeyOperation, (DEVHANDLE hDev,RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,BYTE *pbInput,ULONG ulInputLen,BYTE *pbOutput,ULONG *pulOutputLen),
    (hDev,pRSAPriKeyBlob,pbInput,ulInputLen,pbOutput,pulOutputLen));
SKF_FUNC_DEF(GenECCKeyPair, (HCONTAINER hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pBlob),
    (hContainer,ulAlgId,pBlob));
SKF_FUNC_DEF(ImportECCKeyPair, (HCONTAINER hContainer,ENVELOPEDKEYBLOB *pEnvelopedKeyBlob),
    (hContainer,pEnvelopedKeyBlob));
SKF_FUNC_DEF(ECCSignData, (HCONTAINER hContainer,BYTE *pbDigest,ULONG ulDigestLen,ECCSIGNATUREBLOB *pSignature),
    (hContainer,pbDigest,ulDigestLen,pSignature));
SKF_FUNC_DEF(ECCVerify, (DEVHANDLE hDev,ECCPUBLICKEYBLOB *pECCPubKeyBlob,BYTE *pbData,ULONG ulDataLen,ECCSIGNATUREBLOB *pSignature),
    (hDev,pECCPubKeyBlob,pbData,ulDataLen,pSignature));
SKF_FUNC_DEF(ECCExportSessionKey, (HCONTAINER hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pPubKey,ECCCIPHERBLOB *pData,HANDLE *phSessionKey),
    (hContainer,ulAlgId,pPubKey,pData,phSessionKey));
SKF_FUNC_DEF(ExtECCEncrypt, (DEVHANDLE hDev,ECCPUBLICKEYBLOB *pECCPubKeyBlob,BYTE *pbPlainText,ULONG ulPlainTextLen,ECCCIPHERBLOB *pCipherText),
    (hDev,pECCPubKeyBlob,pbPlainText,ulPlainTextLen,pCipherText));
SKF_FUNC_DEF(ExtECCDecrypt, (DEVHANDLE hDev,ECCPRIVATEKEYBLOB *pECCPriKeyBlob,ECCCIPHERBLOB *pCipherText,BYTE *pbPlainText,ULONG *pulPlainTextLen),
    (hDev,pECCPriKeyBlob,pCipherText,pbPlainText,pulPlainTextLen));
SKF_FUNC_DEF(ExtECCSign, (DEVHANDLE hDev,ECCPRIVATEKEYBLOB *pECCPriKeyBlob,BYTE *pbData,ULONG ulDataLen,ECCSIGNATUREBLOB *pSignature),
    (hDev,pECCPriKeyBlob,pbData,ulDataLen,pSignature));
SKF_FUNC_DEF(ExtECCVerify, (DEVHANDLE hDev,ECCPUBLICKEYBLOB *pECCPubKeyBlob,BYTE *pbData,ULONG ulDataLen,ECCSIGNATUREBLOB *pSignature),
    (hDev,pECCPubKeyBlob,pbData,ulDataLen,pSignature));
SKF_FUNC_DEF(GenerateAgreementDataWithECC, (HCONTAINER hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,BYTE *pbID,ULONG ulIDLen,HANDLE *phAgreementHandle),
    (hContainer,ulAlgId,pTempECCPubKeyBlob,pbID,ulIDLen,phAgreementHandle));
SKF_FUNC_DEF(GenerateAgreementDataAndKeyWithECC, (HANDLE hContainer,ULONG ulAlgId,ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,BYTE *pbID,ULONG ulIDLen,BYTE *pbSponsorID,ULONG ulSponsorIDLen,HANDLE *phKeyHandle),
    (hContainer,ulAlgId,pSponsorECCPubKeyBlob,pSponsorTempECCPubKeyBlob,pTempECCPubKeyBlob,pbID,ulIDLen,pbSponsorID,ulSponsorIDLen,phKeyHandle));
SKF_FUNC_DEF(GenerateKeyWithECC, (HANDLE hAgreementHandle,ECCPUBLICKEYBLOB *pECCPubKeyBlob,ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,BYTE *pbID,ULONG ulIDLen,HANDLE *phKeyHandle),
    (hAgreementHandle,pECCPubKeyBlob,pTempECCPubKeyBlob,pbID,ulIDLen,phKeyHandle));
SKF_FUNC_DEF(ExportPublicKey, (HCONTAINER hContainer,BOOL bSignFlag,BYTE *pbBlob,ULONG *pulBlobLen),
    (hContainer,bSignFlag,pbBlob,pulBlobLen));
SKF_FUNC_DEF(ImportSessionKey, (HCONTAINER hContainer,ULONG ulAlgId,BYTE *pbWrapedData,ULONG ulWrapedLen,HANDLE *phKey),
    (hContainer,ulAlgId,pbWrapedData,ulWrapedLen,phKey));
SKF_FUNC_DEF(SetSymmKey, (DEVHANDLE hDev,BYTE *pbKey,ULONG ulAlgID,HANDLE *phKey),
    (hDev,pbKey,ulAlgID,phKey));
SKF_FUNC_DEF(EncryptInit, (HANDLE hKey,BLOCKCIPHERPARAM EncryptParam),
    (hKey,EncryptParam));
SKF_FUNC_DEF(Encrypt, (HANDLE hKey,BYTE *pbData,ULONG ulDataLen,BYTE *pbEncryptedData,ULONG *pulEncryptedLen),
    (hKey,pbData,ulDataLen,pbEncryptedData,pulEncryptedLen));
SKF_FUNC_DEF(EncryptUpdate, (HANDLE hKey,BYTE *pbData,ULONG ulDataLen,BYTE *pbEncryptedData,ULONG *pulEncryptedLen),
    (hKey,pbData,ulDataLen,pbEncryptedData,pulEncryptedLen));
SKF_FUNC_DEF(EncryptFinal, (HANDLE hKey,BYTE *pbEncryptedData,ULONG *pulEncryptedDataLen),
    (hKey,pbEncryptedData,pulEncryptedDataLen));
SKF_FUNC_DEF(DecryptInit, (HANDLE hKey,BLOCKCIPHERPARAM DecryptParam),
    (hKey,DecryptParam));
SKF_FUNC_DEF(Decrypt, (HANDLE hKey,BYTE *pbEncryptedData,ULONG ulEncryptedLen,BYTE *pbData,ULONG *pulDataLen),
    (hKey,pbEncryptedData,ulEncryptedLen,pbData,pulDataLen));
SKF_FUNC_DEF(DecryptUpdate, (HANDLE hKey,BYTE *pbEncryptedData,ULONG ulEncryptedLen,BYTE *pbData,ULONG *pulDataLen),
    (hKey,pbEncryptedData,ulEncryptedLen,pbData,pulDataLen));
SKF_FUNC_DEF(DecryptFinal, (HANDLE hKey,BYTE *pbDecryptedData,ULONG *pulDecryptedDataLen),
    (hKey,pbDecryptedData,pulDecryptedDataLen));
SKF_FUNC_DEF(DigestInit, (DEVHANDLE hDev,ULONG ulAlgID,ECCPUBLICKEYBLOB *pPubKey,BYTE *pbID,ULONG ulIDLen,HANDLE *phHash),
    (hDev,ulAlgID,pPubKey,pbID,ulIDLen,phHash));
SKF_FUNC_DEF(Digest, (HANDLE hHash,BYTE *pbData,ULONG ulDataLen,BYTE *pbHashData,ULONG *pulHashLen),
    (hHash,pbData,ulDataLen,pbHashData,pulHashLen));
SKF_FUNC_DEF(DigestUpdate, (HANDLE hHash,BYTE *pbData,ULONG ulDataLen),
    (hHash,pbData,ulDataLen));
SKF_FUNC_DEF(DigestFinal, (HANDLE hHash,BYTE *pHashData,ULONG *pulHashLen),
    (hHash,pHashData,pulHashLen));
SKF_FUNC_DEF(MacInit, (HANDLE hKey,BLOCKCIPHERPARAM *pMacParam,HANDLE *phMac),
    (hKey,pMacParam,phMac));
SKF_FUNC_DEF(Mac, (HANDLE hMac,BYTE *pbData,ULONG ulDataLen,BYTE *pbMacData,ULONG *pulMacLen),
    (hMac,pbData,ulDataLen,pbMacData,pulMacLen));
SKF_FUNC_DEF(MacUpdate, (HANDLE hMac,BYTE *pbData,ULONG ulDataLen),
    (hMac,pbData,ulDataLen));
SKF_FUNC_DEF(MacFinal, (HANDLE hMac,BYTE *pbMacData,ULONG *pulMacDataLen),
    (hMac,pbMacData,pulMacDataLen));
SKF_FUNC_DEF(CloseHandle, (HANDLE hHandle),
    (hHandle));
#endif  /* SKF_FUNC_DEF */

# define SKF_CHECK_FUNC(condition)  if (NULL == (condition)) { goto err; }
# define SKF_DL_BIND(h,name)        h.name = (SKF_FUNC_PTR(name))skf_dlsym(h.hDLL, "SKF_" #name)

ULONG DEVAPI
SKF_GlobalInit(LPSTR szLibPath)
{
    if (SKF.bInit) {
        return SAR_OK;
    }

    /* open lib */
    if (NULL == szLibPath) {
        return SAR_INVALIDPARAMERR;
    }
    if (NULL == (SKF.hDLL = skf_dlopen((const char *)szLibPath))) {
        return SAR_DEVICE_REMOVED;
    }

    /* bind standard skf */
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, WaitForDevEvent));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CancelWaitForDevEvent));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EnumDev));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ConnectDev));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DisConnectDev));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GetDevState));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, SetLabel));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GetDevInfo));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, LockDev));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, UnlockDev));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, Transmit));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ChangeDevAuthKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DevAuth));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ChangePIN));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GetPINInfo));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, VerifyPIN));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, UnblockPIN));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ClearSecureState));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CreateApplication));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EnumApplication));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DeleteApplication));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, OpenApplication));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CloseApplication));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CreateFile));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DeleteFile));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EnumFiles));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GetFileInfo));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ReadFile));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, WriteFile));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CreateContainer));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DeleteContainer));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, OpenContainer));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CloseContainer));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EnumContainer));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GetContainerType));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ImportCertificate));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExportCertificate));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenRandom));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenExtRSAKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenRSAKeyPair));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ImportRSAKeyPair));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, RSASignData));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, RSAVerify));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, RSAExportSessionKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExtRSAPubKeyOperation));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExtRSAPriKeyOperation));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenECCKeyPair));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ImportECCKeyPair));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ECCSignData));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ECCVerify));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ECCExportSessionKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExtECCEncrypt));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExtECCDecrypt));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExtECCSign));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExtECCVerify));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenerateAgreementDataWithECC));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenerateAgreementDataAndKeyWithECC));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, GenerateKeyWithECC));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ExportPublicKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, ImportSessionKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, SetSymmKey));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EncryptInit));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, Encrypt));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EncryptUpdate));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, EncryptFinal));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DecryptInit));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, Decrypt));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DecryptUpdate));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DecryptFinal));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DigestInit));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, Digest));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DigestUpdate));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, DigestFinal));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, MacInit));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, Mac));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, MacUpdate));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, MacFinal));
    SKF_CHECK_FUNC(SKF_DL_BIND(SKF, CloseHandle));

    /* bind private skf */
    {
        /* if not set, try load extension */
        size_t i = 0;

        /* success will save extension and break */
        for (i = 0; i < sizeof(SKF_Drivers)/sizeof(SKF_Driver_t *); i++) {
            /* make sure extension valid */
            if (NULL == SKF_Drivers[i]) {
                continue;
            }

            /* extension must exist open extension */
            if (NULL == SKF_Drivers[i]->InitDriver) {
                continue;
            }

            /* try open extension */
            if (SAR_OK != SKF_Drivers[i]->InitDriver(SKF.hDLL)) {
                continue;
            }

            /* save extension */
            SKF.Driver = SKF_Drivers[i];
            break;
        }
    }

    /* flag */
    SKF.bInit = TRUE;

    return SAR_OK;
err:
    SKF_GlobalCleanup();
    return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI
SKF_GlobalCleanup(void)
{
    /* SKF_EXTENSION */
    if (SKF.Driver) {
        if (SKF.Driver->ExitDriver) {
            SKF.Driver->ExitDriver();
        }
        SKF.Driver = NULL;
    }
    /* SKF */
    skf_dlclose(SKF.hDLL);
    memset(&SKF, 0, sizeof(SKF_t));

    return SAR_OK;
}

ULONG DEVAPI
SKF_AuthDev(DEVHANDLE hDev)
{
    if (NULL == SKF.hDLL) {
        return SAR_NOTINITIALIZEERR;
    }
    if (NULL == SKF.Driver || NULL == SKF.Driver->AuthDev) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF.Driver->AuthDev(hDev);
}

ULONG DEVAPI
SKF_ECCDecrypt(HCONTAINER hContainer, BOOL bSignFlag,
    ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText,ULONG *pulPlainTextLen)
{
    if (NULL == SKF.hDLL) {
        return SAR_NOTINITIALIZEERR;
    }
    if (NULL == SKF.Driver || NULL == SKF.Driver->ECCDecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF.Driver->ECCDecrypt(hContainer, bSignFlag, pCipherBlob,
        pbPlainText, pulPlainTextLen);
}

ULONG DEVAPI
SKF_RSADecrypt(HCONTAINER hContainer, BYTE *pbCipherText, ULONG ulCipherTextLen,
    BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    if (NULL == SKF.hDLL) {
        return SAR_NOTINITIALIZEERR;
    }
    if (NULL == SKF.Driver || NULL == SKF.Driver->RSADecrypt) {
        return SAR_NOTSUPPORTYETERR;
    }
    return SKF.Driver->RSADecrypt(hContainer, pbCipherText, ulCipherTextLen,
        pbPlainText, pulPlainTextLen);
}

LPSTR DEVAPI
SKF_StrError(ULONG iRet)
{
    const char *pMsg = NULL;

    switch (iRet)
    {
    case SAR_OK:
        pMsg = "Success"; break;
    case SAR_FAIL:
        pMsg = "Failure"; break;
    case SAR_UNKNOWNERR:
        pMsg = "Unknown error"; break;
    case SAR_NOTSUPPORTYETERR:
        pMsg = "Not supported"; break;
    case SAR_FILEERR:
        pMsg = "File error"; break;
    case SAR_INVALIDHANDLEERR:
        pMsg = "Invalid handle"; break;
    case SAR_INVALIDPARAMERR:
        pMsg = "Invalid parameter"; break;
    case SAR_READFILEERR:
        pMsg = "Read file error"; break;
    case SAR_WRITEFILEERR:
        pMsg = "Write file error"; break;
    case SAR_NAMELENERR:
        pMsg = "Name length error"; break;
    case SAR_KEYUSAGEERR:
        pMsg = "Key usage error"; break;
    case SAR_MODULUSLENERR:
        pMsg = "Modulus length error"; break;
    case SAR_NOTINITIALIZEERR:
        pMsg = "Not initialized"; break;
    case SAR_OBJERR:
        pMsg = "Object error"; break;
    case SAR_MEMORYERR:
        pMsg = "Memory error"; break;
    case SAR_TIMEOUTERR:
        pMsg = "Time out"; break;
    case SAR_INDATALENERR:
        pMsg = "Input data length error"; break;
    case SAR_INDATAERR:
        pMsg = "Input data error"; break;
    case SAR_GENRANDERR:
        pMsg = "Generate randomness error"; break;
    case SAR_HASHOBJERR:
        pMsg = "Hash object error"; break;
    case SAR_HASHERR:
        pMsg = "Hash error"; break;
    case SAR_GENRSAKEYERR:
        pMsg = "Genenerate RSA key error"; break;
    case SAR_RSAMODULUSLENERR:
        pMsg = "RSA modulus length error"; break;
    case SAR_CSPIMPRTPUBKEYERR:
        pMsg = "CSP import public key error"; break;
    case SAR_RSAENCERR:
        pMsg = "RSA encryption error"; break;
    case SAR_RSADECERR:
        pMsg = "RSA decryption error"; break;
    case SAR_HASHNOTEQUALERR:
        pMsg = "Hash not equal"; break;
    case SAR_KEYNOTFOUNTERR:
        pMsg = "Key not found"; break;
    case SAR_CERTNOTFOUNTERR:
        pMsg = "Certificate not found"; break;
    case SAR_NOTEXPORTERR:
        pMsg = "Not exported"; break;
    case SAR_DECRYPTPADERR:
        pMsg = "Decrypt pad error"; break;
    case SAR_MACLENERR:
        pMsg = "MAC length error"; break;
    case SAR_BUFFER_TOO_SMALL:
        pMsg = "Buffer too small"; break;
    case SAR_KEYINFOTYPEERR:
        pMsg = "Key info type error"; break;
    case SAR_NOT_EVENTERR:
        pMsg = "No event error"; break;
    case SAR_DEVICE_REMOVED:
        pMsg = "Device removed"; break;
    case SAR_PIN_INCORRECT:
        pMsg = "PIN incorrect"; break;
    case SAR_PIN_LOCKED:
        pMsg = "PIN locked"; break;
    case SAR_PIN_INVALID:
        pMsg = "PIN invalid"; break;
    case SAR_PIN_LEN_RANGE:
        pMsg = "PIN length error"; break;
    case SAR_USER_ALREADY_LOGGED_IN:
        pMsg = "User already logged in"; break;
    case SAR_USER_PIN_NOT_INITIALIZED:
        pMsg = "User PIN not initialized"; break;
    case SAR_USER_TYPE_INVALID:
        pMsg = "User type invalid"; break;
    case SAR_APPLICATION_NAME_INVALID:
        pMsg = "Application name invalid"; break;
    case SAR_APPLICATION_EXISTS:
        pMsg = "Application already exist"; break;
    case SAR_USER_NOT_LOGGED_IN:
        pMsg = "User not logged in"; break;
    case SAR_APPLICATION_NOT_EXISTS:
        pMsg = "Application not exist"; break;
    case SAR_FILE_ALREADY_EXIST:
        pMsg = "File already exist"; break;
    case SAR_NO_ROOM:
        pMsg = "No file space"; break;
    case SAR_FILE_NOT_EXIST:
        pMsg = "File not exist"; break;
    case SAR_REACH_MAX_CONTAINER_COUNT:
        pMsg = "Reach max container count"; break;
    default:
        pMsg = "Undefined error code"; break;
    }
    return (LPSTR)pMsg;
}

ULONG DEVAPI
SKF_AuthConnectDev(LPSTR pszName, DEVHANDLE *phDev)
{
    ULONG      iRet = SAR_FAIL;
    CHAR       szNameList[1024] = {0};
    ULONG      ulSize = sizeof(szNameList);
    CHAR      *pszNameList = NULL;
    DEVHANDLE  hDev = NULL;

    /* enum device */
    if (SAR_OK != (iRet = SKF_EnumDev(TRUE, szNameList, &ulSize))) {
        return iRet;
    }

    /* loop connect device */
    for (pszNameList = szNameList; *pszNameList; pszNameList = pszNameList + strlen((const char *)pszNameList) + 1) {
        DEVHANDLE dev = NULL;

        /* if set name, only connect this name device */
        if (pszName && strlen((const char *)pszName) && 0 != strcmp((const char *)pszName, (const char *)pszNameList)) {
            continue;
        }

        /* connect device */
        if (SAR_OK != (iRet = SKF_ConnectDev(pszNameList, &dev))) {
            continue;
        }

        /* if extension support auth, auto device auth */
        if (SKF.Driver && SKF.Driver->AuthDev) {
            if (SAR_OK != (iRet = SKF.Driver->AuthDev(dev))) {
                SKF_DisConnectDev(dev);
                continue;
            }
        }

        /* ok and break */
        hDev = dev;
        break;
    }
    if (NULL == hDev) {
        return SAR_DEVICE_REMOVED;
    }

    /* export hDev */
    if (phDev) {
        *phDev = hDev; hDev = NULL;
    }

    /* disconnect */
    SKF_DisConnectDev(hDev);

    return SAR_OK;
}

ULONG DEVAPI SKF_OpenOrCreateApp(DEVHANDLE hDev, LPSTR szAppName,
    LPSTR szAdminPin, LPSTR szUserPin, HAPPLICATION *phApplication)
{
    int           iRet = SAR_FAIL;
    HAPPLICATION  hApplication = NULL;
    ULONG         ulRetryCount = 0;

    /* open application */
    if (SAR_OK != (iRet = SKF_OpenApplication(hDev, szAppName, &hApplication))) {
        /* if error is not application-not-exist, return error */
        if (SAR_APPLICATION_NOT_EXISTS != iRet) {
            return iRet;
        }

        /* auth device */
        if (SAR_OK != (iRet = SKF_AuthDev(hDev))) {
            return iRet;
        }

        /* create application */
        iRet = SKF_CreateApplication(hDev, szAppName,
            szAdminPin, SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT,
            szUserPin, SKF_DEFAULT_USER_PIN_RETRY_COUNT,
            SKF_DEFAULT_FILE_RIGHTS, &hApplication);
        if (iRet != SAR_OK) {
            return iRet;
        }
    }

    /* if input, verify admin pin */
    if (szAdminPin) {
        if (SAR_OK != (iRet = SKF_VerifyPIN(hApplication, ADMIN_TYPE, szAdminPin, &ulRetryCount))) {
            SKF_CloseApplication(hApplication);
            return iRet;
        }
    }

    /* if input, verify user pin */
    if (szUserPin) {
        if (SAR_OK != (iRet = SKF_VerifyPIN(hApplication, USER_TYPE, szUserPin, &ulRetryCount))) {
            SKF_CloseApplication(hApplication);
            return iRet;
        }
    }

    /* export app */
    if (phApplication) {
        *phApplication = hApplication; hApplication = NULL;
    }

    SKF_CloseApplication(hApplication);
    return iRet;
}

ULONG DEVAPI SKF_OpenOrCreateCtnr(HAPPLICATION hApplication, LPSTR szContainerName,
    LPSTR szUserPin, HCONTAINER *phContainer)
{
    int         iRet = SAR_FAIL;
    HCONTAINER  hContainer = NULL;
    ULONG       ulRetryCount = 0;

    /* open container */
    if (SAR_OK != (iRet = SKF_OpenContainer(hApplication, szContainerName, &hContainer))) {
        /* if error is not container-not-exist, return error */
        if (SAR_FILE_NOT_EXIST != iRet) {
            return iRet;
        }

        /* verify user pin */
        if (SAR_OK != (iRet = SKF_VerifyPIN(hApplication, USER_TYPE, szUserPin, &ulRetryCount))) {
            return iRet;
        }

        /* create container */
        if (SAR_OK != (iRet = SKF_CreateContainer(hApplication, szContainerName, &hContainer))) {
            return iRet;
        }
    }

    /* if input, verify user pin */
    if (szUserPin) {
        if (SAR_OK != (iRet = SKF_VerifyPIN(hApplication, USER_TYPE, szUserPin, &ulRetryCount))) {
            SKF_CloseContainer(hContainer);
            return iRet;
        }
    }

    /* export */
    if (phContainer) {
        *phContainer = hContainer; hContainer = NULL;
    }

    SKF_CloseContainer(hContainer);
    return SAR_OK;
}