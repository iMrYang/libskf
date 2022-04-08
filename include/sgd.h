#ifndef __SGD_H
#define __SGD_H

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/**
 * @brief GMT 0006-2012
 *
 */

#include <stdint.h>

/**
 * @brief 5.2.1 ciphers with modes
 *
 */
/* ciphers */
#define SGD_SM1     0x00000100
#define SGD_SSF33   0x00000200
#define SGD_SM4     0x00000400
#define SGD_ZUC     0x00000800
/* block cipher modes */
#define SGD_ECB     0x01
#define SGD_CBC     0x02
#define SGD_CFB     0x04
#define SGD_OFB     0x08
#define SGD_MAC     0x10
/* stream cipher modes */
#define SGD_EEA3    0x01
#define SGD_EIA3    0x02
/* block ciphers */
#define SGD_SM1_ECB     (SGD_SM1|SGD_ECB)
#define SGD_SM1_CBC     (SGD_SM1|SGD_CBC)
#define SGD_SM1_CFB     (SGD_SM1|SGD_CFB)
#define SGD_SM1_OFB     (SGD_SM1|SGD_OFB)
#define SGD_SM1_MAC     (SGD_SM1|SGD_MAC)
#define SGD_SSF33_ECB   (SGD_SSF33|SGD_ECB)
#define SGD_SSF33_CBC   (SGD_SSF33|SGD_CBC)
#define SGD_SSF33_CFB   (SGD_SSF33|SGD_CFB)
#define SGD_SSF33_OFB   (SGD_SSF33|SGD_OFB)
#define SGD_SSF33_MAC   (SGD_SSF33|SGD_MAC)
#define SGD_SM4_ECB     (SGD_SM4|SGD_ECB)
#define SGD_SM4_CBC     (SGD_SM4|SGD_CBC)
#define SGD_SM4_CFB     (SGD_SM4|SGD_CFB)
#define SGD_SM4_OFB     (SGD_SM4|SGD_OFB)
#define SGD_SM4_MAC     (SGD_SM4|SGD_MAC)
#define SGD_ZUC_EEA3    (SGD_ZUC|SGD_EEA3)
#define SGD_ZUC_EIA3    (SGD_ZUC|SGD_EIA3)

/**
 * @brief 5.2.2 asymm key types
 *
 */
#define SGD_RSA         0x00010000
#define SGD_SM2         0x00020000
#define SGD_SM2_1       0x00020100  /* sign */
#define SGD_SM2_2       0x00020200  /* dh */
#define SGD_SM2_3       0x00020400  /* encrypt */


/**
 * @brief 5.2.3 hash type
 *
 */
#define SGD_SM3     0x00000001
#define SGD_SHA1    0x00000002
#define SGD_SHA256  0x00000004

/**
 * @brief 5.2.4 signatue schemes
 *
 */
#define SGD_SM3_RSA     (SGD_SM3|SGD_RSA)
#define SGD_SHA1_RSA    (SGD_SHA1|SGD_RSA)
#define SGD_SHA256_RSA  (SGD_SHA256|SGD_RSA)
#define SGD_SM3_SM2     (SGD_SM3|SGD_SM2)

/**
 * @brief 5.3.1 data type
 *
 */
typedef char            SGD_CHAR;
typedef char            SGD_INT8;
typedef int16_t         SGD_INT16;
typedef int32_t         SGD_INT32;
typedef int64_t         SGD_INT64;
typedef unsigned char   SGD_UCHAR;
typedef uint8_t         SGD_UINT8;
typedef uint16_t        SGD_UINT16;
typedef uint32_t        SGD_UINT32;
typedef uint64_t        SGD_UINT64;
typedef uint32_t        SGD_RV;
typedef void *          SGD_OBJ;
typedef int32_t         SGD_BOOL;

/**
 * @brief 5.3.2 constant type
 *
 */
#define SGD_TRUE        0x00000001
#define SGD_FALSE       0x00000000

/**
 * @brief 5.3.3 object identifies
 *
 */
#define SGD_KEY_INDEX           0x00000101
#define SGD_SECRET_KEY          0x00000102
#define SGD_PUBLIC_KEY_SIGN     0x00000103
#define SGD_PUBLIC_KEY_ENCRYPT  0x00000104
#define SGD_PRIVATE_KEY_SIGN    0x00000105
#define SGD_PRIVATE_KEY_ENCRYPT 0x00000106
#define SGD_KEY_COMPONENT       0x00000107
#define SGD_PASSWORD            0x00000108
#define SGD_PUBLIC_KEY_CERT     0x00000109
#define SGD_ATTRIBUTE_CERT      0x1000010A
#define SGD_SIGNATURE_DATA      0x10000111
#define SGD_ENVELOPE_DATA       0x10000112
#define SGD_RANDOM_DATA         0x10000113
#define SGD_PLAIN_DATA          0x10000114
#define SGD_CIPHER_DATA         0x10000115
#define SGD_DIGEST_DATA         0x10000116
#define SGD_USER_DATA           0x10000117

/**
 * @brief 5.3.4 certificate identifies
 *
 */
#define SGD_CERT_VERSION                    0x00000001
#define SGD_CERT_SERIAL                     0x00000002
#define SGD_CERT_ISSUER                     0x00000005
#define SGD_CERT_VALID_TIME                 0x00000006
#define SGD_CERT_SUBJECT                    0x00000007
#define SGD_CERT_DER_PUBLIC_KEY             0x00000008
#define SGD_CERT_DER_EXTENSIONS             0x00000009
#define SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO 0x00000011
#define SGD_EXT_SUBJECTKEYIDENTIFIER_INFO   0x00000012
#define SGD_EXT_KEYUSAGE_INFO               0x00000013
#define SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO  0x00000014
#define SGD_EXT_CERTIFICATEPOLICIES_INFO    0x00000015
#define SGD_EXT_POLICYMAPPINGS_INFO         0x00000016
#define SGD_EXT_BASICCONSTRAINTS_INFO       0x00000017
#define SGD_EXT_POLICYCONSTRAINTS_INFO      0x00000018
#define SGD_EXT_EXTKEYUSAGE_INFO            0x00000019
#define SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO  0x0000001A
#define SGD_EXT_NETSCAPE_CERT_TYPE_INFO     0x0000001B
#define SGD_EXT_SELFDEFINED_EXTENSION_INFO  0x0000001C
#define SGD_CERT_ISSUER_CN                  0x00000021
#define SGD_CERT_ISSUER_O                   0x00000022
#define SGD_CERT_ISSUER_OU                  0x00000023
#define SGD_CERT_SUBJECT_CN                 0x00000031
#define SGD_CERT_SUBJECT_O                  0x00000032
#define SGD_CERT_SUBJECT_OU                 0x00000033
#define SGD_CERT_SUBJECT_EMAIL              0x00000034
#define SGD_CERT_NOTBEFORE_TIME             0x00000035
#define SGD_CERT_NOTAFTER_TIME              0x00000036

/**
 * @brief 5.3.5 timestamp info identifies
 *
 */
#define SGD_TIME_OF_STAMP                   0x00000201
#define SGD_CN_OF_TSSIGNER                  0x00000202
#define SGD_ORININAL_DATA                   0x00000203
#define SGD_CERT_OF_TSSSERVER               0x00000204
#define SGD_GERTCHAIN_OF_TSSERVER           0x00000205
#define SGD_SOURCE_OF_TIME                  0x00000206
#define SGD_TIME_PRECISION                  0x00000207
#define SGD_RESPONSE_TYPE                   0x00000208
#define SGD_SUBJECT_COUNTRY_OF_TSSIGNER     0x00000209
#define SGD_SUBJECT_ORGNIZATION_OF_TSSIGNER 0x0000020A
#define SGD_SUJECT_CITY_OF_TSSIGNER         0x0000020B
#define SGD_SUBJECT_EMAIL_OF_TSSIGNER       0x0000020C

/**
 * @brief 5.3.6 single sign on identifies
 *
 */
#define SGD_SP_ID       0x00000001
#define SGD_SP_USER_ID  0x00000002
#define SGD_IDP_ID      0x00000003
#define SGD_IDP_USER_ID 0x00000004

/**
 * @brief 5.3.7 data encoding identifies
 *
 */
#define SGD_ENCODING_RAW    0x00000000
#define SGD_ENCODING_DER    0x01000000
#define SGD_ENCODING_BASE64 0x02000000
#define SGD_ENCODING_PEM    0x03000000
#define SGD_ENCODING_TXT    0x04000000

/**
 * @brief 5.4.1 protocol identifies
 *
 */
#define SGD_PROTOCOL_CSP    1 /* Microsoft CryptoAPI */
#define SGD_PROTOCOL_PKCS11 2 /* PKCS#11 */
#define SGD_PROTOCOL_SDS    3 /* SDF API */
#define SGD_PROTOCOL_UKEY   4 /* SKF API */
#define SGD_PROTOCOL_CNG    5 /* Microsoft CryptoAPI Next Gen */
#define SGD_PROTOCOL_GCS    6 /* Generate API */

/**
 * @brief 5.4.2 certificate validation identifies
 *
 */
#define SGD_CRL_VERIFY  1
#define SGD_OCSP_VEIFY  2

/**
 * @brief 6.2.1 role identifies
 *
 */
#define SGD_ROLE_SUPER_MANAGER  0x00000001
#define SGD_ROLE_MANAGER        0x00000002
#define SGD_ROLE_AUDIT_MANAGER  0x00000003
#define SGD_ROLE_AUDITOR        0x00000004
#define SGD_ROLE_OPERATOR       0x00000005
#define SGD_ROLE_USER           0x00000006

/**
 * @brief 6.2.2 user operations identifies
 *
 */
#define SGD_OPERATION_SIGNIN        0x00000001
#define SGD_OPERATION_SIGNOUT       0x00000002
#define SGD_OPERATION_CREATE        0x00000003
#define SGD_OPERATION_DELETE        0x00000004
#define SGD_OPERATION_MODIFY        0x00000005
#define SGD_OPERATION_CHG_PWD       0x00000006
#define SGD_OPERATION_AUTHORIZATION 0x00000007

/**
 * @brief 6.2.3 user operation results
 *
 */
#define SGD_OPERATION_SUCCESS   0x00000000

/**
 * @brief 6.3.1 key types
 *
 */
#define SGD_MAIN_KEY            0x00000101
#define SGD_DEVICE_KEYS         0x00000102
#define SGD_USER_KEYS           0x00000103
#define SGD_KEY                 0x00000104
#define SGD_SESSION_KEY         0x00000105
#define SGD_PRIKEY_PASSWD       0x00000106
#define SGD_COMPARTITION_KEY    0x00000107

/**
 * @brief 6.3.2 key operations
 *
 */
#define SGD_KEY_GENERATION  0x00000101
#define SGD_KEY_DISPENSE    0x00000102
#define SGD_KEY_IMPORT      0x00000103
#define SGD_KEY_EXPORT      0x00000104
#define SGD_KEY_DIVISION    0x00000105
#define SGD_KEY_COMPOSE     0x00000106
#define SGD_KEY_RENEWAL     0x00000107
#define SGD_KEY_BACKUP      0x00000108
#define SGD_KEY_RESTORE     0x00000109
#define SGD_KEY_DESTORY     0x0000010A

/**
 * @brief 6.4 system operations
 *
 */
#define SGD_SYSTEM_INIT     0x00000201
#define SGD_SYSTEM_START    0x00000202
#define SGD_SYSTEM_SHUT     0x00000203
#define SGD_SYSTEM_RESTART  0x00000204
#define SGD_SYSTEM_QUERY    0x00000205
#define SGD_SYSTEM_BACKUP   0x00000206
#define SGD_SYSTEM_RESTORE  0x00000207

/**
 * @brief 6.5 device info
 *
 */
#define SGD_DEVICE_SORT                     0x00000201
#define SGD_DEVICE_TYPE                     0x00000202
#define SGD_DEVICE_NAME                     0x00000203
#define SGD_DEVICE_MANUFACTURER             0x00000204
#define SGD_DEVICE_HARDWARE_VERSION         0x00000205
#define SGD_DEVICE_SOFTWARE_VERSION         0x00000206
#define SGD_DEVICE_STANDARD_VERSION         0x00000207
#define SGD_DEVICE_SERIAL_NUMBER            0x00000208
#define SGD_DEVICE_SUPPORT_SYMM_ALG         0x00000209
#define SGD_DEVICE_SUPPORT_PKEY_ALG         0x0000020A
#define SGD_DEVICE_SUPPORT_HASH_ALG         0x0000020B
#define SGD_DEVICE_SUPPORT_STORAGE_SPACE    0x0000020C
#define SGD_DEVICE_SUPPORT_FREE_SPACE       0x0000020D
#define SGD_DEVICE_RUNTIME                  0x0000020E
#define SGD_DEVICE_USED_TIMES               0x0000020F
#define SGD_DEVICE_LOCATION                 0x00000210
#define SGD_DEVICE_DESCRIPTION              0x00000211
#define SGD_DEVICE_MANAGER_INFO             0x00000212
#define SGD_DEVICE_MAX_DATA_SIZE            0x00000213

/**
 * @brief 6.5.2.2 device types
 *
 */
#define SGD_DEVICE_SORT_SJ  0x02000000  /* Server */
#define SGD_DEVICE_SORT_SK  0x03000000  /* PCI-E Card */
#define SGD_DEVICE_SORT_SM  0x04000000  /* USB-Key and SmartCard */

/**
 * @brief 6.5.2.3 device functionality
 *
 */
#define SGD_DEVICE_SORT_FE        0x00000100 /* encryption */
#define SGD_DEVICE_SORT_FA        0x00000200 /* authentication */
#define SGD_DEVICE_SORT_FM        0x00000300 /* key management */

/**
 * @brief 6.5.4 device status
 *
 */
#define SGD_STATUS_INIT            0x00000201
#define SGD_STATUS_READY        0x00000202
#define SGD_STATUS_EXCEPTION        0x00000203

#ifdef __cplusplus
}
#endif  /* __cplusplus */
#endif  /* __SGD_H */

