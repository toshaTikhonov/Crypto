
#ifndef __RSA_H__
#define __RSA_H__


#include "bastypes.h"
#include "Crypto.urc"


/** ������������ ����� ����� � ������. */
#define MAX_RSA_KEY_LENGTH       256



/** ������ ������, ������������ ���������� RSA */
typedef struct
{
  PUINT8 Modulus;        /**< Pointer to key modulus */
  UINT16 ModulusLength;  /**< Key modulus length in bytes */
  PUINT8 Exponent;       /**< Pointer to key exponent */
  UINT16 ExponentLength; /**< Key exponent length in bytes */
  PUINT8 Data;           /**< Data length is equal to Modulus Length */

} PACKED SRsaInput, *PSRsaInput;



/** ������� ������ �������� ������ - �������� ��� ���������. */
URC Rsa_Encrypt (const SRsaInput *p_pRsaInput);

/** �������������� ������ �������� ������ - �������� ��� ���������. */
URC Rsa_Decrypt (const SRsaInput *p_pRsaInput);

/** ���������� ��������� �� �����, ���������� ��������� ���������� RSA-��������. */
PUINT8 Rsa_GetResult (void);
UINT32 Rsa_GetResultLength(void);

#ifdef __cplusplus
}
#endif


#endif /* __RSA_H__ */
