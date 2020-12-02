
#ifndef __RSA_H__
#define __RSA_H__


#include "bastypes.h"
#include "Crypto.urc"


/** Максимальная длина ключа в байтах. */
#define MAX_RSA_KEY_LENGTH       256



/** Хранит данные, используемые алгоритмом RSA */
typedef struct
{
  PUINT8 Modulus;        /**< Pointer to key modulus */
  UINT16 ModulusLength;  /**< Key modulus length in bytes */
  PUINT8 Exponent;       /**< Pointer to key exponent */
  UINT16 ExponentLength; /**< Key exponent length in bytes */
  PUINT8 Data;           /**< Data length is equal to Modulus Length */

} PACKED SRsaInput, *PSRsaInput;



/** Шифрует данные заданным ключом - открытым или секретным. */
URC Rsa_Encrypt (const SRsaInput *p_pRsaInput);

/** Расшифровывает данные заданным ключом - открытым или секретным. */
URC Rsa_Decrypt (const SRsaInput *p_pRsaInput);

/** Возвращает указатель на буфер, содержащий результат предыдущей RSA-операции. */
PUINT8 Rsa_GetResult (void);
UINT32 Rsa_GetResultLength(void);

#ifdef __cplusplus
}
#endif


#endif /* __RSA_H__ */
