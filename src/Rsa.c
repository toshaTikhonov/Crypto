
#include "crt.h"
#include "Rsa.h"
#include "RsaImp.h"

/** Буфер для хранения  */
static UINT8 m_RSA_Buffer[MAX_RSA_KEY_LENGTH];
static UINT32 m_RsaResultLength;

static URC Rsa_TransformData (const SRsaInput *p_pRsaInput);

/** Шифрует данные заданным ключом - открытым или секретным. */
URC Rsa_Encrypt (const SRsaInput *p_pRsaInput)
{
  return Rsa_TransformData (p_pRsaInput);
}

/** Расшифровывает данные заданным ключом - открытым или секретным. */
URC Rsa_Decrypt (const SRsaInput *p_pRsaInput)
{
  return Rsa_TransformData (p_pRsaInput);
}


/**

  Преобразует данные по алгоритму RSA на заданном ключе. Тип ключа значения не имеет:
  он может быть как открытым, так и секретным.

  @param p_pRsaInput - Указатель на стурктуру SRsaInput, содержащую данные и ключ.

*/

static URC Rsa_TransformData (const SRsaInput *p_pRsaInput)
{
  R_RSA_PUBLIC_KEY_ Key;

  if (p_pRsaInput == NULL)
    URC_LOG_RETURN(URC_CRYPTO_INVALID_PARAMETER);

  if (p_pRsaInput -> Modulus == NULL ||
      p_pRsaInput -> Exponent == NULL ||
      p_pRsaInput -> Data == NULL
  )
    URC_LOG_RETURN(URC_CRYPTO_INVALID_PARAMETER);

  ZEROMEM_REF (Key);
//  Logger_DumpString("Rsa_TransformData 2");

  Key.bits = p_pRsaInput -> ModulusLength * 8;


  MemCpy (
    & Key.modulus [MAX_RSA_MODULUS_LEN - p_pRsaInput -> ModulusLength],
    p_pRsaInput -> Modulus,
    p_pRsaInput -> ModulusLength
  );

  MemCpy (
    & Key.exponent [MAX_RSA_MODULUS_LEN - p_pRsaInput -> ExponentLength],
    p_pRsaInput -> Exponent,
    p_pRsaInput -> ExponentLength
  );

  MemSet (m_RSA_Buffer, 0, MAX_RSA_KEY_LENGTH);

  m_RsaResultLength = 0;


  if (
    RSAPublicBlock (
      m_RSA_Buffer,
      (unsigned int *) & m_RsaResultLength,
      p_pRsaInput -> Data,
      (unsigned int) p_pRsaInput -> ModulusLength,
      & Key
    ) != 0
  )
    URC_LOG_RETURN (URC_CRYPTO_GENERAL_ERROR);


  return URC_OK;

} /* RsaPrc_TransformData */



/** 

  Возвращает указатель на буфер, содержащий результат предыдущей RSA-операции.

*/

PUINT8 Rsa_GetResult (void)
{
  return m_RSA_Buffer;

} /* RsaPrc_GetResult */

UINT32 Rsa_GetResultLength(void)
{
    return m_RsaResultLength;
}
