#include "crt.h"
#include "HashPr.h"
#include "Sha1.h"
#include "Sha256.h"

static Sha1Context m_Sha1Ctx;
static UINT8 m_Hash_Buffer [SHA256_HASH_SIZE];
static SHA256_CTX m_Sha256Ctx;


/** Resets internal hash input storage.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @return Unified result code.
        @retval URC_OK               On success.
        @retval URC_CRYPTO_HASH_WRONG_ALGORITHM  If Hash Algorithm Indicator is unrecognized.
*/
URC HashPrc_Reset(UINT8 p_HashAlgorithmIndicator)
{
    switch (p_HashAlgorithmIndicator)
    {
    case HASH_ALGORITHM_SHA1: 
        SHA1Reset(&m_Sha1Ctx);
        return URC_OK;
    case HASH_ALGORITHM_SHA256:
        sha256_init(&m_Sha256Ctx);
        return URC_OK;

    default: 
        URC_LOG_RETURN (URC_CRYPTO_HASH_WRONG_ALGORITHM);
    }

} /* HashPrc_Reset */

/**
   @brief Concatenates portion of data to hash input storage.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000,
        Book 2, Annex A.
    @param p_pData      Pointer to incoming data.
    @param p_DataLength Length of the incoming data.
    @return Unified result code.
    @retval URC_OK               On success.
    @retval URC_CRYPTO_HASH_WRONG_ALGORITHM  If Hash Algorithm Indicator is unrecognized.
    @retval URC_CRYPTO_INVALID_PARAMETER     If @a p_pData is NULL.
*/
URC HashPrc_Add(UINT8 p_HashAlgorithmIndicator, PCUINT8 p_pData, UINT16 p_DataLength)
{
    if (p_pData == NULL)
        URC_LOG_RETURN(URC_CRYPTO_INVALID_PARAMETER);

    switch (p_HashAlgorithmIndicator)
    {
    case HASH_ALGORITHM_SHA1: 
        SHA1Input(&m_Sha1Ctx, p_pData, p_DataLength);
        return URC_OK;
    case HASH_ALGORITHM_SHA256:
        sha256_update(&m_Sha256Ctx, p_pData, p_DataLength);
        return URC_OK;

    default: 
        URC_LOG_RETURN(URC_CRYPTO_HASH_WRONG_ALGORITHM);
    }

} /* HashPrc_Add */


/** Calculates hash on the input storage using algorithm defined 
        by @a p_HashAlgorithmIndicator.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @return Unified result code.
        @retval URC_OK               On success.
        @retval URC_CRYPTO_HASH_WRONG_ALGORITHM  If Hash Algorithm Indicator is unrecognized.
*/
URC HashPrc_Calculate(UINT8 p_HashAlgorithmIndicator)
{
    switch (p_HashAlgorithmIndicator)
    {
    case HASH_ALGORITHM_SHA1: 
        SHA1Result (&m_Sha1Ctx, m_Hash_Buffer);
        return URC_OK;
    case HASH_ALGORITHM_SHA256:
        sha256_final(&m_Sha256Ctx, m_Hash_Buffer);
        return URC_OK;

    default: 
        URC_LOG_RETURN(URC_CRYPTO_HASH_WRONG_ALGORITHM);
    }

} /* HashPrc_Calculate */



/**
    @brief Compares previously calculated hash to @a p_pHash.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @param p_pHash Hash value to compare.
    @return Equality indicator.
    @retval TRUE  @a p_pHash is equal to previously calculated hash.
    @retval FALSE @a p_pHash is not equal to previously calculated hash.
*/
BOOL HashPrc_IsResultEqualTo(UINT8 p_HashAlgorithmIndicator, PCUINT8 p_pHash)
{
  switch (p_HashAlgorithmIndicator)
  {
    case HASH_ALGORITHM_SHA1: 
      if (p_pHash == NULL) 
          return FALSE;

      return (MemCmp(m_Hash_Buffer, p_pHash, SHA1_HASH_SIZE) == 0) ? TRUE : FALSE;

    case HASH_ALGORITHM_SHA256:
      if (p_pHash == NULL)
          return FALSE;

      return (MemCmp(m_Hash_Buffer, p_pHash, SHA256_HASH_SIZE) == 0) ? TRUE : FALSE;

    default: 
      return FALSE;
  }

} /* HashPrc_IsResultEqualTo */

/**
  @brief Returns pointer to resulting hash storage.
  @return Pointer to internal hash storage.
  @retval NULL if p_HashAlgorithmIndicator is invalid.
*/
PUINT8 HashPrc_GetResult (UINT8 p_HashAlgorithmIndicator)
{
  switch (p_HashAlgorithmIndicator)
  {
    case HASH_ALGORITHM_SHA1: 
      return m_Hash_Buffer;
    case HASH_ALGORITHM_SHA256:
        return m_Hash_Buffer;

    default: 
      return NULL;
  }
} /* HashPrc_GetResult */



/** @brief Returns resulting hash length.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @return Hash length.
    @retval non-0 On success.
    @retval 0     If @a p_HashAlgorithmIndicator is unknown.
*/

UINT16 HashPrc_GetLength(UINT8 p_HashAlgorithmIndicator)
{
  switch (p_HashAlgorithmIndicator)
  {
    case HASH_ALGORITHM_SHA1: 
      return SHA1_HASH_SIZE;
    case HASH_ALGORITHM_SHA256:
        return SHA256_HASH_SIZE;

    default: 
      return 0;
  }
} /* HashPrc_GetLength */
