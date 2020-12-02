#ifndef __HashPr_h__
#define __HashPr_h__

#ifdef __cplusplus
extern "C" {
#endif

#include "bastypes.h"
#include "Crypto.urc"


/** SHA1 Algorithm Indicator */
#define HASH_ALGORITHM_SHA1             0x01
#define HASH_ALGORITHM_SHA256           0x02



/** Resets internal hash input storage.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @return Unified result code.
        @retval URC_OK               On success.
        @retval   URC_CRYPTO_HASH_WRONG_ALGORITHM  If Hash Algorithm Indicator is unrecognized.
*/

URC HashPrc_Reset(UINT8 p_HashAlgorithmIndicator);


/** Concatenates portion of data to hash input storage.

    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @param p_pData      Pointer to incoming data.
    @param p_DataLength Length of the incoming data.
    @return Unified result code.
        @retval URC_OK               On success.
        @retval URC_CRYPTO_HASH_WRONG_ALGORITHM  If Hash Algorithm Indicator is unrecognized.
        @retval URC_CRYPTO_INVALID_PARAMETER     If @a p_pData is NULL.
*/
URC HashPrc_Add(UINT8 p_HashAlgorithmIndicator, PCUINT8 p_pData, UINT16 p_DataLength);


/** Calculates hash on the input storage using algorithm defined 
        by @a p_HashAlgorithmIndicator.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @return Unified result code.
        @retval URC_OK               On success.
        @retval URC_CRYPTO_HASH_WRONG_ALGORITHM  If Hash Algorithm Indicator is unrecognized.
*/
URC HashPrc_Calculate(UINT8 p_HashAlgorithmIndicator);


/** Compares previously calculated hash to @a p_pHash.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @param p_pHash Hash value to compare.
    @return Equality indicator.
        @retval TRUE  @a p_pHash is equal to previously calculated hash.
        @retval FALSE @a p_pHash is not equal to previously calculated hash.
*/
BOOL HashPrc_IsResultEqualTo(UINT8 p_HashAlgorithmIndicator, PCUINT8 p_pHash);


/** Returns pointer to resulting hash storage.
    @return Pointer to internal hash storage.
    @retval NULL if p_HashAlgorithmIndicator is invalid.
*/
PUINT8 HashPrc_GetResult (UINT8 p_HashAlgorithmIndicator);


/** Returns resulting hash length.
    @param p_HashAlgorithmIndicator Hash Algorithm Indicator according to EMV 2000, 
        Book 2, Annex A.
    @return Hash length.
        @retval non-0 On success.
        @retval 0     If @a p_HashAlgorithmIndicator is unknown.
*/
UINT16 HashPrc_GetLength (UINT8 p_HashAlgorithmIndicator);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef __HashPr_h__ */
