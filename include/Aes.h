#ifndef _AES_H
#define _AES_H

#include "bastypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES context structure
 */
typedef struct
{
    UINT32 erk[64];     /*!< encryption round keys */
    UINT32 drk[64];     /*!< decryption round keys */
    INT32 nr;                    /*!< number of rounds      */
}
PACKED aes_context ;
/**
 * \brief          AES key schedule
 *
 * \param ctx      AES context to be initialized
 * \param key      the secret key
 * \param keysize  must be 128, 192 or 256
 */
void crypto_aes_set_key( aes_context *ctx, unsigned char *key, int keysize );

/**
 * \brief          AES block encryption (ECB mode)
 *
 * \param ctx      AES context
 * \param input    plaintext  block
 * \param output   ciphertext block
 */
void crypto_aes_ecb_encrypt( aes_context *ctx,
                  unsigned char input[16],
                  unsigned char output[16] );

/**
 * \brief          AES block decryption (ECB mode)
 *
 * \param ctx      AES context
 * \param input    ciphertext block
 * \param output   plaintext  block
 */
void crypto_aes_ecb_decrypt( aes_context *ctx,
                  unsigned char input[16],
                  unsigned char output[16] );

/**
 * \brief          AES-CBC buffer encryption
 *
 * \param ctx      AES context
 * \param iv       initialization vector (modified after use)
 * \param input    buffer holding the plaintext
 * \param output   buffer holding the ciphertext
 * \param len      length of the data to be encrypted
 */
void crypto_aes_cbc_encrypt( aes_context *ctx,
                      unsigned char iv[16],
                      unsigned char *input,
                      unsigned char *output,
                      int len );

/**
 * \brief          AES-CBC buffer decryption
 *
 * \param ctx      AES context
 * \param iv       initialization vector (modified after use)
 * \param input    buffer holding the ciphertext
 * \param output   buffer holding the plaintext
 * \param len      length of the data to be decrypted
 */
void crypto_aes_cbc_decrypt( aes_context *ctx,
                      unsigned char iv[16],
                      unsigned char *input,
                      unsigned char *output,
                      int len );

#ifdef __cplusplus
}
#endif

#endif /* aes.h */
