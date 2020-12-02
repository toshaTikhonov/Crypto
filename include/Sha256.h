#ifndef __SHA256_H__
#define __SHA256_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "bastypes.h"

#define SHA256_HASH_SIZE 32

/**
 * \brief          The SHA-256 context structure.
 *
 *                 The structure is used both for SHA-256 and for SHA-224
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha256_starts_ret().
 */
typedef struct
{
    UINT32 total[2];          /*!< The number of Bytes processed.  */
    UINT32 state[8];          /*!< The intermediate digest state.  */
    UINT8 buffer[64];         /*!< The data block being processed. */
} PACKED SHA256_CTX;

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const UINT8* input, UINT32 len);
void sha256_final(SHA256_CTX* ctx, UINT8 hash[]);

#ifdef __cplusplus
}
#endif

#endif   // SHA256_H