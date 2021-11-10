/**
 *  sha1.h
 *
 *  Description:
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef __SHA1_H__
#define __SHA1_H__

#include "bastypes.h"

#ifdef __cplusplus
extern "C" {
#endif


#define SHA1_HASH_SIZE 20

/**
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */

typedef struct tag_Sha1Context
{
    UINT32 Intermediate_Hash [SHA1_HASH_SIZE/sizeof (UINT32)]; /**< Message Digest */

    UINT32 Length;                                           /**< Message length in bits */
                               
    UINT8  Message_Block [64];                               /**< 512-bit message blocks */

    BOOL   Computed;                                         /**< Is the digest computed? */

    UINT16 Message_Block_Index;                              /**< Index into message block array */

} Sha1Context, * PSha1Context;

/*
 *  Function Prototypes
 */

void SHA1Reset  (PSha1Context p_Ctx);
void SHA1Input  (PSha1Context p_Ctx, PCUINT8 p_Data, UINT16 p_nDataLength);
void SHA1Result (PSha1Context p_Ctx, UINT8 Message_Digest [SHA1_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef __SHA1_H__ */
