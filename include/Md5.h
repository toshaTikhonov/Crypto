/**
 * \file md5imp.h
 */
#ifndef __MD5IMP_H__
#define __MD5IMP_H__

#include "bastypes.h"

#ifdef __cplusplus
extern "C" {
#endif



#define MD5_HASH_SIZE 16

/**
 * \brief          MD5 context structure
 */
typedef struct
{
    UINT32 total[2];     /**< number of bytes processed  */
    UINT32 state[4];     /**< intermediate digest state  */
    UINT8 buffer[64];   /**< data block being processed */
} Md5Context;

/**
 * \brief          MD5 context setup
 *
 * \param ctx      MD5 context to be initialized
 */
void Md5Reset( Md5Context *ctx );

/**
 * \brief          MD5 process buffer
 *
 * \param ctx      MD5 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void Md5Input( Md5Context *ctx, PCUINT8 input, UINT16 ilen );

/**
 * \brief          MD5 final digest
 *
 * \param ctx      MD5 context
 * \param output   MD5 checksum result
 */
void Md5Result( Md5Context *ctx, UINT8 output[MD5_HASH_SIZE] );


#ifdef __cplusplus
}
#endif

#endif /* __MD5IMP_H__ */
