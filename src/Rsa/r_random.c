/* R_RANDOM.C - random objects for RSAREF
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#include "Rsaref.h"
#include "r_random.h"
#include "Md5.h"

#define RANDOM_BYTES_NEEDED 256

int R_RandomInit (R_RANDOM_STRUCT *randomStruct)
{
  randomStruct->bytesNeeded = RANDOM_BYTES_NEEDED;
  R_memset ((POINTER)randomStruct->state, 0, sizeof (randomStruct->state));
  randomStruct->outputAvailable = 0;
  
  return (0);
}

int R_RandomUpdate (R_RANDOM_STRUCT *randomStruct, unsigned char *block, unsigned int blockLen)
{
    Md5Context context;
    unsigned char digest[16];
    unsigned int i, x;

    Md5Reset(&context);
    Md5Input(&context, block, blockLen);
    Md5Result( &context,digest);

    /* add digest to state */
    x = 0;
    for (i = 0; i < 16; i++) {
        x += randomStruct->state[15-i] + digest[15-i];
        randomStruct->state[15-i] = (unsigned char)x;
        x >>= 8;
    }

    if (randomStruct->bytesNeeded < blockLen)
        randomStruct->bytesNeeded = 0;
    else
        randomStruct->bytesNeeded -= blockLen;

    /* Zeroize sensitive information.
     */
    R_memset ((POINTER)digest, 0, sizeof (digest));
    x = 0;

    return (0);
}

int R_GetRandomBytesNeeded (unsigned int *bytesNeeded, R_RANDOM_STRUCT *randomStruct)
{
  *bytesNeeded = randomStruct->bytesNeeded;
  
  return (0);
}

int R_GenerateBytes (
unsigned char *block,                                              /* block */
unsigned int blockLen,                                   /* length of block */
R_RANDOM_STRUCT *randomStruct)                          /* random structure */
{
    Md5Context context;
    unsigned int available, i;

    if (randomStruct->bytesNeeded)
        return (RE_NEED_RANDOM);

    available = randomStruct->outputAvailable;

    while (blockLen > available) {
        R_memcpy
                ((POINTER)block, (POINTER)&randomStruct->output[16-available],
                 available);
        block += available;
        blockLen -= available;

        /* generate new output */
        Md5Reset(&context);
        Md5Input(&context, randomStruct->state, sizeof(randomStruct->state));
        Md5Result(&context,randomStruct->output);
        available = 16;

        /* increment state */
        for (i = 0; i < 16; i++)
            if (randomStruct->state[ 15 - i ]++)
                break;
    }

    R_memcpy
            ((POINTER)block, (POINTER)&randomStruct->output[16-available], blockLen);
    randomStruct->outputAvailable = available - blockLen;

    return (0);
}

void R_RandomFinal (R_RANDOM_STRUCT *randomStruct)
{
  R_memset ((POINTER)randomStruct, 0, sizeof (*randomStruct));
}
