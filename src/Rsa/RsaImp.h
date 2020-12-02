/* RSA.H - header file for RSA.C
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */
#ifndef __RSAIMP_H__
#define __RSAIMP_H__

#include "Rsaref.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
int RSAPublicEncrypt PROTO_LIST 
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY *, R_RANDOM_STRUCT *));
int RSAPrivateEncrypt PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY_ *));
int RSAPublicDecrypt PROTO_LIST 
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY_ *));
int RSAPrivateDecrypt PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY_ *));
*/
/* Raw RSA private-key operation. Output has same length as modulus.

   Assumes inputLen < length of modulus.
   Requires input < modulus.
 */
int RSAPrivateBlock (
    unsigned char *output,                                      /* output block */
    unsigned int *outputLen,                          /* length of output block */
    unsigned char *input,                                        /* input block */
    unsigned int inputLen,                             /* length of input block */
    R_RSA_PRIVATE_KEY_ *privateKey                           /* RSA private key */
    );

int RSAPublicBlock (
    unsigned char *output,                                      /* output block */
    unsigned int *outputLen,                          /* length of output block */
    unsigned char *input,                                        /* input block */
    unsigned int inputLen,                             /* length of input block */
    R_RSA_PUBLIC_KEY_ *publicKey                              /* RSA public key */
    );

#ifdef __cplusplus
}
#endif

#endif
