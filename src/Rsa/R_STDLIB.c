/* R_STDLIB.C - platform-specific C library routines for RSAREF
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#include <string.h>
#include "Rsaref.h"


void R_memset (
POINTER output,                                             /* output block */
int value,                                                         /* value */
unsigned int len)                                        /* length of block */
{
  if (len)
    memset (output, value, len);
}

void R_memcpy ( POINTER output,                                             /* output block */
                POINTER input,                                               /* input block */
                unsigned int len)                                       /* length of blocks */
{
  if (len)
    memcpy (output, input, len);
}

int R_memcmp (  POINTER firstBlock,                                         /* first block */
                POINTER secondBlock,                                        /* second block */
                unsigned int len )                                          /* length of blocks */
{
  if (len)
    return (memcmp (firstBlock, secondBlock, len));
  else
    return (0);
}
