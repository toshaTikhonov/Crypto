/**
 *  @file sha1.c
 *
 *  @brief:
 *      This file implements the Secure Hashing Algorithm 1 as
 *      defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The SHA-1, produces a 160-bit message digest for a given
 *      data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) to find any two messages with the same digest,
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code
 *      uses <stdint.h> (included via "sha1.h" to define 32 and 8
 *      bit unsigned integer types.  If your C compiler does not
 *      support 32 bit unsigned integers, this code is not
 *      appropriate.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long.  Although SHA-1 allows a message digest to be generated
 *      for messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is
 *      a multiple of the size of an 8-bit character.
 *
 */

#include "Sha1.h"
#include "crt.h"

/**
   \brief Define the SHA1 circular left shift function
 */
UINT32 SHA1CircularShift (UINT8 bits, UINT32 word)
{
  return (((word) << (bits)) | ((word) >> (32-(bits))));
}

/* Local Function Prototyptes */
void SHA1PadMessage(PSha1Context );
void SHA1ProcessMessageBlock(PSha1Context );

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
void SHA1Reset(PSha1Context context)
{
  CRT_ASSERT (NULL != context);
  MemSet (context, 0, sizeof (* context));
  context->Intermediate_Hash[0]   = 0x67452301;
  context->Intermediate_Hash[1]   = 0xEFCDAB89;
  context->Intermediate_Hash[2]   = 0x98BADCFE;
  context->Intermediate_Hash[3]   = 0x10325476;
  context->Intermediate_Hash[4]   = 0xC3D2E1F0;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      Message_Digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
void SHA1Result (PSha1Context context, UINT8 Message_Digest [SHA1_HASH_SIZE])
{
  int i;

  CRT_ASSERT (NULL != context && NULL != Message_Digest);
/*lint -e613 */
  if (! context->Computed)
  {
    SHA1PadMessage(context);

    context->Computed = TRUE;
  }

  /* [AZ] LITTLE ENDIAN - BIG ENDIAN? */
  for (i = 0; i < SHA1_HASH_SIZE; i ++)
  {
    /*lint -e702 */
    Message_Digest[i] = (UINT8)(context->Intermediate_Hash[i>>2] >> (8 * (3 - (i & 0x03))));
    /*lint +e702 */
  }
  /*lint +e613 */
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
void SHA1Input (PSha1Context context, PCUINT8 message_array, UINT16 length)
{
  if (0 == length) return; /* [AZ], [05/10/2004]: Nothing to do */

  CRT_ASSERT (NULL != context && NULL != message_array);

  while (length --)
  {
    /*lint -e613 */
    context -> Message_Block[context->Message_Block_Index++] = (* message_array & 0xFF);    

    context -> Length += 8;

    if (context->Message_Block_Index == 64)
    {
        SHA1ProcessMessageBlock(context);
    }

    message_array++;
    /*lint +e613 */
  }
}

/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:

 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 *
 *
 */
/*lint -e613 */
void SHA1ProcessMessageBlock(PSha1Context context)
{  
  /* Constants defined in SHA-1   */
  READ_ONLY UINT32 K [] = {
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6
  };

  UINT8  t;             /* Loop counter                */
  UINT32 temp;          /* Temporary word value        */
  UINT32 W [80];        /* Word sequence               */
  UINT32 A, B, C, D, E; /* Word buffers                */

  /*
   *  Initialize the first 16 words in the array W
   */
  for(t = 0; t < 16; t++)
  {
      W[t] = context->Message_Block[t * 4] << 24;
      W[t] |= context->Message_Block[t * 4 + 1] << 16;
      W[t] |= context->Message_Block[t * 4 + 2] << 8;
      W[t] |= context->Message_Block[t * 4 + 3];
  }

  for(t = 16; t < 80; t++)
  {
     W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for(t = 0; t < 20; t++)
  {
      temp =  SHA1CircularShift(5,A) +
              ((B & C) | ((~B) & D)) + E + W[t] + K[0];
      E = D;
      D = C;
      C = SHA1CircularShift(30,B);

      B = A;
      A = temp;
  }

  for(t = 20; t < 40; t++)
  {
      temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
      E = D;
      D = C;
      C = SHA1CircularShift(30,B);
      B = A;
      A = temp;
  }

  for(t = 40; t < 60; t++)
  {
      temp = SHA1CircularShift(5,A) +
             ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
      E = D;
      D = C;
      C = SHA1CircularShift(30,B);
      B = A;
      A = temp;
  }

  for(t = 60; t < 80; t++)
  {
      temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
      E = D;
      D = C;
      C = SHA1CircularShift(30,B);
      B = A;
      A = temp;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;

  context->Message_Block_Index = 0;  
}


/*
 *  SHA1PadMessage
 *

 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *      Nothing.
 *
 */

void SHA1PadMessage(PSha1Context context)
{
  /*
   *  Check to see if the current message block is too small to hold
   *  the initial padding bits and length.  If so, we will pad the
   *  block, process it, and then continue padding into a second
   *  block.
   */
  if (context->Message_Block_Index > 55)
  {
      context->Message_Block[context->Message_Block_Index++] = 0x80;
      while(context->Message_Block_Index < 64)
      {
          context->Message_Block[context->Message_Block_Index++] = 0;
      }

      SHA1ProcessMessageBlock(context);

      while(context->Message_Block_Index < 56)
      {
          context->Message_Block[context->Message_Block_Index++] = 0;
      }
  }
  else
  {
      context->Message_Block[context->Message_Block_Index++] = 0x80;
      while(context->Message_Block_Index < 56)
      {

          context->Message_Block[context->Message_Block_Index++] = 0;
      }
  }

  /*
   *  Store the message length as the last 8 octets
   */
  context->Message_Block[56] = 0; /* [AZ], [05/10/2004]: Length is UINT16 */
  context->Message_Block[57] = 0;
  context->Message_Block[58] = 0;
  context->Message_Block[59] = 0;
  context->Message_Block[60] = (UINT8)(context->Length >> 24);
  context->Message_Block[61] = (UINT8)(context->Length >> 16);
  context->Message_Block[62] = (UINT8)(context->Length >> 8);
  context->Message_Block[63] = (UINT8)(context->Length);

  SHA1ProcessMessageBlock(context);
}

/*lint +e613 */


#ifdef SHA1_TEST

/*
 *  sha1test.c
 *
 *  Description:
 *      This file will exercise the SHA-1 code performing the three
 *      tests documented in FIPS PUB 180-1 plus one which calls
 *      SHA1Input with an exact multiple of 512 bits, plus a few
 *      error test checks.
 *
 *  Portability Issues:
 *      None.
 *
 */

#include <stdio.h>
#include <string.h>
#include "sha1.h"

/*
 *  Define patterns for testing
 */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"

#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b

PCUINT8 testarray[4] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4
};

PUINT8 test_names[4] =
{
    "TEST1",
    "TEST2",
    "TEST3",
    "TEST4"
};

long int repeatcount[4] = { 1, 1, 1000000, 10 };

char *resultarray[4] =
{
"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D",
"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1",
"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F",
"\xDE\xA3\x56\xA2\xCD\xDD\x90\xC7\xA7\xEC\xED\xC5\xEB\xB5\x63\x93\x4F\x46\x04\x52"
};

int Sha1_Test (void)
{
    Sha1Context sha;
    int i, j;
    UINT8 Message_Digest[20];

    /*
     *  Perform SHA-1 tests
     */
    for(j = 0; j < 4; ++j)
    {
        SHA1Reset(&sha);

        for(i = 0; i < repeatcount[j]; ++i)
        {

            SHA1Input(&sha, testarray[j], (UINT16)StrLen(testarray[j]));
        }

        SHA1Result(&sha, Message_Digest);

    }

    return 0;
}

#endif /* #ifdef SHA1_TEST */
