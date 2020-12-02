
#include "crt.h"
#include "Rsa.h"
#include "RsaImp.h"

/** Буфер для хранения  */
static UINT8 m_RSA_Buffer[MAX_RSA_KEY_LENGTH];
static UINT32 m_RsaResultLength;

static URC Rsa_TransformData (const SRsaInput *p_pRsaInput);

/** Шифрует данные заданным ключом - открытым или секретным. */
URC Rsa_Encrypt (const SRsaInput *p_pRsaInput)
{
  return Rsa_TransformData (p_pRsaInput);
}

/** Расшифровывает данные заданным ключом - открытым или секретным. */
URC Rsa_Decrypt (const SRsaInput *p_pRsaInput)
{
  return Rsa_TransformData (p_pRsaInput);
}


/**

  Преобразует данные по алгоритму RSA на заданном ключе. Тип ключа значения не имеет:
  он может быть как открытым, так и секретным.

  @param p_pRsaInput - Указатель на стурктуру SRsaInput, содержащую данные и ключ.

*/

static URC Rsa_TransformData (const SRsaInput *p_pRsaInput)
{
  R_RSA_PUBLIC_KEY_ Key;

  if (p_pRsaInput == NULL)
    URC_LOG_RETURN(URC_CRYPTO_INVALID_PARAMETER);

  if (p_pRsaInput -> Modulus == NULL ||
      p_pRsaInput -> Exponent == NULL ||
      p_pRsaInput -> Data == NULL
  )
    URC_LOG_RETURN(URC_CRYPTO_INVALID_PARAMETER);

  ZEROMEM_REF (Key);
//  Logger_DumpString("Rsa_TransformData 2");

  Key.bits = p_pRsaInput -> ModulusLength * 8;


  MemCpy (
    & Key.modulus [MAX_RSA_MODULUS_LEN - p_pRsaInput -> ModulusLength],
    p_pRsaInput -> Modulus,
    p_pRsaInput -> ModulusLength
  );

  MemCpy (
    & Key.exponent [MAX_RSA_MODULUS_LEN - p_pRsaInput -> ExponentLength],
    p_pRsaInput -> Exponent,
    p_pRsaInput -> ExponentLength
  );

  MemSet (m_RSA_Buffer, 0, MAX_RSA_KEY_LENGTH);

  m_RsaResultLength = 0;


  if (
    RSAPublicBlock (
      m_RSA_Buffer,
      (unsigned int *) & m_RsaResultLength,
      p_pRsaInput -> Data,
      (unsigned int) p_pRsaInput -> ModulusLength,
      & Key
    ) != 0
  )
    URC_LOG_RETURN (URC_CRYPTO_GENERAL_ERROR);


  return URC_OK;

} /* RsaPrc_TransformData */



/** 

  Возвращает указатель на буфер, содержащий результат предыдущей RSA-операции.

*/

PUINT8 Rsa_GetResult (void)
{
  return m_RSA_Buffer;

} /* RsaPrc_GetResult */

UINT32 Rsa_GetResultLength(void)
{
    return m_RsaResultLength;
}


#ifdef DEBUG_SELF_TEST

#include <stdio.h>

BOOL Rsa_SelfTest (void)
{
/*
Public Key, 1024 bits:
modulus: b8 31 41 4e 0b 46 13 92 2b d3 5b 4b 36 80 2b c1 e1 e8 1c 95 a2 7c 95 8f 53 82 00 3d f6 46 15 4c a9 2f c1 ce 02 c3 be 04 7a 45 e9 b0 2a 90 89 b4 b9 02 78 23 7c 96 51 92 a0 fc c8 6b b4 9b c8 2a e6 fd c2 de 70 90 06 b8 6c 76 76 ef df 59 76 26 fa d6 33 a4 f7 dc 48 c4 45 d3 7e b5 5f cb 3b 1a bb 95 ba aa 82 6d 53 90 e1 5f d1 4e d4 03 fa 2d 0c b8 41 c6 50 60 95 24 ec 55 5e 3b c5 6c a9 57 
exponent: 01 00 01 

Private Key, 1024 bits:
modulus: b8 31 41 4e 0b 46 13 92 2b d3 5b 4b 36 80 2b c1 e1 e8 1c 95 a2 7c 95 8f 53 82 00 3d f6 46 15 4c a9 2f c1 ce 02 c3 be 04 7a 45 e9 b0 2a 90 89 b4 b9 02 78 23 7c 96 51 92 a0 fc c8 6b b4 9b c8 2a e6 fd c2 de 70 90 06 b8 6c 76 76 ef df 59 76 26 fa d6 33 a4 f7 dc 48 c4 45 d3 7e b5 5f cb 3b 1a bb 95 ba aa 82 6d 53 90 e1 5f d1 4e d4 03 fa 2d 0c b8 41 c6 50 60 95 24 ec 55 5e 3b c5 6c a9 57 
public exponent: 01 00 01 
exponent: aa 8f b9 c8 5a 3a 2e ff 49 23 f3 c3 07 19 d2 eb 3b 94 e3 7b 50 b6 8b 0b e8 a9 56 2e 0a 72 45 60 f2 be 2d 79 e6 27 7a 3a cd 3b 16 35 b2 84 9b 6f c5 6e 5a ef 89 7b ec d7 99 c9 da 91 99 f2 33 7c ac 74 cc 10 9e 3a 28 5e a8 cb 70 85 2b a5 65 70 75 26 d5 2f e2 80 b6 2f 3e b4 fb 08 7d 10 dd e7 c5 8b fa 61 ca b1 2b 8f 0d b7 96 34 d9 7c b9 25 08 2b 8d cd 13 95 00 7e 0d bc d9 1f 5c 2d 2e 39 
prime 1: e1 06 cd d0 08 c9 15 09 14 93 8a 8c a5 d7 84 b8 56 15 42 38 b7 e7 8e 89 cb d6 56 9f 59 76 20 10 7f 5e 6e e1 c3 ea 31 41 90 e0 8e 24 47 5e b8 16 f1 21 1e d1 49 ff 95 33 e5 60 de 4c ae ae f7 35 
prime 2: d1 8b 96 d5 45 45 96 ee 88 a3 3d d9 a1 17 66 42 ae 75 7b c6 18 0a 0d 78 39 b5 5e 99 16 c6 2d d6 ab 02 1b 61 1e a5 0e 9b ee 74 92 c7 10 92 91 70 67 a0 d0 48 6d c8 8c 35 dc 8b 45 ef 4b 55 53 db 
prime exponent 1: 5c 0f a8 8b ff cc 24 6a fe 9c 0e 06 d4 a2 83 8d d6 ca 03 b9 a8 a3 77 51 30 af 93 e8 c5 74 ea 51 55 8a 90 da 94 88 6f 76 5f 8b 3f 1b e0 87 03 d1 7e fd 09 da 9d e7 8e 67 18 e4 b4 8d b2 b9 aa 31 
prime exponent 2: 55 5c 20 b8 86 3c 7f ec 71 9a d6 12 36 6e 3a c9 05 1a 74 ae 50 92 9f c4 0e f6 14 30 16 b7 ea 6a 5d 45 41 74 01 b0 c9 4f ba 06 a0 d8 18 a7 2c 39 f6 ec ea 8b e6 b4 e0 70 fc 83 7b 9c ac 3a 79 2b 
coefficient: b5 3b 46 e3 6d 17 22 21 96 80 cc df b6 76 4a c7 8f 54 c0 65 5a a4 83 0e c6 34 5e 0b 75 ab 30 fd 6b 26 fc 1b f4 41 2f 5f 48 b9 06 28 55 78 83 dd 5b d4 cb cc 84 f7 6c 81 96 69 87 ae 1b 74 15 23 
*/

  SRsaInput RsaInput;

  UINT8 IntermediateResult [MAX_RSA_KEY_LENGTH];

  UINT8 EthalonData [] = 
    "12;hjklGjklhK451"
    "12asvzx3[[12jG51"
    "SDBzxfhfjk1hfN51"
    "123451234d1o]451"
    "1BV451ixcv123C51"
    "1V34512CVB123451"
    "1B3C5X2345123451"
    "12gs512Bvx1fgjh1";

  RsaInput.Modulus = (PUINT8)
    "\xb8\x31\x41\x4e\x0b\x46\x13\x92\x2b\xd3\x5b\x4b\x36\x80\x2b\xc1"
    "\xe1\xe8\x1c\x95\xa2\x7c\x95\x8f\x53\x82\x00\x3d\xf6\x46\x15\x4c"
    "\xa9\x2f\xc1\xce\x02\xc3\xbe\x04\x7a\x45\xe9\xb0\x2a\x90\x89\xb4"
    "\xb9\x02\x78\x23\x7c\x96\x51\x92\xa0\xfc\xc8\x6b\xb4\x9b\xc8\x2a"
    "\xe6\xfd\xc2\xde\x70\x90\x06\xb8\x6c\x76\x76\xef\xdf\x59\x76\x26"
    "\xfa\xd6\x33\xa4\xf7\xdc\x48\xc4\x45\xd3\x7e\xb5\x5f\xcb\x3b\x1a"
    "\xbb\x95\xba\xaa\x82\x6d\x53\x90\xe1\x5f\xd1\x4e\xd4\x03\xfa\x2d"
    "\x0c\xb8\x41\xc6\x50\x60\x95\x24\xec\x55\x5e\x3b\xc5\x6c\xa9\x57";
  
  RsaInput.ModulusLength = 128;

  RsaInput.Exponent = (PUINT8)"\x01\x00\x01"; /* public */

  RsaInput.ExponentLength = 3;

  RsaInput.Data = EthalonData;

  (void)Rsa_Encrypt (& RsaInput);

  MemCpy (IntermediateResult, Rsa_GetResult (), RsaInput.ModulusLength);

  RsaInput.Exponent = (PUINT8)/* private */
    "\xaa\x8f\xb9\xc8\x5a\x3a\x2e\xff\x49\x23\xf3\xc3\x07\x19\xd2\xeb"
    "\x3b\x94\xe3\x7b\x50\xb6\x8b\x0b\xe8\xa9\x56\x2e\x0a\x72\x45\x60"
    "\xf2\xbe\x2d\x79\xe6\x27\x7a\x3a\xcd\x3b\x16\x35\xb2\x84\x9b\x6f"
    "\xc5\x6e\x5a\xef\x89\x7b\xec\xd7\x99\xc9\xda\x91\x99\xf2\x33\x7c"
    "\xac\x74\xcc\x10\x9e\x3a\x28\x5e\xa8\xcb\x70\x85\x2b\xa5\x65\x70"
    "\x75\x26\xd5\x2f\xe2\x80\xb6\x2f\x3e\xb4\xfb\x08\x7d\x10\xdd\xe7"
    "\xc5\x8b\xfa\x61\xca\xb1\x2b\x8f\x0d\xb7\x96\x34\xd9\x7c\xb9\x25"
    "\x08\x2b\x8d\xcd\x13\x95\x00\x7e\x0d\xbc\xd9\x1f\x5c\x2d\x2e\x39";

  RsaInput.ExponentLength = 128;

  RsaInput.Data = IntermediateResult;

  (void)Rsa_Decrypt (& RsaInput);

  if (MemCmp (EthalonData, Rsa_GetResult (), RsaInput.ModulusLength))
  {
    puts ("error");
    return FALSE;
  }

  return TRUE;

} /* RsaPrc_SelfTest */

#endif /* #ifdef DEBUG_SELF_TEST */
