#include "crt.h"
#include "Crypto.urc"
#include "Des.h"


typedef enum
{
  DCM_ENCIPHER,
  DCM_DECIPHER

} E_DES_CALCULATION_MODE;


static void aux_CalculateSingleDes (
  PCUINT8 p_pKey,
  PCUINT8 p_pInData,
  PUINT8 p_pOutData,
  E_DES_CALCULATION_MODE p_CalcMode
);


/**
*   @brief  Сложение 2-х блоков данных методом исключающего ИЛИ.
*
*   @param  p_Result - [out] указатель на буфер, в который будет записан результат 
*                            операции.
*   @param  p_Data1  -  [in] указатель на буфер, содержащий первый операнд. 
*   @param  p_Data2  -  [in] указатель на буфер, содержащий второй операнд.
*   @param  p_Size   -  [in] кол-во байтов для сложения. 
*
*/
/*lint -e613 possible use of null-pointer */
static void XOR (PUINT8 p_pResult, PCUINT8 p_pData1, PCUINT8 p_pData2, UINT8 p_Size)
{
    UINT8 i;

    CRT_ASSERT (p_pResult != NULL && p_pData1 != NULL && p_pData2 != NULL);    

    for (i = 0; i < p_Size; i ++) p_pResult [i] = p_pData1 [i] ^ p_pData2 [i];
} /*lint +e613 */

/**

  Шифрует 8 байтов данных по алгоритму DES.

  @param p_pKey     - указатель на буфер, содержащий 8-байтовое значение
                      ключа при помощи которого нужно выполнить шифрование.
  @param p_pInData  - указатель на буфер, содержащий 8 байтов данных, которые
                      нужно зашифровать.
  @param p_pOutData - указатель на буфер, куда будут помещены 8 байтов
                      зашифрованных данных
*/

URC Des_Single_Encrypt (PCUINT8 p_pKey, PCUINT8 p_pInData, PUINT8 p_pOutData)
{
  if (p_pKey == NULL || p_pInData == NULL || p_pOutData == NULL)
    URC_LOG_RETURN (URC_CRYPTO_INVALID_PARAMETER);
   
  aux_CalculateSingleDes (p_pKey, p_pInData, p_pOutData, DCM_ENCIPHER);

  return URC_OK;

} /* DesPrc_Single_Encrypt */



/**

  Расшифровывает 8 байтов данных по алгоритму DES.

  @param p_Key        - указатель на буфер, содержащий 8-байтовое значение
                        ключа при помощи которого нужно выполнить расшифровку.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байт зашифрованных
                        данных
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байт
                        расшифрованных данных

*/
URC Des_Single_Decrypt (PCUINT8 p_pKey, PCUINT8 p_pInData, PUINT8 p_pOutData)
{
  if (p_pKey == NULL || p_pInData == NULL || p_pOutData == NULL)
    URC_LOG_RETURN (URC_CRYPTO_INVALID_PARAMETER);
    
  aux_CalculateSingleDes (p_pKey, p_pInData, p_pOutData, DCM_DECIPHER);

  return URC_OK;

} /* DesPrc_Single_Decrypt */

/**

  Шифрует 8 байтов данных по алгоритму 3DES.

  @param p_Key        - указатель на буфер, содержащий 16-байтовое значение
                        ключа при помощи которого нужно выполнить шифрование.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байтов данных, которые
                        нужно зашифровать.
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байтов
                        зашифрованных данных.

*/

URC Des_Triple_Encrypt (PCUINT8 p_pKey, PCUINT8 p_pInData, PUINT8 p_pOutData)
{
  UINT8 IntermediateResult [8];

  URC_TRY (
    Des_Single_Encrypt (p_pKey, p_pInData, p_pOutData),
    URC_CRYPTO_ERROR_WHILE_3DES_ENC_FIRST_PHASE
  );

  URC_TRY (
    Des_Single_Decrypt (p_pKey + 8, p_pOutData, IntermediateResult),
    URC_CRYPTO_ERROR_WHILE_3DES_ENC_SECOND_PHASE
  );

  return Des_Single_Encrypt (p_pKey, IntermediateResult, p_pOutData);
  
} /* DesPrc_Triple_Encrypt */



/**

  Расшифровывает 8 байтов данных по алгоритму 3DES.

  @param p_Key        - указатель на буфер, содержащий 16-байтовое значение
                        ключа при помощи которого нужно выполнить расшифровку.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байт зашифрованных
                        данных
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байт
                        расшифрованных данных

*/

URC Des_Triple_Decrypt (PCUINT8 p_pKey, PCUINT8 p_pInData, PUINT8 p_pOutData)
{
  UINT8 IntermediateResult [8];

  URC_TRY (
    Des_Single_Decrypt (p_pKey, p_pInData, p_pOutData),
    URC_CRYPTO_ERROR_WHILE_3DES_DEC_FIRST_PHASE
  );

  URC_TRY (
    Des_Single_Encrypt (p_pKey + 8, p_pOutData, IntermediateResult),
    URC_CRYPTO_ERROR_WHILE_3DES_DEC_SECOND_PHASE
  );

  return Des_Single_Decrypt (p_pKey, IntermediateResult, p_pOutData);

} /* DesPrc_Triple_Decrypt */



/**

Шифрует 8 байтов данных по алгоритму 3DES-CBC.

@param p_Key        - указатель на буфер, содержащий 16-байтовое значение
ключа при помощи которого нужно выполнить шифрование.
@param p_pInBuffer  - указатель на буфер, содержащий 8 байтов данных, которые
нужно зашифровать.
@param p_Len  -      Указатель на разме входного буфера. Выходной буфер может быть увеличен
                     из-за Padding. Если планируется Padding - необходимо передавать на 8 байт больше
@param p_pIV       -   [in] указатель на данные вектора инициализации. Если NULL, значит он стандартный
@param p_Padding   -   [in] Стандарт вычисления Padding
@param p_pInBuffer  - указатель на буфер, содержащий 8 байтов данных, которые
нужно зашифровать.


@param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байтов
зашифрованных данных.

*/

URC Des_Cbc_Encrypt (PCUINT8 p_Key, 
                     PCUINT8 p_pInBuffer, 
                     UINT16  p_Len,
                     PUINT8  p_pIV,
                     UINT8   p_Padding,
                     PUINT8  p_pOutBuffer)
{
    UINT8 Buf [8], i, Quotient;
    UINT8 Block[8];


    if (p_Key == NULL || p_pInBuffer == NULL || p_pOutBuffer == NULL)
        return URC_CRYPTO_INVALID_PARAMETER;

     /*Если не кратно 8, то нужен Padding*/
    if(p_Len%8 > 0)
    {
        switch(p_Padding)
        {
        case DES_PADDING_ZERO:

            /*пока не поддерживается*/
            return URC_CRYPTO_INVALID_PARAMETER;
            break;

        case DES_PADDING_EMV:

            /*пока не поддерживается*/
            return URC_CRYPTO_INVALID_PARAMETER;
            break;

        default:
            return URC_CRYPTO_INVALID_PARAMETER;
            break;
        }
    }
    else
    {
        Quotient = (UINT8)(p_Len / 8);
    }

    /*Инициализация начального вектора*/
    if(p_pIV == NULL)
    {
        MemSet(Buf, 0, sizeof(Buf)); /* начальный вектор */
    }
    else
    {
        MemCpy(Buf,p_pIV,sizeof(Buf));
    }

    memset(Block,0,sizeof(Block));

    for (i = 0; i < Quotient; i ++)
    {  
        
        XOR(Block, p_pInBuffer  + i * 8, Buf , sizeof(Buf));
        
        URC_TRY (
            Des_Triple_Encrypt(p_Key, Block, p_pOutBuffer + i * 8),
            URC_CRYPTO_ERROR_WHILE_3DES_DEC_FIRST_PHASE
            );

        MemCpy(Buf,p_pOutBuffer + i * 8,8);
    }

    return URC_OK;  
}



/**

Расшифровывает 8 байтов данных по алгоритму 3DES-CBC.

@param p_Key        - указатель на буфер, содержащий 16-байтовое значение
ключа при помощи которого нужно выполнить расшифровку.
@param p_pInBuffer  - указатель на буфер, содержащий 8 байт зашифрованных
данных
@param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байт
расшифрованных данных

*/

URC Des_Cbc_Decrypt (PCUINT8 p_Key, 
                     PCUINT8 p_pInBuffer, 
                     UINT16  p_Len,
                     PUINT8  p_pIV,
                     UINT8   p_Padding,
                     PUINT8  p_pOutBuffer)
{

    UINT8 Buf [8], i, Quotient;
    UINT8 Block[8];


    if (p_Key == NULL || p_pInBuffer == NULL || p_pOutBuffer == NULL)
        return URC_CRYPTO_INVALID_PARAMETER;

    /*Если не кратно 8, то нужен Padding*/
    if(p_Len%8 > 0)
    {
        switch(p_Padding)
        {
        case DES_PADDING_ZERO:

            /*пока не поддерживается*/
            return URC_CRYPTO_INVALID_PARAMETER;
            break;

        case DES_PADDING_EMV:

            /*пока не поддерживается*/
            return URC_CRYPTO_INVALID_PARAMETER;
            break;

        default:
            return URC_CRYPTO_INVALID_PARAMETER;
            break;
        }
    }
    else
    {
        Quotient = (UINT8)(p_Len / 8);
    }


    /*Инициализация начального вектора*/
    if(p_pIV == NULL)
    {
        MemSet(Buf, 0, sizeof(Buf)); /* начальный вектор */
    }
    else
    {
        MemCpy(Buf,p_pIV,sizeof(Buf));
    }

    memset(Block,0,sizeof(Block));

    for (i = 0; i < Quotient; i ++)
    {  
        /*Сохраняем для копирования в Buf, который используется в XOR в следующем блоке*/       
        MemCpy(Block,p_pInBuffer + i * 8,8);

        URC_TRY (
            Des_Triple_Decrypt(p_Key, p_pInBuffer + i * 8, p_pOutBuffer + i * 8),
            URC_CRYPTO_ERROR_WHILE_3DES_DEC_FIRST_PHASE
            );

        XOR(p_pOutBuffer  + i * 8, p_pOutBuffer  + i * 8, Buf , sizeof(Buf));
    

        MemCpy(Buf,Block,sizeof(Buf));
    }

    return URC_OK;  
}




/**
  
  Шифрует или расшифровывает данные по алгоритму DES в зависимости от p_CalcMode.

  @param p_pKey     - [in]  указатель на буфер, содержащий 8-байтное значение ключа.
  @param p_pInData  - [in]  указатель на буфер, содержащий 8 байтов входных данных.
  @param p_pOutData - [out] указатель на буфер, куда будут помещены 8 байтов выходных данных.
  @param p_CalcMode - [in]  тип преобразования:
                               DCM_ENCIPHER - шифрование,
                               DCM_DECIPHER - дешифрование.  

*/
/*lint -e613 */
static void aux_CalculateSingleDes (
  PCUINT8 p_pKey, PCUINT8 p_pInData, PUINT8 p_pOutData, E_DES_CALCULATION_MODE p_CalcMode
)
{
  UINT32 x, c, d, r, l;
  INT16  i;
  UINT32 s[64] = { /* * S-tables and permutation E combined */
    0xD8D8DBBC, 0xD737D1C1, 0x8B047441, 0x35A9E2FE, 0x146E9560, 0x8A420CFB, 0xF8FBAF1F, 0xC7B4DD10,
    0x7A97A497, 0x4CFCFA1C, 0x456ADA86, 0xFAC710E9, 0xE52149EF, 0x338D2004, 0x1E5580F1, 0xE04A2F3D,
    0x870A4E20, 0x28BE9C1F, 0x74D5E339, 0x8240BD00, 0x6AA1ABC3, 0x3F55E2A8, 0xAF1F56BC, 0x51BB11CF,
    0xB7FC035E, 0xE00307B0, 0x08A3B44B, 0x3F786D67, 0x09967CBC, 0x45EB7B47, 0xF3683962, 0x9C14C6D2,
    0x16452B42, 0xADDACEBA, 0x58F91ABC, 0x8B68B547, 0xFAA36659, 0x47BF8901, 0x671AEBA9, 0x30C452AB,
    0x493893E1, 0x72C16866, 0xB7C78574, 0xCD1E6B9A, 0xB6DCD49C, 0x9822B7FB, 0x89B07E43, 0x77B78644,
    0xA566F5DF, 0xD22D6AC3, 0xAF9A0423, 0x77B71BBC, 0x81DC043E, 0xC8837314, 0x78659153, 0xAF782C7D,
    0x8C0F78A0, 0x0D3095EF, 0x7A506B8E, 0x8445D610, 0x5223AB47, 0x724C0C34, 0x45AF54BC, 0x38DBF9CB};

  CRT_ASSERT (
    p_pKey != NULL && p_pInData != NULL && p_pOutData != NULL &&
    (p_CalcMode == DCM_ENCIPHER || p_CalcMode == DCM_DECIPHER)
  );

  l = r = c = d = 0L;
  i = 7;
  do 
  {
    x = (UINT32)p_pInData[i];
    l = l << 1 | (x & 1L << 0)    | (x & 1L << 2) << 6 | (x & 1L << 4) << 12 | (x & 1L << 6) << 18;
    r = r << 1 | (x & 1L << 1) >> 1 | (x & 1L << 3) << 5 | (x & 1L << 5) << 11 | (x & 1L << 7) << 17;
    x = (UINT32)p_pKey[i];
    c = c << 1 | (x & 1L << 7) << 17 | (x & 1L << 6) << 10 | (x & 1L << 5) << 3 | (x & 1L << 4) >> 4 ;
    d = d << 1 | (x & 1L << 1) << 19 | (x & 1L << 2) << 10 | (x & 1L << 3) << 1 ;
  } while (--i >= 0);
  d |= c & 0x0000000F;  /* 0x0F; */
  c >>= 4;
  i = 24;

  /* first round is special: one left shift on encipher, no shift on decipher */
  if (p_CalcMode != DCM_ENCIPHER)
       goto startround;
leftby1:
  c = c << 1 | (c >> 27 & 1L);
  d = d << 1 | (d >> 27 & 1L);
startround:
  /* a round - apply PC2, the S-boxes and permutation E */
  x  = (s[(UINT16)(((r>>26&62)|(r&1) )^((c>>6 &32)|(c>>13&16)|(c>>1 &8)|(c>>25&4)|(c>>22&2)|(c>>14&1)))] & 0x00808202) ^ l;
  x ^=  s[(UINT16)(( r>>23&63        )^((c>>20&32)|(c<<4 &16)|(c>>10&8)|(c>>20&4)|(c>>6 &2)|(c>>18&1)))] & 0x40084010;
  x ^=  s[(UINT16)(( r>>19&63        )^((c    &32)|(c>>5 &16)|(c>>13&8)|(c>>22&4)|(c>>1 &2)|(c>>20&1)))] & 0x04010104;
  x ^=  s[(UINT16)(( r>>15&63        )^((c>>7 &32)|(c>>17&16)|(c<<2 &8)|(c>>6 &4)|(c>>14&2)|(c>>26&1)))] & 0x80401040;
  x ^=  s[(UINT16)(( r>>11&63        )^((d>>10&32)|(d    &16)|(d>>22&8)|(d>>17&4)|(d>>8 &2)|(d>>1 &1)))] & 0x21040080;
  x ^=  s[(UINT16)(( r>>7 &63        )^((d>>21&32)|(d>>12&16)|(d>>2 &8)|(d>>9 &4)|(d>>22&2)|(d>>8 &1)))] & 0x10202008;
  x ^=  s[(UINT16)(( r>>3 &63        )^((d>>7 &32)|(d>>3 &16)|(d>>14&8)|(d<<2 &4)|(d>>21&2)|(d>>3 &1)))] & 0x02100401;
  x ^=  s[(UINT16)(((r&31)|(r>>26&32))^((d>>19&32)|(d>>6 &16)|(d>>11&8)|(d>>4 &4)|(d>>19&2)|(d>>27&1)))] & 0x08020820;
  l = r;
  r = x;
  /* decide/perform key shifts */
  if ((i & 7) == 0) 
  {
    i -= 2;
    if (p_CalcMode == DCM_ENCIPHER)
         goto leftby1;
    c = c >> 1 | (c & 1L) << 27;
    d = d >> 1 | (d & 1L) << 27;
    goto startround;
  }
  if (i != 6) 
  {
    --i;
    if (p_CalcMode == DCM_ENCIPHER) {
      c = c << 2 | (c >> 26 & 3L);
      d = d << 2 | (d >> 26 & 3L);
      goto startround;
    } 
    else 
    {
      c = c >> 2 | (c & 3L) << 26;
      d = d >> 2 | (d & 3L) << 26;
      goto startround;
    }
  }
  /* final swap and permutations IP` */
  i = 7;
  do
  {
    * p_pOutData ++ = (UINT8 ) ( (r    & 1L << 0) | (r >> 6 & 1L << 2) | (r >> 12 & 1L << 4) | (r >> 18 & 1L << 6) |
       (l << 1 & 1L << 1) | (l >> 5 & 1L << 3) | (l >> 11 & 1L << 5) | (l >> 17 & 1L << 7) );
    l >>= 1;
    r >>= 1;
  } while (--i >= 0);

} /* aux_CalculateSingleDes */
