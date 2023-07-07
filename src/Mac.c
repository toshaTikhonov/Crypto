#include "crt.h"
#include "Des.h"
#include "Mac.h"

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
static void XOR (PUINT8 p_pResult, PCUINT8 p_pData1, PCUINT8 p_pData2, UINT8 p_Size)
{
  UINT8 i;

  CRT_ASSERT (p_pResult != NULL && p_pData1 != NULL && p_pData2 != NULL);    

  for (i = 0; i < p_Size; i ++) p_pResult [i] = p_pData1 [i] ^ p_pData2 [i];
} /*lint +e613 */


/**
Конвертирует данные из BIN в HEX.

БУДЬТЕ ВНИМАТЕЛЬНЫ! ЭТО НЕ ПРИВЫЧНЫЙ НАМ HEX! Это HEX в нотации Open WAY.

@note Выдержка из документации OW:

"Для обеспечения совместимости с различными типами криптооборудования HOST системы
вводится конфигурационный параметр терминала MACDATA=, который может принимать два
значения BIN и HEX. В первом случае, данные "макируемого" сообщения обрабатываются
криптопроцессором как есть, т.е. в виде потока байтов, содержащих bynary codes
(при этом дополнение до 8-байтовой границы осуществляется двоичными нулями). Во
втором случае, данные перед отправкой на обработку преобразуются в расширенную
HEX форму, когда каждым четырем битам исходной информации соответствует байт HEX
значения (HexValue = 0x30 + FourBitValue). Младшие четыре бита исходных данных
соответствуют предваряющему HEX-коду результирующего потока, а старшие 4 бита
соответствуют последующему HEX-коду результирующего потока. Дополнение до 8-байтовой
границы осуществляется в этом случае HEX кодами нулей 0x30."

@param p_pInputData      Указатель на входные данные.
@param p_Len             Длина входных данных.
@param p_pOutputData     Указатель на выходные данные.

@return Код ответа URC_MAC_XXXX.

*/
static void Mac_aux_BinToHexSpecial(PCUINT8 p_pInputData, UINT16 p_Len, PUINT8 p_pOutputData)
{
  UINT16 i;

  CRT_ASSERT (p_pInputData != NULL && p_pOutputData != NULL);

  for (i = 0; i < p_Len; i ++)
  {
    /* 09/02/2005: [AZ] НИБЛЫ МЕНЯЮТСЯ МЕСТАМИ!!! */
    p_pOutputData [2 * i    ] = '0' + (p_pInputData [i] & 0x0F);
    p_pOutputData [2 * i + 1] = '0' + (p_pInputData [i] >> 4);
  }  
} /* Mac_aux_BinToHexSpecial */


static URC Mac_aux_MakePadding(PUINT8 p_pData, PUINT16 p_pDataLength, 
                                     UINT8 p_Format, UINT8 p_PaddingType)
{
  UINT8 Remainder;

  Remainder= *p_pDataLength % 8;

  if(Remainder == 0)
    return URC_OK;
  
  switch(p_Format)
  {
    case MAC_FORMAT_BIN:
      MemSet (p_pData + *p_pDataLength, 0, 8-Remainder);
      switch(p_PaddingType) 
      {
        case MAC_PADDING_ZERO:
          break;
        case MAC_PADDING_EMV:
          MemSet (p_pData + *p_pDataLength, 0x80, 1);
          break;
        default:
          return URC_CRYPTO_MAC_INVALID_MAC_PADDING_TYPE;
      }
      break;

    case MAC_FORMAT_HEX:
      MemSet (p_pData + *p_pDataLength, '0', 8-Remainder);
      switch(p_PaddingType) 
      {
        case MAC_PADDING_ZERO:
          break;
        case MAC_PADDING_EMV:
          MemSet(p_pData + *p_pDataLength, '8', 1);
          break;
        default:
          return URC_CRYPTO_MAC_INVALID_MAC_PADDING_TYPE;
      }
      break;

    default:
      return URC_CRYPTO_MAC_INVALID_MAC_FORMAT;
  }
  
  *p_pDataLength += (8-Remainder);
  
  return URC_OK;
} /* Mac_aux_MakePadding */


/**
*
*  @brief Программная реализация вычисления MAC.
*
*  @param p_pData      -  [in] указатель на буфер, содержащий данные, для которых 
*                         расчитывается MAC.     
*  @param p_Len        -  [in] размер данных.
*  @param p_pMAC       - [out] указатель на буфер, в который будет записано вычисленное
*                         значение MAC.
*  @param p_Standard   - [in] Стандарт вычисления ANSI X9.19 тип 1/2
*  @param p_pKey       - [in] указатель на буфер, содержащий ключ, при помощи которого 
*                         будет выполняться промежуточное шифрование.
*
*  @retval URC_MAC_XXXX
*
*/
URC Mac_CalcMacSW(PCUINT8 p_pData,
                  UINT16  p_Len,
                  PUINT8  p_pMAC,
                  PUINT8  p_pIV,
                  UINT8   p_Standard,
                  UINT8   p_Padding,
                  PCUINT8 p_pClearKey)
{ 
  UINT8 Buf [8], i, Quotient;
  UINT8 Residuals_count = 0;
  UINT8 MacLastBlock[8];

  MemSet(MacLastBlock,0,sizeof(MacLastBlock));

    switch(p_Padding)
    {
    case MAC_PADDING_ZERO:

        Residuals_count = p_Len%8;

        memcpy(MacLastBlock, &p_pData[p_Len - Residuals_count],  Residuals_count);
        memcpy(&MacLastBlock[Residuals_count], "\x00\x00\x00\x00\x00\x00\x00\x00", 8 - Residuals_count);

        /*Добавляем Padding*/
        p_Len += 8 - Residuals_count;

        Quotient = (UINT8)(p_Len / 8);

        Quotient--; //будем идти до последнего блока

	    break;
    case MAC_PADDING_EMV:

        Residuals_count = p_Len%8;

        memcpy(MacLastBlock, &p_pData[p_Len - Residuals_count],  Residuals_count);
        memcpy(&MacLastBlock[Residuals_count], "\x80\x00\x00\x00\x00\x00\x00\x00", 8 - Residuals_count);

        /*Добавляем Padding*/
        p_Len += 8 - Residuals_count;

        Quotient = (UINT8)(p_Len / 8);

        Quotient--; //будем идти до последнего блока

	    break;

    case MAC_PADDING_NONE:
        /*Еслди нет Padding, тоесть он сделан уже заранее.
          Если он не сделан, то это ошибка*/
        Residuals_count = p_Len%8;
        
        if(Residuals_count > 0)
        {
            return URC_CRYPTO_MAC_INVALID_MAC_FORMAT;
        }

        Quotient = (UINT8)(p_Len / 8);
        memcpy(MacLastBlock, &p_pData[p_Len - 8],  8);

        Quotient--;//будем идти до последнего блока

        break;

    default:
        return URC_CRYPTO_INVALID_PARAMETER;
        break;
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
  
  for (i = 0; i < Quotient; i ++)
  {  
    XOR(Buf, p_pData + i * 8, Buf, sizeof(Buf));
   
    switch(p_Standard)
    {
    case MAC_STANDARD_ANSI_X9_19_TYPE1:
      URC_TRY(Des_Single_Encrypt (p_pClearKey, Buf, Buf),
              URC_CRYPTO_DES_CALCULATION_FAILED_ON_MAC);
      break;
    case MAC_STANDARD_ANSI_X9_19_TYPE2: /* (ANSI X9.19 Alt) */
      URC_TRY(Des_Triple_Encrypt (p_pClearKey, Buf, Buf),
              URC_CRYPTO_DES_CALCULATION_FAILED_ON_MAC);
      break;
    default:
      return URC_CRYPTO_INVALID_MAC_STANDARD;
    }
  }
  
  if (p_Standard==MAC_STANDARD_ANSI_X9_19_TYPE1)
  { 
    XOR(Buf,MacLastBlock, Buf, sizeof(Buf));
      
    URC_TRY(Des_Single_Encrypt (p_pClearKey, Buf, Buf),
          URC_CRYPTO_DES_CALCULATION_FAILED_ON_MAC);
    URC_TRY(Des_Single_Decrypt (p_pClearKey+8, Buf, Buf),
            URC_CRYPTO_DES_CALCULATION_FAILED_ON_MAC);
    URC_TRY(Des_Single_Encrypt (p_pClearKey, Buf, Buf),
            URC_CRYPTO_DES_CALCULATION_FAILED_ON_MAC);
  }
  
  MemCpy(p_pMAC, Buf, sizeof(Buf)); /* 64 bits */

  return URC_OK;

} /* Mac_aux_CalcMacSW */




/** 
*  @brief Вычисляет MAC 
*
*  @param p_Data -  [in] указатель на данные, для которых нужно вычислить MAC.
*  @param p_Len  -  [in] размер данных
*  @param p_pMAC - [out] указатель на буфер, в который будет записано вычисленное 
*                   значение MAC.
*  @param p_Format Формат входных данных BIN/HEX
*  @param p_Standard Стандарт вычисления ANSI X9.19 тип 1/2
*  @param p_PaddingType Тип заполнения блока до полного Zero/EMV
*  @param p_pMacKey - [in] зашифрованное значение MAC-ключа.
*
*  @retval URC_MAC_XXXX
*/
URC Mac_CalcMac(PCUINT8 p_pData, UINT16 p_Len, PUINT8 p_pMAC, UINT8 p_Format, UINT8 p_Standard, UINT8 p_PaddingType,
                PUINT8 p_pMacKey)
{
  UINT8 AsciiData [2048];
  UINT16 DataLength;

  if (p_pData == NULL || p_pMAC == NULL || p_pMacKey == NULL)
    return URC_CRYPTO_INVALID_PARAMETER;

  MemSet(AsciiData, 0, 2048);

  /* проверка длины сообщения и типа входных данных */
  switch(p_Format)
  {
  case MAC_FORMAT_BIN:
    if(p_Len>2048)
      return URC_CRYPTO_MESSAGE_TOO_LONG_TO_CALC_MAC;
    else
    {      
      MemCpy(AsciiData, p_pData, p_Len);
      DataLength = p_Len;
    }
    break;

  case MAC_FORMAT_HEX:
    if(p_Len>256)
      return URC_CRYPTO_MESSAGE_TOO_LONG_TO_CALC_MAC;
    else
    {
      Mac_aux_BinToHexSpecial (p_pData, p_Len, AsciiData);
      DataLength = (UINT16)(p_Len*2);
    }
    break;

  default:
    return URC_CRYPTO_INVALID_MAC_FORMAT;
  }

  /* дополним буфер padding байтами если нужно */
  URC_TRY(Mac_aux_MakePadding(AsciiData, &DataLength, p_Format, p_PaddingType),
          URC_CRYPTO_DES_CALCULATION_FAILED_ON_MAC);

  /* здесь значение p_pMacKey используется, как открытое */
  URC_RETURN(Mac_CalcMacSW(AsciiData, DataLength, p_pMAC,NULL,p_Standard, MAC_PADDING_NONE ,p_pMacKey),
             URC_CRYPTO_LOAD_MAC_KEY_FAILED);
} /* Mac_CalcMac */
