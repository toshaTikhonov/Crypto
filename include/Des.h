#ifndef __DES_H__
#define __DES_H__

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Тип заполнения (padding) при вычислении MAC */
#define DES_PADDING_ZERO                  0x00         /**< Дополнять нулями */
#define DES_PADDING_EMV                   0x01         /**< Дополнять в соответствии  */
#define DES_PADDING_NONE                  0x02         /**< не дополнять, Padding сделан до вызова функции.   */

/**
  @brief Шифрует 8 байтов данных по алгоритму DES.
  @param p_pKey       - указатель на буфер, содержащий 8-байтовое значение
                        ключа при помощи которого нужно выполнить шифрование.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байтов данных, которые
                        нужно зашифровать.
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байтов
                        зашифрованных данных
*/
URC Des_Single_Encrypt (PCUINT8 p_pKey, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
  @brief Расшифровывает 8 байтов данных по алгоритму DES.
  @param p_Key        - указатель на буфер, содержащий 8-байтовое значение
                        ключа при помощи которого нужно выполнить расшифровку.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байт зашифрованных
                        данных
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байт
                        расшифрованных данных
*/
URC Des_Single_Decrypt (PCUINT8 p_pKey, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
  @brief Шифрует 8 байтов данных по алгоритму 3DES.

  @param p_Key        - указатель на буфер, содержащий 16-байтовое значение
                        ключа при помощи которого нужно выполнить шифрование.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байтов данных, которые
                        нужно зашифровать.
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байтов
                        зашифрованных данных.
*/
URC Des_Triple_Encrypt (PCUINT8 p_Key, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
  @brief Расшифровывает 8 байтов данных по алгоритму 3DES.
  @param p_Key        - указатель на буфер, содержащий 16-байтовое значение
                        ключа при помощи которого нужно выполнить расшифровку.
  @param p_pInBuffer  - указатель на буфер, содержащий 8 байт зашифрованных
                        данных
  @param p_pOutBuffer - указатель на буфер, куда будут помещены 8 байт
                        расшифрованных данных
*/
URC Des_Triple_Decrypt (PCUINT8 p_Key, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
    @brief Шифрует 8 байтов данных по алгоритму 3DES-CBC.
    @param p_Key        - указатель на буфер, содержащий 16-байтовое значение
    ключа при помощи которого нужно выполнить шифрование.
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
                     PUINT8  p_pOutBuffer);

/**
    @brief Расшифровывает 8 байтов данных по алгоритму 3DES-CBC.
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
                     PUINT8  p_pOutBuffer);


#ifdef __cplusplus
}
#endif

#endif /* __DES_H__ */
