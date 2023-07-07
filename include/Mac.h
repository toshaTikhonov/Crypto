#ifndef __MAC_H__
#define __MAC_H__

#include "bastypes.h"
#include "Crypto.urc"

#ifdef __cplusplus
extern "C" {
#endif


/** Типы форматов входных данных для вычисления MAC */
#define MAC_FORMAT_BIN                    0x00         /**< Входные данные обрабатываются "как есть" */
#define MAC_FORMAT_HEX                    0x01         /**< Входные данные преобразуются в HEX-формат по спецификации OpenWay */

/** Стандарты вычисления MAC */
#define HALPPD_MAC_STANDARD_ANSI_X9_19_TYPE1     0x00 /**< MAC считается по стандарту ANSI X9.19 тип 1 (3DES на каждом шаге )*/
#define HALPPD_MAC_STANDARD_ANSI_X9_19_TYPE2     0x01 /**< MAC считается по стандарту ANSI X9.19 тип 2 (DES на каждом, 3DES на последнем шаге )*/

/** Стандарты вычисления MAC */
#define MAC_STANDARD_ANSI_X9_19_TYPE1 (0x00) /**< MAC считается по стандарту ANSI X9.19 тип 1 */
#define MAC_STANDARD_ANSI_X9_19_TYPE2 (0x01) /**< MAC считается по стандарту ANSI X9.19 тип 2 */

/** Тип заполнения (padding) при вычислении MAC */
#define MAC_PADDING_ZERO                  0x00         /**< Дополнять нулями */
#define MAC_PADDING_EMV                   0x01         /**< Дополнять в соответствии  */
#define MAC_PADDING_NONE                    0x02         /**< не дополнять, Padding сделан до вызова функции.   */

/**
*
*  @brief Программная реализация вычисления MAC.
*
*  @param p_pData      -  [in] указатель на буфер, содержащий данные, для которых 
*                         расчитывается MAC.     
*  @param p_Len        -  [in] размер данных.
*  @param p_pMAC       -  [out] указатель на буфер, в который будет записано вычисленное
*                         значение MAC.
*  @param p_pIV       -   [in] указатель на данные вектора инициализации. Если NULL, значит он стандартный
*  @param p_Standard   -  [in] Стандарт вычисления ANSI X9.19 тип 1/2
*  @param p_Padding   -   [in] Стандарт вычисления Padding
*  @param p_pKey       -  [in] указатель на буфер, содержащий ключ, при помощи которого 
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
                  PCUINT8 p_pClearKey);

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
                PUINT8 p_pMacKey);

#ifdef __cplusplus
}
#endif

#endif /* __MAC_H__*/
