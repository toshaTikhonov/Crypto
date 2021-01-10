#ifndef __CRCPR_H__
#define __CRCPR_H__

#include "bastypes.h"

/******    CRC    ******/
/*===========================================================================*/
/** Константы, определяющие алгоритм расчёта CRC 
    (каждая константа является индексом элемента массива CrcParameters,
    который определяет полином алгоритма, начальное значение, направления
    сдвигов и т.п.) */
#define CRC16_X25_HDLC                          0 /**< Алгоритм CRC16 для расчёта контрольной суммы протокола HDLC */
#define CRC16_MIFARELOW                         1
#define CRC8_TRANSPORT_DATA                     2
#define CRC16_HELPERS_EXCH                      3
#define CRC16_BITMAP_PLANTAIN_DEF_PRESET        4 /*(CRC16-CCITT (x^16 + x^12 + x^5 + 1) 0x8408 )*/
#define CRC16_BITMAP_PLANTAIN_NO_DEF_PRESET     5 /*(CRC16-CCITT (x^16 + x^12 + x^5 + 1) 0x8408 )*/
#define CRC16_PAYWAVE_CITT                      6
#define CRC16_PAYWAVE_ANSI                      7
#define CRC16_ZIP                               8
#define CRC8_BITMAP                             9
#define CRC32                                  10
#define CRC32BZIP2                             11
#define CRC32C                                 12
#define CRC32D                                 13
#define CRC32MPEG2                             14
#define CRC32POSIX                             15

/*---------------------------------------------------------------------------*/
/** Инициализация выбранного протокола 
    @param ucCrcType - тип используемого алгоритма 
    @return URC_OK - подсистема CRC инициализирована успешно.
        URC_CRYPTO_INVALID_PARAMETER - передан неподдерживаемый тип CRC.
*/
URC Crc_Init(UINT8 ucCrcType);
/*---------------------------------------------------------------------------*/
/** Добавить единичный байт к расчитываемой контрольной сумме.
    @param ucByte - значение байта, которое должно быть добавлено
        к расчитываемой контрольной сумме.
*/
void Crc_AddByte(UINT8 ucByte);
/*---------------------------------------------------------------------------*/
/** Добавить блок данных к расчитываемой контрольной сумме.
    @param pData - указатель на блок данных, который нужно добавить к
        расчитываемой контрольной сумме.
    @param wLength - длина блока данных.
*/
void Crc_AddBlock(PCUINT8 pData, UINT16 wLength);
/*---------------------------------------------------------------------------*/
/** Получить расчитанное значение CRC (для crc32 своя фунция)
    @return Значение полученное путём последовательного вызова функций 
        CryptoPrc_Crc_Init, CryptoPrc_Crc_AddByte (или CryptoPrc_Crc_AddBlock).
*/
UINT16 Crc_GetResult(void);

/** Получить расчитанное значение CRC32
    @return Значение полученное путём последовательного вызова функций
        CryptoPrc_Crc_Init, CryptoPrc_Crc_AddByte (или CryptoPrc_Crc_AddBlock).
*/
UINT32 Crc_GetResult32(void);

#endif

