#ifndef __CRCPR_H__
#define __CRCPR_H__

#include "bastypes.h"

/******    CRC    ******/
/*===========================================================================*/
/** ���������, ������������ �������� ������� CRC 
    (������ ��������� �������� �������� �������� ������� CrcParameters,
    ������� ���������� ������� ���������, ��������� ��������, �����������
    ������� � �.�.) */
#define CRC16_X25_HDLC                          0 /**< �������� CRC16 ��� ������� ����������� ����� ��������� HDLC */
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
/** ������������� ���������� ��������� 
    @param ucCrcType - ��� ������������� ��������� 
    @return URC_OK - ���������� CRC ���������������� �������.
        URC_CRYPTO_INVALID_PARAMETER - ������� ���������������� ��� CRC.
*/
URC Crc_Init(UINT8 ucCrcType);
/*---------------------------------------------------------------------------*/
/** �������� ��������� ���� � ������������� ����������� �����.
    @param ucByte - �������� �����, ������� ������ ���� ���������
        � ������������� ����������� �����.
*/
void Crc_AddByte(UINT8 ucByte);
/*---------------------------------------------------------------------------*/
/** �������� ���� ������ � ������������� ����������� �����.
    @param pData - ��������� �� ���� ������, ������� ����� �������� �
        ������������� ����������� �����.
    @param wLength - ����� ����� ������.
*/
void Crc_AddBlock(PCUINT8 pData, UINT16 wLength);
/*---------------------------------------------------------------------------*/
/** �������� ����������� �������� CRC (��� crc32 ���� ������)
    @return �������� ���������� ���� ����������������� ������ ������� 
        CryptoPrc_Crc_Init, CryptoPrc_Crc_AddByte (��� CryptoPrc_Crc_AddBlock).
*/
UINT16 Crc_GetResult(void);

/** �������� ����������� �������� CRC32
    @return �������� ���������� ���� ����������������� ������ �������
        CryptoPrc_Crc_Init, CryptoPrc_Crc_AddByte (��� CryptoPrc_Crc_AddBlock).
*/
UINT32 Crc_GetResult32(void);

#endif

