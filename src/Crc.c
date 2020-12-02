#include "CrcImp.h"
#include "Crc.h"
#include "Crypto.urc"

/******    CRC    ******/
/*===========================================================================*/

/** ����� �������������� ���������� CRC */
#define CRC_ALGORITHMS_QUANTITY 10
/** ������ �������� ���������� �������������� ���������� CRC */
READ_ONLY SCrcAlgorithm CrcAlgorithms[CRC_ALGORITHMS_QUANTITY] =
{
    { 16, 0x1021, 0xFFFF, TRUE, TRUE, 0xFFFF   }, /* #define CRC16_X25_HDLC   0 */
    { 16, 0x1021, 0xFFFF, FALSE, FALSE, 0x0000 }, /* #define CRC16_MIFARELOW  1 */
    { 8,  0x31  , 0xFF  , FALSE, FALSE, 0x0000 }, /* #define CRC8_TRANSPORT_DATA  2*/
    { 16, 0x8005, 0x0000, FALSE, FALSE, 0x0000 }, /* #define CRC16_HELPERS_EXCH  3*/
    { 16, 0x1021, 0xFFFF, TRUE,  TRUE,  0x0000 }, /* #define CRC16_BITMAP_PLANTAIN_DEF_PRESET  4
                                                   *(CRC16-CCITT (x^16 + x^12 + x^5 + 1) 0x8408 )*/
    { 16, 0x1021, 0xA55A, TRUE,  TRUE,  0x0000 },  /* #define CRC16_BITMAP_PLANTAIN_NO_DEF_PRESET  5
                                                   *(CRC16-CCITT (x^16 + x^12 + x^5 + 1) 0x8408 ),
                                                   * ��������� �������� 0x5AA5*/
    { 16, 0x1021 , 0x0000, FALSE,  FALSE,  0x0000 },/* #define CRC16_PAYWAVE_CITT  6*/
    { 16, 0x8005 , 0xFFFF, TRUE,  TRUE,    0x0000 },/*  #define CRC16_PAYWAVE_ANSI  7*/
    { 16, 0x8005 , 0xFFFF, TRUE,  TRUE,    0x0000 },/*  #define CRC16_ZIP  8*/
    { 8,  0x1D   , 0xC7   , FALSE, FALSE,   0x0000 }, /* #define CRC8_BITMAP  9*/

};
/** ��������� �������� ���������� ��������� CRC */
static SCrcAlgorithm s_CurrentCrcAlgorithm;

/** 
*  @brief  ������������� ���������� ��������� 
*
*  @param ucCrcType - ��� ������������� ��������� 
*
*  @return URC_OK - ���������� CRC ���������������� �������.
*          URC_CRYPTO_INVALID_PARAMETER - ������� ���������������� ��� CRC.
*/
URC Crc_Init(UINT8 ucCrcType)
{
    if (ucCrcType >= CRC_ALGORITHMS_QUANTITY)
        return URC_CRYPTO_INVALID_PARAMETER;
       
    s_CurrentCrcAlgorithm = CrcAlgorithms[ucCrcType]; 
    CrcPrc_Init(s_CurrentCrcAlgorithm.InitValue);
    return URC_OK;
} /* Crc_Init */

/** 
*  @brief  �������� ��������� ���� � ������������� ����������� �����.
*
*  @param  ucByte - �������� �����, ������� ������ ���� ���������
*                 � ������������� ����������� �����.
*/
void Crc_AddByte(UINT8 ucByte)
{
    CrcPrc_AddByte(&s_CurrentCrcAlgorithm, ucByte);
} /* Crc_AddByte */

/** 
*  @brief  �������� ���� ������ � ������������� ����������� �����.
*
*  @param pData - ��������� �� ���� ������, ������� ����� �������� �
*                 ������������� ����������� �����.
*  @param wLength - ����� ����� ������.
*
*/
void Crc_AddBlock(PCUINT8 pData, UINT16 wLength)
{
    UINT16 i;
    
    for(i=0; i<wLength; i++)
    {
        CrcPrc_AddByte(&s_CurrentCrcAlgorithm, *pData);
        pData++;
    }
} /* Crc_AddBlock */

/** 
*  @brief  �������� ����������� �������� CRC
*
*  @return �������� ���������� ���� ����������������� ������ ������� 
*        Crc_Init, Crc_AddByte (��� Crc_AddBlock).
*/
UINT16 Crc_GetResult(void)
{
    return CrcPrc_GetResult(&s_CurrentCrcAlgorithm);
} /* Crc_GetResult */
