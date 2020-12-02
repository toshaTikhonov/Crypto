#ifndef __MAC_H__
#define __MAC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "bastypes.h"
#include "Crypto.urc"

/** ���� �������� ������� ������ ��� ���������� MAC */
#define MAC_FORMAT_BIN                    0x00         /**< ������� ������ �������������� "��� ����" */
#define MAC_FORMAT_HEX                    0x01         /**< ������� ������ ������������� � HEX-������ �� ������������ OpenWay */

/** ��������� ���������� MAC */
#define HALPPD_MAC_STANDARD_ANSI_X9_19_TYPE1     0x00 /**< MAC ��������� �� ��������� ANSI X9.19 ��� 1 (3DES �� ������ ���� )*/
#define HALPPD_MAC_STANDARD_ANSI_X9_19_TYPE2     0x01 /**< MAC ��������� �� ��������� ANSI X9.19 ��� 2 (DES �� ������, 3DES �� ��������� ���� )*/

/** ��������� ���������� MAC */
#define MAC_STANDARD_ANSI_X9_19_TYPE1 (0x00) /**< MAC ��������� �� ��������� ANSI X9.19 ��� 1 */
#define MAC_STANDARD_ANSI_X9_19_TYPE2 (0x01) /**< MAC ��������� �� ��������� ANSI X9.19 ��� 2 */

/** ��� ���������� (padding) ��� ���������� MAC */
#define MAC_PADDING_ZERO                  0x00         /**< ��������� ������ */
#define MAC_PADDING_EMV                   0x01         /**< ��������� � ������������  */
#define MAC_PADDING_NONE                    0x02         /**< �� ���������, Padding ������ �� ������ �������.   */

/**
*
*  @brief ����������� ���������� ���������� MAC.
*
*  @param p_pData      -  [in] ��������� �� �����, ���������� ������, ��� ������� 
*                         ������������� MAC.     
*  @param p_Len        -  [in] ������ ������.
*  @param p_pMAC       -  [out] ��������� �� �����, � ������� ����� �������� �����������
*                         �������� MAC.
*  @param p_pIV       -   [in] ��������� �� ������ ������� �������������. ���� NULL, ������ �� �����������
*  @param p_Standard   -  [in] �������� ���������� ANSI X9.19 ��� 1/2
*  @param p_Padding   -   [in] �������� ���������� Padding
*  @param p_pKey       -  [in] ��������� �� �����, ���������� ����, ��� ������ �������� 
*                         ����� ����������� ������������� ����������.
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
*  @brief ��������� MAC 
*
*  @param p_Data -  [in] ��������� �� ������, ��� ������� ����� ��������� MAC.
*  @param p_Len  -  [in] ������ ������
*  @param p_pMAC - [out] ��������� �� �����, � ������� ����� �������� ����������� 
*                   �������� MAC.
*  @param p_Format ������ ������� ������ BIN/HEX
*  @param p_Standard �������� ���������� ANSI X9.19 ��� 1/2
*  @param p_PaddingType ��� ���������� ����� �� ������� Zero/EMV
*  @param p_pMacKey - [in] ������������� �������� MAC-�����.
*
*  @retval URC_MAC_XXXX
*/
URC Mac_CalcMac(PCUINT8 p_pData, UINT16 p_Len, PUINT8 p_pMAC, UINT8 p_Format, UINT8 p_Standard, UINT8 p_PaddingType,
                PUINT8 p_pMacKey);

#ifdef __cplusplus
}
#endif

#endif /* __MAC_H__*/
