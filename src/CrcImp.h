/**
******************************************************************************
    @file   CrcPrc.h
    @brief  ������ CRC Processor.
    @version  0.0.1
    @author Vladislav Titov, NCT

    <b>������ ���������: </b>
    @li 01/11/2004:  ������
******************************************************************************
*/
#ifndef __CRC_PROCESSOR_H__
#define __CRC_PROCESSOR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "bastypes.h"


/** ���������, ����������� ���� �������� CRC */
typedef struct
{
    UINT8   Width;      /**< ����������� CRC (��� CRC16 =16) */
    UINT16  Polynomial; /**< ������� ���������, ������� � �������� ����, ������� ������� �� ����������� */
    UINT16  InitValue;  /**< ��������� �������� */
    BOOL    ReflectIn;  /**< �������� ����� �� �����? */
    BOOL    ReflectOut; /**< �������� �������� �������� CRC? */
    UINT16  XorOutput;  /**< �������� ��� ���������� �� XOR � �������� ��������� CRC. */
} SCrcAlgorithm, *PSCrcAlgorithm;


/** �������������� �������� �������� 
    @param wInitialValue ��������� �������� ��������. 
*/
void CrcPrc_Init(UINT16 wInitialValue);


/** ��������� ����� ���� � �������� CRC 
    @param pCrcParams - ��������� �� ���������, ���������� ��������� �������������
        ��������� CRC 
    @param ucByte - �������� �����, ����� ���� ������ � CRC 
*/
void CrcPrc_AddByte(PSCrcAlgorithm pCrcParams, UINT8 ucByte);


/** �������� ��������� ���������� CRC ��� ���������� ���������
    @param pCrcParams - ��������� �� ���������, ���������� ��������� �������������
        ��������� CRC
    @return �������������� �������� CRC
*/
UINT16 CrcPrc_GetResult(PSCrcAlgorithm pCrcParams);

#ifdef __cplusplus
}
#endif

#endif /* __CRC_PROCESSOR_H__ */

