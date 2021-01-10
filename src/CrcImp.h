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

#include "bastypes.h"


/** ���������, ����������� ���� �������� CRC */
typedef struct
{
    UINT8   Width;      /**< ����������� CRC (��� CRC16 =16) (��� CRC32 =32)*/
    UINT32  Polynomial; /**< ������� ���������, ������� � �������� ����, ������� ������� �� ����������� */
    UINT32  InitValue;  /**< ��������� �������� */
    BOOL    ReflectIn;  /**< �������� ����� �� �����? */
    BOOL    ReflectOut; /**< �������� �������� �������� CRC? */
    UINT32  XorOutput;  /**< �������� ��� ���������� �� XOR � �������� ��������� CRC. */
} SCrcAlgorithm, *PSCrcAlgorithm;


/** �������������� �������� �������� 
    @param wInitialValue ��������� �������� ��������. 
*/
void CrcPrc_Init(UINT32 wInitialValue);


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
UINT32 CrcPrc_GetResult(PSCrcAlgorithm pCrcParams);


#endif /* __CRC_PROCESSOR_H__ */

