/**
******************************************************************************
    @file   CrcPrc.c
    @brief  ������ CRC Processor.
    @version  0.0.1
    @author Vladislav Titov, NCT

    <b>������ ���������: </b>
    @li 06/07/2004:  ������
******************************************************************************
*/
#include "CrcImp.h"


#define BITMASK(X) (1 << (X))
/** �������, � ������� ������������� �������� CRC */
static UINT32 s_wRegister;


/** ������� ���������� �������� wValue � ����������� ucCount [0,16] �������� ������.
    ��������: reflect(0x3e23L,3) == 0x3e26 
    @param wValue - ��������, � ������� ����� �������� ����
    @param ucCount - ����� �����, ������� ����� ��������
    @return ��������, � ���������� ������
*/
static UINT32 Reflect(UINT32 wValue, UINT8 ucCount)
{
    UINT8 i;
    UINT32 wTemp, wResult;

    wTemp = wValue;
    wResult = wValue;
    for (i=0; i < ucCount; i++)
    {
        if (wTemp & 1L)
            wResult |= BITMASK((ucCount-1)-i);
        else
            wResult &= ~BITMASK((ucCount-1)-i);
        wTemp >>= 1;
    }
    return wResult;
}


/** �������������� �������� �������� 
    @param wInitialValue ��������� �������� ��������. 
*/
void CrcPrc_Init(UINT32 wInitialValue)
{
    s_wRegister = wInitialValue;
}


/** ��������� ����� ���� � �������� CRC 
    @param pCrcParams - ��������� �� ���������, ���������� ��������� �������������
        ��������� CRC 
    @param ucByte - �������� �����, ����� ���� ������ � CRC 
*/
void CrcPrc_AddByte(PSCrcAlgorithm pCrcParams, UINT8 ucByte)
{
    UINT8 i;
    UINT8 wValue;

    wValue = (UINT8)ucByte;

    if (pCrcParams->ReflectIn) 
        wValue = (UINT8)Reflect(wValue,8);

    s_wRegister ^= (wValue << (pCrcParams->Width - 8));
    for (i = 0; i < 8; i++)
    {
        if (s_wRegister & BITMASK(pCrcParams->Width - 1))
            s_wRegister = (s_wRegister << 1) ^ pCrcParams->Polynomial;
        else
            s_wRegister <<= 1;
        if(pCrcParams->Width < 32)
            s_wRegister &= ((1 << pCrcParams->Width) - 1);
    }
}


/** �������� ��������� ���������� CRC ��� ���������� ���������
    @param pCrcParams - ��������� �� ���������, ���������� ��������� �������������
        ��������� CRC
    @return �������������� �������� CRC
*/
UINT32 CrcPrc_GetResult(PSCrcAlgorithm pCrcParams)
{
    if (pCrcParams->ReflectOut)
        return pCrcParams->XorOutput ^ Reflect(s_wRegister, pCrcParams->Width);
    else
        return pCrcParams->XorOutput ^ s_wRegister;
}

