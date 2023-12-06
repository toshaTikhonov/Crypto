/**
******************************************************************************
    @file   CrcPrc.c
    @brief  Модуль CRC Processor.
    @version  0.0.1
    @author Vladislav Titov, NCT

    <b>Список изменений: </b>
    @li 06/07/2004:  Создан
******************************************************************************
*/
#include "CrcImp.h"


#define BITMASK(X) (1l << (X))
/** Регистр, в котором накапливается значение CRC */
static UINT32 s_wRegister;


/** Функция возвращает значение wValue с обращенными ucCount [0,16] младшими битами.
    Например: reflect(0x3e23L,3) == 0x3e26 
    @param wValue - значение, в котором нужно обернуть биты
    @param ucCount - число битов, которое нужно обернуть
    @return Значение, с обернутыми битами
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


/** Инициализирует значение регистра 
    @param wInitialValue начальное значение регистра. 
*/
void CrcPrc_Init(UINT32 wInitialValue)
{
    s_wRegister = wInitialValue;
}


/** Учитывает новый байт в регистре CRC 
    @param pCrcParams - указатель на структуру, содержащую параметры используемого
        алгоритма CRC 
    @param ucByte - значение байта, котое надо учесть в CRC 
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
            s_wRegister &= BITMASK(pCrcParams->Width - 1);
    }
}


/** Получить результат вычисления CRC для выбранного алгоритма
    @param pCrcParams - указатель на структуру, содержащую параметры используемого
        алгоритма CRC
    @return Результирующее значение CRC
*/
UINT32 CrcPrc_GetResult(PSCrcAlgorithm pCrcParams)
{
    if (pCrcParams->ReflectOut)
        return pCrcParams->XorOutput ^ Reflect(s_wRegister, pCrcParams->Width);
    else
        return pCrcParams->XorOutput ^ s_wRegister;
}

