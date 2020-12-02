/**
******************************************************************************
    @file   CrcPrc.h
    @brief  Модуль CRC Processor.
    @version  0.0.1
    @author Vladislav Titov, NCT

    <b>Список изменений: </b>
    @li 01/11/2004:  Создан
******************************************************************************
*/
#ifndef __CRC_PROCESSOR_H__
#define __CRC_PROCESSOR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "bastypes.h"


/** Структура, описывающая один алгоритм CRC */
typedef struct
{
    UINT8   Width;      /**< Разрядность CRC (для CRC16 =16) */
    UINT16  Polynomial; /**< Полином алгоритма, задаётся в бинарном виде, старшая единица не учитывается */
    UINT16  InitValue;  /**< Начальное значение */
    BOOL    ReflectIn;  /**< Обращать байты на входе? */
    BOOL    ReflectOut; /**< Обращать конечное значение CRC? */
    UINT16  XorOutput;  /**< Величина для комбинации по XOR с конечным значением CRC. */
} SCrcAlgorithm, *PSCrcAlgorithm;


/** Инициализирует значение регистра 
    @param wInitialValue начальное значение регистра. 
*/
void CrcPrc_Init(UINT16 wInitialValue);


/** Учитывает новый байт в регистре CRC 
    @param pCrcParams - указатель на структуру, содержащую параметры используемого
        алгоритма CRC 
    @param ucByte - значение байта, котое надо учесть в CRC 
*/
void CrcPrc_AddByte(PSCrcAlgorithm pCrcParams, UINT8 ucByte);


/** Получить результат вычисления CRC для выбранного алгоритма
    @param pCrcParams - указатель на структуру, содержащую параметры используемого
        алгоритма CRC
    @return Результирующее значение CRC
*/
UINT16 CrcPrc_GetResult(PSCrcAlgorithm pCrcParams);

#ifdef __cplusplus
}
#endif

#endif /* __CRC_PROCESSOR_H__ */

