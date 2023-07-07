#ifndef __CRCPR32_H__
#define __CRCPR32_H__

#include "bastypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/******    CRC32    ******/
/*===========================================================================*/

/** 
*  @brief  Инициализация данных для расчета crc32.
*/
void Crc32_InitCrc(void);

/**
    @brief CRC32 рассчитывается на фиксированном палиндроме 0x04C11DB7
           Начальное значение 0xFFFFFFFF.
           Функция добавляет блок данных к расчитываемой контрольной сумме.
    @param buf - указатель на блок данных, который нужно добавить к
                 расчитываемой контрольной сумме.
           len - длина блока данных.
    @return - crc32
*/
UINT32 Crc32_AddBlockCrc(UINT8 *buf, UINT32 len);

#ifdef __cplusplus
}
#endif

#endif

