#include "Crc32.h"

/******  ћодуль расчета CRC32    ******/
/*===========================================================================*/

static UINT32 m_crc32; /* сохранение текущего значени€ crc32*/
static UINT32 crc32_table[256]; 

/** 
*  @brief  »нициализаци€ данных дл€ расчета crc32.
*/
void Crc32_InitCrc(void)
{
    INT32 i, j;
    UINT32 crc;

    m_crc32 = 0xFFFFFFFFUL;

    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;

        crc32_table[i] = crc;
    };
}

/**
    @brief CRC32 рассчитываетс€ на фиксированном палиндроме 0x04C11DB7
           Ќачальное значение 0xFFFFFFFF.
           ‘ункци€ добавл€ет блок данных к расчитываемой контрольной сумме.
    @param buf - указатель на блок данных, который нужно добавить к
                 расчитываемой контрольной сумме.
           len - длина блока данных.
    @return - crc32
*/
UINT32 Crc32_AddBlockCrc(UINT8 *buf, UINT32 len)
{
    UINT32 crc; 
    INT32 i;

    crc = m_crc32;

    i = 0;
    while (len--)
    {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
        i++;
    }
    m_crc32 = crc;
    return crc ^ 0xFFFFFFFFUL;
}
