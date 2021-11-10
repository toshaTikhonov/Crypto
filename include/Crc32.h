#ifndef __CRCPR32_H__
#define __CRCPR32_H__

#include "urc.h"
#include "bastypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/******    CRC32    ******/
/*===========================================================================*/

/** 
*  @brief  ������������� ������ ��� ������� crc32.
*/
void Crc32_InitCrc(void);

/**
    @brief CRC32 �������������� �� ������������� ���������� 0x04C11DB7
           ��������� �������� 0xFFFFFFFF.
           ������� ��������� ���� ������ � ������������� ����������� �����.
    @param buf - ��������� �� ���� ������, ������� ����� �������� �
                 ������������� ����������� �����.
           len - ����� ����� ������.
    @return - crc32
*/
UINT32 Crc32_AddBlockCrc(UINT8 *buf, UINT32 len);

#ifdef __cplusplus
}
#endif

#endif

