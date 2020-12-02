#include "crt.h"

URC Urc_LogError(URC p_ErrCode)
{
    return p_ErrCode;
}

/**

  @brief Seeds random number generator.

  @param p_Seed Seed for random-number generation.

*/

void CRT_SeedRandom (UINT16 p_nSeed)
{
    srand ((unsigned int) p_nSeed);

} /* CRT_SeedRandom */
/**

  @brief Returns random number in range [min..max] according to normal distribution law.

  @return 1-byte random number.
*/

UINT8 CRT_GetRandom (UINT8 min, UINT8 max)
{
    UINT32 R;
    UINT8  t;

    /* ���� ������� ��������� � ����� ������� ������ ���������, �� ������ �������� �������.
       �� ���� ����������. */
    if (min > max) {t = min; min = max; max = t;}

    /* ����� �������� ��-���������� ����������� �������������,
       ����� ��������� ������� �������� �� 1 � ��������� ������ ��������� �����.
       �.�. �� ����� �������� �������� �� 0 �� RAND_MAX �� ������ ��������� ������
       � (max - min + 1).
    */
    do
    {
        R = rand (); /* rand ���������� 16-�������� ��������. */
    }
    while (R == RAND_MAX);

/* ������ ������� ������ ������������ ������ �.�. �� ������ � GCC 4.3.2
   ������� rand() ���������� �� 16-�������� , � 32-�������� �������� � ��������� ����
   �� ������ ������� �� ����� �������� �������� 0..1.
  return (UINT8)(min + R * (max + 1 - min) / RAND_MAX);
*/
    return (UINT8)(min + R % ((max - min) + 1));

} /* CRT_GetRandom */
