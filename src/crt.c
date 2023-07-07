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

    /* Если нашелся приколист и задал минимум больше максимума, то меняем значения местами.
       Мы тоже приколисты. */
    if (min > max) {t = min; min = max; max = t;}

    /* Чтобы получить по-настоящему равномерное распределение,
       нужно расширить целевой диапазон на 1 и исключить правую граничную точку.
       Т.е. мы делим исходный диапазон от 0 до RAND_MAX на равные интревалы числом
       в (max - min + 1).
    */
    do
    {
        R = rand (); /* rand возвращает 16-тибитное значение. */
    }
    while (R == RAND_MAX);

/* Данную формулу больше использовать нельзя т.к. на сажеме с GCC 4.3.2
   функция rand() возвращает не 16-тибитное , а 32-тибитное значение в следствии чего
   на выходе функции мы имеем диапазон значений 0..1.
  return (UINT8)(min + R * (max + 1 - min) / RAND_MAX);
*/
    return (UINT8)(min + R % ((max - min) + 1));

} /* CRT_GetRandom */
