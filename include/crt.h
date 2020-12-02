
#ifndef __CRT_H__
#define __CRT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include "bastypes.h"


typedef void *MEM_PTR;
typedef const void *MEM_CPTR;
typedef char *STR_PTR;
typedef const char *STR_CPTR;



#define INLINE      __forceinline




#define MemCpy(dst, src, len)           memcpy((MEM_PTR)(dst), (MEM_PTR)(src), len)

#define MemSet(dst, srcval, len)        memset((MEM_PTR)(dst), (srcval), (len))

#define MemCmp(buf1, buf2, len )        memcmp((MEM_PTR)(buf1), (MEM_PTR)(buf2), len)

#define MemMove( dst, src, size)        memmove((MEM_PTR)(dst), (MEM_PTR)(src), (size))

#define StrCpy(dst, src)                strcpy((STR_PTR)(dst), (STR_PTR)(src))

#define StrLen(str)                     strlen((STR_PTR)(str))

#define StrNCpy(dst, src, len)          strncpy((STR_PTR)(dst), (STR_PTR)(src), (int)(len))

#define StrChr( str, c )                strchr((STR_PTR)(str), (int)(c))

#define StrCat( dst, src )              strcat((STR_PTR)(dst), (STR_PTR)(src))

#define StrUpr( src )                   strupr((STR_PTR)(src))

#define StrLwr( src )                   strlwr((STR_PTR)(src))

#define StrCmp( src1, src2 )            strcmp((STR_PTR)(src1), (STR_PTR)(src2))

#define StrStr( string, strCharSet )    strstr((STR_PTR)(string), (STR_PTR)(strCharSet))

#define ATOI( src )                     atoi((STR_PTR)(src))

#define LTOA( value, string, radix )    _ltoa( value, string, radix )

#define ATOL( src )                     atol((STR_PTR)(src))

#define ZEROMEM(a) memset ((MEM_PTR) a, 0, sizeof (a))
#define ZEROMEM_REF(a) memset ((MEM_PTR) & a, 0, sizeof (a))
#define OFFSET_OF(Struct, Member) ((UINT32)(& (((Struct *)0) -> Member)))

#ifndef max
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif


#define IsSpace isspace
#define IsDigit isdigit
#define IsAlpha isalpha

URC Urc_LogError(URC p_ErrCode);
/**

  @brief Seeds random number generator.

  @param p_Seed Seed for random-number generation.

*/

void CRT_SeedRandom (UINT16 p_nSeed);
/**

  @brief Returns random number in range [min..max] according to normal distribution law.

  @return 1-byte random number.
*/

UINT8 CRT_GetRandom (UINT8 min, UINT8 max);



#define CRT_ASSERT(Exp) ;
#define URC_SUCCESS( rhRetCode ) ((rhRetCode) == 0L)

#define URC_FAILED( rhRetCode ) ((rhRetCode) != 0L)


#define URC_LOG_RETURN(ErrCode) return Urc_LogError( ErrCode );

#define URC_TRY(Function, ErrCode)   \
   do {                              \
     if (URC_FAILED(Function))       \
       return Urc_LogError(ErrCode); \
   } while (0)

#define URC_RETURN(Function, ErrCode)  \
   do {                                \
     return (URC_FAILED(Function)) ?   \
       Urc_LogError(ErrCode) : 0L;     \
   } while (0)

#endif /* __CRT_H__ */
