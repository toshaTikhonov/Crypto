#ifndef __BASTYPES_H__
#define __BASTYPES_H__

#ifndef NULL
  #define NULL   0
#endif


#ifndef BOOL
typedef int BOOL;
#endif

#ifndef FALSE
#define FALSE   ((BOOL)0)
#endif

#ifndef TRUE
#define TRUE   ((BOOL)1)
#endif


#define READ_ONLY const

typedef char                CHAR;
typedef CHAR*               PSTR;
typedef READ_ONLY CHAR*         PCSTR;

typedef signed char           INT8;
typedef signed char*          PINT8;

typedef unsigned char         UINT8;
typedef unsigned char*        PUINT8;
typedef READ_ONLY unsigned char * PCUINT8;

typedef signed short           INT16;
typedef unsigned short         UINT16;
typedef unsigned short*        PUINT16;
typedef READ_ONLY unsigned short * PCUINT16;

typedef int                    INT32;
typedef int*                   PINT32;
typedef READ_ONLY int          *PCINT32;
typedef unsigned int           UINT32;
typedef READ_ONLY unsigned int *PCUINT32;
typedef UINT32  URC;

typedef unsigned long long     UINT64;
typedef unsigned long long*    PUINT64;
typedef READ_ONLY unsigned long long*    PCUINT64;

typedef long long               INT64;
typedef long long*              PINT64;
typedef READ_ONLY long long*    PCINT64;




#endif 

