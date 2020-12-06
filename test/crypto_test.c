/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include "crt.h"
#include "Base64.h"
#include "Md5.h"
#include "Aes.h"
#include "Des.h"
#include "Sha1.h"
#include "Rsa.h"
#include "HashPr.h"

static const unsigned char base64_test_dec[64] =
        {
                0x24, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD,
                0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A, 0x01,
                0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09,
                0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22, 0xEE, 0x13,
                0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31,
                0x6C, 0x08, 0x34, 0xFF, 0x8D, 0xC2, 0x6C, 0x38,
                0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B,
                0xD1, 0x41, 0xBA, 0x95, 0x31, 0x5A, 0x0B, 0x97
        };

static const unsigned char base64_test_enc[] =
        "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPK"
        "swcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==";

START_TEST(base64_self_test)
{
    int len;
    unsigned char *src, buffer[128];

//    printf( "  Base64 encoding test: " );

    len = sizeof( buffer );
    src = (unsigned char *) base64_test_dec;

    ck_assert_int_eq(base64_encode( buffer, &len, src, 64 ),0);
    ck_assert_mem_eq(base64_test_enc,  buffer, 88);
//    printf( "passed\n" );
//    printf( "  Base64 decoding test: " );

    len = sizeof( buffer );
    src = (unsigned char *) base64_test_enc;

    ck_assert_int_eq(base64_decode( buffer, &len, src, 88 ),0);
    ck_assert_mem_eq(base64_test_dec,  buffer, 64);
//    printf( "passed\n\n" );
}
END_TEST

/*
 * RFC 1321 test vectors
 */
static const char md5_test_str[7][81] =
        {
                { "" },
                { "a" },
                { "abc" },
                { "message digest" },
                { "abcdefghijklmnopqrstuvwxyz" },
                { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
                { "12345678901234567890123456789012345678901234567890123456789012345678901234567890" }
        };

static const unsigned char md5_test_sum[7][16] =
        {
                { 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
                        0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E },
                { 0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8,
                        0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77, 0x26, 0x61 },
                { 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
                        0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 },
                { 0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D,
                        0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1, 0x61, 0xD0 },
                { 0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00,
                        0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B },
                { 0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5,
                        0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F },
                { 0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55,
                        0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07, 0xB6, 0x7A }
        };

/*
 * Checkup routine
 */
START_TEST(md5_self_test )
{
    int i;
    unsigned char md5sum[16];
    Md5Context ctx;

    for( i = 0; i < 7; i++ )
    {
//        printf( "  MD5 test #%d: ", i + 1 );

        Md5Reset ( &ctx );
        Md5Input( &ctx, (unsigned char *) md5_test_str[i], (UINT16)strlen( md5_test_str[i] ));
        Md5Result( &ctx, md5sum );

        ck_assert_mem_eq(md5sum, md5_test_sum[i],16);
//        printf( "passed\n" );
    }
}
END_TEST
/*
 * AES-ECB test vectors (source: NIST, rijndael-vals.zip)
 */
static const UINT8 aes_enc_test[3][16] =
        {
                { 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
                        0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
                { 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
                        0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
                { 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
                        0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
        };

static const UINT8 aes_dec_test[3][16] =
        {
                { 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
                        0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
                { 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
                        0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
                { 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
                        0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
        };

/*
 * Checkup routine
 */
START_TEST(aes_self_test )
{
    int i, j, u, v;
    aes_context ctx;
    unsigned char buf[32];

    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i & 1;

//        printf( "  AES-ECB-%3d (%s): ", 128 + u * 64,
//                ( v == 0 ) ? "enc" : "dec" );

        memset( buf, 0, 32 );
        crypto_aes_set_key( &ctx, buf, 128 + u * 64 );

        for( j = 0; j < 10000; j++ )
        {
            if( v == 0 ) crypto_aes_ecb_encrypt( &ctx, buf, buf );
            if( v == 1 ) crypto_aes_ecb_decrypt( &ctx, buf, buf );
        }

        if( ( v == 0 && memcmp( buf, aes_enc_test[u], 16 ) != 0 ) ||
            ( v == 1 && memcmp( buf, aes_dec_test[u], 16 ) != 0 ) )
        {
//            printf( "failed\n" );
            ck_abort();
        }

//        printf( "passed\n" );
    }

//    printf( "\n" );
}
END_TEST

#define DIM(a) (sizeof(a)/sizeof(a [0]))

START_TEST( des_self_test )
{
    struct SSampleDataDes
    {
        /* 07.03.2007: [AZ] ASCIIZ здесь только для простоты задания тестовых данных */
        UINT8 Key  [8 + 1];
        UINT8 Data [8 + 1];

    } SampleDataDes [] =
            {
                    {"43211234", "werttre"},
                    {"43211234", "\x00\x00\x00\x00\x00\x00\x00\x00"},
                    {"43211234", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
                    {"43211234", "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"},
                    {"00000000", "werttrew"},
                    {"43211234", "werttrew"},
                    {"43211234", "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"},
                    {"\x00\x00\x00\x00\x00\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\x00"},
                    {"\x00\x00\x00\x00\x00\x00\x00\x00", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
                    {"\x00\x00\x00\x00\x00\x00\x00\x00", "sdfv98dt"},
                    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "\x00\x00\x00\x00\x00\x00\x00\x00"},
                    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
                    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "d82,c0[z"}
            };

    struct SSampleData3Des
    {
        /* 07.03.2007: [AZ] ASCIIZ здесь только для простоты задания тестовых данных */
        UINT8 Key  [16 + 1];
        UINT8 Data [8 + 1];

    } SampleData3Des [] =
            {
                    {"432112345793mn2.", "werttres"},
                    {"43211234fdaf5geh", "\x00\x00\x00\x00\x00\x00\x00\x00"},
                    {"432112341qdf678j", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
                    {"43211234aFGASDDS", "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"},
                    {"0000000011111111", "werttrew"},
                    {"4321123443211234", "wert35ew"},
                    {"4321123443211234", "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"},
                    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\x00"},
                    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
                    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "sdfv98dt"},
                    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "\x00\x00\x00\x00\x00\x00\x00\x00"},
                    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
                    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "d82,c0[z"}
            };

    UINT16 i, j;
    UINT8 CipheredData [8], ClearData [8], EthalonData [8], Key [16];


    for (i = 0; i < DIM (SampleDataDes); i++)
    {
        (void)Des_Single_Encrypt (SampleDataDes [i].Key, SampleDataDes [i].Data, CipheredData);
        (void)Des_Single_Decrypt (SampleDataDes [i].Key, CipheredData, ClearData);
        if (MemCmp (ClearData, SampleDataDes [i].Data, 8))
        {
            puts ("error!");
            ck_abort();
        }

        (void)Des_Triple_Encrypt (SampleData3Des [i].Key, SampleData3Des [i].Data, CipheredData);
        (void)Des_Triple_Decrypt (SampleData3Des [i].Key, CipheredData, ClearData);
        if (MemCmp (ClearData, SampleData3Des [i].Data, 8))
        {
            puts ("error");
            ck_abort();
        }
    }

    CRT_SeedRandom (1);

    for (i = 0; i < 60000; i ++)
    {
        for (j = 0; j < 8; j ++) EthalonData [j] = CRT_GetRandom (0, 255);

        for (j = 0; j < 16; j ++) Key [j] = CRT_GetRandom (0, 255);

        (void)Des_Single_Encrypt (Key, EthalonData, CipheredData);
        (void)Des_Single_Decrypt (Key, CipheredData, ClearData);

        if (MemCmp (ClearData, EthalonData, 8))
        {
            puts ("error");
            ck_abort();
        }

        (void)Des_Triple_Encrypt (Key, EthalonData, CipheredData);
        (void)Des_Triple_Decrypt (Key, CipheredData, ClearData);

        if (MemCmp (ClearData, EthalonData, 8))
        {
            puts ("error");
            ck_abort();
        }
    }
}
END_TEST


START_TEST(sha1_self_test)
{
    Sha1Context sha;
    int i, j;
    UINT8 Message_Digest[20];
/*
 *  Define patterns for testing
 */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"

#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b

    char* testarray[4] =
            {
                    TEST1,
                    TEST2,
                    TEST3,
                    TEST4
            };

    long int repeatcount[4] = { 1, 1, 1000000, 10 };


    /*
     *  Perform SHA-1 tests
     */
    for(j = 0; j < 4; ++j)
    {
        SHA1Reset(&sha);

        for(i = 0; i < repeatcount[j]; ++i)
        {

            SHA1Input(&sha, (PCUINT8)testarray[j], (UINT16)StrLen(testarray[j]));
        }

        SHA1Result(&sha, Message_Digest);

    }
}
END_TEST
START_TEST( rsa_self_test )
{
/*
Public Key, 1024 bits:
modulus: b8 31 41 4e 0b 46 13 92 2b d3 5b 4b 36 80 2b c1 e1 e8 1c 95 a2 7c 95 8f 53 82 00 3d f6 46 15 4c a9 2f c1 ce 02 c3 be 04 7a 45 e9 b0 2a 90 89 b4 b9 02 78 23 7c 96 51 92 a0 fc c8 6b b4 9b c8 2a e6 fd c2 de 70 90 06 b8 6c 76 76 ef df 59 76 26 fa d6 33 a4 f7 dc 48 c4 45 d3 7e b5 5f cb 3b 1a bb 95 ba aa 82 6d 53 90 e1 5f d1 4e d4 03 fa 2d 0c b8 41 c6 50 60 95 24 ec 55 5e 3b c5 6c a9 57
exponent: 01 00 01

Private Key, 1024 bits:
modulus: b8 31 41 4e 0b 46 13 92 2b d3 5b 4b 36 80 2b c1 e1 e8 1c 95 a2 7c 95 8f 53 82 00 3d f6 46 15 4c a9 2f c1 ce 02 c3 be 04 7a 45 e9 b0 2a 90 89 b4 b9 02 78 23 7c 96 51 92 a0 fc c8 6b b4 9b c8 2a e6 fd c2 de 70 90 06 b8 6c 76 76 ef df 59 76 26 fa d6 33 a4 f7 dc 48 c4 45 d3 7e b5 5f cb 3b 1a bb 95 ba aa 82 6d 53 90 e1 5f d1 4e d4 03 fa 2d 0c b8 41 c6 50 60 95 24 ec 55 5e 3b c5 6c a9 57
public exponent: 01 00 01
exponent: aa 8f b9 c8 5a 3a 2e ff 49 23 f3 c3 07 19 d2 eb 3b 94 e3 7b 50 b6 8b 0b e8 a9 56 2e 0a 72 45 60 f2 be 2d 79 e6 27 7a 3a cd 3b 16 35 b2 84 9b 6f c5 6e 5a ef 89 7b ec d7 99 c9 da 91 99 f2 33 7c ac 74 cc 10 9e 3a 28 5e a8 cb 70 85 2b a5 65 70 75 26 d5 2f e2 80 b6 2f 3e b4 fb 08 7d 10 dd e7 c5 8b fa 61 ca b1 2b 8f 0d b7 96 34 d9 7c b9 25 08 2b 8d cd 13 95 00 7e 0d bc d9 1f 5c 2d 2e 39
prime 1: e1 06 cd d0 08 c9 15 09 14 93 8a 8c a5 d7 84 b8 56 15 42 38 b7 e7 8e 89 cb d6 56 9f 59 76 20 10 7f 5e 6e e1 c3 ea 31 41 90 e0 8e 24 47 5e b8 16 f1 21 1e d1 49 ff 95 33 e5 60 de 4c ae ae f7 35
prime 2: d1 8b 96 d5 45 45 96 ee 88 a3 3d d9 a1 17 66 42 ae 75 7b c6 18 0a 0d 78 39 b5 5e 99 16 c6 2d d6 ab 02 1b 61 1e a5 0e 9b ee 74 92 c7 10 92 91 70 67 a0 d0 48 6d c8 8c 35 dc 8b 45 ef 4b 55 53 db
prime exponent 1: 5c 0f a8 8b ff cc 24 6a fe 9c 0e 06 d4 a2 83 8d d6 ca 03 b9 a8 a3 77 51 30 af 93 e8 c5 74 ea 51 55 8a 90 da 94 88 6f 76 5f 8b 3f 1b e0 87 03 d1 7e fd 09 da 9d e7 8e 67 18 e4 b4 8d b2 b9 aa 31
prime exponent 2: 55 5c 20 b8 86 3c 7f ec 71 9a d6 12 36 6e 3a c9 05 1a 74 ae 50 92 9f c4 0e f6 14 30 16 b7 ea 6a 5d 45 41 74 01 b0 c9 4f ba 06 a0 d8 18 a7 2c 39 f6 ec ea 8b e6 b4 e0 70 fc 83 7b 9c ac 3a 79 2b
coefficient: b5 3b 46 e3 6d 17 22 21 96 80 cc df b6 76 4a c7 8f 54 c0 65 5a a4 83 0e c6 34 5e 0b 75 ab 30 fd 6b 26 fc 1b f4 41 2f 5f 48 b9 06 28 55 78 83 dd 5b d4 cb cc 84 f7 6c 81 96 69 87 ae 1b 74 15 23
*/

    SRsaInput RsaInput;

    UINT8 IntermediateResult [MAX_RSA_KEY_LENGTH];

    UINT8 EthalonData [] =
            "12;hjklGjklhK451"
            "12asvzx3[[12jG51"
            "SDBzxfhfjk1hfN51"
            "123451234d1o]451"
            "1BV451ixcv123C51"
            "1V34512CVB123451"
            "1B3C5X2345123451"
            "12gs512Bvx1fgjh1";

    RsaInput.Modulus = (PUINT8)
            "\xb8\x31\x41\x4e\x0b\x46\x13\x92\x2b\xd3\x5b\x4b\x36\x80\x2b\xc1"
            "\xe1\xe8\x1c\x95\xa2\x7c\x95\x8f\x53\x82\x00\x3d\xf6\x46\x15\x4c"
            "\xa9\x2f\xc1\xce\x02\xc3\xbe\x04\x7a\x45\xe9\xb0\x2a\x90\x89\xb4"
            "\xb9\x02\x78\x23\x7c\x96\x51\x92\xa0\xfc\xc8\x6b\xb4\x9b\xc8\x2a"
            "\xe6\xfd\xc2\xde\x70\x90\x06\xb8\x6c\x76\x76\xef\xdf\x59\x76\x26"
            "\xfa\xd6\x33\xa4\xf7\xdc\x48\xc4\x45\xd3\x7e\xb5\x5f\xcb\x3b\x1a"
            "\xbb\x95\xba\xaa\x82\x6d\x53\x90\xe1\x5f\xd1\x4e\xd4\x03\xfa\x2d"
            "\x0c\xb8\x41\xc6\x50\x60\x95\x24\xec\x55\x5e\x3b\xc5\x6c\xa9\x57";

    RsaInput.ModulusLength = 128;

    RsaInput.Exponent = (PUINT8)"\x01\x00\x01"; /* public */

    RsaInput.ExponentLength = 3;

    RsaInput.Data = EthalonData;

    (void)Rsa_Encrypt (& RsaInput);

    MemCpy (IntermediateResult, Rsa_GetResult (), RsaInput.ModulusLength);

    RsaInput.Exponent = (PUINT8)/* private */
            "\xaa\x8f\xb9\xc8\x5a\x3a\x2e\xff\x49\x23\xf3\xc3\x07\x19\xd2\xeb"
            "\x3b\x94\xe3\x7b\x50\xb6\x8b\x0b\xe8\xa9\x56\x2e\x0a\x72\x45\x60"
            "\xf2\xbe\x2d\x79\xe6\x27\x7a\x3a\xcd\x3b\x16\x35\xb2\x84\x9b\x6f"
            "\xc5\x6e\x5a\xef\x89\x7b\xec\xd7\x99\xc9\xda\x91\x99\xf2\x33\x7c"
            "\xac\x74\xcc\x10\x9e\x3a\x28\x5e\xa8\xcb\x70\x85\x2b\xa5\x65\x70"
            "\x75\x26\xd5\x2f\xe2\x80\xb6\x2f\x3e\xb4\xfb\x08\x7d\x10\xdd\xe7"
            "\xc5\x8b\xfa\x61\xca\xb1\x2b\x8f\x0d\xb7\x96\x34\xd9\x7c\xb9\x25"
            "\x08\x2b\x8d\xcd\x13\x95\x00\x7e\x0d\xbc\xd9\x1f\x5c\x2d\x2e\x39";

    RsaInput.ExponentLength = 128;

    RsaInput.Data = IntermediateResult;

    (void)Rsa_Decrypt (& RsaInput);

    if (MemCmp (EthalonData, Rsa_GetResult (), RsaInput.ModulusLength))
    {
        ck_abort();
    }
}
END_TEST


START_TEST(hashprc_self_test)
{
    /*
    *  Define patterns for testing
    */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b

    long int repeatcount[4] = { 1, 1, 1000000, 10 };

    char *resultarray[4] =
            {
                    "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D",
                    "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1",
                    "\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F",
                    "\xDE\xA3\x56\xA2\xCD\xDD\x90\xC7\xA7\xEC\xED\xC5\xEB\xB5\x63\x93\x4F\x46\x04\x52"
            };

    int i, j;
    UINT8 Message_Digest[20];

    PCSTR testarray[4];

    testarray[0] = TEST1;
    testarray[1] = TEST2;
    testarray[2] = TEST3;
    testarray[3] = TEST4;

/*
  PUINT8 test_names[4] =
  {
    "TEST1",
    "TEST2",
    "TEST3",
    "TEST4"
  };
*/


    /*
    *  Perform SHA-1 tests
    */
    for(j = 0; j < 4; ++j)
    {
        (void)HashPrc_Reset (HASH_ALGORITHM_SHA1);

        for(i = 0; i < repeatcount[j]; ++i)
        {
            (void)HashPrc_Add (HASH_ALGORITHM_SHA1, (PCUINT8)testarray[j], (UINT16)strlen(testarray[j]));
        }

        (void)HashPrc_Calculate (HASH_ALGORITHM_SHA1);

        MemCpy (
                Message_Digest,
                HashPrc_GetResult (HASH_ALGORITHM_SHA1),
                HashPrc_GetLength (HASH_ALGORITHM_SHA1)
        );

        if (MemCmp (Message_Digest, resultarray[j], 20))
        {
            puts ("error");
            ck_abort();
        }
    }

}END_TEST
static Suite *crypto_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Crypto tests functions");
    tc_core = tcase_create("Crypto Framework");
    tcase_add_test(tc_core, base64_self_test);
    tcase_add_test(tc_core,md5_self_test);
    tcase_add_test(tc_core,aes_self_test);
    tcase_add_test(tc_core,des_self_test);
    tcase_add_test(tc_core,sha1_self_test);
    tcase_add_test(tc_core,rsa_self_test);
    tcase_add_test(tc_core,hashprc_self_test);
    tcase_set_timeout(tc_core, 30);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = crypto_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
