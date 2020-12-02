/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include "Base64.h"
#include "Md5.h"

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



static Suite *crypto_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Crypto tests functions");
  tc_core = tcase_create("Crypto Framework");
  tcase_add_test(tc_core, base64_self_test);
  tcase_add_test(tc_core,md5_self_test);
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
