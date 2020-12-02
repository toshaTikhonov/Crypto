/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include "Base64.h"

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

    printf( "  Base64 encoding test: " );

    len = sizeof( buffer );
    src = (unsigned char *) base64_test_dec;

    ck_assert_int_eq(base64_encode( buffer, &len, src, 64 ),0);
    ck_assert_mem_eq(base64_test_enc,  buffer, 88);
    printf( "passed\n" );
    printf( "  Base64 decoding test: " );

    len = sizeof( buffer );
    src = (unsigned char *) base64_test_enc;

    ck_assert_int_eq(base64_decode( buffer, &len, src, 88 ),0);
    ck_assert_mem_eq(base64_test_dec,  buffer, 64);
    printf( "passed\n\n" );
}
END_TEST



static Suite *crypto_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Crypto tests functions");
  tc_core = tcase_create("test_Crypto");
  tcase_add_test(tc_core, base64_self_test);
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
