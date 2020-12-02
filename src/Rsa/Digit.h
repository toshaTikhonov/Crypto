/* DIGIT.H - header file for DIGIT.C
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */
/** @brief Computes a = b * c, where b and c are digits.
   Lengths: a[2].
 */
void NN_DigitMult PROTO_LIST ((NN_DIGIT [2], NN_DIGIT, NN_DIGIT));
/** @brief Sets a = b / c, where a and c are digits.
   Lengths: b[2].
   Assumes b[1] < c and HIGH_HALF (c) > 0. For efficiency, c should be
   normalized.
 */
void NN_DigitDiv PROTO_LIST ((NN_DIGIT *, NN_DIGIT [2], NN_DIGIT));
