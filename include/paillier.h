/*
 * Implemetation of Paillier cryptosystem using bigi multiprecision modulo arithmetic lib
 */
#ifndef PAILLIER_H
#define PAILLIER_H

#include <bigi.h>
#include <rng.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief        Initialize Paillier cryptosytem with p,q such that gcd(pq, (p-1)(q-1) = 1) - this holds if both are the same length
 *
 *  @param[in]     Large prime
 *  @param[in]     Large prime
 *  @param[out]    Private key
 *  @param[out]    Public key
 *
 */
int paillier_init(bigint_type *p, bigint_type *q, bigint_type *dk, bigint_type *ek);

/**
 *  @brief        Encrypt message m < n
 *
 *  @param[in]     Public key
 *  @param[in]     Plaintext
 *  @param[out]    Resulting ciphertext, valid only if the return value is 0
 *  @return        0 if OK, 1 if not m < n
 *
 */
int paillier_enc(bigint_type *ek, bigint_type *m, bigint_type *c);

/**
 *  @brief        Decrypt ciphertext
 *
 *  @param[in]     Public key
 *  @param[in]     Private key
 *  @param[in]     ciphertext
 *  @param[out]    Resulting plaintext, valid only if the return value is 0
 *  @return        0 if OK, 1 if not m < n
 *
 */
int paillier_dec(bigint_type *ek, bigint_type *dk, bigint_type *c, bigint_type *m);


#if defined( __MIKROC_PRO_FOR_ARM__ )
/*initialize paillier, load PKE with dk and ek*/
int paillier_rsa_init(bigint_type *p, bigint_type *q, bigint_type *dk, bigint_type *ek);
/*if EK is NULL, key from PKE memory is used*/
int paillier_rsa_enc(bigint_type *ek, bigint_type *m, bigint_type *c);
/*if DK is NULL, key from PKE memory is used*/
int paillier_rsa_dec(bigint_type *ek, bigint_type *dk, bigint_type *c, bigint_type *m);

#ifdef __cplusplus
}
#endif

#endif
#endif
