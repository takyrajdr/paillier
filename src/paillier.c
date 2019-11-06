#include <paillier.h>

/*Nina Pettersen
  Applications of Pailliers cryptosystem
  g = n + 1 => simplifies paillier
*/
int paillier_init(bigint_type *p, bigint_type *q, bigint_type *dk, bigint_type *ek)
{
    bigint_t ONE, DIVISOR, P_one, Q_one;
    int i;
    bigint_copy(P_one, p);
    bigint_copy(Q_one, q);

    for ( i = 0; i < NUM_SIZE; i++)
    {
        ONE[i] = 0;
        DIVISOR[i] = 0;
    }
    ONE[NUM_SIZE-1] = 1;

    /* *ek = *p * *q; */
    bigint_mult_fit(p,q,ek);
    bigint_sub(P_one, ONE, P_one);
    bigint_sub(Q_one, ONE, Q_one);
    bigint_gcd(P_one, Q_one, DIVISOR);
    /* *dk = ((*p-1)*(*q-1) * inverse) % *ek; */
    bigint_mult_fit(P_one, Q_one, dk);
    bigint_div(dk, DIVISOR, 0, dk);

    return 1;
}

int paillier_enc(bigint_type *ek, bigint_type* m, bigint_type *c)
{
    bigint_t n2; /*  = *ek * *ek; this requires multiplication!! BUT! always fits into range */
    bigint_t  r; /*  = 2; */
    bigint_t ONE;
    bigint_t gm;
    bigint_t rn;
    bigint_t mm, eek;
    int i;

    for (i = 0; i < NUM_SIZE; i++)
    {
        ONE[i] = 0;
        r[i] = 0;
        c[i] = 0;
    }
    ONE[NUM_SIZE-1] = 1;

    /* r[NUM_SIZE-1] = 2; */
    rng_get_bigint(r,30);
    bigint_mult_fit(ek,ek,n2);
    bigint_copy(mm,m);
    bigint_copy(eek,ek);
    /* bigint_pow_mod(g, mm, n2, gm); */
    /* dirty trick with binomial expansion */
    bigint_mult_mod(eek,mm,n2,gm);
    bigint_add(gm,ONE,gm);
    bigint_pow_mod_mont(r, eek, n2, rn);
    bigint_mult_mod(gm, rn, n2, c);
    /* *c = (*en + 1)^m*r^n mod n^2; */

    return 1;
}

int paillier_dec(bigint_type *ek, bigint_type *dk, bigint_type *c, bigint_type *m)
{
    bigint_t n2;
    bigint_t upper, ONE;
    bigint_t d_inverse;
    bigint_t cc,dd,nn;
    bigint_t dkk;
    int i, err;
    bigint_copy(cc,c);
    bigint_copy(dkk,dk);
    bigint_copy(dd,dk);
    bigint_copy(nn,ek);

    for (i = 0; i < NUM_SIZE; i++)
    {
        ONE[i] = 0;
        d_inverse[i] = 0;
    }
    ONE[NUM_SIZE-1] = 1;

#if defined( __MIKROC_PRO_FOR_ARM__ )
    ADC1_Init();
    ADC1_Read(1);
#endif

    bigint_mult_fit(ek,ek, n2);
    bigint_pow_mod_mont(cc, dkk, n2, upper);
    /* upper -= 1; */
    bigint_sub(upper, ONE, upper);
    /* upper /= nn; */
    bigint_div(upper, nn, 0, upper);
    err = bigint_mul_inv(dd, nn, d_inverse);
    if (err == 1) return 0;
    bigint_mult_mod(upper, d_inverse, nn, m);

    return 1;
#if defined( __MIKROC_PRO_FOR_ARM__ )
    ADC1_Disable();
#endif
}

#if defined( __MIKROC_PRO_FOR_ARM__ )
int paillier_rsa_init(bigint_type *p, bigint_type *q, bigint_type *dk, bigint_type *ek)
{
    bigint_t ONE, DIVISOR, P_one, Q_one, N2;
    uint8_t return_sts = 0;
    uint8_t priv[(NUM_SIZE-3)*4];
    uint8_t pub[(NUM_SIZE-3)*4];
    uint8_t mod[(NUM_SIZE-3)*4];
    int i;
    bigint_copy(P_one, p);
    bigint_copy(Q_one, q);

    for ( i = 0; i < NUM_SIZE; i++)
    {
        ONE[i] = 0;
        DIVISOR[i] = 0;
    }
    ONE[NUM_SIZE-1] = 1;

    /* *ek = *p * *q; */
    bigint_mult_fit(p,q,ek);
    bigint_sub(P_one, ONE, P_one);
    bigint_sub(Q_one, ONE, Q_one);
    bigint_gcd(P_one, Q_one, DIVISOR);
    /* *dk = ((*p-1)*(*q-1) * inverse) % *ek; */
    bigint_mult_fit(P_one, Q_one, dk);
    bigint_div(dk, DIVISOR, 0, dk);

    bigint_mult_fit(ek,ek,N2);
    /* load keys into RSA engine */
    bigint_32_to_8(dk, priv);
    bigint_32_to_8(ek, pub);
    bigint_32_to_8(N2, mod);
    pke_power(0x01);
    /* while(pke_busy() == 0x01); */
    return_sts = rsa_load_key(2048, &priv[0], &mod[0], &pub[0],128,0);

    if(return_sts != PKE_RET_OK)
    {
        return 0;
    }
    /* RSA engine is now loaded & ready to start
     * encryption uses rsa_encrypt, decryption rsa_decrypt */

    return 1;
}

int paillier_rsa_enc(bigint_type *ek, bigint_type* m, bigint_type *c){
    bigint_t n2; /*  = *ek * *ek; this requires multiplication!! BUT! always fits into range */
    bigint_t  r; /*  = 2; */
    bigint_t ONE;
    bigint_t gm;
    bigint_t rn;
    bigint_t mm, eek;
    int i;
    uint8_t in[(NUM_SIZE-3)*4];
    uint8_t out[(NUM_SIZE-3)*4];
    uint8_t return_sts = 0;
    uint16_t  nBytes = 0;

    for (i = 0; i < NUM_SIZE; i++)
    {
        ONE[i] = 0;
        c[i] = 0;
    }
    ONE[NUM_SIZE-1] = 1;

    bigint_mult_fit(ek,ek,n2);
    bigint_copy(mm,m);
    bigint_copy(eek,ek);
    /* bigint_pow_mod(g, mm, n2, gm); */
    /* dirty trick with binomial expansion */
    bigint_mult_mod(eek,mm,n2,gm);
    bigint_add(gm,ONE,gm);

    /* bigint_pow_mod(r, eek, n2, rn); */
    bigint_init(r);
    /* r[NUM_SIZE-1] = 2; */
    rng_get_bigint(r,30);
    bigint_32_to_8(r,in);

    return_sts = rsa_encrypt(2048, &in[0], 128, 1);
    if (return_sts != PKE_RET_OK)
    {
        return 0;
    }

    while(pke_busy() == 1);
    nBytes = pke_read_scm(&out[0], 256, 5, 0);
    bigint_8_to_32(out, rn);
    bigint_mult_mod(gm, rn, n2, c);
    /* *c = (*en + 1)^m*r^n mod n^2; */

    return 1;
}

int paillier_rsa_dec(bigint_type *ek, bigint_type *dk, bigint_type *c, bigint_type *m)
{
    bigint_t n2;
    bigint_t upper, ONE;
    bigint_t d_inverse;
    bigint_t cc,dd,nn;
    bigint_t dkk;
    uint8_t inout[(NUM_SIZE-3)*4];
    uint8_t return_sts = 0;
    uint16_t  nBytes = 0;
    int i, err;
    bigint_copy(cc,c);
    bigint_copy(dkk,dk);
    bigint_copy(dd,dk);
    bigint_copy(nn,ek);

    for (i = 0; i < NUM_SIZE; i++)
    {
        ONE[i] = 0;
        d_inverse[i] = 0;
        upper[i] = 0;
    }

    ONE[NUM_SIZE-1] = 1;
    ADC1_Init();
    ADC1_Read(1);
    bigint_mult_fit(ek,ek, n2);
    /* bigint_pow_mod(cc, dkk, n2, upper); */
    bigint_32_to_8(cc,inout);
    return_sts = rsa_decrypt(2048, &inout[0], 256, 1);

    if (return_sts != PKE_RET_OK)
    {
        return 0;
    }

    while(pke_busy() == 1);
    nBytes = pke_read_scm(&inout[0], 256, 5, 0);
    bigint_8_to_32(inout,upper);
    /* upper -= 1; */
    bigint_sub(upper, ONE, upper);
    /* upper /= nn; */
    bigint_div(upper, nn, 0, upper);
    err = bigint_mul_inv(dd, nn, d_inverse);
    if (err == 1) return 0;
    bigint_mult_mod(upper, d_inverse, nn, m);
    ADC1_Disable();

    return 1;
}
#endif
