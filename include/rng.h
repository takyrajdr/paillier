#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <stdlib.h>
#include <rng.h>

volatile int init_done = 0;

void rng_init();

uint32_t rng_get_bigint(uint32_t * BUFF, uint32_t words);

void rng_rst();

#if defined( __MIKROC_PRO_FOR_ARM__ )
void rng_pause();
#endif

#endif
