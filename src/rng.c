#include <time.h>
#include <bigi.h>
#include <rng.h>

void rng_init()
{
    if (init_done == 0)
    {
#if defined( __MIKROC_PRO_FOR_ARM__ )
        rng_power(1); /* power RNG block */
        rng_reset();  /* reset RNG */
        rng_mode(0);  /* set RNG to truly random mode */
        rng_start();  /* start filling 1024 bit FIFO */
#elif __x86_64__
        srand(time(NULL));
#endif
        init_done = 1;
    }
}

uint32_t rng_get_bigint(uint32_t *BUFF, uint32_t words)
{
    uint32_t rng;
    int i;
#if defined( __MIKROC_PRO_FOR_ARM__ )
    rng = rng_get_words(&BUFF[NUM_SIZE-words], words);
#elif __x86_64__
    for (i = 0; i < words; i++)
    {
        BUFF[NUM_SIZE-1-i] = rand();
    }
    rng = words;
#endif

    return rng;
}

void rng_rst()
{
#if defined( __MIKROC_PRO_FOR_ARM__ )
    rng_reset();
#endif
    init_done = 0;
}

#if defined( __MIKROC_PRO_FOR_ARM__ )
void rng_pause()
{
    rng_stop();
}
#endif
