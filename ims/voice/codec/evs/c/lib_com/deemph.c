/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#include "options.h"
#include "prot.h"

/*-------------------------------------------------------------------*
 * deemph()
 *
 * Deemphasis: filtering through 1/(1-mu z^-1)
 *-------------------------------------------------------------------*/

void deemph(
    float *signal,  /* i/o: signal            */
    const float mu,       /* i  : deemphasis factor */
    const short L,        /* i  : vector size       */
    float *mem      /* i/o: memory (y[-1])    */
)
{
    short i;

    signal[0] = signal[0] + mu * (*mem);
    for (i=1; i<L; i++)
    {
        signal[i] = signal[i] + mu * signal[i-1];
    }

    *mem = signal[L-1];

    if( (*mem < 1e-10) & (*mem > -1e-10) )
    {
        *mem = 0;
    }

    return;
}
