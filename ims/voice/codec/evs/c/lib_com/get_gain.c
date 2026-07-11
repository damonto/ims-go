/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#include "options.h"
#include "prot.h"


/*----------------------------------------------------------------------------------*
*  get_gain()
*
*
*----------------------------------------------------------------------------------*/

float get_gain(     /* output: codebook gain (adaptive or fixed)    */
    float x[],        /* input : target signal                        */
    float y[],        /* input : filtered codebook excitation         */
    int n,            /* input : segment length                       */
    float *en_y       /* output: energy of y (sum of y[]^2, optional) */
)
{
    float corr = 0.0f, ener = 1e-6f;
    short i;

    for (i = 0; i < n; i++)
    {
        corr += x[i]*y[i];
        ener += y[i]*y[i];
    }

    if (en_y)
    {
        *en_y = ener;
    }

    return(corr/ener);
}
