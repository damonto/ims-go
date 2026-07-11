/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#include <math.h>
#include "prot.h"

/*-------------------------------------------------------------------*
 * Correlation_shift
 *
 * Find normalized correlation correction dependent on estimated noise
 * Note: this variable is basically active only if noise suppression
 * is desactivated. * Otherwise, (for default NS = 14 dB and up to 10dB SNR)
 * it can be assumed about 0
 *-------------------------------------------------------------------*/

#define MAX_CORR_SHIFT 0.5f

float correlation_shift(       /* o  : noise dependent voicing correction     */
    const float totalNoise     /* i  : noise estimate over all critical bands */
)
{
    float corr_shift;

    corr_shift = 0.0f;
    if( totalNoise > 28.18225893613955f )  /* to make corr_shift > 0.0 */
    {
        /* useful values range from 0 to 1 (can saturate at 1.0) */
        corr_shift = 2.4492e-4f * (float)exp( 0.1596f * totalNoise ) - 0.022f;
    }
    if( corr_shift > MAX_CORR_SHIFT )
    {
        corr_shift = MAX_CORR_SHIFT;
    }
    return corr_shift;
}
