/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/


#include "basop_mpy.h"
#include "options.h"

Word32 Mpy_32_16_1(Word32 x, Word16 y)
{
    Word32 mh;
    UWord16 ml;

    Mpy_32_16_ss(x, y, &mh, &ml);

    return (mh);
}

Word32 Mpy_32_16(Word32 x, Word16 y)
{
    Word32 mh;
    UWord16 ml;

    Mpy_32_16_ss(x, y, &mh, &ml);

    return (mh);
}

Word32 Mpy_32_16_r(Word32 x, Word16 y)
{
    Word32 mh;
    UWord16 ml;

    Mpy_32_16_ss(x, y, &mh, &ml);

    if(s_and(ml, -32768 /* 0x8000 */))
    {
        mh = L_add(mh, 1);
    }

    return (mh);
}


Word32 Mpy_32_32(Word32 x, Word32 y)
{
    Word32 mh;
    UWord32 ml;

    Mpy_32_32_ss(x, y, &mh, &ml);

    return (mh);
}

