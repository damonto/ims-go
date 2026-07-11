/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#include <stdlib.h>
#include <assert.h>
#include "options.h"
#include "cnst.h"
#include "prot.h"
#include "rom_com.h"

/*-----------------------------------------------------------------*
 * Local functions
 *-----------------------------------------------------------------*/

static void cdftForw( short n, float *a, const short *ip, const float *w );
static void bitrv2_SR( short n, const short *ip, float *a );
static void cftfsub( short n, float *a, const float *w );
static void cft1st(short n, float *a, const float *w);
static void cftmdl(short n, short l, float *a, const float *w);
static void fft16( float *x, float *y, const short *Idx );
static void fft5_shift1( int n1, float *zRe, float *zIm, const short *Idx );
static void fft8( float *x, float *y, const short *Idx );
static void fft15_shift2( int n1, float *zRe, float *zIm, const short *Idx );
static void fft15_shift8( int n1, float *zRe, float *zIm, const short *Idx );
static void fft5_shift4( int   n1, float *zRe, float *zIm, const short *Idx );
static void fft5_32( float *zRe, float *zIm, const short *Idx );
static void fft64( float *x, float *y, const short *Idx );
static void fft32_15( float *x, float *y, const short *Idx );
static void fft32_5( float *x, float *y, const short *Idx );
static void fft8_5( float *x, float *y, const short *Idx );
static void fft5_8( int n1, float *zRe, float *zIm, const short *Idx );
static void fft4_5( float *x, float *y, const short *Idx );
static void fft5_4( int n1, float *zRe, float *zIm, const short *Idx );

static float fmac(float a, float b, float c)
{
    return (((a) * (b)) + (c));
}

static float fnms(float a, float b, float c)
{
    return ((c) - ((a) * (b)));
}

/*-----------------------------------------------------------------*
 * fft15_shift2()
 * 15-point FFT with 2-point circular shift
 *-----------------------------------------------------------------*/

static void fft15_shift2(
    int   n1,      /* i   : length of data                           */
    float *zRe,    /* i/o : real part of input and output data       */
    float *zIm,    /* i/o : imaginary part of input and output data  */
    const short   *Idx     /* i   : pointer of the address table             */
)
{
    short in0, in8, in16, in24, in32, in1, in9, in17, in25, in33, in2, in10, in18, in26, in34;
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8, fi9, fi10, fi11, fi12, fi13, fi14, fi15;
    float fi16, fi17, fi18, fi19, fi20, fi21, fi22, fi23, fi24, fi25, fi26, fi27, fi28, fi29, fi30; 
    float f2i1, f2i2, f2i3, f2i4, f2i5, f2i6, f2i7, f2i8, f2i9, f2i10, f2i11, f2i12; 
    float f2i13, f2i14, f2i15, f2i16, f2i17, f2i18, f2i19, f2i20, f2i21, f2i22, f2i23, f2i24;
    float f3i1, f3i2, f3i3, f3i4, f3i5, f3i6, f3i7, f3i8, f3i9, f3i10, f3i11, f3i12, f3i13, f3i14, f3i15; //CR
    float f4i1,f4i2, f4i3, f4i4, f4i5,f4i6, f4i7, f4i8, f4i9; 
    float f4i10, f4i11, f4i12, f4i13, f4i14, f4i15, f4i16, f4i17, f4i18, f4i19, f4i20, fo1, fo2, fo3, fo4;
    float fo5,fo6, fo7, fo8, fo9,fo10, fo11, fo12, fo13, fo14, fo15, fo16, fo17, fo18;
    float f2o1, f2o2, f2o3, f2o4, f2o5, f2o6, f2o7, f2o8, f2o9,f2o10, f2o11, f2o12, f2o13;
    float f2o14, f2o15, f3o1, f3o2, f3o3, f3o4, f3o5, f3o6, f3o7,f3o8, f3o9, f3o10, f3o11;
    float f3o12, f3o13, f3o14, f3o15, f4o1,f4o2, f4o3, f4o4, f4o5, f4o6;
    float f4o7, f4o8, f4o9, f4o10,f4o11, f4o12, f4o13, f4o14, f4o15, f4o16, f4o17, f4o18, f4o19;

    in0 = Idx[0];
    in8 = Idx[n1];
    in16 = Idx[n1*2];
    in24 = Idx[n1*3];
    in32 = Idx[n1*4];
    in1 = Idx[n1*5];
    in9 = Idx[n1*6];
    in17 = Idx[n1*7];
    in25 = Idx[n1*8];
    in33 = Idx[n1*9];
    in2 = Idx[n1*10];
    in10 = Idx[n1*11];
    in18 = Idx[n1*12];
    in26 = Idx[n1*13];
    in34 = Idx[n1*14];

    f2i13 = zRe[in0];
    f2i14 = zIm[in0];
    f2i21 = zRe[in1];
    f2i22 = zRe[in2];
    f2i23 = zIm[in1];
    f2i24 = zIm[in2];

    f2i15 = f2i21 + f2i22;
    f2i16 = FFT_15PONIT_WNK4 * (f2i22 - f2i21);
    f2i17 = FFT_15PONIT_WNK4 * (f2i23 - f2i24);
    f2i18 = f2i23 + f2i24;
    fi1 = f2i13 + f2i15;
    fi2 = f2i14 + f2i18;

    f2i19 = fnms(0.5f, f2i15, f2i13);
    f2i20 = fnms(0.5f, f2i18, f2i14);
    fi3 = f2i19 - f2i17;
    fi4 = f2i19 + f2i17;
    fi5 = f2i16 + f2i20;
    fi6 = f2i20 - f2i16;

    f3i1 = zRe[in9];
    f4i2 = zRe[in10];
    f4i3 = zRe[in8];
    f3i2 = f4i2 + f4i3;
    f3i3 = fnms(0.5f, f3i2, f3i1);
    f3i4 = FFT_15PONIT_WNK4 * (f4i3 - f4i2);

    f3i5 = zIm[in9];
    f4i4 = zIm[in10];
    f4i5 = zIm[in8];
    f3i6 = f4i4 + f4i5;
    f3i7 = FFT_15PONIT_WNK4 * (f4i4 - f4i5);
    f3i8 = fnms(0.5f, f3i6, f3i5);

    f3i9 = zRe[in33];
    f4i6 = zRe[in34];
    f4i7 = zRe[in32];
    f3i10 = f4i6 + f4i7;
    f3i11 = fnms(0.5f, f3i10, f3i9);
    f3i12 = FFT_15PONIT_WNK4 * (f4i7 - f4i6);

    f3i13 = zIm[in33];
    f4i8 = zIm[in34];
    f4i9 = zIm[in32];
    f3i14 = f4i8 + f4i9;
    f3i15 = FFT_15PONIT_WNK4 * (f4i8 - f4i9);
    f4i1 = fnms(0.5f, f3i14, f3i13);

    fi7 = f3i1 + f3i2;
    fi8 = f3i9 + f3i10;
    fi9 = fi7 + fi8;
    fi10 = f3i3 - f3i7;
    fi11 = f3i11 - f3i15;
    fi12 = fi10 + fi11;
    fi13 = f3i5 + f3i6;
    fi14 = f3i13 + f3i14;
    fi15 = fi13 + fi14;
    fi16 = f3i8 - f3i4;
    fi17 = f4i1 - f3i12;
    fi18 = fi16 + fi17;
    fi19 = f3i4 + f3i8;
    fi20 = f3i12 + f4i1;
    fi21 = fi19 + fi20;
    fi22 = f3i3 + f3i7;
    fi23 = f3i11 + f3i15;
    fi24 = fi22 + fi23;

    f4i10 = zRe[in24];
    fo6 = zRe[in25];
    fo7 = zRe[in26];
    f4i11 = fo6 + fo7;
    f4i12 = fnms(0.5f, f4i11, f4i10);
    f4i13 = FFT_15PONIT_WNK4 * (fo7 - fo6);

    f4i14 = zIm[in24];
    fo8 = zIm[in25];
    fo9 = zIm[in26];
    f4i15 = fo8 + fo9;
    f4i16 = FFT_15PONIT_WNK4 * (fo8 - fo9);
    f4i17 = fnms(0.5f, f4i15, f4i14);

    f4i18 = zRe[in18];
    f2o10 = zRe[in16];
    f2o11 = zRe[in17];
    f4i19 = f2o10 + f2o11;
    f4i20 = fnms(0.5f, f4i19, f4i18);
    fo1 = FFT_15PONIT_WNK4 * (f2o11 - f2o10);

    fo2 = zIm[in18];
    f2o12 = zIm[in16];
    f2o13 = zIm[in17];
    fo3 = f2o12 + f2o13;
    fo4 = FFT_15PONIT_WNK4 * (f2o12 - f2o13);
    fo5 = fnms(0.5f, fo3, fo2);

    fi25 = f4i10 + f4i11;
    fi26 = f4i18 + f4i19;
    fi27 = fi25 + fi26;
    fi28 = f4i12 - f4i16;
    fi29 = f4i20 - fo4;
    fi30 = fi28 + fi29;
    f2i1 = f4i14 + f4i15;
    f2i2 = fo2 + fo3;
    f2i3 = f2i1 + f2i2;
    f2i4 = f4i17 - f4i13;
    f2i5 = fo5 - fo1;
    f2i6 = f2i4 + f2i5;
    f2i7 = f4i13 + f4i17;
    f2i8 = fo1 + fo5;
    f2i9 = f2i7 + f2i8;
    f2i10 = f4i12 + f4i16;
    f2i11 = f4i20 + fo4;
    f2i12 = f2i10 + f2i11;

    fo10 = FFT_15PONIT_WNK1 * (fi27 - fi9);
    fo11 = fi27 + fi9;
    fo12 = fnms(FFT_15PONIT_WNK5, fo11, fi1);
    fo15 = fi13 - fi14;
    fo16 = f2i1 - f2i2;
    fo13 = fnms(FFT_15PONIT_WNK3, fo16, FFT_15PONIT_WNK2 * fo15);
    fo14 = fmac(FFT_15PONIT_WNK2, fo16, FFT_15PONIT_WNK3 * fo15);

    zRe[in0] = fi1 + fo11;
    fo17 = fo10 + fo12;
    zRe[in18] = fo17 - fo14;
    zRe[in24] = fo17 + fo14;
    fo18 = fo12 - fo10;
    zRe[in9] = fo18 - fo13;
    zRe[in33] = fo18 + fo13;

    f2o1 = FFT_15PONIT_WNK1 * (f2i3 - fi15);
    f2o2 = f2i3 + fi15;
    f2o3 = fnms(FFT_15PONIT_WNK5, f2o2, fi2);
    f2o6 = fi7 - fi8;
    f2o7 = fi25 - fi26;
    f2o4 = fnms(FFT_15PONIT_WNK3, f2o7, FFT_15PONIT_WNK2 * f2o6);
    f2o5 = fmac(FFT_15PONIT_WNK2, f2o7, FFT_15PONIT_WNK3 * f2o6);
    zIm[in0] = fi2 + f2o2;
    f2o8 = f2o1 + f2o3;
    zIm[in24] = f2o8 - f2o5;
    zIm[in18] = f2o5 + f2o8;
    f2o9 = f2o3 - f2o1;
    zIm[in33] = f2o9 - f2o4;
    zIm[in9] = f2o4 + f2o9;

    f2o14 = FFT_15PONIT_WNK1 * (fi30 - fi12);
    f2o15 = fi30 + fi12;
    f3o1 = fnms(FFT_15PONIT_WNK5, f2o15, fi3);
    f3o4 = fi16 - fi17;
    f3o5 = f2i4 - f2i5;
    f3o2 = fnms(FFT_15PONIT_WNK3, f3o5, FFT_15PONIT_WNK2 * f3o4);
    f3o3 = fmac(FFT_15PONIT_WNK2, f3o5, FFT_15PONIT_WNK3 * f3o4);
    zRe[in2] = fi3 + f2o15;
    f3o6 = f2o14 + f3o1;
    zRe[in17] = f3o6 - f3o3;
    zRe[in26] = f3o6 + f3o3;
    f3o7 = f3o1 - f2o14;
    zRe[in8] = f3o7 - f3o2;
    zRe[in32] = f3o7 + f3o2;

    f3o8 = FFT_15PONIT_WNK1 * (f2i6 - fi18);
    f3o9 = f2i6 + fi18;
    f3o10 = fnms(FFT_15PONIT_WNK5, f3o9, fi6);
    f3o13 = fi10 - fi11;
    f3o14 = fi28 - fi29;
    f3o11 = fnms(FFT_15PONIT_WNK3, f3o14, FFT_15PONIT_WNK2 * f3o13);
    f3o12 = fmac(FFT_15PONIT_WNK2, f3o14, FFT_15PONIT_WNK3 * f3o13);
    zIm[in2] = fi6 + f3o9;
    f3o15 = f3o8 + f3o10;
    zIm[in26] = f3o15 - f3o12;
    zIm[in17] = f3o12 + f3o15;
    f4o1 = f3o10 - f3o8;
    zIm[in8] = f3o11 + f4o1;
    zIm[in32] = f4o1 - f3o11;

    f4o2 = FFT_15PONIT_WNK1 * (f2i9 - fi21);
    f4o3 = f2i9 + fi21;
    f4o4 = fnms(FFT_15PONIT_WNK5, f4o3, fi5);
    f4o7 = f2i10 - f2i11;
    f4o8 = fi22 - fi23;
    f4o5 = fmac(FFT_15PONIT_WNK2, f4o7, FFT_15PONIT_WNK3 * f4o8);
    f4o6 = fnms(FFT_15PONIT_WNK3, f4o7, FFT_15PONIT_WNK2 * f4o8);
    zIm[in1] = fi5 + f4o3;
    f4o9 = f4o4 - f4o2;
    f4o10 = f4o2 + f4o4;

    zIm[in10] = f4o6 + f4o9;
    zIm[in34] = f4o9 - f4o6;
    zIm[in25] = f4o10 - f4o5;
    zIm[in16] = f4o5 + f4o10;

    f4o11 = FFT_15PONIT_WNK1 * (f2i12 - fi24);
    f4o12 = f2i12 + fi24;
    f4o13 = fnms(FFT_15PONIT_WNK5, f4o12, fi4);
    f4o16 = f2i7 - f2i8;
    f4o17 = fi19 - fi20;
    f4o14 = fmac(FFT_15PONIT_WNK2, f4o16, FFT_15PONIT_WNK3 * f4o17);
    f4o15 = fnms(FFT_15PONIT_WNK3, f4o16, FFT_15PONIT_WNK2 * f4o17);
    zRe[in1] = fi4 + f4o12;
    f4o18 = f4o13 - f4o11;
    f4o19 = f4o11 + f4o13;

    zRe[in10] = f4o18 - f4o15;
    zRe[in34] = f4o18 + f4o15;
    zRe[in16] = f4o19 - f4o14;
    zRe[in25] = f4o19 + f4o14;

    return;
}

/*-----------------------------------------------------------------*
 * fft15_shift8()
 * 15-point FFT with 8-point circular shift
 *-----------------------------------------------------------------*/

static void fft15_shift8(
    int   n1,      /* i   : length of data                           */
    float *zRe,    /* i/o : real part of input and output data       */
    float *zIm,    /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short in0, in8, in16, in24, in32, in1, in9, in17, in25, in33, in2, in10, in18, in26, in34;
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8, fi9, fi10, fi11, fi12, fi13, fi14, fi15;
    float fi16, fi17, fi18, fi19, fi20, fi21, fi22, fi23, fi24, fi25, fi26, fi27, fi28, fi29, fi30;
    float f2i1, f2i2, f2i3, f2i4, f2i5, f2i6, f2i7, f2i8, f2i9, f2i10, f2i11, f2i12;
    float f2i13, f2i14, f2i15, f3i1, f3i2, f3i3, f3i4, f3i5, f3i6, f3i7, f3i8, f3i9;
    float f3i10, f3i11, f3i12, f3i13, f3i14, f3i15, f4i1, f4i2, f4i3, f4i4, f4i5, f4i6, f4i7, f4i8, f4i9;
    float f4i10, f4i11, f4i12, f4i13, f4i14, f4i15, fo1, fo2, fo3, fo4, fo5, fo6;
    float fo7, fo8, fo9, fo10, fo11, fo12, fo13, fo14, fo15, f2o1, f2o2, f2o3, f2o4;
    float f2o5, f2o6, f2o7, f2o8, f2o9, f2o10, f2o11, f2o12, f2o13, f2o14, f2o15;
    float f3o1, f3o2, f3o3, f3o4, f3o5, f3o6, f3o7, f3o8, f3o9, f3o10, f3o11, f3o12;
    float f3o13, f3o14, f3o15, f4o1, f4o2, f4o3, f4o4, f4o5, f4o6, f4o7, f4o8, f4o9;
    float f4o10, f4o11, f4o12, f4o13, f4o14, f4o15, f5o1, f5o2, f5o3, f5o4, f5o5, f5o6, f5o7;
    float f5o8, f5o9, f5o10, f5o11, f5o12, f5o13, f5o14, f5o15, f5o16, f5o17, f5o18, f5o19, f5o21, f5o22;

    in0 = Idx[0] ;
    in8 = Idx[n1];
    in16 = Idx[n1*2];
    in24 = Idx[n1*3];
    in32 = Idx[n1*4];
    in1 = Idx[n1*5];
    in9 = Idx[n1*6];
    in17 = Idx[n1*7];
    in25 = Idx[n1*8];
    in33 = Idx[n1*9];
    in2 = Idx[n1*10];
    in10 = Idx[n1*11];
    in18 = Idx[n1*12];
    in26 = Idx[n1*13];
    in34 = Idx[n1*14];

    f2i13 = zRe[in0];
    f2i14 = zIm[in0];
    f3i6 = zRe[in1];
    f3i7 = zRe[in2];
    f3i8 = zIm[in1];
    f3i9 = zIm[in2];

    f2i15 = f3i6 + f3i7;
    f3i1 = FFT_15PONIT_WNK4 * (f3i7 - f3i6);
    f3i2 = FFT_15PONIT_WNK4 * (f3i8 - f3i9);
    f3i3 = f3i8 + f3i9;

    fi1 = f2i13 + f2i15;
    fi2 = f2i14 + f3i3;
    f3i4 = fnms(0.5f, f2i15, f2i13);
    fi3 = f3i4 - f3i2;
    fi4 = f3i4 + f3i2;
    f3i5 = fnms(0.5f, f3i3, f2i14);
    fi5 = f3i1 + f3i5;
    fi6 = f3i5 - f3i1;

    f3i10 = zRe[in9];
    f4i11 = zRe[in10];
    f4i12 = zRe[in8];
    f3i14 = zIm[in9];
    f4i13 = zIm[in10];
    f4i14 = zIm[in8];
    f4i3 = zRe[in33];
    f4i15 = zRe[in34];
    fo1 = zRe[in32];
    f4i7 = zIm[in33];
    fo2 = zIm[in34];
    fo3 = zIm[in32];


    f3i11 = f4i11 + f4i12;
    f3i12 = fnms(0.5f, f3i11, f3i10);
    f3i13 = FFT_15PONIT_WNK4 * (f4i12 - f4i11);
    f3i15 = f4i13 + f4i14;
    f4i1 = FFT_15PONIT_WNK4 * (f4i13 - f4i14);
    f4i2 = fnms(0.5f, f3i15, f3i14);
    f4i4 = f4i15 + fo1;
    f4i5 = fnms(0.5f, f4i4, f4i3);
    f4i6 = FFT_15PONIT_WNK4 * (fo1 - f4i15);
    f4i8 = fo2 + fo3;
    f4i9 = FFT_15PONIT_WNK4 * (fo2 - fo3);
    f4i10 = fnms(0.5f, f4i8, f4i7);

    fi7 = f3i10 + f3i11;
    fi8 = f4i3 + f4i4;
    fi9 = fi7 + fi8;
    fi10 = f3i12 - f4i1;
    fi11 = f4i5 - f4i9;
    fi12 = fi10 + fi11;
    fi13 = f3i14 + f3i15;
    fi14 = f4i7 + f4i8;
    fi15 = fi13 + fi14;
    fi16 = f4i2 - f3i13;
    fi17 = f4i10 - f4i6;
    fi18 = fi16 + fi17;
    fi19 = f3i13 + f4i2;
    fi20 = f4i6 + f4i10;
    fi21 = fi19 + fi20;
    fi22 = f3i12 + f4i1;
    fi23 = f4i5 + f4i9;
    fi24 = fi22 + fi23;

    fo4 = zRe[in24];
    f2o5 = zRe[in25];
    f2o6 = zRe[in26];
    fo8 = zIm[in24];
    f2o7 = zIm[in25];
    f2o8 = zIm[in26];
    fo12 = zRe[in18];
    f2o9 = zRe[in16];
    f2o10 = zRe[in17];
    f2o1 = zIm[in18];
    f2o11 = zIm[in16];
    f2o12 = zIm[in17];


    fo5 = f2o5 + f2o6;
    fo6 = fnms(0.5f, fo5, fo4);
    fo7 = FFT_15PONIT_WNK4 * (f2o6 - f2o5);
    fo9 = f2o7 + f2o8;
    fo10 = FFT_15PONIT_WNK4 * (f2o7 - f2o8);
    fo11 = fnms(0.5f, fo9, fo8);
    fo13 = f2o9 + f2o10;
    fo14 = fnms(0.5f, fo13, fo12);
    fo15 = FFT_15PONIT_WNK4 * (f2o10 - f2o9);
    f2o2 = f2o11 + f2o12;
    f2o3 = FFT_15PONIT_WNK4 * (f2o11 - f2o12);
    f2o4 = fnms(0.5f, f2o2, f2o1);

    fi25 = fo4 + fo5;
    fi26 = fo12 + fo13;
    fi27 = fi25 + fi26;
    fi28 = fo6 - fo10;
    fi29 = fo14 - f2o3;
    fi30 = fi28 + fi29;
    f2i1 = fo8 + fo9;
    f2i2 = f2o1 + f2o2;
    f2i3 = f2i1 + f2i2;
    f2i4 = fo11 - fo7;
    f2i5 = f2o4 - fo15;
    f2i6 = f2i4 + f2i5;
    f2i7 = fo7 + fo11;
    f2i8 = fo15 + f2o4;
    f2i9 = f2i7 + f2i8;
    f2i10 = fo6 + fo10;
    f2i11 = fo14 + f2o3;
    f2i12 = f2i10 + f2i11;

    f2o13 = FFT_15PONIT_WNK1 * (fi27 - fi9);
    f2o14 = fi27 + fi9;
    f2o15 = fnms(FFT_15PONIT_WNK5, f2o14, fi1);
    f3o3 = fi13 - fi14;
    f3o4 = f2i1 - f2i2;
    f3o1 = fnms(FFT_15PONIT_WNK3, f3o4, FFT_15PONIT_WNK2 * f3o3);
    f3o2 = fmac(FFT_15PONIT_WNK2, f3o4, FFT_15PONIT_WNK3 * f3o3);
    zRe[in0] = fi1 + f2o14;
    f3o5 = f2o13 + f2o15;
    zRe[in24] = f3o5 - f3o2;
    zRe[in18] = f3o5 + f3o2;
    f3o6 = f2o15 - f2o13;
    zRe[in33] = f3o6 - f3o1;
    zRe[in9] = f3o6 + f3o1;

    f3o7 = FFT_15PONIT_WNK1 * (f2i3 - fi15);
    f3o8 = f2i3 + fi15;
    f3o9 = fnms(FFT_15PONIT_WNK5, f3o8, fi2);
    f3o12 = fi7 - fi8;
    f3o13 = fi25 - fi26;
    f3o10 = fnms(FFT_15PONIT_WNK3, f3o13, FFT_15PONIT_WNK2 * f3o12);
    f3o11 = fmac(FFT_15PONIT_WNK2, f3o13, FFT_15PONIT_WNK3 * f3o12);
    zIm[in0] = fi2 + f3o8;
    f3o14 = f3o7 + f3o9;
    zIm[in18] = f3o14 - f3o11;
    zIm[in24] = f3o11 + f3o14;
    f3o15 = f3o9 - f3o7;
    zIm[in9] = f3o15 - f3o10;
    zIm[in33] = f3o10 + f3o15;

    f4o1 = FFT_15PONIT_WNK1 * (fi30 - fi12);
    f4o2 = fi30 + fi12;
    f4o3 = fnms(FFT_15PONIT_WNK5, f4o2, fi3);
    f4o6 = fi16 - fi17;
    f4o7 = f2i4 - f2i5;
    f4o4 = fnms(FFT_15PONIT_WNK3, f4o7, FFT_15PONIT_WNK2 * f4o6);
    f4o5 = fmac(FFT_15PONIT_WNK2, f4o7, FFT_15PONIT_WNK3 * f4o6);
    zRe[in2] = fi3 + f4o2;
    f4o8 = f4o1 + f4o3;
    zRe[in26] = f4o8 - f4o5;
    zRe[in17] = f4o8 + f4o5;
    f4o9 = f4o3 - f4o1;
    zRe[in32] = f4o9 - f4o4;
    zRe[in8] = f4o9 + f4o4;

    f4o10 = FFT_15PONIT_WNK1 * (f2i6 - fi18);
    f4o11 = f2i6 + fi18;
    f4o12 = fnms(FFT_15PONIT_WNK5, f4o11, fi6);
    f4o15 = fi10 - fi11;
    f5o1 = fi28 - fi29;
    f4o13 = fnms(FFT_15PONIT_WNK3, f5o1, FFT_15PONIT_WNK2 * f4o15);
    f4o14 = fmac(FFT_15PONIT_WNK2, f5o1, FFT_15PONIT_WNK3 * f4o15);
    zIm[in2] = fi6 + f4o11;
    f5o2 = f4o10 + f4o12;
    zIm[in17] = f5o2 - f4o14;
    zIm[in26] = f4o14 + f5o2;
    f5o3 = f4o12 - f4o10;
    zIm[in32] = f4o13 + f5o3;
    zIm[in8] = f5o3 - f4o13;

    f5o4 = FFT_15PONIT_WNK1 * (f2i9 - fi21);
    f5o5 = f2i9 + fi21;
    f5o6 = fnms(FFT_15PONIT_WNK5, f5o5, fi5);
    f5o9 = f2i10 - f2i11;
    f5o10 = fi22 - fi23;
    f5o7 = fmac(FFT_15PONIT_WNK2, f5o9, FFT_15PONIT_WNK3 * f5o10);
    f5o8 = fnms(FFT_15PONIT_WNK3, f5o9, FFT_15PONIT_WNK2 * f5o10);
    zIm[in1] = fi5 + f5o5;
    f5o11 = f5o6 - f5o4;
    f5o12 = f5o4 + f5o6;
    zIm[in34] = f5o8 + f5o11;
    zIm[in10] = f5o11 - f5o8;

    zIm[in16] = f5o12 - f5o7;
    zIm[in25] = f5o7 + f5o12;

    f5o13 = FFT_15PONIT_WNK1 * (f2i12 - fi24);
    f5o14 = f2i12 + fi24;
    f5o15 = fnms(FFT_15PONIT_WNK5, f5o14, fi4);
    f5o18 = f2i7 - f2i8;
    f5o19 = fi19 - fi20;
    f5o16 = fmac(FFT_15PONIT_WNK2, f5o18, FFT_15PONIT_WNK3 * f5o19);
    f5o17 = fnms(FFT_15PONIT_WNK3, f5o18, FFT_15PONIT_WNK2 * f5o19);
    zRe[in1] = fi4 + f5o14;
    f5o21 = f5o15 - f5o13;
    f5o22 = f5o13 + f5o15;

    zRe[in34] = f5o21 - f5o17;
    zRe[in10] = f5o21 + f5o17;
    zRe[in25] = f5o22 - f5o16;
    zRe[in16] = f5o22 + f5o16;

    return;
}

/*-----------------------------------------------------------------*
 * fft5_shift1()
 * 5-point FFT with 1-point circular shift
 *-----------------------------------------------------------------*/

static void fft5_shift1(
    int   n1,      /* i   : length of data                           */
    float *zRe,    /* i/o : real part of input and output data       */
    float *zIm,    /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8;
    float fo1, fo2, fo3, fo4, fo5, fo6, fo7, fo8;
    short in1,in2,in3,in4,in5;

    in1 = Idx[0];
    in2 = Idx[n1];
    in3 = Idx[n1*2];
    in4 = Idx[n1*3];
    in5 = Idx[n1*4];

    fi1 = zRe[in1];
    fi2 = zIm[in1];
    fo3 = zRe[in2];
    fo4 = zRe[in5];
    fo6 = zRe[in3];
    fo7 = zRe[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi3 = fo5 + fo8;
    fi4 = fo6 - fo7;
    fi5 = FFT_15PONIT_WNK1 * (fo5 - fo8);
    fi6 = fo3 - fo4;

    fo3 = zIm[in2];
    fo4 = zIm[in5];
    fo6 = zIm[in3];
    fo7 = zIm[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi7 = fo3 - fo4;
    fi8 = fo5 + fo8;
    fo1 = fo6 - fo7;
    fo2 = FFT_15PONIT_WNK1 * (fo5 - fo8);

    zRe[in1] = fi1 + fi3;
    zIm[in1] = fi2 + fi8;

    fo3 = FFT_15PONIT_WNK2*fi7 + FFT_15PONIT_WNK3*fo1;
    fo4 = FFT_15PONIT_WNK2*fo1 - FFT_15PONIT_WNK3*fi7;
    fo7 = fi1-fi3/4;
    fo5 = fi5 + fo7;
    fo6 = fo7 - fi5;

    zRe[in2] = fo5 + fo3;
    zRe[in3] = fo6 - fo4;
    zRe[in4] = fo6 + fo4;
    zRe[in5] = fo5 - fo3;

    fo3 = FFT_15PONIT_WNK2 * fi6 + FFT_15PONIT_WNK3 * fi4;
    fo4 = FFT_15PONIT_WNK2 * fi4 - FFT_15PONIT_WNK3 * fi6;
    fo7 = fi2-fi8/4;
    fo5 = fo2 + fo7;
    fo6 = fo7 - fo2;

    zIm[in2] = fo5 - fo3;
    zIm[in3] = fo4 + fo6;
    zIm[in4] = fo6 - fo4;
    zIm[in5] = fo3 + fo5;

    return;
}

/*-----------------------------------------------------------------*
 * fft5_shift4()
 * 5-point FFT with 4-point circular shift
 *-----------------------------------------------------------------*/

static void fft5_shift4(
    int   n1,      /* i   : length of data                           */
    float *zRe,    /* i/o : real part of input and output data       */
    float *zIm,    /* i/o : imaginary part of input and output data  */
    const short   *Idx     /* i   : pointer of the address table             */
)
{
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8;
    float fo1, fo2, fo3, fo4, fo5, fo6, fo7, fo8;
    short in1,in2,in3,in4,in5;

    in1 = Idx[0];
    in2 = Idx[n1];
    in3 = Idx[n1*2];
    in4 = Idx[n1*3];
    in5 = Idx[n1*4];

    fi1 = zRe[in1];
    fi2 = zIm[in1];
    fo3 = zRe[in2];
    fo4 = zRe[in5];
    fo6 = zRe[in3];
    fo7 = zRe[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi3 = fo5 + fo8;
    fi4 = fo6 - fo7;
    fi5 = FFT_15PONIT_WNK1 * (fo5 - fo8);
    fi6 = fo3 - fo4;

    fo3 = zIm[in2];
    fo4 = zIm[in5];
    fo6 = zIm[in3];
    fo7 = zIm[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi7 = fo3 - fo4;
    fi8 = fo5 + fo8;
    fo1 = fo6 - fo7;
    fo2 = FFT_15PONIT_WNK1 * (fo5 - fo8);

    zRe[in1] = fi1 + fi3;
    zIm[in1] = fi2 + fi8;

    fo3 = FFT_15PONIT_WNK2*fi7 + FFT_15PONIT_WNK3*fo1;
    fo4 = FFT_15PONIT_WNK2*fo1 - FFT_15PONIT_WNK3*fi7;
    fo7 = fi1-fi3/4;
    fo5 = fi5 + fo7;
    fo6 = fo7 - fi5;
    zRe[in2] = fo5 - fo3;
    zRe[in4] = fo6 - fo4;
    zRe[in3] = fo6 + fo4;
    zRe[in5] = fo5 + fo3;

    fo3 = FFT_15PONIT_WNK2 * fi6 + FFT_15PONIT_WNK3 * fi4;
    fo4 = FFT_15PONIT_WNK2 * fi4 - FFT_15PONIT_WNK3 * fi6;
    fo7 = fi2-fi8/4;
    fo5 = fo2 + fo7;
    fo6 = fo7 - fo2;

    zIm[in3] = fo6 - fo4;
    zIm[in2] = fo3 + fo5;
    zIm[in4] = fo4 + fo6;
    zIm[in5] = fo5 - fo3;

    return;
}

/*-----------------------------------------------------------------*
 * fft5_32()
 * 5-point FFT called for 32 times
 *-----------------------------------------------------------------*/

static void fft5_32(
    float *zRe,    /* i/o : real part of input and output data       */
    float *zIm,    /* i/o : imaginary part of input and output data  */
    const short   *Idx     /* i   : pointer of the address table             */
)
{
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8;
    float fo1, fo2, fo3, fo4, fo5, fo6, fo7, fo8;
    short in1,in2,in3,in4,in5;

    in1 = Idx[0];
    in2 = Idx[32];
    in3 = Idx[64];
    in4 = Idx[96];
    in5 = Idx[128];

    fi1 = zRe[in1];
    fi2 = zIm[in1];
    fo3 = zRe[in2];
    fo4 = zRe[in5];
    fo6 = zRe[in3];
    fo7 = zRe[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi3 = fo5 + fo8;
    fi4 = fo6 - fo7;
    fi5 = FFT_15PONIT_WNK1 * (fo5 - fo8);
    fi6 = fo3 - fo4;

    fo3 = zIm[in2];
    fo4 = zIm[in5];
    fo6 = zIm[in3];
    fo7 = zIm[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi7 = fo3 - fo4;
    fi8 = fo5 + fo8;
    fo1 = fo6 - fo7;
    fo2 = FFT_15PONIT_WNK1 * (fo5 - fo8);

    zRe[in1] = fi1 + fi3;
    zIm[in1] = fi2 + fi8;

    fo3 = FFT_15PONIT_WNK2*fi7 + FFT_15PONIT_WNK3*fo1;
    fo4 = FFT_15PONIT_WNK2*fo1 - FFT_15PONIT_WNK3*fi7;
    fo7 = fi1-fi3/4;
    fo5 = fi5 + fo7;
    fo6 = fo7 - fi5;

    zRe[in2] = fo6 + fo4;
    zRe[in3] = fo5 + fo3;
    zRe[in4] = fo5 - fo3;
    zRe[in5] = fo6 - fo4;

    fo3 = FFT_15PONIT_WNK2 * fi6 + FFT_15PONIT_WNK3 * fi4;
    fo4 = FFT_15PONIT_WNK2 * fi4 - FFT_15PONIT_WNK3 * fi6;
    fo7 = fi2-fi8/4;
    fo5 = fo2 + fo7;
    fo6 = fo7 - fo2;

    zIm[in2] = fo6 - fo4;
    zIm[in3] = fo5 - fo3;
    zIm[in4] = fo3 + fo5;
    zIm[in5] = fo4 + fo6;

    return;
}

/*-----------------------------------------------------------------*
 * fft64()
 * 64-point FFT
 *-----------------------------------------------------------------*/

static void fft64(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short i,id,jd;
    float z[128];
    for ( i=0; i<64; i++ )
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(128,z,Ip_fft64,w_fft64);

    for( i=0; i<64 ; i++)
    {
        jd = Odx_fft64[i];
        id = Idx[jd];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }

    return;
}


/*-----------------------------------------------------------------*
 * fft32_15()
 * 32-point FFT called for 15 times
 *-----------------------------------------------------------------*/

static void fft32_15(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short i,id,jd;
    float z[64];

    for( i=0; i<32; i++ )
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(64,z,Ip_fft32,w_fft32);

    for( i=0; i<32; i++ )
    {
        jd = Odx_fft32_15[i];
        id = Idx[jd];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }

    return;
}

/*-----------------------------------------------------------------*
 * fft32_5()
 * 32-point FFT called for 5 times
 *-----------------------------------------------------------------*/

static void fft32_5(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short i,id,jd;
    float z[64];

    for( i=0; i<32; i++ )
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(64,z,Ip_fft32,w_fft32);

    for( i=0; i<32; i++ )
    {
        jd = Odx_fft32_5[i];
        id = Idx[jd];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }

    return;
}

/*-----------------------------------------------------------------*
 * fft16()
 * 16-point FFT
 *-----------------------------------------------------------------*/

static void fft16(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short i,id,jd;
    float z[32];

    for(i=0; i<16 ; i++)
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(32,z,Ip_fft16,w_fft16);

    for(i=0; i<16; i++)
    {
        jd = Odx_fft16[i];
        id = Idx[jd];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }

    return;
}

/*-----------------------------------------------------------------*
 * fft8()
 * 8-point FFT
 *-----------------------------------------------------------------*/

static void fft8(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short   *Idx     /* i   : pointer of the address table             */
)
{
    short i,id;
    float z[16];

    for(i=0; i<8; i++)
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(16,z,Ip_fft8,w_fft8);

    for(i=0; i<8; i++)
    {
        id = Idx[i];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }

    return;
}

/*-----------------------------------------------------------------*
 * fft8_5()
 * 8-point FFT with shift 5
 *-----------------------------------------------------------------*/

static void fft8_5(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short i,id,jd;
    float z[16];

    for(i=0; i<8; i++)
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(16,z,Ip_fft8,w_fft8);

    for(i=0; i<8; i++)
    {
        jd = Odx_fft8_5[i];
        id = Idx[jd];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }
    return;
}

/*-----------------------------------------------------------------*
* fft5_8()
* 5-point FFT with shift 2
*-----------------------------------------------------------------*/

static void fft5_8(
    int   n1,      /* i   : length of data                           */
    float *zRe,    /* i/o : real part of input and output data       */
    float *zIm,    /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8;
    float fo1, fo2, fo3, fo4, fo5, fo6, fo7, fo8;
    short in1,in2,in3,in4,in5;

    in1 = Idx[0];
    in2 = Idx[n1];
    in3 = Idx[n1*2];
    in4 = Idx[n1*3];
    in5 = Idx[n1*4];

    fi1 = zRe[in1];
    fi2 = zIm[in1];
    fo3 = zRe[in2];
    fo4 = zRe[in5];
    fo6 = zRe[in3];
    fo7 = zRe[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi3 = fo5 + fo8;
    fi4 = fo6 - fo7;
    fi5 = FFT_15PONIT_WNK1 * (fo5 - fo8);
    fi6 = fo3 - fo4;

    fo3 = zIm[in2];
    fo4 = zIm[in5];
    fo6 = zIm[in3];
    fo7 = zIm[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi7 = fo3 - fo4;
    fi8 = fo5 + fo8;
    fo1 = fo6 - fo7;
    fo2 = FFT_15PONIT_WNK1 * (fo5 - fo8);

    zRe[in1] = fi1 + fi3;
    zIm[in1] = fi2 + fi8;

    fo3 = FFT_15PONIT_WNK2*fi7 + FFT_15PONIT_WNK3*fo1;
    fo4 = FFT_15PONIT_WNK2*fo1 - FFT_15PONIT_WNK3*fi7;
    fo7 = fi1-fi3/4;
    fo5 = fi5 + fo7;
    fo6 = fo7 - fi5;

    zRe[in2] = fo6 - fo4;
    zRe[in3] = fo5 - fo3;
    zRe[in5] = fo6 + fo4;
    zRe[in4] = fo5 + fo3;

    fo3 = FFT_15PONIT_WNK2 * fi6 + FFT_15PONIT_WNK3 * fi4;
    fo4 = FFT_15PONIT_WNK2 * fi4 - FFT_15PONIT_WNK3 * fi6;
    fo7 = fi2-fi8/4;
    fo5 = fo2 + fo7;
    fo6 = fo7 - fo2;

    zIm[in2] = fo4 + fo6;
    zIm[in3] = fo3 + fo5;
    zIm[in4] = fo5 - fo3;
    zIm[in5] = fo6 - fo4;

    return;
}

/*-----------------------------------------------------------------*
 * fft4_5()
 * 8-point FFT with shift 1
 *-----------------------------------------------------------------*/

static void fft4_5(
    float *x,      /* i/o : real part of input and output data       */
    float *y,      /* i/o : imaginary part of input and output data  */
    const short *Idx     /* i   : pointer of the address table             */
)
{
    short i,id,jd;
    float z[8];

    for(i=0; i<4; i++)
    {
        id = Idx[i];
        z[2*i]   = x[id];
        z[2*i+1] = y[id];
    }

    cdftForw(8,z,Ip_fft4,w_fft4);

    for(i=0; i<4; i++)
    {
        jd = Odx_fft4_5[i];
        id = Idx[jd];
        x[id]=z[2*i];
        y[id]=z[2*i+1];
    }
    return;
}

/*-----------------------------------------------------------------*
 * fft5_4()
 * 5-point FFT with shift 4
 *-----------------------------------------------------------------*/

static void fft5_4( int n1, float *zRe, float *zIm, const short *Idx )
{
    float fi1, fi2, fi3, fi4, fi5, fi6, fi7, fi8;
    float fo1, fo2, fo3, fo4, fo5, fo6, fo7, fo8;
    short in1,in2,in3,in4,in5;

    in1 = Idx[0];
    in2 = Idx[n1];
    in3 = Idx[n1*2];
    in4 = Idx[n1*3];
    in5 = Idx[n1*4];

    fi1 = zRe[in1];
    fi2 = zIm[in1];
    fo3 = zRe[in2];
    fo4 = zRe[in5];
    fo6 = zRe[in3];
    fo7 = zRe[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi3 = fo5 + fo8;
    fi4 = fo6 - fo7;
    fi5 = FFT_15PONIT_WNK1 * (fo5 - fo8);
    fi6 = fo3 - fo4;

    fo3 = zIm[in2];
    fo4 = zIm[in5];
    fo6 = zIm[in3];
    fo7 = zIm[in4];

    fo5 = fo3 + fo4;
    fo8 = fo6 + fo7;
    fi7 = fo3 - fo4;
    fi8 = fo5 + fo8;
    fo1 = fo6 - fo7;
    fo2 = FFT_15PONIT_WNK1 * (fo5 - fo8);

    zRe[in1] = fi1 + fi3;
    zIm[in1] = fi2 + fi8;

    fo3 = FFT_15PONIT_WNK2*fi7 + FFT_15PONIT_WNK3*fo1;
    fo4 = FFT_15PONIT_WNK2*fo1 - FFT_15PONIT_WNK3*fi7;
    fo7 = fi1-fi3/4;
    fo5 = fi5 + fo7;
    fo6 = fo7 - fi5;

    zRe[in2] = fo5 - fo3;
    zRe[in4] = fo6 - fo4;
    zRe[in3] = fo6 + fo4;
    zRe[in5] = fo5 + fo3;

    fo3 = FFT_15PONIT_WNK2 * fi6 + FFT_15PONIT_WNK3 * fi4;
    fo4 = FFT_15PONIT_WNK2 * fi4 - FFT_15PONIT_WNK3 * fi6;
    fo7 = fi2-fi8/4;
    fo5 = fo2 + fo7;
    fo6 = fo7 - fo2;

    zIm[in2] = fo3 + fo5;
    zIm[in3] = fo6 - fo4;
    zIm[in4] = fo4 + fo6;
    zIm[in5] = fo5 - fo3;

    return;
}


/*-----------------------------------------------------------------*
 * DoRTFT80()
 * a low complexity 2-dimensional DFT of 80 points
 *-----------------------------------------------------------------*/

void DoRTFT80(
    float *x,   /* i/o : real part of input and output data       */
    float *y    /* i/o : imaginary part of input and output data  */
)
{
    short j;

    /* Applying 16-point FFT for 5 times based on the address table Idx_dortft80 */
    for(j=0; j<5; j++)
    {
        fft16(x,y,Idx_dortft80+16*j);
    }

    /* Applying 5-point FFT for 16 times based on the address table Idx_dortft80 */
    for(j=0; j<16; j++)
    {
        fft5_shift1(16,x,y,Idx_dortft80+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT120()
 * a low complexity 2-dimensional DFT of 120 points
 *-----------------------------------------------------------------*/

void DoRTFT120(
    float *x,       /* i/o : real part of input and output data       */
    float *y        /* i/o : imaginary part of input and output data  */
)
{
    short j;

    /* Applying 8-point FFT for 15 times based on the address table Idx_dortft120 */
    for(j=0; j<15; j++)
    {
        fft8(x,y,Idx_dortft120+8*j);
    }

    /* Applying 15-point FFT for 8 times based on the address table Idx_dortft120 */
    for(j=0; j<8; j++)
    {
        fft15_shift2(8,x,y,Idx_dortft120+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT160()
 * a low complexity 2-dimensional DFT of 160 points
 *-----------------------------------------------------------------*/

void DoRTFT160(
    float x[],     /* i/o : real part of input and output data       */
    float y[]      /* i/o : imaginary part of input and output data  */
)
{
    short j;

    /* Applying 32-point FFT for 5 times based on the address table Idx_dortft160 */
    for(j=0; j<5; j++)
    {
        fft32_5(x,y,Idx_dortft160+32*j);
    }

    /* Applying 5-point FFT for 32 times based on the address table Idx_dortft160 */
    for(j=0; j<32; j++)
    {
        fft5_32(x,y,Idx_dortft160+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT320()
 * a low complexity 2-dimensional DFT of 320 points
 *-----------------------------------------------------------------*/

void DoRTFT320(
    float *x,   /* i/o : real part of input and output data       */
    float *y    /* i/o : imaginary part of input and output data  */
)
{
    short j;

    /* Applying 64-point FFT for 5 times based on the address table Idx_dortft160 */
    for(j=0; j<5; j++)
    {
        fft64(x,y,Idx_dortft320+64*j);
    }

    /* Applying 5-point FFT for 64 times based on the address table Idx_dortft160 */
    for(j=0; j<64; j++)
    {
        fft5_shift4(64,x,y,Idx_dortft320+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT480()
 * a low complexity 2-dimensional DFT of 480 points
 *-----------------------------------------------------------------*/

void DoRTFT480(
    float *x,    /* i/o : real part of input and output data       */
    float *y     /* i/o : imaginary part of input and output data  */
)
{
    short j;

    /* Applying 32-point FFT for 15 times based on the address table Idx_dortft160 */
    for(j=0; j<15; j++)
    {
        fft32_15(x,y,Idx_dortft480+32*j);
    }

    /* Applying 5-point FFT for 32 times based on the address table Idx_dortft160 */
    for(j=0; j<32; j++)
    {
        fft15_shift8(32,x,y,Idx_dortft480+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT40()
 * a low complexity 2-dimensional DFT of 40 points
 *-----------------------------------------------------------------*/

void DoRTFT40(
    float *x,    /* i/o : real part of input and output data       */
    float *y     /* i/o : imaginary part of input and output data  */
)
{
    short j;
    /* Applying 8-point FFT for 5 times based on the address table Idx_dortft40 */
    for(j=0; j<5; j++)
    {
        fft8_5(x,y,Idx_dortft40+8*j);
    }

    /* Applying 5-point FFT for 8 times based on the address table Idx_dortft40 */
    for(j=0; j<8; j++)
    {
        fft5_8(8,x,y,Idx_dortft40+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT20()
 * a low complexity 2-dimensional DFT of 20 points
 *-----------------------------------------------------------------*/

void DoRTFT20(
    float *x,    /* i/o : real part of input and output data       */
    float *y     /* i/o : imaginary part of input and output data  */
)
{
    short j;

    /* Applying 4-point FFT for 5 times based on the address table Idx_dortft20 */
    for(j=0; j<5; j++)
    {
        fft4_5(x,y,Idx_dortft20+4*j);
    }

    /* Applying 5-point FFT for 4 times based on the address table Idx_dortft20 */
    for(j=0; j<4; j++)
    {
        fft5_4(4,x,y,Idx_dortft20+j);
    }

    return;
}

/*-----------------------------------------------------------------*
 * DoRTFT128()
 * FFT with 128 points
 *-----------------------------------------------------------------*/

void DoRTFT128(
    float *x,    /* i/o : real part of input and output data       */
    float *y     /* i/o : imaginary part of input and output data  */
)
{

    int i;
    float z[256];

    for ( i=0; i<128; i++ )
    {
        z[2*i]   = x[i];
        z[2*i+1] = y[i];
    }

    cdftForw(256,z,Ip_fft128,w_fft128);

    x[0]=z[0];
    y[0]=z[1];
    for( i=1; i<128 ; i++)
    {
        x[128-i]=z[2*i];
        y[128-i]=z[2*i+1];
    }

    return;
}

/*-----------------------------------------------------------------*
 * cdftForw()
 * Main fuction of Complex Discrete Fourier Transform
 *-----------------------------------------------------------------*/

static void cdftForw(
    short n,    /* i    : data length of real and imag  */
    float *a,   /* i/o  : input/output data             */
    const short *ip,  /* i    : work area for bit reversal    */
    const float *w    /* i    : cos/sin table                 */
)
{
    /* bit reversal */
    bitrv2_SR(n, ip + 2, a);

    /* Do FFT */
    cftfsub(n, a, w);
}

/*-----------------------------------------------------------------*
 * bitrv2_SR()
 * Bit reversal
 *-----------------------------------------------------------------*/

static void bitrv2_SR(
    short n,     /* i    : data length of real and imag  */
    const short *ip,   /* i/o  : work area for bit reversal    */
    float *a     /* i/o  : input/output data             */
)
{
    short j, j1, k, k1, m, m2;
    short l;
    float xr, xi, yr, yi;

    if (n == 64)
    {
        m = 4;
        l = -1;
    }
    else if (n == 256)
    {
        m = 8;
        l = -1;
    }
    else if (n == 16)
    {
        m = 2;
        l = -1;
    }
    else
    {
        l = n;
        m = 1;

        while ((m << 3) < l)
        {
            l >>= 1;
            m <<= 1;
        }
        l -= m * 8;
    }

    m2 = 2 * m;

    if (l == 0)
    {
        for (k = 0; k < m; k++)
        {
            for (j = 0; j < k; j++)
            {
                j1 = 2 * j + ip[k];
                k1 = 2 * k + ip[j];
                xr = a[j1];
                xi = a[j1 + 1];
                yr = a[k1];
                yi = a[k1 + 1];
                a[j1] = yr;
                a[j1 + 1] = yi;
                a[k1] = xr;
                a[k1 + 1] = xi;
                j1 += m2;
                k1 += 2 * m2;
                xr = a[j1];
                xi = a[j1 + 1];
                yr = a[k1];
                yi = a[k1 + 1];
                a[j1] = yr;
                a[j1 + 1] = yi;
                a[k1] = xr;
                a[k1 + 1] = xi;
                j1 += m2;
                k1 -= m2;
                xr = a[j1];
                xi = a[j1 + 1];
                yr = a[k1];
                yi = a[k1 + 1];
                a[j1] = yr;
                a[j1 + 1] = yi;
                a[k1] = xr;
                a[k1 + 1] = xi;
                j1 += m2;
                k1 += 2 * m2;
                xr = a[j1];
                xi = a[j1 + 1];
                yr = a[k1];
                yi = a[k1 + 1];
                a[j1] = yr;
                a[j1 + 1] = yi;
                a[k1] = xr;
                a[k1 + 1] = xi;
            }

            j1 = 2 * k + m2 + ip[k];
            k1 = j1 + m2;
            xr = a[j1];
            xi = a[j1 + 1];
            yr = a[k1];
            yi = a[k1 + 1];
            a[j1] = yr;
            a[j1 + 1] = yi;
            a[k1] = xr;
            a[k1 + 1] = xi;
        }
    }
    else
    {
        for (k = 1; k < m; k++)
        {
            for (j = 0; j < k; j++)
            {
                j1 = 2 * j + ip[k];
                k1 = 2 * k + ip[j];
                xr = a[j1];
                xi = a[j1 + 1];
                yr = a[k1];
                yi = a[k1 + 1];
                a[j1] = yr;
                a[j1 + 1] = yi;
                a[k1] = xr;
                a[k1 + 1] = xi;
                j1 += m2;
                k1 += m2;
                xr = a[j1];
                xi = a[j1 + 1];
                yr = a[k1];
                yi = a[k1 + 1];
                a[j1] = yr;
                a[j1 + 1] = yi;
                a[k1] = xr;
                a[k1 + 1] = xi;
            }
        }
    }

    return;
}

/*-----------------------------------------------------------------*
 * cftfsub()
 * Complex Discrete Fourier Transform
 *-----------------------------------------------------------------*/

static void cftfsub(
    short n,     /* i    : data length of real and imag  */
    float *a,    /* i/o  : input/output data             */
    const float *w     /* i    : cos/sin table                 */
)
{
    short j, j1, j2, j3, l;
    float x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i;

    l = 2;
    if (n > 8)
    {
        cft1st(n, a, w);

        l = 8;
        while ((l << 2) < n)
        {
            cftmdl(n, l, a, w);
            l <<= 2;
        }
    }

    if ((l << 2) == n)
    {
        for (j = 0; j < l; j += 2)
        {
            j1 = j + l;
            j2 = j1 + l;
            j3 = j2 + l;
            x0r = a[j] + a[j1];
            x0i = a[j + 1] + a[j1 + 1];
            x1r = a[j] - a[j1];
            x1i = a[j + 1] - a[j1 + 1];
            x2r = a[j2] + a[j3];
            x2i = a[j2 + 1] + a[j3 + 1];
            x3r = a[j2] - a[j3];
            x3i = a[j2 + 1] - a[j3 + 1];
            a[j] = x0r + x2r;
            a[j + 1] = x0i + x2i;
            a[j2] = x0r - x2r;
            a[j2 + 1] = x0i - x2i;
            a[j1] = x1r - x3i;
            a[j1 + 1] = x1i + x3r;
            a[j3] = x1r + x3i;
            a[j3 + 1] = x1i - x3r;
        }
    }
    else
    {
        for (j = 0; j < l; j += 2)
        {
            j1 = j + l;
            x0r = a[j] - a[j1];
            x0i = a[j + 1] - a[j1 + 1];
            a[j] += a[j1];
            a[j + 1] += a[j1 + 1];
            a[j1] = x0r;
            a[j1 + 1] = x0i;
        }
    }

    return;
}

/*-----------------------------------------------------------------*
 * cft1st()
 * Subfunction of Complex Discrete Fourier Transform
 *-----------------------------------------------------------------*/

static void cft1st(
    short n,     /* i    : data length of real and imag  */
    float *a,    /* i/o  : input/output data             */
    const  float *w     /* i    : cos/sin table                 */
)
{
    short j, k1, k2;
    float wk1r, wk1i, wk2r, wk2i, wk3r, wk3i;
    float x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i;

    x0r = a[0] + a[2];
    x0i = a[1] + a[3];
    x1r = a[0] - a[2];
    x1i = a[1] - a[3];
    x2r = a[4] + a[6];
    x2i = a[5] + a[7];
    x3r = a[4] - a[6];
    x3i = a[5] - a[7];
    a[0] = x0r + x2r;
    a[1] = x0i + x2i;
    a[4] = x0r - x2r;
    a[5] = x0i - x2i;
    a[2] = x1r - x3i;
    a[3] = x1i + x3r;
    a[6] = x1r + x3i;
    a[7] = x1i - x3r;
    wk1r = w[2];
    x0r = a[8] + a[10];
    x0i = a[9] + a[11];
    x1r = a[8] - a[10];
    x1i = a[9] - a[11];
    x2r = a[12] + a[14];
    x2i = a[13] + a[15];
    x3r = a[12] - a[14];
    x3i = a[13] - a[15];
    a[8] = x0r + x2r;
    a[9] = x0i + x2i;
    a[12] = x2i - x0i;
    a[13] = x0r - x2r;
    x0r = x1r - x3i;
    x0i = x1i + x3r;
    a[10] = wk1r * (x0r - x0i);
    a[11] = wk1r * (x0r + x0i);
    x0r = x3i + x1r;
    x0i = x3r - x1i;
    a[14] = wk1r * (x0i - x0r);
    a[15] = wk1r * (x0i + x0r);
    k1 = 0;

    for (j = 16; j < n; j += 16)
    {
        k1 += 2;
        k2 = 2 * k1;
        wk2r = w[k1];
        wk2i = w[k1 + 1];
        wk1r = w[k2];
        wk1i = w[k2 + 1];
        wk3r = wk1r - 2 * wk2i * wk1i;
        wk3i = 2 * wk2i * wk1r - wk1i;
        x0r = a[j] + a[j + 2];
        x0i = a[j + 1] + a[j + 3];
        x1r = a[j] - a[j + 2];
        x1i = a[j + 1] - a[j + 3];
        x2r = a[j + 4] + a[j + 6];
        x2i = a[j + 5] + a[j + 7];
        x3r = a[j + 4] - a[j + 6];
        x3i = a[j + 5] - a[j + 7];
        a[j] = x0r + x2r;
        a[j + 1] = x0i + x2i;
        x0r -= x2r;
        x0i -= x2i;
        a[j + 4] = wk2r * x0r - wk2i * x0i;
        a[j + 5] = wk2r * x0i + wk2i * x0r;
        x0r = x1r - x3i;
        x0i = x1i + x3r;
        a[j + 2] = wk1r * x0r - wk1i * x0i;
        a[j + 3] = wk1r * x0i + wk1i * x0r;
        x0r = x1r + x3i;
        x0i = x1i - x3r;
        a[j + 6] = wk3r * x0r - wk3i * x0i;
        a[j + 7] = wk3r * x0i + wk3i * x0r;
        wk1r = w[k2 + 2];
        wk1i = w[k2 + 3];
        wk3r = wk1r - 2 * wk2r * wk1i;
        wk3i = 2 * wk2r * wk1r - wk1i;
        x0r = a[j + 8] + a[j + 10];
        x0i = a[j + 9] + a[j + 11];
        x1r = a[j + 8] - a[j + 10];
        x1i = a[j + 9] - a[j + 11];
        x2r = a[j + 12] + a[j + 14];
        x2i = a[j + 13] + a[j + 15];
        x3r = a[j + 12] - a[j + 14];
        x3i = a[j + 13] - a[j + 15];
        a[j + 8] = x0r + x2r;
        a[j + 9] = x0i + x2i;
        x0r -= x2r;
        x0i -= x2i;
        a[j + 12] = -wk2i * x0r - wk2r * x0i;
        a[j + 13] = -wk2i * x0i + wk2r * x0r;
        x0r = x1r - x3i;
        x0i = x1i + x3r;
        a[j + 10] = wk1r * x0r - wk1i * x0i;
        a[j + 11] = wk1r * x0i + wk1i * x0r;
        x0r = x1r + x3i;
        x0i = x1i - x3r;
        a[j + 14] = wk3r * x0r - wk3i * x0i;
        a[j + 15] = wk3r * x0i + wk3i * x0r;
    }

    return;
}

/*-----------------------------------------------------------------*
 * cftmdl()
 * Subfunction of Complex Discrete Fourier Transform
 *-----------------------------------------------------------------*/

static void cftmdl(
    short n,     /* i    : data length of real and imag   */
    short l,     /* i    : initial shift for processing */
    float *a,    /* i/o  : input/output data              */
    const  float *w     /* i    : cos/sin table                 */
)
{
    short j, j1, j2, j3, k, k1, k2, m, m2;
    float wk1r, wk1i, wk2r, wk2i, wk3r, wk3i;
    float x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i;

    m = l << 2;
    for (j = 0; j < l; j += 2)
    {
        j1 = j + l;
        j2 = j1 + l;
        j3 = j2 + l;
        x0r = a[j] + a[j1];
        x0i = a[j + 1] + a[j1 + 1];
        x1r = a[j] - a[j1];
        x1i = a[j + 1] - a[j1 + 1];
        x2r = a[j2] + a[j3];
        x2i = a[j2 + 1] + a[j3 + 1];
        x3r = a[j2] - a[j3];
        x3i = a[j2 + 1] - a[j3 + 1];
        a[j] = x0r + x2r;
        a[j + 1] = x0i + x2i;
        a[j2] = x0r - x2r;
        a[j2 + 1] = x0i - x2i;
        a[j1] = x1r - x3i;
        a[j1 + 1] = x1i + x3r;
        a[j3] = x1r + x3i;
        a[j3 + 1] = x1i - x3r;
    }

    wk1r = w[2];
    for (j = m; j < l + m; j += 2)
    {
        j1 = j + l;
        j2 = j1 + l;
        j3 = j2 + l;
        x0r = a[j] + a[j1];
        x0i = a[j + 1] + a[j1 + 1];
        x1r = a[j] - a[j1];
        x1i = a[j + 1] - a[j1 + 1];
        x2r = a[j2] + a[j3];
        x2i = a[j2 + 1] + a[j3 + 1];
        x3r = a[j2] - a[j3];
        x3i = a[j2 + 1] - a[j3 + 1];
        a[j] = x0r + x2r;
        a[j + 1] = x0i + x2i;
        a[j2] = x2i - x0i;
        a[j2 + 1] = x0r - x2r;
        x0r = x1r - x3i;
        x0i = x1i + x3r;
        a[j1] = wk1r * (x0r - x0i);
        a[j1 + 1] = wk1r * (x0r + x0i);
        x0r = x3i + x1r;
        x0i = x3r - x1i;
        a[j3] = wk1r * (x0i - x0r);
        a[j3 + 1] = wk1r * (x0i + x0r);
    }

    k1 = 0;
    m2 = 2 * m;
    for (k = m2; k < n; k += m2)
    {
        k1 += 2;
        k2 = 2 * k1;
        wk2r = w[k1];
        wk2i = w[k1 + 1];
        wk1r = w[k2];
        wk1i = w[k2 + 1];
        wk3r = wk1r - 2 * wk2i * wk1i;
        wk3i = 2 * wk2i * wk1r - wk1i;
        for (j = k; j < l + k; j += 2)
        {
            j1 = j + l;
            j2 = j1 + l;
            j3 = j2 + l;
            x0r = a[j] + a[j1];
            x0i = a[j + 1] + a[j1 + 1];
            x1r = a[j] - a[j1];
            x1i = a[j + 1] - a[j1 + 1];
            x2r = a[j2] + a[j3];
            x2i = a[j2 + 1] + a[j3 + 1];
            x3r = a[j2] - a[j3];
            x3i = a[j2 + 1] - a[j3 + 1];
            a[j] = x0r + x2r;
            a[j + 1] = x0i + x2i;
            x0r -= x2r;
            x0i -= x2i;
            a[j2] = wk2r * x0r - wk2i * x0i;
            a[j2 + 1] = wk2r * x0i + wk2i * x0r;
            x0r = x1r - x3i;
            x0i = x1i + x3r;
            a[j1] = wk1r * x0r - wk1i * x0i;
            a[j1 + 1] = wk1r * x0i + wk1i * x0r;
            x0r = x1r + x3i;
            x0i = x1i - x3r;
            a[j3] = wk3r * x0r - wk3i * x0i;
            a[j3 + 1] = wk3r * x0i + wk3i * x0r;
        }

        wk1r = w[k2 + 2];
        wk1i = w[k2 + 3];
        wk3r = wk1r - 2 * wk2r * wk1i;
        wk3i = 2 * wk2r * wk1r - wk1i;
        for (j = k + m; j < l + (k + m); j += 2)
        {
            j1 = j + l;
            j2 = j1 + l;
            j3 = j2 + l;
            x0r = a[j] + a[j1];
            x0i = a[j + 1] + a[j1 + 1];
            x1r = a[j] - a[j1];
            x1i = a[j + 1] - a[j1 + 1];
            x2r = a[j2] + a[j3];
            x2i = a[j2 + 1] + a[j3 + 1];
            x3r = a[j2] - a[j3];
            x3i = a[j2 + 1] - a[j3 + 1];
            a[j] = x0r + x2r;
            a[j + 1] = x0i + x2i;
            x0r -= x2r;
            x0i -= x2i;
            a[j2] = -wk2i * x0r - wk2r * x0i;
            a[j2 + 1] = -wk2i * x0i + wk2r * x0r;
            x0r = x1r - x3i;
            x0i = x1i + x3r;
            a[j1] = wk1r * x0r - wk1i * x0i;
            a[j1 + 1] = wk1r * x0i + wk1i * x0r;
            x0r = x1r + x3i;
            x0i = x1i - x3r;
            a[j3] = wk3r * x0r - wk3i * x0i;
            a[j3 + 1] = wk3r * x0i + wk3i * x0r;
        }
    }

    return;
}

static
void cftbsub(
    short n,
    float *a,
    const  float *w     /* i    : cos/sin table                 */
)
{
    short j, j1, j2, j3, l;
    float x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i;

    l = 2;
    if (n > 8)
    {
        cft1st(n, a, w);
        l = 8;

        while ((l << 2) < n)
        {
            cftmdl(n, l, a, w);
            l <<= 2;
        }
    }

    if ((l << 2) == n)
    {
        for (j = 0; j < l; j += 2)
        {
            j1 = j + l;
            j2 = j1 + l;
            j3 = j2 + l;
            x0r = a[j] + a[j1];
            x0i = -a[j + 1] - a[j1 + 1];
            x1r = a[j] - a[j1];
            x1i = -a[j + 1] + a[j1 + 1];
            x2r = a[j2] + a[j3];
            x2i = a[j2 + 1] + a[j3 + 1];
            x3r = a[j2] - a[j3];
            x3i = a[j2 + 1] - a[j3 + 1];
            a[j] = x0r + x2r;
            a[j + 1] = x0i - x2i;
            a[j2] = x0r - x2r;
            a[j2 + 1] = x0i + x2i;
            a[j1] = x1r - x3i;
            a[j1 + 1] = x1i - x3r;
            a[j3] = x1r + x3i;
            a[j3 + 1] = x1i + x3r;
        }
    }
    else
    {
        for (j = 0; j < l; j += 2)
        {
            j1 = j + l;
            x0r = a[j] - a[j1];
            x0i = -a[j + 1] + a[j1 + 1];
            a[j] += a[j1];
            a[j + 1] = -a[j + 1] - a[j1 + 1];
            a[j1] = x0r;
            a[j1 + 1] = x0i;
        }
    }
}

static
void rftfsub(
    short n,
    float *a,
    short nc,
    const float *c
)
{
    short j, k, kk, ks, m;
    float wkr, wki, xr, xi, yr, yi;

    m = n >> 1;
    ks = 2 * nc / m;
    kk = 0;
    for (j = 2; j < m; j += 2)
    {
        k = n - j;
        kk += ks;
        wkr = 0.5f - c[nc - kk];
        wki = c[kk];
        xr = a[j] - a[k];
        xi = a[j + 1] + a[k + 1];
        yr = wkr * xr - wki * xi;
        yi = wkr * xi + wki * xr;
        a[j] -= yr;
        a[j + 1] -= yi;
        a[k] += yr;
        a[k + 1] -= yi;
    }
}


static
void rftbsub(
    short n,
    float *a,
    short nc,
    const float *c
)
{
    short j, k, kk, ks, m;
    float wkr, wki, xr, xi, yr, yi;

    a[1] = -a[1];
    m = n >> 1;
    ks = 2 * nc / m;
    kk = 0;
    for (j = 2; j < m; j += 2)
    {
        k = n - j;
        kk += ks;
        wkr = 0.5f - c[nc - kk];
        wki = c[kk];
        xr = a[j] - a[k];
        xi = a[j + 1] + a[k + 1];
        yr = wkr * xr + wki * xi;
        yi = wkr * xi - wki * xr;
        a[j] -= yr;
        a[j + 1] = yi - a[j + 1];
        a[k] += yr;
        a[k + 1] = yi - a[k + 1];
    }
    a[m + 1] = -a[m + 1];
}


static
void dctsub(
    short n,
    float *a,
    short nc,
    const float *c
)
{
    short j, k, kk, ks, m;
    float wkr, wki, xr;

    m = n >> 1;
    ks = nc / n;
    kk = 0;
    for (j = 1; j < m; j++)
    {
        k = n - j;
        kk += ks;
        wkr = c[kk] - c[nc - kk];
        wki = c[kk] + c[nc - kk];
        xr = wki * a[j] - wkr * a[k];
        a[j] = wkr * a[j] + wki * a[k];
        a[k] = xr;
    }
    a[m] *= c[0];
}


/*-----------------------------------------------------------------*
 * edct2()
 *
 * Transformation of the signal to DCT domain
 * OR Inverse EDCT-II for short frames
 *-----------------------------------------------------------------*/

void edct2(
    short n,
    short isgn,
    float *in,
    float *a,
    const short *ip,
    const float *w
)
{
    short j, nw, nc;
    float xr;

    mvr2r(in, a, n);

    nw = ip[0];
    if (n > (nw << 2))
    {
        nw = n >> 2;
    }

    nc = ip[1];
    if (n > nc)
    {
        nc = n;
    }

    if (isgn < 0)
    {
        xr = a[n - 1];
        for (j = n - 2; j >= 2; j -= 2)
        {
            a[j + 1] = a[j] - a[j - 1];
            a[j] += a[j - 1];
        }
        a[1] = a[0] - xr;
        a[0] += xr;

        if (n > 4)
        {
            rftbsub(n, a, nc, w + nw);
            bitrv2_SR(n, ip + 2, a);
            cftbsub(n, a, w);
        }
        else if (n == 4)
        {
            cftfsub(n, a, w);
        }
    }

    if (isgn >= 0)
    {
        a[0] *= 0.5f;
    }

    dctsub(n, a, nc, w + nw);

    if (isgn >= 0)
    {
        if (n > 4)
        {
            bitrv2_SR(n, ip + 2, a);
            cftfsub(n, a, w);
            rftfsub(n, a, nc, w + nw);
        }
        else if (n == 4)
        {
            cftfsub(n, a, w);
        }
        xr = a[0] - a[1];
        a[0] += a[1];
        for (j = 2; j < n; j += 2)
        {
            a[j - 1] = a[j] - a[j + 1];
            a[j] += a[j + 1];
        }
        a[n - 1] = xr;

        for (j = 0; j < n; j ++)
        {
            a[j] /= 32.0f;
        }
    }
}


void DoRTFTn(
    float *x,         /* i/o : real part of input and output data       */
    float *y,         /* i/o : imaginary part of input and output data  */
    const short n     /* i   : size of the FFT up to 1024 */
)
{

    int i;
    float z[2048];

    for ( i=0; i<n; i++ )
    {
        z[2*i]   = x[i];
        z[2*i+1] = y[i];
    }

    switch (n)
    {
    case(16):
        cdftForw(2*n,z,Ip_fft16,w_fft16);
        break;
    case(32):
        cdftForw(2*n,z,Ip_fft32,w_fft32);
        break;
    case(64):
        cdftForw(2*n,z,Ip_fft64,w_fft64);
        break;
    case(128):
        cdftForw(2*n,z,Ip_fft128,w_fft128);
        break;
    case(256):
        cdftForw(2*n,z,Ip_fft256,w_fft256);
        break;
    case(512):
        cdftForw(2*n,z,Ip_fft512,w_fft512);
        break;
    default:
        assert(0);
    }

    x[0]=z[0];
    y[0]=z[1];
    for( i=1; i<n ; i++)
    {
        x[n-i]=z[2*i];
        y[n-i]=z[2*i+1];
    }

    return;
}




void fft3(
    const float X[],
    float Y[],
    const short n
)
{
    float Z[PH_ECU_SPEC_SIZE];
    float *Z0, *Z1, *Z2;
    float *z0, *z1, *z2;
    const float *x;
    const float *t_sin = sincos_t_rad3;
    short m, step, order;
    short i, j;
    short c1_ind, s1_ind, c2_ind, s2_ind;
    short c1_step, s1_step, c2_step, s2_step;
    float *RY, *IY, *RZ0, *IZ0, *RZ1, *IZ1, *RZ2, *IZ2;

    /* Determine the order of the transform, the length of decimated  */
    /* transforms m, and the step for the sine and cosine tables.     */
    switch(n)
    {
    case 1536:
        order = 9;
        m = 512;
        step = 1;
        break;
    case 384:
        order = 7;
        m = 128;
        step = 4;
        break;
    default:
        order = 9;
        m = 512;
        step = 1;
    }

    /* Compose decimated sequences X[3i], X[3i+1],X[3i+2] */
    /* compute their FFT of length m.                                 */
    Z0 = &Z[0];
    z0 = &Z0[0];
    Z1 = &Z0[m];
    z1 = &Z1[0];   /* Z1 = &Z[ m];     */
    Z2 = &Z1[m];
    z2 = &Z2[0];   /* Z2 = &Z[2m];     */
    x  =  &X[0];
    for (i = 0; i < n/3; i++)
    {
        *z0++ = *x++;            /* Z0[i] = X[3i];   */
        *z1++ = *x++;            /* Z1[i] = X[3i+1]; */
        *z2++ = *x++;            /* Z2[i] = X[3i+2]; */
    }

    fft_rel(&Z0[0], m, order);
    fft_rel(&Z1[0], m, order);
    fft_rel(&Z2[0], m, order);

    /* Butterflies of order 3. */
    /* pointer initialization */
    RY = &Y[0];
    IY = &Y[n];
    RZ0 = &Z0[0];
    IZ0 = &Z0[m];
    RZ1 = &Z1[0];
    IZ1 = &Z1[m];
    RZ2 = &Z2[0];
    IZ2 = &Z2[m];

    c1_step = -step;
    s1_step = step;
    c2_step = -2*step;
    s2_step = 2*step;
    c1_ind = T_SIN_PI_2 + c1_step;
    s1_ind = s1_step;
    c2_ind = T_SIN_PI_2 + c2_step;
    s2_ind = s2_step;

    /* special case: i = 0 */
    RY[0] = RZ0[0] + RZ1[0] + RZ2[0] ;

    /* first 3/12 */
    for (i=1; i<3*m/8; i++, c1_ind += c1_step, s1_ind += s1_step, c2_ind += c2_step, s2_ind += s2_step)
    {
        RY[i] = RZ0[i] + RZ1[i] * t_sin[c1_ind] + IZ1[-i] * t_sin[s1_ind] + RZ2[i] * t_sin[c2_ind] + IZ2[-i] * t_sin[s2_ind];
        IY[-i] = IZ0[-i] - RZ1[i] * t_sin[s1_ind] + IZ1[-i] * t_sin[c1_ind] - RZ2[i] * t_sin[s2_ind] + IZ2[-i] * t_sin[c2_ind];
    }

    /* next 1/12 */
    for (; i<4*m/8; i++, c1_ind += c1_step, s1_ind += s1_step, c2_ind -= c2_step, s2_ind -= s2_step)
    {
        RY[i] =  RZ0[i]  + RZ1[i] * t_sin[c1_ind] + IZ1[-i] * t_sin[s1_ind] - RZ2[i] * t_sin[c2_ind] + IZ2[-i] * t_sin[s2_ind];
        IY[-i] = IZ0[-i] - RZ1[i] * t_sin[s1_ind] + IZ1[-i] * t_sin[c1_ind] - RZ2[i] * t_sin[s2_ind] - IZ2[-i] * t_sin[c2_ind];
    }

    /* special case: i = m/2 i.e. 1/3 */
    RY[i]    =  RZ0[i]  + RZ1[i] * t_sin[c1_ind] - RZ2[i] * t_sin[c2_ind];
    IY[-i]   =          - RZ1[i] * t_sin[s1_ind] - RZ2[i] * t_sin[s2_ind];
    i++;

    c1_ind += c1_step, s1_ind += s1_step, c2_ind -= c2_step, s2_ind -= s2_step;

    /* next  2/12 */
    for (j=i-2; i<6*m/8; i++, j--, c1_ind += c1_step, s1_ind += s1_step, c2_ind -= c2_step, s2_ind -= s2_step)
    {
        RY[i] =  RZ0[j]  + RZ1[j] * t_sin[c1_ind] - IZ1[-j] * t_sin[s1_ind] - RZ2[j] * t_sin[c2_ind] - IZ2[-j] * t_sin[s2_ind];
        IY[-i] =-IZ0[-j] - RZ1[j] * t_sin[s1_ind] - IZ1[-j] * t_sin[c1_ind] - RZ2[j] * t_sin[s2_ind] + IZ2[-j] * t_sin[c2_ind];
    }

    /*--------------------------half--------------------------*/
    /* next 2/12 */
    for (; i<8*m/8; i++, j--, c1_ind -= c1_step, s1_ind -= s1_step, c2_ind += c2_step, s2_ind += s2_step)
    {
        RY[i] =  RZ0[j]  - RZ1[j] * t_sin[c1_ind] - IZ1[-j] * t_sin[s1_ind] - RZ2[j] * t_sin[c2_ind] + IZ2[-j] * t_sin[s2_ind];
        IY[-i] =-IZ0[-j] - RZ1[j] * t_sin[s1_ind] + IZ1[-j] * t_sin[c1_ind] + RZ2[j] * t_sin[s2_ind] + IZ2[-j] * t_sin[c2_ind];
    }

    /* special case: i = m, i.e 2/3 */
    RY[i]    =  RZ0[j]  - RZ1[j] * t_sin[c1_ind] - RZ2[j] * t_sin[c2_ind];
    IY[-i++] =          - RZ1[j] * t_sin[s1_ind] + RZ2[j] * t_sin[s2_ind];
    c1_ind -= c1_step, s1_ind -= s1_step, c2_ind += c2_step, s2_ind += s2_step;

    /* next 1/12 */
    for (j=1; i<9*m/8; i++, j++, c1_ind -= c1_step, s1_ind -= s1_step, c2_ind += c2_step, s2_ind += s2_step)
    {
        RY[ i] = RZ0[ j] - RZ1[j] * t_sin[c1_ind] + IZ1[-j] * t_sin[s1_ind] - RZ2[j] * t_sin[c2_ind] - IZ2[-j] * t_sin[s2_ind];
        IY[-i] = IZ0[-j] - RZ1[j] * t_sin[s1_ind] - IZ1[-j] * t_sin[c1_ind] + RZ2[j] * t_sin[s2_ind] - IZ2[-j] * t_sin[c2_ind];
    }

    /* last 3/12 */
    for (; i<12*m/8; i++, j++, c1_ind -= c1_step, s1_ind -= s1_step, c2_ind -= c2_step, s2_ind -= s2_step)
    {
        RY[ i] = RZ0[ j] - RZ1[j] * t_sin[c1_ind] + IZ1[-j] * t_sin[s1_ind] + RZ2[j] * t_sin[c2_ind] - IZ2[-j] * t_sin[s2_ind];
        IY[-i] = IZ0[-j] - RZ1[j] * t_sin[s1_ind] - IZ1[-j] * t_sin[c1_ind] + RZ2[j] * t_sin[s2_ind] + IZ2[-j] * t_sin[c2_ind];
    }

    /* special case: i = 3*m/2 */
    RY[i] = RZ0[j] - RZ1[j] * t_sin[c1_ind] + RZ2[j] * t_sin[c2_ind];

    return;
}

void ifft3(const float Z[], float X[], const short n)
{
    float Y[PH_ECU_SPEC_SIZE];
    const float *t_sin = sincos_t_rad3;
    short m, step, step2, order;
    short i;
    short c0_ind, s0_ind, c1_ind, s1_ind, c2_ind, s2_ind;
    float scale;
    const float *RZ0, *IZ0, *RZ1, *IZ1, *RZ2, *IZ2;
    float *RY0, *IY0, *RY1, *IY1, *RY2, *IY2, *y0, *y1, *y2;

    /* Determine the order of the transform, the length of decimated  */
    /* transforms m, and the step for the sine and cosine tables.     */
    switch(n)
    {
    case 1536:
        order = 9;
        m = 512;
        step = 1;
        break;
    case 384:
        order = 7;
        m = 128;
        step = 4;
        break;
    default:
        order = 9;
        m = 512;
        step = 1;
    }

    /* pointer initialization */
    RY0 = &Y[0];
    IY0 = &RY0[m];
    RY1 = &RY0[m];
    IY1 = &RY1[m];
    RY2 = &RY1[m];
    IY2 = &RY2[m];

    RZ0 = &Z[0];
    RZ1 = RZ0+m;
    RZ2 = RZ0+n/2-m/2;
    IZ0 = &Z[n];
    IZ1 = IZ0-m;
    IZ2 = IZ0-n/2+m/2;

    /* Inverse butterflies of order 3. */

    /* Construction of Y0 */
    RY0[0] = RZ0[0] + RZ1[0] + RZ2[0];
    for (i=1; i<m/2; i++)
    {
        RY0[i] = RZ0[i] + RZ1[i] + RZ2[-i];
        IY0[-i] = IZ0[-i] + IZ1[-i] - IZ2[i];
    }

    /* m/2 */
    RY0[i] = RZ0[i] + RZ1[i] + RZ2[-i];

    /* Construction of Y1 */
    c0_ind=T_SIN_PI_2;
    s0_ind=0;
    c1_ind=T_SIN_PI_2 * 1/3;
    s1_ind=T_SIN_PI_2 * 2/3;
    c2_ind=T_SIN_PI_2 * 1/3;
    s2_ind=T_SIN_PI_2 * 2/3;

    RY1[0] = RZ0[0]  * t_sin[c0_ind] - RZ1[0] * t_sin[c1_ind] - RZ2[0] * t_sin[c2_ind]
             - IZ1[0] * t_sin[s1_ind] - IZ2[0] * t_sin[s2_ind];

    c0_ind-=step, s0_ind+=step, c1_ind+=step, s1_ind-=step, c2_ind-=step, s2_ind+=step;
    for (i=1; i<m/4; i++, c0_ind-=step,s0_ind+=step,c1_ind+=step,s1_ind-=step,c2_ind-=step,s2_ind+=step)
    {
        RY1[i]  = RZ0[i]  * t_sin[c0_ind] - RZ1[i]  * t_sin[c1_ind] - RZ2[-i] * t_sin[c2_ind]
                  - IZ0[-i] * t_sin[s0_ind] - IZ1[-i] * t_sin[s1_ind] - IZ2[i]  * t_sin[s2_ind];
        IY1[-i] = IZ0[-i] * t_sin[c0_ind] - IZ1[-i] * t_sin[c1_ind] + IZ2[i]  * t_sin[c2_ind]
                  + RZ0[i]  * t_sin[s0_ind] + RZ1[i]  * t_sin[s1_ind] - RZ2[-i] * t_sin[s2_ind];
    }

    for (; i<m/2; i++, c0_ind-=step,s0_ind+=step,c1_ind+=step,s1_ind-=step,c2_ind+=step,s2_ind-=step)
    {
        RY1[i]  = RZ0[i]  * t_sin[c0_ind] - RZ1[i]  * t_sin[c1_ind] + RZ2[-i] * t_sin[c2_ind]
                  - IZ0[-i] * t_sin[s0_ind] - IZ1[-i] * t_sin[s1_ind] - IZ2[i]  * t_sin[s2_ind];
        IY1[-i] = IZ0[-i] * t_sin[c0_ind] - IZ1[-i] * t_sin[c1_ind] - IZ2[i]  * t_sin[c2_ind]
                  + RZ0[i]  * t_sin[s0_ind] + RZ1[i]  * t_sin[s1_ind] - RZ2[-i] * t_sin[s2_ind];
    }

    /* m/2 */
    RY1[i] = RZ0[i]  * t_sin[c0_ind] - RZ1[i]  * t_sin[c1_ind] + RZ2[-i] * t_sin[c2_ind]
             - IZ0[-i] * t_sin[s0_ind] - IZ1[-i] * t_sin[s1_ind] - IZ2[i]  * t_sin[s2_ind];

    /* Construction of Y2 */
    c0_ind=T_SIN_PI_2;
    s0_ind=0;
    c1_ind=T_SIN_PI_2 * 1/3;
    s1_ind=T_SIN_PI_2 * 2/3;
    c2_ind=T_SIN_PI_2 * 1/3;
    s2_ind=T_SIN_PI_2 * 2/3;
    step2 = 2*step;
    RY2[0] = RZ0[0]  * t_sin[c0_ind] - RZ1[0] * t_sin[c1_ind] - RZ2[0] * t_sin[c2_ind]
             + IZ1[0] * t_sin[s1_ind] + IZ2[0] * t_sin[s2_ind];

    c0_ind-=step2,s0_ind+=step2,c1_ind-=step2,s1_ind+=step2,c2_ind+=step2,s2_ind-=step2;
    for (i=1; i<m/8; i++, c0_ind-=step2,s0_ind+=step2,c1_ind-=step2,s1_ind+=step2,c2_ind+=step2,s2_ind-=step2)
    {
        RY2[i]  = RZ0[i]  * t_sin[c0_ind] - RZ1[i]  * t_sin[c1_ind] - RZ2[-i] * t_sin[c2_ind]
                  - IZ0[-i] * t_sin[s0_ind] + IZ1[-i] * t_sin[s1_ind] + IZ2[i]  * t_sin[s2_ind];
        IY2[-i] = IZ0[-i] * t_sin[c0_ind] - IZ1[-i] * t_sin[c1_ind] + IZ2[i]  * t_sin[c2_ind]
                  + RZ0[i]  * t_sin[s0_ind] - RZ1[i]  * t_sin[s1_ind] + RZ2[-i] * t_sin[s2_ind];
    }

    for (; i<m/4; i++, c0_ind-=step2,s0_ind+=step2,c1_ind+=step2,s1_ind-=step2,c2_ind+=step2,s2_ind-=step2)
    {
        RY2[i]  = RZ0[i]  * t_sin[c0_ind] + RZ1[i]  * t_sin[c1_ind] - RZ2[-i] * t_sin[c2_ind]
                  - IZ0[-i] * t_sin[s0_ind] + IZ1[-i] * t_sin[s1_ind] + IZ2[i]  * t_sin[s2_ind];
        IY2[-i] = IZ0[-i] * t_sin[c0_ind] + IZ1[-i] * t_sin[c1_ind] + IZ2[i]  * t_sin[c2_ind]
                  + RZ0[i]  * t_sin[s0_ind] - RZ1[i]  * t_sin[s1_ind] + RZ2[-i] * t_sin[s2_ind];
    }

    for (; i<3*m/8; i++, c0_ind-=step2,s0_ind+=step2,c1_ind+=step2,s1_ind-=step2,c2_ind-=step2,s2_ind+=step2)
    {
        RY2[i]  = RZ0[i]  * t_sin[c0_ind] + RZ1[i]  * t_sin[c1_ind] - RZ2[-i] * t_sin[c2_ind]
                  - IZ0[-i] * t_sin[s0_ind] + IZ1[-i] * t_sin[s1_ind] - IZ2[i]  * t_sin[s2_ind];
        IY2[-i] = IZ0[-i] * t_sin[c0_ind] + IZ1[-i] * t_sin[c1_ind] + IZ2[i]  * t_sin[c2_ind]
                  + RZ0[i]  * t_sin[s0_ind] - RZ1[i]  * t_sin[s1_ind] - RZ2[-i] * t_sin[s2_ind];
    }

    for (; i<m/2; i++, c0_ind+=step2,s0_ind-=step2,c1_ind+=step2,s1_ind-=step2,c2_ind-=step2,s2_ind+=step2)
    {
        RY2[i]  = - RZ0[i]  * t_sin[c0_ind] + RZ1[i]  * t_sin[c1_ind] - RZ2[-i] * t_sin[c2_ind]
                  - IZ0[-i] * t_sin[s0_ind] + IZ1[-i] * t_sin[s1_ind] - IZ2[i]  * t_sin[s2_ind];
        IY2[-i] = - IZ0[-i] * t_sin[c0_ind] + IZ1[-i] * t_sin[c1_ind] + IZ2[i]  * t_sin[c2_ind]
                  + RZ0[i]  * t_sin[s0_ind] - RZ1[i]  * t_sin[s1_ind] - RZ2[-i] * t_sin[s2_ind];
    }

    /* m/2 */
    RY2[i]  = - RZ0[i]  * t_sin[c0_ind] + RZ1[i]  * t_sin[c1_ind] - RZ2[-i] * t_sin[c2_ind]
              - IZ0[-i] * t_sin[s0_ind] + IZ1[-i] * t_sin[s1_ind] - IZ2[i]  * t_sin[s2_ind];

    /* Compute the inverse FFT for all 3 blocks. */
    ifft_rel(RY0, m, order);
    ifft_rel(RY1, m, order);
    ifft_rel(RY2, m, order);

    y0 = RY0;
    y1 = RY1;
    y2 = RY2;

    /* Interlacing and scaling, scale = 1/3 */
    scale =1.0f/3;
    for (i = 0; i < n;)
    {
        X[i++] = (*y0++)*scale;
        X[i++] = (*y1++)*scale;
        X[i++] = (*y2++)*scale;
    }

    return;
}


static void rfft_post(const float* sine_table, float* buf, int len)
{
    float tmp1, tmp2, tmp3, tmp4, s, c;
    int i = 0;

    tmp1 = buf[0] + buf[1];
    buf[1] = buf[0] - buf[1];
    buf[0] = tmp1;

    for (i = 1; i <= (len + 2) / 4; i++)
    {
        s = sine_table[i];           /* sin(pi*i/(len/2)) */
        c = sine_table[i + len / 4]; /* cos(pi*i/(len/2)) */

        tmp1 = buf[2 * i] - buf[len - 2 * i];
        tmp2 = buf[2 * i + 1] + buf[len - 2 * i + 1];
        tmp3 = s * tmp1 - c * tmp2; /* real part of j*W(k,N)*[T(k) - T'(N-k)] */
        tmp4 = c * tmp1 + s * tmp2; /* imag part of j*W(k,N)*[T(k) - T'(N-k)] */
        tmp1 = buf[2 * i] + buf[len - 2 * i];
        tmp2 = buf[2 * i + 1] - buf[len - 2 * i + 1];

        buf[2 * i] = 0.5f * (tmp1 - tmp3);
        buf[2 * i + 1] = 0.5f * (tmp2 - tmp4);
        buf[len - 2 * i] = 0.5f * (tmp1 + tmp3);
        buf[len - 2 * i + 1] = -0.5f * (tmp2 + tmp4);
    }
}

static void rfft_pre(const float* sine_table, float* buf, int len)
{
    const float scale = 1.0f / len;
    float tmp1, tmp2, tmp3, tmp4, s, c;
    int i = 0;

    tmp1 = buf[0] + buf[1];
    buf[1] = scale * (buf[0] - buf[1]);
    buf[0] = scale * tmp1;

    for (i = 1; i <= (len + 2) / 4; i++)
    {
        s = sine_table[i];           /* sin(pi*i/(len/2)) */
        c = sine_table[i + len / 4]; /* cos(pi*i/(len/2)) */

        tmp1 = buf[2 * i] - buf[len - 2 * i];
        tmp2 = buf[2 * i + 1] + buf[len - 2 * i + 1];
        tmp3 = s * tmp1 + c * tmp2;  /* real part of j*W(k,N)*[T(k) - T'(N-k)] */
        tmp4 = -c * tmp1 + s * tmp2; /* imag part of j*W(k,N)*[T(k) - T'(N-k)] */
        tmp1 = buf[2 * i] + buf[len - 2 * i];
        tmp2 = buf[2 * i + 1] - buf[len - 2 * i + 1];

        buf[2 * i] = scale * (tmp1 + tmp3);
        buf[2 * i + 1] = -scale * (tmp2 + tmp4);
        buf[len - 2 * i] = scale * (tmp1 - tmp3);
        buf[len - 2 * i + 1] = scale * (tmp2 - tmp4);
    }
}

int RFFTN(float* data, const float* sine_table, int len, int sign)
{
    assert(len <= 640 && len > 0);

    if (len == 640)
    {
        float x[320], y[320];
        int i;

        if (sign != -1)
        {
            rfft_pre(sine_table, data, len);
        }

        for (i = 0; i < 320; i++)
        {
            x[i] = data[2*i];
            y[i] = data[2*i+1];
        }
        DoRTFT320(x, y);
        for (i = 0; i < 320; i++)
        {
            data[2*i] = x[i];
            data[2*i+1] = y[i];
        }

        if (sign == -1)
        {
            rfft_post(sine_table, data, len);
        }
    }
    else
    {
        if (len == 512)
        {
            int i;
            int const log2 = 9;
            float reordered_data[512];

            if (sign == -1)
            {
                fft_rel(data, len, log2);
                reordered_data[0] = data[0];
                reordered_data[1] = data[len/2];
                for (i = 1; i < len/2; i++)
                {
                    reordered_data[2*i] = data[i];
                    reordered_data[2*i+1] = data[len-i];
                }
            }
            else
            {
                reordered_data[0] = data[0];
                reordered_data[len/2] = data[1];
                for (i = 1; i < len/2; i++)
                {
                    reordered_data[i] = data[2*i];
                    reordered_data[len-i] = data[2*i+1];
                }
                ifft_rel(reordered_data, len, log2);
            }
            mvr2r(reordered_data, data, len);
        }
        else
        {
            assert(!"Not supported FFT length!");
        }
    }

    return 0;
}

static void butterfly(const float a, const float b, float *aPlusb, float *aMinusb)
{
    *aPlusb  = a + b;
    *aMinusb = a - b;
}

static void fft2(float *pInOut)
{
    /*  FFT MATRIX:
        1.0000             1.0000
        1.0000            -1.0000
    */
    float re1, im1;
    float re2, im2;

    re1 = pInOut[0];
    im1 = pInOut[1];
    re2 = pInOut[2];
    im2 = pInOut[3];
    pInOut[0] = re1 + re2;
    pInOut[1] = im1 + im2;

    pInOut[2] = re1 - re2;
    pInOut[3] = im1 - im2;

}

static const float C31 = 0.5f;                /* cos(PI/3); sin(2*PI/3) */
static const float C32 = 0.866025403784439f;  /* cos(PI/3); sin(2*PI/3) */

static void fft3_2(float *pInOut)
{
    float re1, im1;
    float re2, im2;
    float re3, im3;

    float tmp1, tmp2;
    float tmp3, tmp4;

    re1 = pInOut[0];
    im1 = pInOut[1];
    re2 = pInOut[2];
    im2 = pInOut[3];
    re3 = pInOut[4];
    im3 = pInOut[5];

    /*  FFT MATRIX:
       1.0000             1.0000             1.0000
                            C31      C32
       1.0000            -0.5000 - 0.8660i  -0.5000 + 0.8660i
       1.0000            -0.5000 + 0.8660i  -0.5000 - 0.8660i
    */
    tmp1 = re2 + re3;
    tmp3 = im2 + im3;
    tmp2 = re2 - re3;
    tmp4 = im2 - im3;
    pInOut[0] = re1 + tmp1;
    pInOut[1] = im1 + tmp3;
    pInOut[2] = re1 - C31 * tmp1 + C32 * tmp4;
    pInOut[4] = re1 - C31 * tmp1 - C32 * tmp4;

    pInOut[3] = im1 - C32 * tmp2 - C31 * tmp3;
    pInOut[5] = im1 + C32 * tmp2 - C31 * tmp3;

}


static void fft4(float *pInOut)
{
    float re1, im1;
    float re2, im2;
    float re3, im3;
    float re4, im4;

    float tmp1, tmp2;
    float tmp3, tmp4;
    float tmp5, tmp6;
    float tmp7, tmp8;

    re1 = pInOut[0];
    im1 = pInOut[1];
    re2 = pInOut[2];
    im2 = pInOut[3];
    re3 = pInOut[4];
    im3 = pInOut[5];
    re4 = pInOut[6];
    im4 = pInOut[7];

    /*
     1.0000    1.0000      1.0000    1.0000
     1.0000   -1.0000i    -1.0000    1.0000i
     1.0000   -1.0000      1.0000   -1.0000
     1.0000    1.0000i    -1.0000   -1.0000i
    */
    tmp1 = re1 + re3;
    tmp3 = re2 + re4;
    tmp5 = im1 + im3;
    tmp7 = im2 + im4;
    pInOut[0] =  tmp1 + tmp3;
    pInOut[4] =  tmp1 - tmp3;

    pInOut[1] =  tmp5 + tmp7;
    pInOut[5] =  tmp5 - tmp7;
    tmp2 = re1 - re3;
    tmp4 = re2 - re4;
    tmp6 = im1 - im3;
    tmp8 = im2 - im4;
    pInOut[2] =  tmp2 + tmp8;
    pInOut[6] =  tmp2 - tmp8;

    pInOut[3] = -tmp4 + tmp6;
    pInOut[7] =  tmp4 + tmp6;

}

static const float C51 = 0.309016994374947f;    /* cos(2*PI/5);   */
static const float C52 = 0.951056516295154f;    /* sin(2*PI/5);   */
static const float C53 = 0.809016994374947f;    /* cos(  PI/5);   */
static const float C54 = 0.587785252292473f;    /* sin(  PI/5);   */

static void fft5(float *pInOut)
{
    float re1, im1;
    float re2, im2;
    float re3, im3;
    float re4, im4;
    float re5, im5;

    float tmp1, tmp2;
    float tmp3, tmp4;
    float tmp5, tmp6;
    float tmp7, tmp8;


    re1 = pInOut[0];
    im1 = pInOut[1];
    re2 = pInOut[2];
    im2 = pInOut[3];
    re3 = pInOut[4];
    im3 = pInOut[5];
    re4 = pInOut[6];
    im4 = pInOut[7];
    re5 = pInOut[8];
    im5 = pInOut[9];

    /*
     1.0000             1.0000             1.0000             1.0000             1.0000
                          C51      C52      C53       C54
     1.0000             0.3090 - 0.9511i  -0.8090 - 0.5878i  -0.8090 + 0.5878i   0.3090 + 0.9511i
     1.0000            -0.8090 - 0.5878i   0.3090 + 0.9511i   0.3090 - 0.9511i  -0.8090 + 0.5878i
     1.0000            -0.8090 + 0.5878i   0.3090 - 0.9511i   0.3090 + 0.9511i  -0.8090 - 0.5878i
     1.0000             0.3090 + 0.9511i  -0.8090 + 0.5878i  -0.8090 - 0.5878i   0.3090 - 0.9511i
    */
    tmp1 = re2 + re5;
    tmp2 = re2 - re5;
    tmp3 = im2 + im5;
    tmp4 = im2 - im5;
    tmp5 = re3 + re4;
    tmp6 = re3 - re4;
    tmp7 = im3 + im4;
    tmp8 = im3 - im4;


    pInOut[0] = re1 + tmp1 + tmp5;
    pInOut[1] = im1 + tmp3 + tmp7;

    pInOut[2] = re1 + C51 * tmp1 - C53 * tmp5 + C52 * tmp4 + C54 * tmp8;
    pInOut[8] = re1 + C51 * tmp1 - C53 * tmp5 - C52 * tmp4 - C54 * tmp8;
    pInOut[3] = im1 - C52 * tmp2 - C54 * tmp6 + C51 * tmp3 - C53 * tmp7;
    pInOut[9] = im1 + C52 * tmp2 + C54 * tmp6 + C51 * tmp3 - C53 * tmp7;
    pInOut[4] = re1 - C53 * tmp1 + C51 * tmp5 + C54 * tmp4 - C52 * tmp8;
    pInOut[6] = re1 - C53 * tmp1 + C51 * tmp5 - C54 * tmp4 + C52 * tmp8;
    pInOut[5] = im1 - C54 * tmp2 + C52 * tmp6 - C53 * tmp3 + C51 * tmp7;
    pInOut[7] = im1 + C54 * tmp2 - C52 * tmp6 - C53 * tmp3 + C51 * tmp7;


}

static const float C81  = 0.707106781186548f;    /* cos(PI/4);   */

static void fft8_2(float *pInOut)
{
    float re0, im0, re4, im4;

    float re1_7p, re1_7m;
    float im1_7p, im1_7m;
    float re2_6p, re2_6m;
    float im2_6p, im2_6m;
    float re3_5p, re3_5m;
    float im3_5p, im3_5m;

    re0 = pInOut[0];
    im0 = pInOut[1];
    re4 = pInOut[8];
    im4 = pInOut[9];
    butterfly(pInOut[1*2  ], pInOut[7*2  ],&re1_7p, &re1_7m);
    butterfly(pInOut[1*2+1], pInOut[7*2+1],&im1_7p, &im1_7m);
    butterfly(pInOut[2*2  ], pInOut[6*2  ],&re2_6p, &re2_6m);
    butterfly(pInOut[2*2+1], pInOut[6*2+1],&im2_6p, &im2_6m);
    butterfly(pInOut[3*2  ], pInOut[5*2  ],&re3_5p, &re3_5m);
    butterfly(pInOut[3*2+1], pInOut[5*2+1],&im3_5p, &im3_5m);

    /*
    0:  1 + 0i	   1   + 0i    1 + 0i 	   1 +   0i    1 + 0i      1 +   0i	    1 + 0i      1 +   0i
    1:  1 + 0i	 C81 - C81i	   0 - 1i	  -C81 - C81i   -1 - 0i   -C81 + C81i   - 0 + 1i    C81 + C81i
    2:  1 + 0i	   0 -   1i	  -1 - 0i	  -  0 +   1i    1 + 0i      0 -   1i   - 1 - 0i   -  0 +   1i
    3:  1 + 0i	-C81 - C81i	  -0 + 1i	   C81 - C81i   -1 - 0i    C81 + C81i     0 - 1i   -C81 + C81i
    4:  1 + 0i	-  1 -   0i	   1 + 0i	  -  1 -   0i    1 + 0i   -  1 -   0i     1 + 0i	 -  1 -   0i
    5:  1 + 0i	-C81 + C81i	   0 - 1i	   C81 + C81i   -1 - 0i    C81 - C81i   - 0 + 1i	 -C81 - C81i
    6:  1 + 0i	-  0 +   1i	  -1 - 0i	     0 -   1i    1 + 0i   -  0 +   1i   - 1 - 0i	 - 0 -    1i
    7:  1 + 0i	 C81 + C81i	  -0 + 1i	  -C81 + C81i   -1 - 0i   -C81 - C81i   - 0 - 1i  	C81 - C81i
    */
    pInOut[ 0] = re0 + re4 + re1_7p + re2_6p + re3_5p;
    pInOut[ 1] = im0 + im4 + im1_7p + im2_6p + im3_5p;

    pInOut[ 2] = re0 + C81*(re1_7p - re3_5p) - re4 + C81*( im1_7m + im3_5m) + im2_6m;
    pInOut[ 3] = im0 + C81*(im1_7p - im3_5p) - im4 - C81* (re1_7m + re3_5m) - re2_6m;

    pInOut[ 4] = re0 - re2_6p + re4 + im1_7m - im3_5m;
    pInOut[ 5] = im0 - im2_6p + im4 - re1_7m + re3_5m;

    pInOut[ 6] = re0 + C81*(-re1_7p + re3_5p) - re4 + C81*( im1_7m + im3_5m) - im2_6m;
    pInOut[ 7] = im0 + C81*(-im1_7p + im3_5p) - im4 - C81* (re1_7m + re3_5m) + re2_6m;

    pInOut[ 8] = re0 - re1_7p + re2_6p - re3_5p + re4;
    pInOut[ 9] = im0 - im1_7p + im2_6p - im3_5p + im4;

    pInOut[10] = re0 + C81*(-re1_7p + re3_5p) - re4 - C81*( im1_7m + im3_5m) + im2_6m;
    pInOut[11] = im0 + C81*(-im1_7p + im3_5p) - im4 + C81* (re1_7m + re3_5m) - re2_6m;

    pInOut[12] = re0 - re2_6p + re4 - im1_7m + im3_5m;
    pInOut[13] = im0 - im2_6p + im4 + re1_7m - re3_5m;

    pInOut[14] = re0 + C81*(re1_7p - re3_5p) - re4 - C81*( im1_7m + im3_5m) - im2_6m;
    pInOut[15] = im0 + C81*(im1_7p - im3_5p) - im4 + C81* (re1_7m + re3_5m) + re2_6m;

}

static void nextFFT(float *x, int length)
{
    switch(length)
    {
    case 2:
        fft2(x);
        break;
    case 3:
        fft3_2(x);
        break;
    case 4:
        fft4(x);
        break;
    case 5:
        fft5(x);
        break;
    case 8:
        fft8_2(x);
        break;
    default:
        assert(!"length not supported");
        break;
    }
}

static const int CTFFTfactors[] = {9,8,7,5,4,3,2,0};

static __inline int findFactor(const int length)
{
    int i = 0;
    int factor = 0;

    while(CTFFTfactors[i]!=0)
    {
        if(0==(length%CTFFTfactors[i]))
        {
            factor = CTFFTfactors[i];
            break;
        }
        i++;
    }
    return factor;
}

static __inline void twiddle(float *x, const int length, const int n1, const int n2)
{
    int i, ii;
    double pi = 4. * atan(1.);
    float sinValOrg, cosValOrg;
    float sinVal=0.f, cosVal=1.f;
    float twReal=0.f, twImag=1.f;

    cosValOrg = (float) cos(-2*pi*1./(double)length);
    sinValOrg = (float) sin(-2*pi*1./(double)length);
    for(i=1; i<n1; i++)
    {
        float tmp;
        twReal = 1.f;
        twImag = 0.f;
        tmp    = cosVal*cosValOrg - sinVal*sinValOrg;
        sinVal = sinVal*cosValOrg + cosVal*sinValOrg;
        cosVal = tmp;
        for(ii=1; ii<n2; ii++)
        {
            float xRe, xIm, tmpReal;
            /* cos(x+y) = cos(x)*cos(y) - sin(x)*sin(y); */
            /* sin(x+y) = sin(x)*cos(y) + sin(y)*cos(x); */
            tmpReal = twReal*cosVal - twImag*sinVal;
            twImag  = twImag*cosVal + sinVal*twReal;
            twReal  = tmpReal;
            xRe = x[2*(i*n2+ii)  ];
            xIm = x[2*(i*n2+ii)+1];
            x[2*(i*n2+ii)  ] = twReal*xRe - twImag*xIm;
            x[2*(i*n2+ii)+1] = twImag*xRe + twReal*xIm;
        }
        tmp = cosVal;
    }

}

static void cooleyTukeyFFT(float *x, const int length, float *scratch)
{
    int factor;
    int i, ii;
    int n1, n2;
    int cnt = 0;
    float *src, *dest;

    switch(length)
    {
    case 1:
        break;
    case 2:
        fft2(x);
        break;
    case 3:
        fft3_2(x);
        break;
    case 4:
        fft4(x);
        break;
    case 5:
        fft5(x);
        break;
    case 8:
        fft8_2(x);
        break;
    default:
    {
        factor = findFactor(length);
        if(factor>0&&(length/factor>1))
        {
            n1 = factor;
            n2 = length/factor;

            /* DATA Resorting for stage1 */
            dest = scratch;
            for (i=0; i<2*n1; i+=2)
            {
                src  = x+i;
                for(ii=0; ii<n2; ii++)
                {
                    /* *dest++ = x[2*(i+ii*n1)]; */
                    /* *dest++ = x[2*(i+ii*n1)+1]; */
                    *dest++ = *src;
                    *dest++ = *(src+1);
                    src += 2*n1;

                }
            }
            src  = scratch;
            dest = x;
            for (i=0; i<length; i++)
            {
                *dest++ = *src++;
                *dest++ = *src++;
            }
            /* perform n1 ffts of length n2 */
            for (i=0; i<n1; i++)
            {
                cooleyTukeyFFT(x+2*i*n2, n2, scratch+2*i*n2);
            }
            /*data twiddeling */
            twiddle(x, length, n1, n2);
            /* DATA Resorting for stage2 */
            cnt = 0;
            for (i=0; i<n2; i++)
            {
                for(ii=0; ii<n1; ii++)
                {
                    scratch[2*cnt  ] = x[2*(i+ii*n2)  ];
                    scratch[2*cnt+1] = x[2*(i+ii*n2)+1];
                    cnt++;
                }
            }
            /* perform n2 ffts of length n1 */
            for (i=0; i<n2; i++)
            {
                nextFFT(scratch+2*i*n1, n1);
            }
            cnt = 0;
            for (i=0; i<n1; i++)
            {
                for(ii=0; ii<n2; ii++)
                {
                    x[2*cnt  ] = scratch[2*(i+ii*n1)  ];
                    x[2*cnt+1] = scratch[2*(i+ii*n1)+1];
                    cnt++;
                }
            }
        }
        else
        {
            assert(!"length not supported");
        }
    }
    }

}

static void pfaDFT(float *x, const int length, float *scratch1, const int numFactors, const int *const factor)
{

    int i, ii;
    int cnt;

    if(numFactors>1)
    {
        float *tmp = scratch1;
        int n1_inv=1, n2_inv=1;
        int n2 = factor[0/*idx*/];
        int n1 = length/n2;
        int idx, incr;

        while(((n1_inv*n1)%n2)!=1)
        {
            n1_inv++;
        }
        while(((n2_inv*n2)%n1)!=1)
        {
            n2_inv++;
        }
        idx  = 0;
        incr = n1*n1_inv;
        cnt = 0;
        for(i=0; i<n1; i++)
        {
            for(ii=0; ii<n2-1; ii++)
            {
                tmp[cnt++] = x[2*idx  ];
                tmp[cnt++] = x[2*idx+1];

                idx += incr;
                if (idx>length)
                {
                    idx -= length;
                }
            }
            tmp[cnt++] = x[2*idx  ];
            tmp[cnt++] = x[2*idx+1];
            idx++;
        }
        for(cnt=0; cnt<length; cnt+=n2)
        {
            cooleyTukeyFFT(tmp+2*cnt, n2, x+2*cnt);
        }
        for(cnt=0; cnt<n1; cnt++)
        {
            for(i=0; i<n2; i++)
            {
                x[2*(cnt+i*n1)  ] = tmp[2*(cnt*n2+i)  ];
                x[2*(cnt+i*n1)+1] = tmp[2*(cnt*n2+i)+1];
            }
        }
        for(cnt=0; cnt<length; cnt+=n1)
        {
            pfaDFT(x+2*cnt, n1, tmp, numFactors-1, &factor[1]);
        }
        idx = 0;
        cnt = 0;
        for(i=0; i<n2; i++)
        {
            idx = i*n1;
            for(ii=0; ii<n1; ii++)
            {
                tmp[2*idx  ] = x[cnt++];
                tmp[2*idx+1] = x[cnt++];
                idx += n2;
                if (idx>length)
                {
                    idx -= length;
                }
            }
        }
        for(cnt=0; cnt<length; cnt++)
        {
            x[2*cnt  ] = tmp[2*cnt  ];
            x[2*cnt+1] = tmp[2*cnt+1];
        }
    }
    else
    {
        cooleyTukeyFFT(x, length, scratch1);
    }

}

static void fftf_interleave(float* re, float* im, float* out, int len)
{
    int i = 0;
    for (i = 0; i < len; i++)
    {
        *out++ = *re++;
        *out++ = *im++;
    }

}

static void fftf_deinterleave(float* in, float* re, float* im, int len)
{
    int i = 0;
    for (i = 0; i < len; i++)
    {
        *re++ = *in++;
        *im++ = *in++;
    }

}

static void DoRTFT600(
    float *x,                         /* i/o : real part of input and output data       */
    float *y                          /* i/o : imaginary part of input and output data  */
)
{
    float scratch[1200], cmplx[1200];
    int factors[3] = { 25, 8, 3};
    fftf_interleave(x, y, cmplx, 600);
    pfaDFT(cmplx, 600, scratch, 3, factors);
    fftf_deinterleave(cmplx, x, y, 600);
}

static void DoRTFT400(
    float *x,                         /* i/o : real part of input and output data       */
    float *y                          /* i/o : imaginary part of input and output data  */
)
{
    float scratch[800], cmplx[800];
    int factors[2] = { 25, 16};
    fftf_interleave(x, y, cmplx, 400);
    pfaDFT(cmplx, 400, scratch, 2, factors);
    fftf_deinterleave(cmplx, x, y, 400);
}

static void DoRTFT240(
    float *x,                         /* i/o : real part of input and output data       */
    float *y                          /* i/o : imaginary part of input and output data  */
)
{
    float scratch[480], cmplx[480];
    int factors[3] = { 16, 5, 3};
    fftf_interleave(x, y, cmplx, 240);
    pfaDFT(cmplx, 240, scratch, 3, factors);
    fftf_deinterleave(cmplx, x, y, 240);
}

static void DoRTFT200(
    float *x,                         /* i/o : real part of input and output data       */
    float *y                          /* i/o : imaginary part of input and output data  */
)
{
    float scratch[400], cmplx[400];
    int factors[2] = { 25, 8};
    fftf_interleave(x, y, cmplx, 200);
    pfaDFT(cmplx, 200, scratch, 2, factors);
    fftf_deinterleave(cmplx, x, y, 200);
}

static void DoRTFT100(
    float *x,                         /* i/o : real part of input and output data       */
    float *y                          /* i/o : imaginary part of input and output data  */
)
{
    float scratch[200], cmplx[200];
    int factors[2] = { 25, 4};
    fftf_interleave(x, y, cmplx, 100);
    pfaDFT(cmplx, 100, scratch, 2, factors);
    fftf_deinterleave(cmplx, x, y, 100);
}


void DoFFT(float * re2, float * im2, short length)
{
    switch (length)
    {
    case 600:
        DoRTFT600(re2, im2);
        break;
    case 480:
        DoRTFT480(re2, im2);
        break;
    case 400:
        DoRTFT400(re2, im2);
        break;
    case 320:
        DoRTFT320(re2, im2);
        break;
    case 256:
        DoRTFTn(re2, im2, 256);
        break;
    case 240:
        DoRTFT240(re2, im2);
        break;
    case 200:
        DoRTFT200(re2, im2);
        break;
    case 160:
        DoRTFT160(re2, im2);
        break;
    case 128:
        DoRTFT128(re2, im2);
        break;
    case 120:
        DoRTFT120(re2, im2);
        break;
    case 100:
        DoRTFT100(re2, im2);
        break;
    case 80:
        DoRTFT80(re2, im2);
        break;
    case 64:
        DoRTFTn(re2, im2, 64);
        break;
    case 40:
        DoRTFT40(re2, im2);
        break;
    case 20:
        DoRTFT20(re2, im2);
        break;
    default:
        assert(!"fft is not supported!");
    }
}


#define SCALEFACTOR8        ( 4)
#define SCALEFACTOR64       ( 7)
#define SCALEFACTORN2       ( 3)

#define SHC(x)              ((Word16)x)
#define FFTC(x)             WORD322WORD16((Word32)x)

#define C81_FX              (FFTC(0x5a82799a))      /* FL2WORD32( 7.071067811865475e-1) */
#define C82_FX              (FFTC(0xa57d8666))      /* FL2WORD32(-7.071067811865475e-1) */

#define cplxMpy4_8_0(re,im,a,b,c,d)   re = L_shr(L_sub(Mpy_32_16(a,c),Mpy_32_16(b,d)),1); \
                                      im = L_shr(L_add(Mpy_32_16(a,d),Mpy_32_16(b,c)),1);

#define cplxMpy4_8_1(re,im,a,b)       re = L_shr(a,1); \
                                      im = L_shr(b,1);


/**
 * \brief    Twiddle factors are unscaled
 */
static const Word16 RotVector_256[2*(256-32)] =
{
    SHC(0x7fff), SHC(0x0000), SHC(0x7ff6), SHC(0xfcdc), SHC(0x7fd9), SHC(0xf9b8), SHC(0x7fa7), SHC(0xf695),
    SHC(0x7f62), SHC(0xf374), SHC(0x7f0a), SHC(0xf055), SHC(0x7e9d), SHC(0xed38), SHC(0x7e1e), SHC(0xea1e),
    SHC(0x7d8a), SHC(0xe707), SHC(0x7ce4), SHC(0xe3f4), SHC(0x7c2a), SHC(0xe0e6), SHC(0x7b5d), SHC(0xdddc),
    SHC(0x7a7d), SHC(0xdad8), SHC(0x798a), SHC(0xd7d9), SHC(0x7885), SHC(0xd4e1), SHC(0x776c), SHC(0xd1ef),
    SHC(0x7642), SHC(0xcf04), SHC(0x7505), SHC(0xcc21), SHC(0x73b6), SHC(0xc946), SHC(0x7255), SHC(0xc673),
    SHC(0x70e3), SHC(0xc3a9), SHC(0x6f5f), SHC(0xc0e9), SHC(0x6dca), SHC(0xbe32), SHC(0x6c24), SHC(0xbb85),
    SHC(0x6a6e), SHC(0xb8e3), SHC(0x68a7), SHC(0xb64c), SHC(0x66d0), SHC(0xb3c0), SHC(0x64e9), SHC(0xb140),
    SHC(0x62f2), SHC(0xaecc), SHC(0x60ec), SHC(0xac65), SHC(0x5ed7), SHC(0xaa0a), SHC(0x5cb4), SHC(0xa7bd),
    SHC(0x7fff), SHC(0x0000), SHC(0x7fd9), SHC(0xf9b8), SHC(0x7f62), SHC(0xf374), SHC(0x7e9d), SHC(0xed38),
    SHC(0x7d8a), SHC(0xe707), SHC(0x7c2a), SHC(0xe0e6), SHC(0x7a7d), SHC(0xdad8), SHC(0x7885), SHC(0xd4e1),
    SHC(0x7642), SHC(0xcf04), SHC(0x73b6), SHC(0xc946), SHC(0x70e3), SHC(0xc3a9), SHC(0x6dca), SHC(0xbe32),
    SHC(0x6a6e), SHC(0xb8e3), SHC(0x66d0), SHC(0xb3c0), SHC(0x62f2), SHC(0xaecc), SHC(0x5ed7), SHC(0xaa0a),
    SHC(0x5a82), SHC(0xa57e), SHC(0x55f6), SHC(0xa129), SHC(0x5134), SHC(0x9d0e), SHC(0x4c40), SHC(0x9930),
    SHC(0x471d), SHC(0x9592), SHC(0x41ce), SHC(0x9236), SHC(0x3c57), SHC(0x8f1d), SHC(0x36ba), SHC(0x8c4a),
    SHC(0x30fc), SHC(0x89be), SHC(0x2b1f), SHC(0x877b), SHC(0x2528), SHC(0x8583), SHC(0x1f1a), SHC(0x83d6),
    SHC(0x18f9), SHC(0x8276), SHC(0x12c8), SHC(0x8163), SHC(0x0c8c), SHC(0x809e), SHC(0x0648), SHC(0x8027),
    SHC(0x7fff), SHC(0x0000), SHC(0x7fa7), SHC(0xf695), SHC(0x7e9d), SHC(0xed38), SHC(0x7ce4), SHC(0xe3f4),
    SHC(0x7a7d), SHC(0xdad8), SHC(0x776c), SHC(0xd1ef), SHC(0x73b6), SHC(0xc946), SHC(0x6f5f), SHC(0xc0e9),
    SHC(0x6a6e), SHC(0xb8e3), SHC(0x64e9), SHC(0xb140), SHC(0x5ed7), SHC(0xaa0a), SHC(0x5843), SHC(0xa34c),
    SHC(0x5134), SHC(0x9d0e), SHC(0x49b4), SHC(0x9759), SHC(0x41ce), SHC(0x9236), SHC(0x398d), SHC(0x8dab),
    SHC(0x30fc), SHC(0x89be), SHC(0x2827), SHC(0x8676), SHC(0x1f1a), SHC(0x83d6), SHC(0x15e2), SHC(0x81e2),
    SHC(0x0c8c), SHC(0x809e), SHC(0x0324), SHC(0x800a), SHC(0xf9b8), SHC(0x8027), SHC(0xf055), SHC(0x80f6),
    SHC(0xe707), SHC(0x8276), SHC(0xdddc), SHC(0x84a3), SHC(0xd4e1), SHC(0x877b), SHC(0xcc21), SHC(0x8afb),
    SHC(0xc3a9), SHC(0x8f1d), SHC(0xbb85), SHC(0x93dc), SHC(0xb3c0), SHC(0x9930), SHC(0xac65), SHC(0x9f14),
    SHC(0x7fff), SHC(0x0000), SHC(0x7f62), SHC(0xf374), SHC(0x7d8a), SHC(0xe707), SHC(0x7a7d), SHC(0xdad8),
    SHC(0x7642), SHC(0xcf04), SHC(0x70e3), SHC(0xc3a9), SHC(0x6a6e), SHC(0xb8e3), SHC(0x62f2), SHC(0xaecc),
    SHC(0x5a82), SHC(0xa57e), SHC(0x5134), SHC(0x9d0e), SHC(0x471d), SHC(0x9592), SHC(0x3c57), SHC(0x8f1d),
    SHC(0x30fc), SHC(0x89be), SHC(0x2528), SHC(0x8583), SHC(0x18f9), SHC(0x8276), SHC(0x0c8c), SHC(0x809e),
    SHC(0x0000), SHC(0x8000), SHC(0xf374), SHC(0x809e), SHC(0xe707), SHC(0x8276), SHC(0xdad8), SHC(0x8583),
    SHC(0xcf04), SHC(0x89be), SHC(0xc3a9), SHC(0x8f1d), SHC(0xb8e3), SHC(0x9592), SHC(0xaecc), SHC(0x9d0e),
    SHC(0xa57e), SHC(0xa57e), SHC(0x9d0e), SHC(0xaecc), SHC(0x9592), SHC(0xb8e3), SHC(0x8f1d), SHC(0xc3a9),
    SHC(0x89be), SHC(0xcf04), SHC(0x8583), SHC(0xdad8), SHC(0x8276), SHC(0xe707), SHC(0x809e), SHC(0xf374),
    SHC(0x7fff), SHC(0x0000), SHC(0x7f0a), SHC(0xf055), SHC(0x7c2a), SHC(0xe0e6), SHC(0x776c), SHC(0xd1ef),
    SHC(0x70e3), SHC(0xc3a9), SHC(0x68a7), SHC(0xb64c), SHC(0x5ed7), SHC(0xaa0a), SHC(0x539b), SHC(0x9f14),
    SHC(0x471d), SHC(0x9592), SHC(0x398d), SHC(0x8dab), SHC(0x2b1f), SHC(0x877b), SHC(0x1c0c), SHC(0x831c),
    SHC(0x0c8c), SHC(0x809e), SHC(0xfcdc), SHC(0x800a), SHC(0xed38), SHC(0x8163), SHC(0xdddc), SHC(0x84a3),
    SHC(0xcf04), SHC(0x89be), SHC(0xc0e9), SHC(0x90a1), SHC(0xb3c0), SHC(0x9930), SHC(0xa7bd), SHC(0xa34c),
    SHC(0x9d0e), SHC(0xaecc), SHC(0x93dc), SHC(0xbb85), SHC(0x8c4a), SHC(0xc946), SHC(0x8676), SHC(0xd7d9),
    SHC(0x8276), SHC(0xe707), SHC(0x8059), SHC(0xf695), SHC(0x8027), SHC(0x0648), SHC(0x81e2), SHC(0x15e2),
    SHC(0x8583), SHC(0x2528), SHC(0x8afb), SHC(0x33df), SHC(0x9236), SHC(0x41ce), SHC(0x9b17), SHC(0x4ec0),
    SHC(0x7fff), SHC(0x0000), SHC(0x7e9d), SHC(0xed38), SHC(0x7a7d), SHC(0xdad8), SHC(0x73b6), SHC(0xc946),
    SHC(0x6a6e), SHC(0xb8e3), SHC(0x5ed7), SHC(0xaa0a), SHC(0x5134), SHC(0x9d0e), SHC(0x41ce), SHC(0x9236),
    SHC(0x30fc), SHC(0x89be), SHC(0x1f1a), SHC(0x83d6), SHC(0x0c8c), SHC(0x809e), SHC(0xf9b8), SHC(0x8027),
    SHC(0xe707), SHC(0x8276), SHC(0xd4e1), SHC(0x877b), SHC(0xc3a9), SHC(0x8f1d), SHC(0xb3c0), SHC(0x9930),
    SHC(0xa57e), SHC(0xa57e), SHC(0x9930), SHC(0xb3c0), SHC(0x8f1d), SHC(0xc3a9), SHC(0x877b), SHC(0xd4e1),
    SHC(0x8276), SHC(0xe707), SHC(0x8027), SHC(0xf9b8), SHC(0x809e), SHC(0x0c8c), SHC(0x83d6), SHC(0x1f1a),
    SHC(0x89be), SHC(0x30fc), SHC(0x9236), SHC(0x41ce), SHC(0x9d0e), SHC(0x5134), SHC(0xaa0a), SHC(0x5ed7),
    SHC(0xb8e3), SHC(0x6a6e), SHC(0xc946), SHC(0x73b6), SHC(0xdad8), SHC(0x7a7d), SHC(0xed38), SHC(0x7e9d),
    SHC(0x7fff), SHC(0x0000), SHC(0x7e1e), SHC(0xea1e), SHC(0x7885), SHC(0xd4e1), SHC(0x6f5f), SHC(0xc0e9),
    SHC(0x62f2), SHC(0xaecc), SHC(0x539b), SHC(0x9f14), SHC(0x41ce), SHC(0x9236), SHC(0x2e11), SHC(0x8894),
    SHC(0x18f9), SHC(0x8276), SHC(0x0324), SHC(0x800a), SHC(0xed38), SHC(0x8163), SHC(0xd7d9), SHC(0x8676),
    SHC(0xc3a9), SHC(0x8f1d), SHC(0xb140), SHC(0x9b17), SHC(0xa129), SHC(0xaa0a), SHC(0x93dc), SHC(0xbb85),
    SHC(0x89be), SHC(0xcf04), SHC(0x831c), SHC(0xe3f4), SHC(0x8027), SHC(0xf9b8), SHC(0x80f6), SHC(0x0fab),
    SHC(0x8583), SHC(0x2528), SHC(0x8dab), SHC(0x398d), SHC(0x9930), SHC(0x4c40), SHC(0xa7bd), SHC(0x5cb4),
    SHC(0xb8e3), SHC(0x6a6e), SHC(0xcc21), SHC(0x7505), SHC(0xe0e6), SHC(0x7c2a), SHC(0xf695), SHC(0x7fa7),
    SHC(0x0c8c), SHC(0x7f62), SHC(0x2224), SHC(0x7b5d), SHC(0x36ba), SHC(0x73b6), SHC(0x49b4), SHC(0x68a7)
};

/*-----------------------------------------------------------------*
 * BASOP_fft8()
 *
 * Function performs a complex 8-point FFT
 * The FFT is performed inplace. The result of the FFT
 * is scaled by SCALEFACTOR8 bits.
 *
 * WOPS with 32x16 bit multiplications: 108 cycles
 *-----------------------------------------------------------------*/

static void BASOP_fft8(
    Word32 *re,
    Word32 *im,
    Word16 s
)
{
    Word32 x00,x01,x02,x03,x04,x05,x06,x07;
    Word32 x08,x09,x10,x11,x12,x13,x14,x15;
    Word32 t00,t01,t02,t03,t04,t05,t06,t07;
    Word32 t08,t09,t10,t11,t12,t13,t14,t15;
    Word32 s00,s01,s02,s03,s04,s05,s06,s07;
    Word32 s08,s09,s10,s11,s12,s13,s14,s15;


    /* Pre-additions */

    x00 = L_shr(re[s*0],SCALEFACTOR8);
    x01 = L_shr(im[s*0],SCALEFACTOR8);
    x02 = L_shr(re[s*1],SCALEFACTOR8);
    x03 = L_shr(im[s*1],SCALEFACTOR8);
    x04 = L_shr(re[s*2],SCALEFACTOR8);
    x05 = L_shr(im[s*2],SCALEFACTOR8);
    x06 = L_shr(re[s*3],SCALEFACTOR8);
    x07 = L_shr(im[s*3],SCALEFACTOR8);
    x08 = L_shr(re[s*4],SCALEFACTOR8);
    x09 = L_shr(im[s*4],SCALEFACTOR8);
    x10 = L_shr(re[s*5],SCALEFACTOR8);
    x11 = L_shr(im[s*5],SCALEFACTOR8);
    x12 = L_shr(re[s*6],SCALEFACTOR8);
    x13 = L_shr(im[s*6],SCALEFACTOR8);
    x14 = L_shr(re[s*7],SCALEFACTOR8);
    x15 = L_shr(im[s*7],SCALEFACTOR8);

    t00 = L_add(x00,x08);
    t02 = L_sub(x00,x08);
    t01 = L_add(x01,x09);
    t03 = L_sub(x01,x09);
    t04 = L_add(x02,x10);
    t06 = L_sub(x02,x10);
    t05 = L_add(x03,x11);
    t07 = L_sub(x03,x11);
    t08 = L_add(x04,x12);
    t10 = L_sub(x04,x12);
    t09 = L_add(x05,x13);
    t11 = L_sub(x05,x13);
    t12 = L_add(x06,x14);
    t14 = L_sub(x06,x14);
    t13 = L_add(x07,x15);
    t15 = L_sub(x07,x15);

    /* Pre-additions and core multiplications */

    s00 = L_add(t00,t08);
    s04 = L_sub(t00,t08);
    s01 = L_add(t01,t09);
    s05 = L_sub(t01,t09);
    s08 = L_sub(t02,t11);
    s10 = L_add(t02,t11);
    s09 = L_add(t03,t10);
    s11 = L_sub(t03,t10);
    s02 = L_add(t04,t12);
    s07 = L_sub(t04,t12);
    s03 = L_add(t05,t13);
    s06 = L_sub(t13,t05);

    t01 = L_add(t06,t14);
    t02 = L_sub(t06,t14);
    t00 = L_add(t07,t15);
    t03 = L_sub(t07,t15);

    s12 = Mpy_32_16(L_add(t00,t02),C81_FX);
    s14 = Mpy_32_16(L_sub(t00,t02),C81_FX);
    s13 = Mpy_32_16(L_sub(t03,t01),C81_FX);
    s15 = Mpy_32_16(L_add(t01,t03),C82_FX);

    /* Post-additions */

    re[s*0] = L_add(s00,s02);
    move32();
    re[s*4] = L_sub(s00,s02);
    move32();
    im[s*0] = L_add(s01,s03);
    move32();
    im[s*4] = L_sub(s01,s03);
    move32();
    re[s*2] = L_sub(s04,s06);
    move32();
    re[s*6] = L_add(s04,s06);
    move32();
    im[s*2] = L_sub(s05,s07);
    move32();
    im[s*6] = L_add(s05,s07);
    move32();
    re[s*3] = L_add(s08,s14);
    move32();
    re[s*7] = L_sub(s08,s14);
    move32();
    im[s*3] = L_add(s09,s15);
    move32();
    im[s*7] = L_sub(s09,s15);
    move32();
    re[s*1] = L_add(s10,s12);
    move32();
    re[s*5] = L_sub(s10,s12);
    move32();
    im[s*1] = L_add(s11,s13);
    move32();
    im[s*5] = L_sub(s11,s13);
    move32();

    return;
}


/*-----------------------------------------------------------------*
 * fftN2()
 *
 * Combined FFT
 *-----------------------------------------------------------------*/

static void BASOP_fftN2(
    Word32 *re,       /* i/o: real part                                       */
    Word32 *im,       /* i/o: imag part                                       */
    const Word16 *W,  /* i  : rotation factor                                 */
    Word16 dim1,      /* i  : length of fft1                                  */
    Word16 dim2,      /* i  : length of fft2                                  */
    Word16 sx,        /* i  : stride real and imag part                       */
    Word16 sc,        /* i  : stride phase rotation coefficients              */
    Word32 *x,        /* tmp: 32-bit workbuffer                               */
    Word16 Woff       /* i  : offset for addressing the rotation vector table */
)
{
    Word16 i,j;
    Word32 x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
    Word32 t00,t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15;
    Word32 s00,s01,s02,s03,s04,s05,s06,s07,s08,s09,s10,s11,s12,s13,s14,s15;

    FOR (i=0; i<dim2; i++)
    {
        FOR(j=0; j<dim1; j++)
        {
            x[2*i*dim1+2*j]   = re[sx*i+sx*j*dim2];
            move32();
            x[2*i*dim1+2*j+1] = im[sx*i+sx*j*dim2];
            move32();
        }
    }

    /* dim1 == 8 */
    FOR(i=0; i<dim2; i++)
    {
        BASOP_fft8( &x[i*2*dim1], &x[i*2*dim1+1], 2 );
    }

    /* dim2 == 8 */
    FOR(i=0; i<dim1; i++)
    {
        cplxMpy4_8_1(x00,x01,x[2*i+2*0*dim1],x[2*i+2*0*dim1+1]);

        IF (i==0)
        {
            cplxMpy4_8_1(x02,x03,x[2*i+2*1*dim1],x[2*i+2*1*dim1+1]);
            cplxMpy4_8_1(x04,x05,x[2*i+2*2*dim1],x[2*i+2*2*dim1+1]);
            cplxMpy4_8_1(x06,x07,x[2*i+2*3*dim1],x[2*i+2*3*dim1+1]);
            cplxMpy4_8_1(x08,x09,x[2*i+2*4*dim1],x[2*i+2*4*dim1+1]);
            cplxMpy4_8_1(x10,x11,x[2*i+2*5*dim1],x[2*i+2*5*dim1+1]);
            cplxMpy4_8_1(x12,x13,x[2*i+2*6*dim1],x[2*i+2*6*dim1+1]);
            cplxMpy4_8_1(x14,x15,x[2*i+2*7*dim1],x[2*i+2*7*dim1+1]);
        }
        ELSE
        {
            cplxMpy4_8_0(x02,x03,x[2*i+2*1*dim1],x[2*i+2*1*dim1+1],W[sc*i+sc*1*dim1-Woff],W[sc*i+sc*1*dim1+1-Woff]);
            cplxMpy4_8_0(x04,x05,x[2*i+2*2*dim1],x[2*i+2*2*dim1+1],W[sc*i+sc*2*dim1-Woff],W[sc*i+sc*2*dim1+1-Woff]);
            cplxMpy4_8_0(x06,x07,x[2*i+2*3*dim1],x[2*i+2*3*dim1+1],W[sc*i+sc*3*dim1-Woff],W[sc*i+sc*3*dim1+1-Woff]);
            cplxMpy4_8_0(x08,x09,x[2*i+2*4*dim1],x[2*i+2*4*dim1+1],W[sc*i+sc*4*dim1-Woff],W[sc*i+sc*4*dim1+1-Woff]);
            cplxMpy4_8_0(x10,x11,x[2*i+2*5*dim1],x[2*i+2*5*dim1+1],W[sc*i+sc*5*dim1-Woff],W[sc*i+sc*5*dim1+1-Woff]);
            cplxMpy4_8_0(x12,x13,x[2*i+2*6*dim1],x[2*i+2*6*dim1+1],W[sc*i+sc*6*dim1-Woff],W[sc*i+sc*6*dim1+1-Woff]);
            cplxMpy4_8_0(x14,x15,x[2*i+2*7*dim1],x[2*i+2*7*dim1+1],W[sc*i+sc*7*dim1-Woff],W[sc*i+sc*7*dim1+1-Woff]);
        }
        t00 = L_shr(L_add(x00,x08),SCALEFACTORN2-1);
        t02 = L_shr(L_sub(x00,x08),SCALEFACTORN2-1);
        t01 = L_shr(L_add(x01,x09),SCALEFACTORN2-1);
        t03 = L_shr(L_sub(x01,x09),SCALEFACTORN2-1);
        t04 = L_shr(L_add(x02,x10),SCALEFACTORN2-1);
        t06 = L_sub(x02,x10);
        t05 = L_shr(L_add(x03,x11),SCALEFACTORN2-1);
        t07 = L_sub(x03,x11);
        t08 = L_shr(L_add(x04,x12),SCALEFACTORN2-1);
        t10 = L_shr(L_sub(x04,x12),SCALEFACTORN2-1);
        t09 = L_shr(L_add(x05,x13),SCALEFACTORN2-1);
        t11 = L_shr(L_sub(x05,x13),SCALEFACTORN2-1);
        t12 = L_shr(L_add(x06,x14),SCALEFACTORN2-1);
        t14 = L_sub(x06,x14);
        t13 = L_shr(L_add(x07,x15),SCALEFACTORN2-1);
        t15 = L_sub(x07,x15);

        s00 = L_add(t00,t08);
        s04 = L_sub(t00,t08);
        s01 = L_add(t01,t09);
        s05 = L_sub(t01,t09);
        s08 = L_sub(t02,t11);
        s10 = L_add(t02,t11);
        s09 = L_add(t03,t10);
        s11 = L_sub(t03,t10);
        s02 = L_add(t04,t12);
        s07 = L_sub(t04,t12);
        s03 = L_add(t05,t13);
        s06 = L_sub(t13,t05);

        t01 = L_shr(L_add(t06,t14),SCALEFACTORN2-1);
        t02 = L_shr(L_sub(t06,t14),SCALEFACTORN2-1);
        t00 = L_shr(L_add(t07,t15),SCALEFACTORN2-1);
        t03 = L_shr(L_sub(t07,t15),SCALEFACTORN2-1);

        s12 = Mpy_32_16(L_add(t00,t02),C81_FX);
        s14 = Mpy_32_16(L_sub(t00,t02),C81_FX);
        s13 = Mpy_32_16(L_sub(t03,t01),C81_FX);
        s15 = Mpy_32_16(L_add(t01,t03),C82_FX);

        re[sx*i+sx*0*dim1] = L_add(s00,s02);
        move32();
        im[sx*i+sx*0*dim1] = L_add(s01,s03);
        move32();
        re[sx*i+sx*1*dim1] = L_add(s10,s12);
        move32();
        im[sx*i+sx*1*dim1] = L_add(s11,s13);
        move32();
        re[sx*i+sx*2*dim1] = L_sub(s04,s06);
        move32();
        im[sx*i+sx*2*dim1] = L_sub(s05,s07);
        move32();
        re[sx*i+sx*3*dim1] = L_add(s08,s14);
        move32();
        im[sx*i+sx*3*dim1] = L_add(s09,s15);
        move32();
        re[sx*i+sx*4*dim1] = L_sub(s00,s02);
        move32();
        im[sx*i+sx*4*dim1] = L_sub(s01,s03);
        move32();
        re[sx*i+sx*5*dim1] = L_sub(s10,s12);
        move32();
        im[sx*i+sx*5*dim1] = L_sub(s11,s13);
        move32();
        re[sx*i+sx*6*dim1] = L_add(s04,s06);
        move32();
        im[sx*i+sx*6*dim1] = L_add(s05,s07);
        move32();
        re[sx*i+sx*7*dim1] = L_sub(s08,s14);
        move32();
        im[sx*i+sx*7*dim1] = L_sub(s09,s15);
        move32();
    }

    return;
}


/*-----------------------------------------------------------------*
 * BASOP_cfft()
 *
 * Complex valued FFT
 *-----------------------------------------------------------------*/

void BASOP_cfft(
    Word32 *re,             /* i/o: real part                   */
    Word32 *im,             /* i/o: imag part                   */
    Word16 s,               /* i  : stride real and imag part   */
    Word16 *scale           /* i  : scalefactor                 */
)
{
    Word32 x[2*64];

    /* FFT for len = FDNS_NPTS */
    BASOP_fftN2( re, im, RotVector_256, 8, 8, s, 8, x, 64 );
    s = add(*scale,SCALEFACTOR64);

    *scale = s;
    move16();

    return;
}
