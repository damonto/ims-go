/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "rtpdump.h"

#ifdef __cplusplus
extern "C" {
#endif

static const int32_t AMRWB_IOmode2rate[16] =
{
  6600,    /* AMRWB_IO_6600 */
  8850,    /* AMRWB_IO_8850 */
  12650,    /* AMRWB_IO_1265 */
  14250,    /* AMRWB_IO_1425 */
  15850,    /* AMRWB_IO_1585 */
  18250,    /* AMRWB_IO_1825 */
  19850,    /* AMRWB_IO_1985 */
  23050,    /* AMRWB_IO_2305 */
  23850,    /* AMRWB_IO_2385 */
  1750,    /* AMRWB_IO_SID: SID_1k75 followed by STI bit and CMI bits (A.2.2.1.3) */
  -1,    /* AMRWB_IO_FUT1 */
  -1,    /* AMRWB_IO_FUT2 */
  -1,    /* AMRWB_IO_FUT3 */
  -1,    /* AMRWB_IO_FUT4 */
  0,    /* SPEECH_LOST    */
  0     /* NO_DATA       */
};

static const int32_t PRIMARYmode2rate[16] =
{
  2800,   /* PRIMARY_2800 */
  7200,   /* PRIMARY_7200 */
  8000,   /* PRIMARY_8000 */
  9600,   /* PRIMARY_9600 */
  13200,   /* PRIMARY_13200 */
  16400,   /* PRIMARY_16400 */
  24400,   /* PRIMARY_24400 */
  32000,   /* PRIMARY_32000 */
  48000,   /* PRIMARY_48000 */
  64000,   /* PRIMARY_64000 */
  96000,   /* PRIMARY_96000 */
  128000,   /* PRIMARY_128000 */
  2400,   /* PRIMARY_SID */
  -1,   /* PRIMARY_FUT1 */
  0,   /* SPEECH_LOST */
  0    /* NO_DATA */
};

static const uint16_t evsPayloadProtectedSizes[22] = {
  48,
  56,
  136,
  144,
  160,
  184,
  192,
  256,
  264,
  288,
  320,
  328,
  368,
  400,
  464,
  480,
  488,
  640,
  960,
  1280,
  1920,
  2560
};

static const bool evsPayloadProtectedSizes_isAMRWB_IOmode[22] = {
  0,
  0, /* Special case (see clause A.2.1.3) */
  1,
  0,
  0,
  1,
  0,
  1,
  0,
  1,
  1,
  0,
  1,
  1,
  1,
  1,
  0,
  0,
  0,
  0,
  0,
  0
};

static const uint16_t evsPayloadProtectedSizes_frameTypeIndex[22] = {
    12, /* PRIMARY_SID */
    0, /* Special case (see clause A.2.1.3) */
    0, /* AMRWB_IO_6600 */
    1, /* PRIMARY_7200 */
    2, /* PRIMARY_8000 */
    1, /* AMRWB_IO_8850 */
    3, /* PRIMARY_9600 */
    2, /* AMRWB_IO_1265 */
    4, /* PRIMARY_13200 */
    3, /* AMRWB_IO_1425 */
    4, /* AMRWB_IO_1585 */
    5, /* PRIMARY_16400 */
    5, /* AMRWB_IO_1825 */
    6, /* AMRWB_IO_1985 */
    7, /* AMRWB_IO_2305 */
    8, /* AMRWB_IO_2385 */
    6, /* PRIMARY_24400 */
    7, /* PRIMARY_32000 */
    8, /* PRIMARY_48000 */
    9, /* PRIMARY_64000 */
    10, /* PRIMARY_96000 */
    11  /* PRIMARY_128000 */
};

bool evsPayload_unpackFrame(bool hf_only, const char *payload, uint16_t payloadSizeBytes, uint16_t frameIndex,
                            bool *isAMRWB_IOmode, bool *frameFollowing, uint16_t *frameTypeIndex, bool *qBit,
                            unsigned char **framePtr, uint16_t *frameSizeBits);

bool evsPayload_getFrameTypeFromSize(int16_t frameSizeBits, bool *isAMRWB_IOmode, uint16_t *frameTypeIndex);

bool evsHeaderFullPayload_unpackFrame(const char *payload, uint16_t payloadSizeBytes, uint16_t frameIndex,
    bool *isAMRWB_IOmode, bool *frameFollowing, uint16_t *frameTypeIndex, bool *qBit,
    unsigned char **frame, uint16_t *frameSizeBits);

typedef struct {
  RTPDUMP_HANDLE rtpdump;
  bool hf_only;
  RTPDUMP_RTPPACKET rtpPacket;
  uint32_t timeoffset_ms;
  uint16_t frameIndex;
  bool frameFollowing;
} EVS_RTPDUMP_DEPACKER;

typedef enum {
  EVS_RTPDUMP_DEPACKER_NO_ERROR = 0,
  EVS_RTPDUMP_DEPACKER_EOF = -1,
  EVS_RTPDUMP_DEPACKER_RTPDUMP_ERROR = 1,
  EVS_RTPDUMP_DEPACKER_PAYLOAD_ERROR
} EVS_RTPDUMP_DEPACKER_ERROR;

EVS_RTPDUMP_DEPACKER_ERROR EVS_RTPDUMP_DEPACKER_open(EVS_RTPDUMP_DEPACKER *self, FILE *file, bool hf_only);

EVS_RTPDUMP_DEPACKER_ERROR EVS_RTPDUMP_DEPACKER_readNextFrame(
    EVS_RTPDUMP_DEPACKER *self,
    uint16_t *rtpSequenceNumber,
    uint32_t *rtpTimeStamp,
    uint32_t *rcvTime_ms,
    bool *isAMRWB_IOmode,
    uint16_t *frameTypeIndex,
    bool *qBit,
    unsigned char **frame,
    uint16_t *frameSizeBits);

void EVS_RTPDUMP_DEPACKER_close(EVS_RTPDUMP_DEPACKER *self);

#ifdef __cplusplus
}
#endif
