/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#pragma once
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _RTPDUMP_ERROR
{
  RTPDUMP_NO_ERROR          = 0x0000,
  RTPDUMP_MEMORY_ERROR      = 0x0001,
  RTPDUMP_WRONG_PARAMS      = 0x0002,
  RTPDUMP_INIT_ERROR        = 0x0003,
  RTPDUMP_WRITE_ERROR       = 0x0004,
  RTPDUMP_READ_ERROR        = 0x0005,
  RTPDUMP_FILE_NOT_FOUND    = 0x0006,
  RTPDUMP_NOT_IMPLEMENTED   = 0x0010,
  RTPDUMP_NOT_INITIALIZED   = 0x0100,
  RTPDUMP_READ_ENDOFFILE    = 0x0101,
  RTPDUMP_UNKNOWN_ERROR     = 0x1000
} RTPDUMP_ERROR;

typedef struct RTPDUMP *     RTPDUMP_HANDLE;
typedef struct RTPDUMP RTPDUMP;

typedef struct RTPDUMP_RTPPACKET
{
  unsigned char v_p_x_xx; /* version, padding, extension etc. */
  unsigned char payloadTypeId;
  unsigned short sequenceNumber;
  unsigned int timeStamp;
  unsigned int ssrc;
  char data[1500 + 12]; /* raw RTP packet */
  unsigned short headerSize;
  unsigned short payloadSize;
} RTPDUMP_RTPPACKET;


RTPDUMP_ERROR
RTPDUMP_OpenForReading(RTPDUMP_HANDLE* phRTPDUMP, const char * filename);

RTPDUMP_ERROR
RTPDUMP_OpenWithFileToRead(RTPDUMP_HANDLE* phRTPDUMP, FILE *file);

RTPDUMP_ERROR
RTPDUMP_OpenForWriting(RTPDUMP_HANDLE* phRTPDUMP, const char * filename);

RTPDUMP_ERROR
RTPDUMP_ReadPacket(RTPDUMP_HANDLE hRTPDUMP,
                   RTPDUMP_RTPPACKET * packet,
                   uint32_t * timeoffset_ms);

RTPDUMP_ERROR
RTPDUMP_WritePacket(RTPDUMP_HANDLE hRTPDUMP,
                    const RTPDUMP_RTPPACKET * packet,
                    uint32_t timeoffset_ms);

void
RTPDUMP_Close(RTPDUMP_HANDLE* phRTPDUMP, short closeFile);

void
RTPDUMP_SetDefaultRtpPacketHeader(RTPDUMP_RTPPACKET * packet);

void
RTPDUMP_ParseRTPHeader(RTPDUMP_RTPPACKET * packet);

#ifdef __cplusplus
}
#endif
