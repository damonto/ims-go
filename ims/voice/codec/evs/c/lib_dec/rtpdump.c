/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rtpdump.h"

struct RTPDUMP
{
  FILE * file;
  unsigned int startSeconds;
  unsigned int startMicroSeconds;
  unsigned int source;
  unsigned short port;
};

/** function to read a 32-bit value from a buffer */
static unsigned char * parseLong( unsigned char * buffer, unsigned int * value )
{
  *value = 0;
  *value  = (unsigned int)( buffer[3] & 0xFF );
  *value |= (unsigned int)( buffer[2] & 0xFF ) <<  8;
  *value |= (unsigned int)( buffer[1] & 0xFF ) << 16;
  *value |= (unsigned int)( buffer[0] & 0xFF ) << 24;
  return buffer + 4;
}

/** function to read a 16-bit value from a buffer */
static unsigned char * parseShort( unsigned char * buffer, unsigned short * value )
{
  *value = 0;
  *value  = (unsigned int)( buffer[1] & 0xFF );
  *value |= (unsigned int)( buffer[0] & 0xFF ) <<  8;
  return buffer + 2;
}

/** function to read a 8-bit value from a buffer */
static unsigned char * parseByte( unsigned char * buffer, unsigned char * value )
{
  *value = 0;
  *value  = (unsigned int)( buffer[0] & 0xFF );
  return buffer + 1;
}

/** function to read a 32-bit value from the file */
static int readLong( FILE * file, unsigned int * value )
{
  char buffer[4] = {0};
  if( fread( buffer, 4, 1, file ) != 1U )
  {
    return -1;
  }
  *value = 0;
  *value  = (unsigned int)( buffer[3] & 0xFF );
  *value |= (unsigned int)( buffer[2] & 0xFF ) <<  8;
  *value |= (unsigned int)( buffer[1] & 0xFF ) << 16;
  *value |= (unsigned int)( buffer[0] & 0xFF ) << 24;
  return 0;
}

/** function to read a 16-bit value from the file */
static int readShort( FILE * file, unsigned short * value )
{
  char buffer[2] = {0};
  if( fread( buffer, 2, 1, file ) != 1U )
  {
    return -1;
  }
  *value = 0;
  *value  = (unsigned int)( buffer[1] & 0xFF );
  *value |= (unsigned int)( buffer[0] & 0xFF ) <<  8;
  return 0;
}

/** function to write a 32-bit value to the file */
static int writeLong( FILE * file, unsigned int value )
{
  char buffer[4] = {0};
  buffer[3] = value & 0xff;
  buffer[2] = (value >> 8) & 0xff;
  buffer[1] = (value >> 16) & 0xff;
  buffer[0] = (value >> 24) & 0xff;
  if( fwrite( buffer, 4, 1, file ) != 1U )
  {
    return -1;
  }
  return 0;
}

/** function to write a 16-bit value to the file */
static int writeShort( FILE * file, unsigned short value )
{
  char buffer[2] = {0};
  buffer[1] = value & 0xff;
  buffer[0] = (value >> 8) & 0xff;
  if( fwrite( buffer, 2, 1, file ) != 1U )
  {
    return -1;
  }
  return 0;
}

/** function to write a 8-bit value to the file */
static int writeByte( FILE * file, unsigned char value )
{
  if(fputc(value, file) == value)
  {
    return 0;
  }
  return -1;
}

/** function to parse the rtpdump file header */
static int readHeader(struct RTPDUMP * hRTPDUMP)
{
  unsigned short padding;
  char buffer[255] = {0};
  /* read identifier */
  /*
  char buffer[255] = {0};
  const char id [] = "#!rtpplay1.0";
  fgets( buffer, sizeof(buffer), hRTPDUMP->file );
  if( memcmp( buffer, id, sizeof(id)-1 ) != 0 )
    return -1;
  */
  char version [4] = {0};
  char address [128] = {0};
  unsigned int port = 0;
  unsigned int a, b, c, d;

  fgets( buffer, sizeof(buffer), hRTPDUMP->file );
  if(sscanf(buffer, "#!rtpplay%3s %127[0123456789.]/%u\n", version, address, &port) == 3)
  {
    if(sscanf(address, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    {
      return -1;
    }
  } else if(sscanf(buffer, "#!rtpplay%3s %127[0123456789abcdef:]/%u\n", version, address, &port) == 3)
    /* no verification of IPv6 addresses yet */
  {
  } else
  {
    fprintf(stderr, "unable to read rtpplay\n");
    fprintf(stderr, "Buffer: %s\n", buffer);
    return -1;
  }
  if(strcmp(version, "1.0"))
  {
    return -1;
  }

  /* read binary header (RD_hdr_t) */
  readLong( hRTPDUMP->file, &(hRTPDUMP->startSeconds));
  readLong( hRTPDUMP->file, &(hRTPDUMP->startMicroSeconds));
  readLong( hRTPDUMP->file, &(hRTPDUMP->source));
  readShort( hRTPDUMP->file, &(hRTPDUMP->port) );
  readShort( hRTPDUMP->file, &padding );

  return 0;
}

static int writeHeader(struct RTPDUMP * hRTPDUMP)
{
  /* write rtpdump header */
  fprintf(hRTPDUMP->file, "#!rtpplay%s %s/%d\n", "1.0", "127.0.0.1", 5000);
  if(!writeLong(hRTPDUMP->file, hRTPDUMP->startSeconds) &&
     !writeLong(hRTPDUMP->file, hRTPDUMP->startMicroSeconds) &&
     !writeLong(hRTPDUMP->file, hRTPDUMP->source) &&
     !writeShort(hRTPDUMP->file, hRTPDUMP->port) &&
     !writeShort(hRTPDUMP->file, 0)
    )
  {
    return 0;
  }
  return -1;
}

RTPDUMP_ERROR
RTPDUMP_OpenForReading(RTPDUMP_HANDLE* phRTPDUMP, const char * filename)
{
  return RTPDUMP_OpenWithFileToRead(phRTPDUMP, fopen( filename, "rb" ));
}

RTPDUMP_ERROR
RTPDUMP_OpenWithFileToRead(RTPDUMP_HANDLE* phRTPDUMP, FILE *file)
{
  *phRTPDUMP = (RTPDUMP_HANDLE) calloc(1, sizeof(struct RTPDUMP) );
  if ( !phRTPDUMP )
  {
    return RTPDUMP_MEMORY_ERROR;
  }

  /* open file stream */
  (*phRTPDUMP)->file = file;
  if( (*phRTPDUMP)->file == NULL )
  {
    return RTPDUMP_FILE_NOT_FOUND;
  }

  if( readHeader(*phRTPDUMP) != 0)
  {
    return RTPDUMP_INIT_ERROR;
  }

  return RTPDUMP_NO_ERROR;
}

RTPDUMP_ERROR
RTPDUMP_OpenForWriting(RTPDUMP_HANDLE* phRTPDUMP, const char * filename)
{
  *phRTPDUMP = (RTPDUMP_HANDLE) calloc(1, sizeof(struct RTPDUMP) );
  if ( !phRTPDUMP )
  {
    return RTPDUMP_MEMORY_ERROR;
  }

  /* open file stream */
  (*phRTPDUMP)->file = fopen( filename, "wb" );
  if( (*phRTPDUMP)->file == NULL )
  {
    return RTPDUMP_FILE_NOT_FOUND;
  }

  if( writeHeader(*phRTPDUMP) != 0)
  {
    return RTPDUMP_INIT_ERROR;
  }

  return RTPDUMP_NO_ERROR;
}

RTPDUMP_ERROR
RTPDUMP_ReadPacket(RTPDUMP_HANDLE hRTPDUMP,
                    RTPDUMP_RTPPACKET * packet,
                    uint32_t * timeoffset_ms)
{
  unsigned short length = 0;

  if(!hRTPDUMP)
  {
    return RTPDUMP_NOT_INITIALIZED;
  }

  /* length of packet, including this header (may be smaller than plen if not whole packet recorded) */
  if( readShort(hRTPDUMP->file, &length ) )
  {
    return RTPDUMP_READ_ENDOFFILE;
  }
  length -= 8;

  /* actual header+payload length for RTP, 0 for RTCP */
  if( readShort(hRTPDUMP->file, &(packet->payloadSize) ) )
  {
    return RTPDUMP_READ_ERROR;
  }
  if(packet->payloadSize < length )
  {
    return RTPDUMP_UNKNOWN_ERROR;
  }

  /* remove size of RTP header so that plen is payload length */
  packet->headerSize = 12;
  packet->payloadSize -= packet->headerSize;

  /* milliseconds since the start of recording */
  if( readLong(hRTPDUMP->file, timeoffset_ms ) )
  {
    return RTPDUMP_READ_ERROR;
  }

  if(length > sizeof(packet->data) / sizeof(packet->data[0]))
  {
    return RTPDUMP_UNKNOWN_ERROR;
  }

  /* read entire RTP packet */
  if( length != 0U)
  {
    fread( packet->data, length, 1, hRTPDUMP->file );
  }

  RTPDUMP_ParseRTPHeader(packet);
  return RTPDUMP_NO_ERROR;
}

RTPDUMP_ERROR
RTPDUMP_WritePacket(RTPDUMP_HANDLE hRTPDUMP,
                    const RTPDUMP_RTPPACKET * packet,
                    uint32_t timeoffset_ms)
{
  /* rtpdump packet header */
  writeShort(hRTPDUMP->file, 8 + packet->headerSize + packet->payloadSize);
  writeShort(hRTPDUMP->file, packet->headerSize + packet->payloadSize);
  writeLong(hRTPDUMP->file, timeoffset_ms);

  /* RTP header */
  writeByte(hRTPDUMP->file, packet->v_p_x_xx);
  writeByte(hRTPDUMP->file, packet->payloadTypeId);
  writeShort(hRTPDUMP->file, packet->sequenceNumber);
  writeLong(hRTPDUMP->file, packet->timeStamp);
  writeLong(hRTPDUMP->file, packet->ssrc);

  /* RTP payload */
  fwrite(packet->data + packet->headerSize, packet->payloadSize, 1, hRTPDUMP->file);
  return RTPDUMP_NO_ERROR;
}

void
RTPDUMP_Close(RTPDUMP_HANDLE* phRTPDUMP, short closeFile)
{
  if ( !phRTPDUMP )
  {
    return;
  }

  if ( !(*phRTPDUMP) )
  {
    return;
  }

  if(closeFile && (*phRTPDUMP)->file)
  {
    fclose((*phRTPDUMP)->file);
  }

  free(*phRTPDUMP);
  *phRTPDUMP = NULL;
}

void RTPDUMP_SetDefaultRtpPacketHeader(RTPDUMP_RTPPACKET * packet)
{
  packet->v_p_x_xx = 128;
  packet->payloadTypeId = 96;
  packet->sequenceNumber = 0;
  packet->timeStamp = 0;
  packet->ssrc = 0xaabbccdd;
  packet->headerSize = 12;
  packet->payloadSize = 0;
}

void RTPDUMP_ParseRTPHeader(RTPDUMP_RTPPACKET * packet)
{
  unsigned char *payload = (unsigned char *)packet->data;
  payload = parseByte(payload, &(packet->v_p_x_xx));
  payload = parseByte(payload, &(packet->payloadTypeId));
  payload = parseShort(payload, &(packet->sequenceNumber));
  payload = parseLong(payload, &(packet->timeStamp));
  parseLong(payload, &(packet->ssrc));
}
