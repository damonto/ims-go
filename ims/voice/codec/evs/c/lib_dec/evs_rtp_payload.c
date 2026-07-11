/*====================================================================================
    EVS Codec 3GPP TS26.443 Nov 04, 2021. Version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0
  ====================================================================================*/

#include <assert.h>
#include <stdio.h>
#include "evs_rtp_payload.h"

static void evsPayload_unpackFrame_compact_amrWbIo(const char *payload, uint16_t payloadSizeBits, uint16_t iProtectedSize,
                                                   unsigned char **framePtr, uint16_t *frameSizeInBits) {
  uint16_t i, iBit0;
  unsigned char d0, *frame = *framePtr;
  /* ignore 3 bit CMR and padding bits for EVS AMR-WB IO */
  if (iProtectedSize == 2) { /* EVS AMR-WB IO 6.6 */
    *frameSizeInBits = payloadSizeBits - 4;
  }
  else if (iProtectedSize == 5) { /* EVS AMR-WB IO 8.85 */
    *frameSizeInBits = payloadSizeBits - 7;
  }
  else {
    *frameSizeInBits = payloadSizeBits - 3;
  }
  iBit0 = *frameSizeInBits + 3 - 1;
  d0 = (((unsigned char)payload[iBit0 / 8]) >> (7 - (iBit0 % 8))) & 0x01;
  frame[0] = (d0 << 7) | ((payload[0] & 0x1f) << 2); /* d(1..5) */
  ++payload;
  for (i = 1; i != (payloadSizeBits + 7) / 8; ++i) {
    *frame++ |= (*payload & 0xc0) >> 6;
    *frame = (*payload & 0x3f) << 2;
    ++payload;
  }
  assert(frame == *framePtr + (*frameSizeInBits + 7) / 8 - 1);
  /* last payload byte contained d(0), clear it */
  (*framePtr)[*frameSizeInBits / 8] &= ~(0x80 >> (*frameSizeInBits % 8));
}

static void evsPayload_unpackFrame_compact_evsPrimary(const char *payload, uint16_t payloadSizeBits,
                                                      unsigned char **framePtr, uint16_t *frameSizeInBits) {
  *framePtr = (unsigned char*)payload; /* no need to copy frame bytes */
  *frameSizeInBits = payloadSizeBits;
}


static void evsPayload_unpackFrame_compact(const char *payload, uint16_t payloadSizeBits, uint16_t iProtectedSize,
                                           bool *isAMRWB_IOmode, uint16_t *frameTypeIndex,
                                           unsigned char **framePtr, uint16_t *frameSizeInBits) {
  if (iProtectedSize == 1) { /* A.2.1.3 Special case for 56 bit payload size (EVS Primary or EVS AMR-WB IO SID) */
    assert((payload[0] & 0x80) == 0); /* AMR-WB IO SID has no compact format and therefore is handled outside this function */
    *isAMRWB_IOmode = false;
    *frameTypeIndex = 0; /* PRIMARY_2800 */
  }
  else {
    *isAMRWB_IOmode = evsPayloadProtectedSizes_isAMRWB_IOmode[iProtectedSize];
    *frameTypeIndex = evsPayloadProtectedSizes_frameTypeIndex[iProtectedSize];
  }
  if (*isAMRWB_IOmode) {
    evsPayload_unpackFrame_compact_amrWbIo(payload, payloadSizeBits, iProtectedSize, framePtr, frameSizeInBits);
  }
  else {
    evsPayload_unpackFrame_compact_evsPrimary(payload, payloadSizeBits, framePtr, frameSizeInBits);
  }
}

bool evsPayload_unpackFrame(bool hf_only, const char *payload, uint16_t payloadSizeBytes, uint16_t frameIndex,
                            bool *isAMRWB_IOmode, bool *frameFollowing, uint16_t *frameTypeIndex, bool *qBit,
                            unsigned char **framePtr, uint16_t *frameSizeInBits) {
  uint16_t payloadSizeBits = payloadSizeBytes * 8;
  bool specialCaseIoSid = payloadSizeBits == 56 && (payload[0] & 0x80); /* A.2.1.3 Special case for 56 bit payload size */
  if (!hf_only && !specialCaseIoSid) { /* A.2.3.1 Default format handling */
    uint16_t i;
    for (i = 0; i != sizeof(evsPayloadProtectedSizes) / sizeof(evsPayloadProtectedSizes)[0]; ++i) {
      if (payloadSizeBits == evsPayloadProtectedSizes[i]) {
        assert(frameIndex == 0);
        *frameFollowing = false;
        *qBit = true;
        evsPayload_unpackFrame_compact(payload, payloadSizeBits, i, isAMRWB_IOmode, frameTypeIndex, framePtr, frameSizeInBits);
        return true;
      }
    }
  } /* else: A.2.3.2 Header-Full-only format handling */
  return evsHeaderFullPayload_unpackFrame(payload, payloadSizeBytes, frameIndex, isAMRWB_IOmode,
                                          frameFollowing, frameTypeIndex, qBit, framePtr, frameSizeInBits);
}

static void evsHeaderFullPayload_parseToc(uint8_t toc, bool *isAMRWB_IOmode, bool *frameFollowing, uint16_t *frameTypeIndex, bool *qBit, int32_t *bitrate) {
  bool evsModeBit = (toc & 0x20) != 0;
  *isAMRWB_IOmode = evsModeBit;
  *frameFollowing = (toc & 0x40) != 0;
  *frameTypeIndex = toc & 0x0f;
  if (!*isAMRWB_IOmode) {
    *qBit = true;  /* assume good q_bit for the unused EVS-mode bit */
    *bitrate = PRIMARYmode2rate[*frameTypeIndex];
  }
  else {
    *qBit = (toc & 0x10) != 0;
    *bitrate = AMRWB_IOmode2rate[*frameTypeIndex];
  }
}

bool evsPayload_getFrameTypeFromSize(int16_t frameSizeBits, bool *isAMRWB_IOmode, uint16_t *frameTypeIndex) {
    int16_t i;
    int32_t rate = frameSizeBits * 50;
    if (rate == 0) {
        assert(0); /* VOIP_G192_RTP should not transmit empty frames */
        return false; /* no information available */
    }
    for (i = 0; i <= 9; ++i) {
        if (rate == AMRWB_IOmode2rate[i]) {
            *isAMRWB_IOmode = true;
            *frameTypeIndex = i;
            return true;
        }
    }
    for (i = 0; i <= 12; ++i) {
        if (rate == PRIMARYmode2rate[i]) {
            *isAMRWB_IOmode = false;
            *frameTypeIndex = i;
            return true;
        }
    }
    return false;
}

bool evsHeaderFullPayload_unpackFrame(const char *payload, uint16_t payloadSizeBytes, uint16_t frameIndex,
    bool *isAMRWB_IOmode, bool *frameFollowing, uint16_t *frameTypeIndex, bool *qBit,
    unsigned char **frame, uint16_t *frameSizeInBits) {
  bool someIsAMRWB_IOmode, someFrameFollowing = true, someQBit;
  uint16_t someFrameTypeIndex, someFrameSizeInBits;
  int32_t bitrate;
  uint16_t iFrame;
  if (payloadSizeBytes < 1) {
    fprintf(stderr, "Error: payload too small to parse ToC\n");
    return false;
  }
  /* skip CMR */
  if (*payload & 0x80) {
    ++payload;
    --payloadSizeBytes;
  }
  /* parse all ToC entries */
  *frame = (unsigned char *)payload; /* no need to copy frame bytes */
  for (iFrame = 0; someFrameFollowing; ++iFrame) {
    if ((int16_t)payloadSizeBytes <= 0) {
      fprintf(stderr, "Error: payload too small\n");
      return false;
    }
    if (*payload & 0x80) {
      fprintf(stderr, "Error: expected ToC, found CMR\n");
      return false;
    }
    evsHeaderFullPayload_parseToc(*payload, &someIsAMRWB_IOmode, &someFrameFollowing, &someFrameTypeIndex, &someQBit, &bitrate);
    if (bitrate < 0) {
      fprintf(stderr, "Error: unexpected frameTypeIndex in ToC\n");
      return false;
    }
    ++payload;
    ++*frame;
    someFrameSizeInBits = (uint16_t)(bitrate / 50);
    /* just keep/copy zero padding bits
     * in case of AMRWB_IO_SID the STI bit and CMI bits following the SID_1k75 frame are also kept (A.2.2.1.3) */
    payloadSizeBytes -= 1 + (someFrameSizeInBits + 7) / 8;
    if (iFrame < frameIndex) {
      *frame += (someFrameSizeInBits + 7) / 8;
      if (!someFrameFollowing) {
        fprintf(stderr, "Error: expected ToC with F bit set\n");
        return false;
      }
    }
    else if (iFrame == frameIndex) {
      *isAMRWB_IOmode = someIsAMRWB_IOmode;
      *frameFollowing = someFrameFollowing;
      *frameTypeIndex = someFrameTypeIndex;
      *qBit = someQBit;
      *frameSizeInBits = someFrameSizeInBits;
    }
    if ((int16_t)payloadSizeBytes < 0) {
      fprintf(stderr, "Error: payload too small for frame %u data\n", frameIndex);
      return false;
    }
  }
  return true;
}

EVS_RTPDUMP_DEPACKER_ERROR EVS_RTPDUMP_DEPACKER_open(EVS_RTPDUMP_DEPACKER *self, FILE *file, bool hf_only) {
  RTPDUMP_ERROR rtpdumpError;
  self->hf_only = hf_only;
  self->frameFollowing = false;
  rtpdumpError = RTPDUMP_OpenWithFileToRead(&self->rtpdump, file);
  if (rtpdumpError != RTPDUMP_NO_ERROR) {
    return EVS_RTPDUMP_DEPACKER_RTPDUMP_ERROR;
  }
  return EVS_RTPDUMP_DEPACKER_NO_ERROR;
}

EVS_RTPDUMP_DEPACKER_ERROR EVS_RTPDUMP_DEPACKER_readNextFrame(
    EVS_RTPDUMP_DEPACKER *self,
    uint16_t *rtpSequenceNumber,
    uint32_t *rtpTimeStamp,
    uint32_t *rcvTime_ms,
    bool *isAMRWB_IOmode,
    uint16_t *frameTypeIndex,
    bool *qBit,
    unsigned char **frame,
    uint16_t *frameSizeBits)
{
  /* read next RTP packet from rtpdump */
  if (!self->frameFollowing) {
    RTPDUMP_ERROR rtpdumpError = RTPDUMP_ReadPacket(self->rtpdump, &self->rtpPacket, &self->timeoffset_ms);
    if (rtpdumpError == RTPDUMP_READ_ENDOFFILE) {
      return EVS_RTPDUMP_DEPACKER_EOF;
    }
    else if (rtpdumpError != RTPDUMP_NO_ERROR) {
      return EVS_RTPDUMP_DEPACKER_RTPDUMP_ERROR;
    }
    self->frameIndex = 0;
  }
  /* unpack next frame from RTP packet */
  if (!evsPayload_unpackFrame(self->hf_only, self->rtpPacket.data + self->rtpPacket.headerSize,
                              self->rtpPacket.payloadSize, self->frameIndex,
                              isAMRWB_IOmode, &self->frameFollowing, frameTypeIndex, qBit,
                              frame, frameSizeBits))
  {
    return EVS_RTPDUMP_DEPACKER_PAYLOAD_ERROR;
  }
  /* return frame */
  *rtpSequenceNumber = self->rtpPacket.sequenceNumber;
  *rtpTimeStamp = self->rtpPacket.timeStamp + self->frameIndex * 16000 / 50;
  *rcvTime_ms = self->timeoffset_ms;
  ++self->frameIndex;
  return EVS_RTPDUMP_DEPACKER_NO_ERROR;
}

void EVS_RTPDUMP_DEPACKER_close(EVS_RTPDUMP_DEPACKER *self) {
  if (!self) {
    return;
  }
  RTPDUMP_Close(&self->rtpdump, 0);
}
