#include "evs_shim.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cnst.h"
#include "prot.h"
#include "stat_dec.h"
#include "stat_enc.h"

#define EVS_EXPORT __attribute__((visibility("default")))
#define EVS_AU_CAPACITY ((MAX_BITS_PER_FRAME + 7) / 8)

typedef struct {
    Encoder_State state;
    Indice indices[MAX_NUM_INDICES];
    short pcm[L_FRAME48k];
    UWord8 output[EVS_AU_CAPACITY];
    int bitrate;
    short bandwidth;
    short dtx;
    short rf_offset;
    short rf_indicator;
    short frame_type;
    short is_amrwb_io;
    short core_bits;
    short output_bytes;
    short initialized;
} EvsEncoder;

typedef struct {
    Decoder_State state;
    UWord8 input[EVS_AU_CAPACITY];
    float synthesis[L_FRAME48k];
    short pcm[L_FRAME48k];
} EvsDecoder;

static int valid_sample_rate(int sample_rate)
{
    return sample_rate == 8000 || sample_rate == 16000 ||
           sample_rate == 32000 || sample_rate == 48000;
}

static int is_amrwb_bitrate(int bitrate)
{
    switch (bitrate) {
    case ACELP_6k60:
    case ACELP_8k85:
    case ACELP_12k65:
    case ACELP_14k25:
    case ACELP_15k85:
    case ACELP_18k25:
    case ACELP_19k85:
    case ACELP_23k05:
    case ACELP_23k85:
        return 1;
    default:
        return 0;
    }
}

static int native_codec_mode(int bitrate)
{
    switch (bitrate) {
    case 2800:
    case ACELP_5k90:
    case ACELP_7k20:
    case ACELP_8k00:
    case ACELP_13k20:
    case ACELP_32k:
    case ACELP_64k:
        return MODE1;
    case ACELP_9k60:
    case ACELP_16k40:
    case ACELP_24k40:
    case ACELP_48k:
    case 96000:
    case 128000:
        return MODE2;
    default:
        return 0;
    }
}

static int encoder_configure(EvsEncoder *encoder, int bitrate, int bandwidth,
                             int dtx, int rf_offset, int rf_indicator)
{
    Encoder_State *st;
    int codec_mode;
    int amrwb_io;
    int sc_vbr;
    int actual_bitrate;
    int old_rf;
    int new_rf;

    if (encoder == NULL) {
        return EVS_ERR_ARGUMENT;
    }
    if (bandwidth < NB || bandwidth > FB) {
        return EVS_ERR_BANDWIDTH;
    }
    if (rf_offset != 0 && rf_offset != 2 && rf_offset != 3 &&
        rf_offset != 5 && rf_offset != 7) {
        return EVS_ERR_ARGUMENT;
    }
    if (rf_indicator != 0 && rf_indicator != 1) {
        return EVS_ERR_ARGUMENT;
    }

    amrwb_io = is_amrwb_bitrate(bitrate);
    sc_vbr = bitrate == ACELP_5k90;
    actual_bitrate = sc_vbr ? ACELP_7k20 : bitrate;
    codec_mode = amrwb_io ? MODE1 : native_codec_mode(bitrate);
    if (codec_mode == 0 || (sc_vbr && !dtx)) {
        return EVS_ERR_BITRATE;
    }

    st = &encoder->state;
    old_rf = st->Opt_RF_ON;
    if (st->input_Fs == 8000 && bandwidth > NB) {
        bandwidth = NB;
    } else if (st->input_Fs == 16000 && bandwidth > WB) {
        bandwidth = WB;
    } else if (st->input_Fs == 32000 && bandwidth > SWB) {
        bandwidth = SWB;
    }
    if ((st->input_Fs == 8000 || bandwidth == NB) && actual_bitrate > ACELP_24k40) {
        return EVS_ERR_BITRATE;
    }

    st->total_brate = actual_bitrate;
    st->Opt_AMR_WB = (short)amrwb_io;
    st->Opt_DTX_ON = dtx != 0;
    st->Opt_SC_VBR = (short)sc_vbr;
    st->max_bwidth = (short)bandwidth;
    st->codec_mode = (short)codec_mode;
    new_rf = 0;
    st->Opt_RF_ON = 0;
    st->rf_fec_offset = 0;
    st->rf_fec_indicator = (short)rf_indicator;
    if (!amrwb_io && actual_bitrate == ACELP_13k20 && st->input_Fs != 8000 &&
        bandwidth != NB && rf_offset != 0) {
        st->codec_mode = MODE2;
        st->Opt_RF_ON = 1;
        st->rf_fec_offset = (short)rf_offset;
        new_rf = 1;
    }
    if (encoder->initialized && old_rf != new_rf) {
        reset_rf_indices(st);
    }

    encoder->bitrate = bitrate;
    encoder->bandwidth = (short)bandwidth;
    encoder->dtx = dtx != 0;
    encoder->rf_offset = (short)rf_offset;
    encoder->rf_indicator = (short)rf_indicator;
    return EVS_OK;
}

static int encoder_init(EvsEncoder *encoder, int sample_rate, int bitrate,
                        int bandwidth, int dtx, int rf_offset, int rf_indicator)
{
    Encoder_State *st = &encoder->state;
    int result;

    memset(st, 0, sizeof(*st));
    encoder->initialized = 0;
    memset(encoder->indices, 0, sizeof(encoder->indices));
    st->input_Fs = sample_rate;
    st->ind_list = encoder->indices;
    st->interval_SID = FIXED_SID_RATE;
    st->var_SID_rate_flag = 0;
    st->rf_fec_indicator = 1;
    st->bitstreamformat = MIME;
    result = encoder_configure(encoder, bitrate, bandwidth, dtx, rf_offset, rf_indicator);
    if (result != EVS_OK) {
        return result;
    }
    st->last_codec_mode = st->codec_mode;
    st->last_Opt_SC_VBR = st->Opt_SC_VBR;
    init_encoder(st);
    encoder->initialized = 1;
    return EVS_OK;
}

static int native_frame_type(int bits)
{
    switch (bits) {
    case 56: return 0;
    case 144: return 1;
    case 160: return 2;
    case 192: return 3;
    case 264: return 4;
    case 328: return 5;
    case 488: return 6;
    case 640: return 7;
    case 960: return 8;
    case 1280: return 9;
    case 1920: return 10;
    case 2560: return 11;
    case 48: return 12;
    case 0: return 15;
    default: return -1;
    }
}

static int amrwb_frame_type(int bits)
{
    switch (bits) {
    case 132: return 0;
    case 177: return 1;
    case 253: return 2;
    case 285: return 3;
    case 317: return 4;
    case 365: return 5;
    case 397: return 6;
    case 461: return 7;
    case 477: return 8;
    case 35: return 9;
    case 0: return 15;
    default: return -1;
    }
}

EVS_EXPORT uint32_t evs_abi_version(void)
{
    return EVS_ABI_VERSION;
}

EVS_EXPORT uint32_t evs_encoder_create(int32_t sample_rate, int32_t bitrate,
                                       int32_t bandwidth, int32_t dtx,
                                       int32_t rf_offset, int32_t rf_indicator)
{
    EvsEncoder *encoder;
    int result;

    if (!valid_sample_rate(sample_rate)) {
        return 0;
    }
    encoder = (EvsEncoder *)calloc(1, sizeof(*encoder));
    if (encoder == NULL) {
        return 0;
    }
    result = encoder_init(encoder, sample_rate, bitrate, bandwidth, dtx,
                          rf_offset, rf_indicator);
    if (result != EVS_OK) {
        free(encoder);
        return 0;
    }
    return (uint32_t)(uintptr_t)encoder;
}

EVS_EXPORT void evs_encoder_destroy(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    if (encoder == NULL) {
        return;
    }
    destroy_encoder(&encoder->state);
    free(encoder);
}

EVS_EXPORT int32_t evs_encoder_reset(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    int sample_rate;
    int bitrate;
    int bandwidth;
    int dtx;
    int rf_offset;
    int rf_indicator;

    if (encoder == NULL) {
        return EVS_ERR_ARGUMENT;
    }
    sample_rate = encoder->state.input_Fs;
    bitrate = encoder->bitrate;
    bandwidth = encoder->bandwidth;
    dtx = encoder->dtx;
    rf_offset = encoder->rf_offset;
    rf_indicator = encoder->rf_indicator;
    destroy_encoder(&encoder->state);
    memset(encoder->pcm, 0, sizeof(encoder->pcm));
    memset(encoder->output, 0, sizeof(encoder->output));
    return encoder_init(encoder, sample_rate, bitrate, bandwidth, dtx,
                        rf_offset, rf_indicator);
}

EVS_EXPORT int32_t evs_encoder_configure(uint32_t handle, int32_t bitrate,
                                         int32_t bandwidth, int32_t dtx,
                                         int32_t rf_offset, int32_t rf_indicator)
{
    return encoder_configure((EvsEncoder *)(uintptr_t)handle, bitrate, bandwidth,
                             dtx, rf_offset, rf_indicator);
}

EVS_EXPORT uint32_t evs_encoder_pcm_ptr(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    return encoder == NULL ? 0 : (uint32_t)(uintptr_t)encoder->pcm;
}

EVS_EXPORT uint32_t evs_encoder_output_ptr(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    return encoder == NULL ? 0 : (uint32_t)(uintptr_t)encoder->output;
}

EVS_EXPORT int32_t evs_encoder_frame_samples(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    return encoder == NULL ? EVS_ERR_ARGUMENT : encoder->state.input_Fs / 50;
}

EVS_EXPORT int32_t evs_encoder_delay_samples(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    return encoder == NULL ? EVS_ERR_ARGUMENT :
           NS2SA(encoder->state.input_Fs, get_delay(ENC, encoder->state.input_Fs) + 0.5f);
}

EVS_EXPORT int32_t evs_encoder_encode(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;
    Encoder_State *st;
    Word16 bits = 0;
    int frame_type;

    if (encoder == NULL) {
        return EVS_ERR_ARGUMENT;
    }
    st = &encoder->state;
    memset(encoder->output, 0, sizeof(encoder->output));
    if (st->Opt_AMR_WB) {
        amr_wb_enc(st, encoder->pcm, (short)(st->input_Fs / 50));
    } else {
        evs_enc(st, encoder->pcm, (short)(st->input_Fs / 50));
    }
    indices_to_serial(st, encoder->output, &bits);
    frame_type = st->Opt_AMR_WB ? amrwb_frame_type(bits) : native_frame_type(bits);
    if (frame_type < 0) {
        reset_indices_enc(st);
        return EVS_ERR_FRAME;
    }
    encoder->frame_type = (short)frame_type;
    encoder->is_amrwb_io = st->Opt_AMR_WB;
    encoder->core_bits = bits;
    encoder->output_bytes = (short)((bits + 7) / 8);
    if (st->Opt_AMR_WB && bits == 35) {
        encoder->output_bytes = 5;
    }
    reset_indices_enc(st);
    return EVS_OK;
}

EVS_EXPORT uint64_t evs_encoder_result(uint32_t handle)
{
    EvsEncoder *encoder = (EvsEncoder *)(uintptr_t)handle;

    if (encoder == NULL) {
        return 0;
    }
    return (uint64_t)(uint8_t)encoder->frame_type |
           ((uint64_t)(uint8_t)encoder->is_amrwb_io << 8) |
           ((uint64_t)(uint16_t)encoder->core_bits << 16) |
           ((uint64_t)(uint16_t)encoder->output_bytes << 32);
}

static int decoder_init(EvsDecoder *decoder, int sample_rate)
{
    Decoder_State *st = &decoder->state;

    memset(st, 0, sizeof(*st));
    st->output_Fs = sample_rate;
    st->bitstreamformat = VOIP_RTPDUMP;
    st->amrwb_rfc4867_flag = 1;
    st->Opt_VOIP = 1;
    init_decoder(st);
    reset_indices_dec(st);
    return EVS_OK;
}

EVS_EXPORT uint32_t evs_decoder_create(int32_t sample_rate)
{
    EvsDecoder *decoder;

    if (!valid_sample_rate(sample_rate)) {
        return 0;
    }
    decoder = (EvsDecoder *)calloc(1, sizeof(*decoder));
    if (decoder == NULL) {
        return 0;
    }
    if (decoder_init(decoder, sample_rate) != EVS_OK) {
        free(decoder);
        return 0;
    }
    return (uint32_t)(uintptr_t)decoder;
}

EVS_EXPORT void evs_decoder_destroy(uint32_t handle)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    if (decoder == NULL) {
        return;
    }
    destroy_decoder(&decoder->state);
    free(decoder);
}

EVS_EXPORT int32_t evs_decoder_reset(uint32_t handle)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    int sample_rate;

    if (decoder == NULL) {
        return EVS_ERR_ARGUMENT;
    }
    sample_rate = decoder->state.output_Fs;
    destroy_decoder(&decoder->state);
    memset(decoder->input, 0, sizeof(decoder->input));
    memset(decoder->synthesis, 0, sizeof(decoder->synthesis));
    memset(decoder->pcm, 0, sizeof(decoder->pcm));
    return decoder_init(decoder, sample_rate);
}

EVS_EXPORT uint32_t evs_decoder_input_ptr(uint32_t handle)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    return decoder == NULL ? 0 : (uint32_t)(uintptr_t)decoder->input;
}

EVS_EXPORT int32_t evs_decoder_input_capacity(uint32_t handle)
{
    return handle == 0 ? EVS_ERR_ARGUMENT : EVS_AU_CAPACITY;
}

EVS_EXPORT uint32_t evs_decoder_output_ptr(uint32_t handle)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    return decoder == NULL ? 0 : (uint32_t)(uintptr_t)decoder->pcm;
}

EVS_EXPORT int32_t evs_decoder_frame_samples(uint32_t handle)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    return decoder == NULL ? EVS_ERR_ARGUMENT : decoder->state.output_Fs / 50;
}

EVS_EXPORT int32_t evs_decoder_delay_samples(uint32_t handle)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    return decoder == NULL ? EVS_ERR_ARGUMENT :
           NS2SA(decoder->state.output_Fs, get_delay(DEC, decoder->state.output_Fs) + 0.5f);
}

EVS_EXPORT int32_t evs_decoder_decode(uint32_t handle, int32_t core_bits,
                                      int32_t is_amrwb_io, int32_t frame_type,
                                      int32_t quality, int32_t partial,
                                      int32_t next_coder_type)
{
    EvsDecoder *decoder = (EvsDecoder *)(uintptr_t)handle;
    Decoder_State *st;
    int frame_mode;

    if (decoder == NULL || core_bits < 0 || core_bits > MAX_BITS_PER_FRAME ||
        (is_amrwb_io != 0 && is_amrwb_io != 1) ||
        (quality != 0 && quality != 1) ||
        (partial != 0 && partial != 1)) {
        return EVS_ERR_ARGUMENT;
    }
    st = &decoder->state;
    read_indices_from_djb(st, core_bits == 0 ? NULL : decoder->input, core_bits,
                          (Word16)is_amrwb_io, (Word16)frame_type, (Word16)quality,
                          (short)partial, (short)next_coder_type);
    if (partial) {
        st->codec_mode = MODE2;
        st->use_partial_copy = 1;
    }

    if (st->codec_mode == MODE1) {
        if (st->Opt_AMR_WB) {
            amr_wb_dec(st, decoder->synthesis);
        } else {
            evs_dec(st, decoder->synthesis, FRAMEMODE_NORMAL);
        }
    } else if (st->codec_mode == MODE2) {
        frame_mode = st->bfi == 0 ? FRAMEMODE_NORMAL :
                     (st->bfi == 2 ? FRAMEMODE_FUTURE : FRAMEMODE_MISSING);
        evs_dec(st, decoder->synthesis, frame_mode);
    } else {
        memset(decoder->pcm, 0, sizeof(short) * (size_t)(st->output_Fs / 50));
        return EVS_OK;
    }

    syn_output(decoder->synthesis, (short)(st->output_Fs / 50), decoder->pcm);
    if (st->ini_frame < MAX_FRAME_COUNTER) {
        st->ini_frame++;
    }
    return EVS_OK;
}
