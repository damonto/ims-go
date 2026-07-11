#ifndef IMS_GO_EVS_SHIM_H
#define IMS_GO_EVS_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    EVS_ABI_VERSION = 2,
    EVS_OK = 0,
    EVS_ERR_ARGUMENT = -1,
    EVS_ERR_MEMORY = -2,
    EVS_ERR_SAMPLE_RATE = -3,
    EVS_ERR_BITRATE = -4,
    EVS_ERR_BANDWIDTH = -5,
    EVS_ERR_FRAME = -6
};

uint32_t evs_abi_version(void);

uint32_t evs_encoder_create(int32_t sample_rate, int32_t bitrate, int32_t bandwidth,
                            int32_t dtx, int32_t rf_offset, int32_t rf_indicator);
void evs_encoder_destroy(uint32_t handle);
int32_t evs_encoder_reset(uint32_t handle);
int32_t evs_encoder_configure(uint32_t handle, int32_t bitrate, int32_t bandwidth,
                              int32_t dtx, int32_t rf_offset, int32_t rf_indicator);
uint32_t evs_encoder_pcm_ptr(uint32_t handle);
uint32_t evs_encoder_output_ptr(uint32_t handle);
int32_t evs_encoder_frame_samples(uint32_t handle);
int32_t evs_encoder_delay_samples(uint32_t handle);
int32_t evs_encoder_encode(uint32_t handle);
uint64_t evs_encoder_result(uint32_t handle);

uint32_t evs_decoder_create(int32_t sample_rate);
void evs_decoder_destroy(uint32_t handle);
int32_t evs_decoder_reset(uint32_t handle);
uint32_t evs_decoder_input_ptr(uint32_t handle);
int32_t evs_decoder_input_capacity(uint32_t handle);
uint32_t evs_decoder_output_ptr(uint32_t handle);
int32_t evs_decoder_frame_samples(uint32_t handle);
int32_t evs_decoder_delay_samples(uint32_t handle);
int32_t evs_decoder_decode(uint32_t handle, int32_t core_bits, int32_t is_amrwb_io,
                           int32_t frame_type, int32_t quality, int32_t partial,
                           int32_t next_coder_type);

#ifdef __cplusplus
}
#endif

#endif
