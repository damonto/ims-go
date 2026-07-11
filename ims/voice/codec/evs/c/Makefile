CC := clang
WASI_SYSROOT ?= /usr/share/wasi-sysroot
TARGET ?= ../evs.wasm
BUILD := build

include sources.mk

CPPFLAGS := -Ilib_com -Ilib_enc -Ilib_dec
CFLAGS := --target=wasm32-wasip1 --sysroot=$(WASI_SYSROOT) -D__unix__ -std=c11 -O2 \
	-ffunction-sections -fdata-sections -ffp-contract=off -fvisibility=hidden \
	-Wall -Wextra -Wno-unused-parameter -Wno-unused-function
# The reference codec keeps its large persistent state on the heap. Two MiB
# leaves conservative headroom for temporary call stacks without charging each
# call-scoped module for the previous eight MiB reservation.
LDFLAGS := --target=wasm32-wasip1 --sysroot=$(WASI_SYSROOT) -nostartfiles \
	$(WASI_SYSROOT)/lib/wasm32-wasip1/crt1-reactor.o \
	-Wl,--no-entry -Wl,--gc-sections -Wl,--export-memory \
	-Wl,--export=evs_abi_version \
	-Wl,--export=evs_encoder_create \
	-Wl,--export=evs_encoder_destroy \
	-Wl,--export=evs_encoder_reset \
	-Wl,--export=evs_encoder_configure \
	-Wl,--export=evs_encoder_pcm_ptr \
	-Wl,--export=evs_encoder_output_ptr \
	-Wl,--export=evs_encoder_frame_samples \
	-Wl,--export=evs_encoder_delay_samples \
	-Wl,--export=evs_encoder_encode \
	-Wl,--export=evs_encoder_result \
	-Wl,--export=evs_decoder_create \
	-Wl,--export=evs_decoder_destroy \
	-Wl,--export=evs_decoder_reset \
	-Wl,--export=evs_decoder_input_ptr \
	-Wl,--export=evs_decoder_input_capacity \
	-Wl,--export=evs_decoder_output_ptr \
	-Wl,--export=evs_decoder_frame_samples \
	-Wl,--export=evs_decoder_delay_samples \
	-Wl,--export=evs_decoder_decode \
	-Wl,-z,stack-size=2097152 -Wl,--max-memory=134217728

OBJECTS := $(patsubst %.c,$(BUILD)/%.o,$(SOURCES))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -lm -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD) $(TARGET)
