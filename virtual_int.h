/*-
 * Copyright (c) 2012-2018 Hans Petter Selasky. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _VIRTUAL_INT_H_
#define	_VIRTUAL_INT_H_

#include <samplerate.h>

#define	VMAX_CHAN 64
#define	VMAX_STRING 64	/* characters */

#define	VTYPE_OSS_DAT 0
#define	VTYPE_WAV_HDR 1
#define	VTYPE_WAV_DAT 2

#define	VPREFERRED_SNE_AFMT \
  (AFMT_S8 | AFMT_S16_NE | AFMT_S24_NE | AFMT_S32_NE)
#define	VPREFERRED_UNE_AFMT \
  (AFMT_U8 | AFMT_U16_NE | AFMT_U24_NE | AFMT_U32_NE)
#define	VPREFERRED_SLE_AFMT \
  (AFMT_S8 | AFMT_S16_LE | AFMT_S24_LE | AFMT_S32_LE)
#define	VPREFERRED_SBE_AFMT \
  (AFMT_S8 | AFMT_S16_BE | AFMT_S24_BE | AFMT_S32_BE)
#define	VPREFERRED_ULE_AFMT \
  (AFMT_U8 | AFMT_U16_LE | AFMT_U24_LE | AFMT_U32_LE)
#define	VPREFERRED_UBE_AFMT \
  (AFMT_U8 | AFMT_U16_BE | AFMT_U24_BE | AFMT_U32_BE)

#define	VSUPPORTED_AFMT \
  (AFMT_S16_BE | AFMT_S16_LE | AFMT_U16_BE | AFMT_U16_LE | \
  AFMT_S24_BE | AFMT_S24_LE | AFMT_U24_BE | AFMT_U24_LE | \
  AFMT_S32_BE | AFMT_S32_LE | AFMT_U32_BE | AFMT_U32_LE | \
  AFMT_U8 | AFMT_S8)

struct virtual_profile;

#if 0
{
#endif

typedef TAILQ_ENTRY(virtual_profile) vprofile_entry_t;
typedef TAILQ_HEAD(, virtual_profile) vprofile_head_t;
typedef struct virtual_profile vprofile_t;

struct virtual_client;

typedef TAILQ_ENTRY(virtual_client) vclient_entry_t;
typedef TAILQ_HEAD(, virtual_client) vclient_head_t;
typedef struct virtual_client vclient_t;

struct virtual_monitor;
typedef TAILQ_ENTRY(virtual_monitor) vmonitor_entry_t;
typedef TAILQ_HEAD(, virtual_monitor) vmonitor_head_t;
typedef struct virtual_monitor vmonitor_t;

struct virtual_resample;
typedef struct virtual_resample vresample_t;

#if 0
}
#endif

struct cuse_methods;

struct virtual_profile {
	vprofile_entry_t entry;
	char oss_name[VMAX_STRING];
	char wav_name[VMAX_STRING];
	vclient_head_t *pvc_head;
	int64_t	rx_peak_value[VMAX_CHAN];
	int64_t	tx_peak_value[VMAX_CHAN];
	int8_t	rx_shift[VMAX_CHAN];
	int8_t	tx_shift[VMAX_CHAN];
	uint8_t	rx_src[VMAX_CHAN];
	uint8_t	tx_dst[VMAX_CHAN];
	uint8_t	rx_mute[VMAX_CHAN];
	uint8_t	tx_mute[VMAX_CHAN];
	uint8_t	rx_pol[VMAX_CHAN];
	uint8_t	tx_pol[VMAX_CHAN];
	uint8_t	bits;
	uint8_t	channels;
	uint8_t	limiter;
	uint32_t rec_delay;
	int fd_sta;
	int synchronized:1;
	int padding:31;
};

struct virtual_ring {
	uint8_t *buf_start;
	uint32_t pos_read;
	uint32_t total_size;
	uint32_t len_write;
};

struct virtual_resample {
	SRC_DATA data;
	SRC_STATE *state;
	float *data_in;
	float *data_out;
};

struct virtual_client {
	vclient_entry_t entry;
	struct virtual_ring rx_ring[2];
  	struct virtual_ring tx_ring[2];
	vresample_t rx_resample;
	vresample_t tx_resample;
	struct virtual_profile *profile;
	uint64_t start_block;
	uint64_t last_ts;
	uint32_t buffer_frags;
	uint32_t buffer_size;
	uint32_t rec_delay;
	uint32_t noise_rem;
	int	rx_busy;
	int	tx_busy;
	int	channels;
	int	format;
	int	rx_enabled;
	int	tx_enabled;
	int	tx_volume;
	int	type;		/* VTYPE_XXX */
	int	sample_rate;
	int	buffer_size_set:1;
	int	buffer_frags_set:1;
	int	sync_busy:1;
	int	closing:1;
	int	padding:28;
};

struct virtual_monitor {
	vmonitor_entry_t entry;
	int64_t	peak_value;
	uint8_t	src_chan;
	uint8_t	dst_chan;
	uint8_t	pol;
	uint8_t	mute;
	int8_t	shift;
};

extern vclient_head_t virtual_client_head;
extern vclient_head_t virtual_loopback_head;

extern vprofile_head_t virtual_profile_client_head;
extern vprofile_head_t virtual_profile_loopback_head;

extern vmonitor_head_t virtual_monitor_input;
extern vmonitor_head_t virtual_monitor_output;

extern const struct cuse_methods vctl_methods;

extern uint8_t voss_output_group[VMAX_CHAN];
extern uint8_t voss_output_limiter[VMAX_CHAN];
extern int64_t voss_output_peak[VMAX_CHAN];
extern int64_t voss_input_peak[VMAX_CHAN];
extern uint32_t voss_max_channels;
extern uint32_t voss_mix_channels;
extern uint32_t voss_dsp_samples;
extern uint32_t voss_dsp_max_channels;
extern uint32_t voss_dsp_sample_rate;
extern uint32_t voss_dsp_bits;
extern uint32_t voss_dsp_rx_fmt;
extern uint32_t voss_dsp_tx_fmt;
extern uint8_t voss_libsamplerate_enable;
extern uint8_t voss_libsamplerate_quality;
extern uint64_t voss_dsp_blocks;
extern int voss_is_recording;
extern int voss_has_synchronization;
extern char voss_dsp_rx_device[VMAX_STRING];
extern char voss_dsp_tx_device[VMAX_STRING];
extern char voss_ctl_device[VMAX_STRING];
extern char voss_sta_device[VMAX_STRING];

extern void atomic_lock(void);
extern void atomic_unlock(void);
extern void atomic_wait(void);
extern void atomic_wakeup(void);

extern int vring_alloc(struct virtual_ring *, size_t);
extern void vring_free(struct virtual_ring *);
extern void vring_reset(struct virtual_ring *);
extern void vring_get_read(struct virtual_ring *, uint8_t **, size_t *);
extern void vring_get_write(struct virtual_ring *, uint8_t **, size_t *);
extern void vring_inc_read(struct virtual_ring *, size_t);
extern void vring_inc_write(struct virtual_ring *, size_t);
extern size_t vring_total_read_len(struct virtual_ring *);
extern size_t vring_total_write_len(struct virtual_ring *);
extern size_t vring_write_linear(struct virtual_ring *, const uint8_t *, size_t);
extern size_t vring_read_linear(struct virtual_ring *, uint8_t *, size_t);
extern size_t vring_write_zero(struct virtual_ring *, size_t);

extern uint32_t vclient_sample_bytes(vclient_t *);
extern uint32_t vclient_bufsize_internal(vclient_t *);
extern uint32_t vclient_bufsize_scaled(vclient_t *);

extern int64_t vclient_noise(vclient_t *, int64_t, int8_t);

extern vmonitor_t *vmonitor_alloc(int *, vmonitor_head_t *);

extern uint32_t format_best(uint32_t);
extern void format_import(uint32_t, const uint8_t *, uint32_t, int64_t *);
extern void format_export(uint32_t, const int64_t *, uint8_t *, uint32_t, const uint8_t *, uint8_t);
extern int64_t format_max(uint32_t);
extern void format_maximum(const int64_t *, int64_t *, uint32_t, uint32_t, int8_t);
extern void format_remix(int64_t *, uint32_t, uint32_t, uint32_t);
extern void format_silence(uint32_t, uint8_t *, uint32_t);

extern void *virtual_oss_process(void *);

/* Audio Delay prototypes */
extern uint32_t voss_ad_last_delay;
extern uint32_t voss_dsp_rx_refresh;
extern uint32_t voss_dsp_tx_refresh;
extern uint8_t voss_ad_enabled;
extern uint8_t voss_ad_output_signal;
extern uint8_t voss_ad_input_channel;
extern uint8_t voss_ad_output_channel;
extern void voss_ad_reset(void);
extern void voss_ad_init(uint32_t);
extern double voss_ad_getput_sample(double);

/* Add audio options prototype */
extern void voss_add_options(char *);

/* Get current timestamp */
uint64_t virtual_oss_timestamp(void);

#endif					/* _VIRTUAL_INT_H_ */
