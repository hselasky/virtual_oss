/*-
 * Copyright (c) 2012 Hans Petter Selasky. All rights reserved.
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

#define	VMAX_CHAN 64
#define	VMAX_FRAGS 16

struct virtual_profile;

typedef TAILQ_ENTRY(virtual_profile) vprofile_entry_t;
typedef TAILQ_HEAD(,virtual_profile) vprofile_head_t;
typedef struct virtual_profile vprofile_t;

struct virtual_block;

typedef TAILQ_ENTRY(virtual_block) vblock_entry_t;
typedef TAILQ_HEAD(,virtual_block) vblock_head_t;
typedef struct virtual_block vblock_t;

struct virtual_client;

typedef TAILQ_ENTRY(virtual_client) vclient_entry_t;
typedef TAILQ_HEAD(,virtual_client) vclient_head_t;
typedef struct virtual_client vclient_t;

struct virtual_monitor;

typedef TAILQ_ENTRY(virtual_monitor) vmonitor_entry_t;
typedef TAILQ_HEAD(,virtual_monitor) vmonitor_head_t;
typedef struct virtual_monitor vmonitor_t;

struct cuse_methods;

struct virtual_profile {
	vprofile_entry_t entry;
	const char *name;
	vclient_head_t *pvc_head;
	int64_t rx_peak_value[VMAX_CHAN];
	int64_t tx_peak_value[VMAX_CHAN];
	int8_t rx_shift[VMAX_CHAN];
	int8_t tx_shift[VMAX_CHAN];
	uint8_t rx_src[VMAX_CHAN];
	uint8_t tx_dst[VMAX_CHAN];
	uint8_t rx_mute[VMAX_CHAN];
	uint8_t tx_mute[VMAX_CHAN];
	uint8_t rx_pol[VMAX_CHAN];
	uint8_t tx_pol[VMAX_CHAN];
	uint8_t bits;
	uint8_t channels;
	uint8_t limiter;
	uint32_t bufsize;
	uint32_t rate;
};

struct virtual_block {
	vblock_entry_t entry;
	uint8_t *buf_start;
	uint32_t buf_size;
	uint32_t buf_pos;
};

struct virtual_client {
	vclient_entry_t entry;
	vblock_head_t rx_ready;
	vblock_head_t rx_free;
	vblock_head_t tx_ready;
	vblock_head_t tx_free;
	struct virtual_profile *profile;
	int rx_busy;
	int tx_busy;
	int mono;
	int format;
	int rx_enabled;
	int tx_enabled;
};

struct virtual_monitor {
	vmonitor_entry_t entry;
	int64_t peak_value;
	uint8_t src_chan;
	uint8_t dst_chan;
	uint8_t pol;
	uint8_t mute;
	int8_t shift;
};

extern vclient_head_t virtual_client_head;
extern vclient_head_t virtual_loopback_head;
extern vprofile_head_t virtual_profile_head;

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
extern uint32_t voss_dsp_channels;
extern uint32_t voss_dsp_sample_rate;
extern uint32_t voss_dsp_bits;
extern uint32_t voss_dsp_fmt;
extern const char *voss_dsp_rx_device;
extern const char *voss_dsp_tx_device;
extern const char *voss_ctl_device;

extern void atomic_lock(void);
extern void atomic_unlock(void);
extern void atomic_wait(void);
extern void atomic_wakeup(void);

extern vblock_t *vblock_peek(vblock_head_t *);
extern void vblock_insert(vblock_t *, vblock_head_t *);
extern void vblock_remove(vblock_t *, vblock_head_t *);
extern vmonitor_t *vmonitor_alloc(int *, vmonitor_head_t *);

extern void format_import(uint32_t, const uint8_t *, uint32_t, int64_t *);
extern void format_export(uint32_t, const int64_t *, uint8_t *, uint32_t, const uint8_t *, uint8_t);
extern int64_t format_max(uint32_t);
extern void format_maximum(const int64_t *, int64_t *, uint32_t, uint32_t);
extern void format_remix(int64_t *, uint32_t, uint32_t, uint32_t);

extern void *virtual_oss_process(void *);

#endif		/* _VIRTUAL_INT_H_ */
