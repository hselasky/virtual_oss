/*-
 * Copyright (c) 2012-2019 Hans Petter Selasky. All rights reserved.
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

#ifndef _VIRTUAL_OSS_H_
#define	_VIRTUAL_OSS_H_

#include <sys/ioccom.h>

#define	VIRTUAL_OSS_NAME_MAX	32
#define	VIRTUAL_OSS_VERSION 0x00010006
#define	VIRTUAL_OSS_LIMITER_MAX	64	/* exclusive */
#define	VIRTUAL_OSS_OPTIONS_MAX	1024	/* bytes */
#define	VIRTUAL_OSS_FILTER_MAX 65536	/* samples */

#define	VIRTUAL_OSS_GET_VERSION		_IOR('O', 0, int)

struct virtual_oss_io_info {
	int	number;			/* must be first */
	int	channel;
	char	name[VIRTUAL_OSS_NAME_MAX];
	int	bits;
	int	rx_amp;
	int	tx_amp;
	int	rx_chan;
	int	tx_chan;
	int	rx_mute;
	int	tx_mute;
	int	rx_pol;
	int	tx_pol;
	int	rx_delay;		/* in samples */
	int	rx_delay_limit;		/* in samples */
};

#define	VIRTUAL_OSS_GET_DEV_INFO	_IOWR('O', 1, struct virtual_oss_io_info)
#define	VIRTUAL_OSS_SET_DEV_INFO	 _IOW('O', 2, struct virtual_oss_io_info)

#define	VIRTUAL_OSS_GET_LOOP_INFO	_IOWR('O', 3, struct virtual_oss_io_info)
#define	VIRTUAL_OSS_SET_LOOP_INFO	 _IOW('O', 4, struct virtual_oss_io_info)

struct virtual_oss_mon_info {
	int	number;
	int	bits;
	int	src_chan;
	int	dst_chan;
	int	pol;
	int	mute;
	int	amp;
};

#define	VIRTUAL_OSS_GET_INPUT_MON_INFO	_IOWR('O', 5, struct virtual_oss_mon_info)
#define	VIRTUAL_OSS_SET_INPUT_MON_INFO	 _IOW('O', 6, struct virtual_oss_mon_info)

#define	VIRTUAL_OSS_GET_OUTPUT_MON_INFO	_IOWR('O', 7, struct virtual_oss_mon_info)
#define	VIRTUAL_OSS_SET_OUTPUT_MON_INFO	 _IOW('O', 8, struct virtual_oss_mon_info)

struct virtual_oss_io_peak {
	int	number;			/* must be first */
	int	channel;
	char	name[VIRTUAL_OSS_NAME_MAX];
	int	bits;
	long long rx_peak_value;
	long long tx_peak_value;
};

#define	VIRTUAL_OSS_GET_DEV_PEAK	_IOWR('O', 9, struct virtual_oss_io_peak)
#define	VIRTUAL_OSS_GET_LOOP_PEAK	_IOWR('O', 10, struct virtual_oss_io_peak)

struct virtual_oss_mon_peak {
	int	number;
	int	bits;
	long long peak_value;
};

#define	VIRTUAL_OSS_GET_INPUT_MON_PEAK	_IOWR('O', 11, struct virtual_oss_mon_peak)
#define	VIRTUAL_OSS_GET_OUTPUT_MON_PEAK	_IOWR('O', 12, struct virtual_oss_mon_peak)

#define	VIRTUAL_OSS_ADD_INPUT_MON	 _IOR('O', 13, int)
#define	VIRTUAL_OSS_ADD_OUTPUT_MON	 _IOR('O', 14, int)

struct virtual_oss_output_chn_grp {
	int	channel;
	int	group;
};

#define	VIRTUAL_OSS_SET_OUTPUT_CHN_GRP	 _IOW('O', 15, struct virtual_oss_output_chn_grp)
#define	VIRTUAL_OSS_GET_OUTPUT_CHN_GRP	_IOWR('O', 16, struct virtual_oss_output_chn_grp)

struct virtual_oss_output_limit {
	int	group;
	int	limit;
};

#define	VIRTUAL_OSS_SET_OUTPUT_LIMIT	_IOW('O', 17, struct virtual_oss_output_limit)
#define	VIRTUAL_OSS_GET_OUTPUT_LIMIT   _IOWR('O', 18, struct virtual_oss_output_limit)

struct virtual_oss_io_limit {
	int	number;			/* must be first */
	int	limit;
};

#define	VIRTUAL_OSS_SET_DEV_LIMIT	_IOW('O', 19, struct virtual_oss_io_limit)
#define	VIRTUAL_OSS_GET_DEV_LIMIT      _IOWR('O', 20, struct virtual_oss_io_limit)

#define	VIRTUAL_OSS_SET_LOOP_LIMIT	_IOW('O', 21, struct virtual_oss_io_limit)
#define	VIRTUAL_OSS_GET_LOOP_LIMIT      _IOWR('O', 22, struct virtual_oss_io_limit)

struct virtual_oss_master_peak {
	int	channel;
	int	bits;
	long long peak_value;
};

#define	VIRTUAL_OSS_GET_OUTPUT_PEAK	_IOWR('O', 23, struct virtual_oss_master_peak)
#define	VIRTUAL_OSS_GET_INPUT_PEAK	_IOWR('O', 24, struct virtual_oss_master_peak)

#define	VIRTUAL_OSS_SET_RECORDING	_IOW('O', 25, int)
#define	VIRTUAL_OSS_GET_RECORDING	_IOR('O', 26, int)

struct virtual_oss_audio_delay_locator {
	int	channel_output;
	int	channel_input;
	int	channel_last;
	int	signal_output_level;	/* 2**n */
	int	signal_input_delay;	/* in samples, roundtrip */
	int	signal_delay_hz;	/* in samples, HZ */
	int	locator_enabled;
};

#define	VIRTUAL_OSS_SET_AUDIO_DELAY_LOCATOR	_IOW('O', 27, struct virtual_oss_audio_delay_locator)
#define	VIRTUAL_OSS_GET_AUDIO_DELAY_LOCATOR	_IOR('O', 28, struct virtual_oss_audio_delay_locator)
#define	VIRTUAL_OSS_RST_AUDIO_DELAY_LOCATOR	_IO('O', 29)

struct virtual_oss_midi_delay_locator {
	int	channel_output;
	int	channel_input;
	int	signal_delay;
	int	signal_delay_hz;	/* in samples, HZ */
	int	locator_enabled;
};

#define	VIRTUAL_OSS_SET_MIDI_DELAY_LOCATOR	_IOW('O', 30, struct virtual_oss_midi_delay_locator)
#define	VIRTUAL_OSS_GET_MIDI_DELAY_LOCATOR	_IOR('O', 31, struct virtual_oss_midi_delay_locator)
#define	VIRTUAL_OSS_RST_MIDI_DELAY_LOCATOR	_IO('O', 32)

#define	VIRTUAL_OSS_ADD_OPTIONS			_IOWR('O', 33, char [VIRTUAL_OSS_OPTIONS_MAX])

struct virtual_oss_fir_filter {
	int	number;			/* must be first */
	int	filter_size;
	double *filter_data;
};

#define	VIRTUAL_OSS_GET_RX_DEV_FIR_FILTER	_IOWR('O', 34, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_SET_RX_DEV_FIR_FILTER	_IOWR('O', 35, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_GET_TX_DEV_FIR_FILTER	_IOWR('O', 36, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_SET_TX_DEV_FIR_FILTER	_IOWR('O', 37, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_GET_RX_LOOP_FIR_FILTER	_IOWR('O', 38, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_SET_RX_LOOP_FIR_FILTER	_IOWR('O', 39, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_GET_TX_LOOP_FIR_FILTER	_IOWR('O', 40, struct virtual_oss_fir_filter)
#define	VIRTUAL_OSS_SET_TX_LOOP_FIR_FILTER	_IOWR('O', 41, struct virtual_oss_fir_filter)

#define	VIRTUAL_OSS_GET_SAMPLE_RATE		_IOR('O', 42, int)
  
#endif					/* _VIRTUAL_OSS_H_ */
