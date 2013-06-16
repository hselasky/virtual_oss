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

#ifndef _VIRTUAL_OSS_H_
#define	_VIRTUAL_OSS_H_

#include <sys/ioccom.h>

#define	VIRTUAL_OSS_NAME_MAX	32
#define	VIRTUAL_OSS_VERSION 0x00010002
#define	VIRTUAL_OSS_LIMITER_MAX	64	/* exclusive */

#define	VIRTUAL_OSS_GET_VERSION		_IOR('O', 0, int)

struct virtual_oss_dev_info {
	char	name[VIRTUAL_OSS_NAME_MAX];
	int	number;
	int	channel;
	int	bits;
	int	rx_amp;
	int	tx_amp;
	int	rx_chan;
	int	tx_chan;
	int	rx_mute;
	int	tx_mute;
	int	rx_pol;
	int	tx_pol;
};

#define	VIRTUAL_OSS_GET_DEV_INFO	_IOWR('O', 1, struct virtual_oss_dev_info)
#define	VIRTUAL_OSS_SET_DEV_INFO	 _IOW('O', 2, struct virtual_oss_dev_info)

struct virtual_oss_mon_info {
	int	number;
	int	bits;
	int	src_chan;
	int	dst_chan;
	int	pol;
	int	mute;
	int	amp;
};

#define	VIRTUAL_OSS_GET_INPUT_MON_INFO	_IOWR('O', 3, struct virtual_oss_mon_info)
#define	VIRTUAL_OSS_SET_INPUT_MON_INFO	 _IOW('O', 4, struct virtual_oss_mon_info)
#define	VIRTUAL_OSS_GET_OUTPUT_MON_INFO	_IOWR('O', 5, struct virtual_oss_mon_info)
#define	VIRTUAL_OSS_SET_OUTPUT_MON_INFO	 _IOW('O', 6, struct virtual_oss_mon_info)

struct virtual_oss_dev_peak {
	char	name[VIRTUAL_OSS_NAME_MAX];
	int	number;
	int	channel;
	int	bits;
	long long rx_peak_value;
	long long tx_peak_value;
};

#define	VIRTUAL_OSS_GET_DEV_PEAK	_IOWR('O', 7, struct virtual_oss_dev_peak)

struct virtual_oss_mon_peak {
	int	number;
	int	bits;
	long long peak_value;
};

#define	VIRTUAL_OSS_GET_INPUT_MON_PEAK	_IOWR('O', 8, struct virtual_oss_dev_peak)
#define	VIRTUAL_OSS_GET_OUTPUT_MON_PEAK	_IOWR('O', 9, struct virtual_oss_dev_peak)

#define	VIRTUAL_OSS_ADD_INPUT_MON	 _IOR('O', 10, int)
#define	VIRTUAL_OSS_ADD_OUTPUT_MON	 _IOR('O', 11, int)

struct virtual_oss_output_chn_grp {
	int channel;
	int group;
};

#define	VIRTUAL_OSS_SET_OUTPUT_CHN_GRP	 _IOW('O', 12, struct virtual_oss_output_chn_grp)
#define	VIRTUAL_OSS_GET_OUTPUT_CHN_GRP	_IOWR('O', 13, struct virtual_oss_output_chn_grp)

struct virtual_oss_output_limit {
	int group;
	int limit;
};

#define	VIRTUAL_OSS_SET_OUTPUT_LIMIT	_IOW('O', 14, struct virtual_oss_output_limit)
#define	VIRTUAL_OSS_GET_OUTPUT_LIMIT   _IOWR('O', 15, struct virtual_oss_output_limit)

struct virtual_oss_dev_limit {
	int number;
	int limit;
};

#define	VIRTUAL_OSS_SET_DEV_LIMIT	_IOW('O', 16, struct virtual_oss_dev_limit)
#define	VIRTUAL_OSS_GET_DEV_LIMIT      _IOWR('O', 17, struct virtual_oss_dev_limit)

struct virtual_oss_master_peak {
	int	channel;
	int	bits;
	long long peak_value;
};

#define	VIRTUAL_OSS_GET_OUTPUT_PEAK	_IOWR('O', 18, struct virtual_oss_master_peak)
#define	VIRTUAL_OSS_GET_INPUT_PEAK	_IOWR('O', 19, struct virtual_oss_master_peak)

#endif					/* _VIRTUAL_OSS_H_ */
