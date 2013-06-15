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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/queue.h>

#include <cuse4bsd.h>

#include "virtual_int.h"

#include "virtual_oss.h"

uint8_t voss_output_group[VMAX_CHAN];
uint8_t voss_output_limiter[VMAX_CHAN];
int64_t voss_output_peak[VMAX_CHAN];

static int
vctl_open(struct cuse_dev *pdev, int fflags)
{
	return (0);
}

static int
vctl_close(struct cuse_dev *pdev, int fflags)
{
	return (0);
}

static vprofile_t *
vprofile_by_index(int index)
{
	vprofile_t *pvp;

	TAILQ_FOREACH(pvp, &virtual_profile_head, entry) {
		if (!index--)
			return (pvp);
	}
	return (NULL);
}

static vmonitor_t *
vmonitor_by_index(int index, vmonitor_head_t *phead)
{
	vmonitor_t *pvm;

	TAILQ_FOREACH(pvm, phead, entry) {
		if (!index--)
			return (pvm);
	}
	return (NULL);
}

static int
vctl_ioctl(struct cuse_dev *pdev, int fflags,
    unsigned long cmd, void *peer_data)
{
	union {
		int	val;
		struct virtual_oss_dev_info dev_info;
		struct virtual_oss_mon_info mon_info;
		struct virtual_oss_dev_peak dev_peak;
		struct virtual_oss_mon_peak mon_peak;
		struct virtual_oss_output_chn_grp out_chg;
		struct virtual_oss_output_limit out_lim;
		struct virtual_oss_dev_limit dev_lim;
		struct virtual_oss_output_peak out_peak;
	}     data;

	vprofile_t *pvp;
	vmonitor_t *pvm;

	int chan;
	int len;
	int error;

	len = IOCPARM_LEN(cmd);

	if (len < 0 || len > (int)sizeof(data))
		return (CUSE_ERR_INVALID);

	if (cmd & IOC_IN) {
		error = cuse_copy_in(peer_data, &data, len);
		if (error)
			return (error);
	} else {
		error = 0;
	}

	atomic_lock();

	switch (cmd) {
	case VIRTUAL_OSS_GET_VERSION:
		data.val = VIRTUAL_OSS_VERSION;
		break;
	case VIRTUAL_OSS_GET_DEV_INFO:
		pvp = vprofile_by_index(data.dev_info.number);
		if (pvp == NULL ||
		    data.dev_info.channel < 0 ||
		    data.dev_info.channel >= (int)pvp->channels) {
			error = CUSE_ERR_INVALID;
			break;
		}
		strlcpy(data.dev_info.name, pvp->name, sizeof(data.dev_info.name));
		chan = data.dev_info.channel;
		data.dev_info.rx_amp = pvp->rx_shift[chan];
		data.dev_info.tx_amp = pvp->tx_shift[chan];
		data.dev_info.rx_chan = pvp->rx_src[chan];
		data.dev_info.tx_chan = pvp->tx_dst[chan];
		data.dev_info.rx_mute = pvp->rx_mute[chan] ? 1 : 0;
		data.dev_info.tx_mute = pvp->tx_mute[chan] ? 1 : 0;
		data.dev_info.rx_pol = pvp->rx_pol[chan] ? 1 : 0;
		data.dev_info.tx_pol = pvp->tx_pol[chan] ? 1 : 0;
		data.dev_info.bits = pvp->bits;
		break;
	case VIRTUAL_OSS_SET_DEV_INFO:
		pvp = vprofile_by_index(data.dev_info.number);
		if (pvp == NULL ||
		    data.dev_info.channel < 0 ||
		    data.dev_info.channel >= (int)pvp->channels ||
		    data.dev_info.rx_amp < -31 || data.dev_info.rx_amp > 31 ||
		    data.dev_info.tx_amp < -31 || data.dev_info.tx_amp > 31) {
			error = CUSE_ERR_INVALID;
			break;
		}
		chan = data.dev_info.channel;
		pvp->rx_shift[chan] = data.dev_info.rx_amp;
		pvp->tx_shift[chan] = data.dev_info.tx_amp;
		pvp->rx_src[chan] = data.dev_info.rx_chan;
		pvp->tx_dst[chan] = data.dev_info.tx_chan;
		pvp->rx_mute[chan] = data.dev_info.rx_mute ? 1 : 0;
		pvp->tx_mute[chan] = data.dev_info.tx_mute ? 1 : 0;
		pvp->rx_pol[chan] = data.dev_info.rx_pol ? 1 : 0;
		pvp->tx_pol[chan] = data.dev_info.tx_pol ? 1 : 0;
		break;
	case VIRTUAL_OSS_GET_INPUT_MON_INFO:
		pvm = vmonitor_by_index(data.mon_info.number,
		    &virtual_monitor_input);
		if (pvm == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.mon_info.src_chan = pvm->src_chan;
		data.mon_info.dst_chan = pvm->dst_chan;
		data.mon_info.pol = pvm->pol;
		data.mon_info.mute = pvm->mute;
		data.mon_info.amp = pvm->shift;
		data.mon_info.bits = voss_dsp_bits;
		break;
	case VIRTUAL_OSS_SET_INPUT_MON_INFO:
		pvm = vmonitor_by_index(data.mon_info.number,
		    &virtual_monitor_input);
		if (pvm == NULL ||
		    data.mon_info.amp < -31 ||
		    data.mon_info.amp > 31) {
			error = CUSE_ERR_INVALID;
			break;
		}
		pvm->src_chan = data.mon_info.src_chan;
		pvm->dst_chan = data.mon_info.dst_chan;
		pvm->pol = data.mon_info.pol ? 1 : 0;
		pvm->mute = data.mon_info.mute ? 1 : 0;
		pvm->shift = data.mon_info.amp;
		break;
	case VIRTUAL_OSS_GET_OUTPUT_MON_INFO:
		pvm = vmonitor_by_index(data.mon_info.number,
		    &virtual_monitor_output);
		if (pvm == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.mon_info.src_chan = pvm->src_chan;
		data.mon_info.dst_chan = pvm->dst_chan;
		data.mon_info.pol = pvm->pol;
		data.mon_info.mute = pvm->mute;
		data.mon_info.amp = pvm->shift;
		data.mon_info.bits = voss_dsp_bits;
		break;
	case VIRTUAL_OSS_SET_OUTPUT_MON_INFO:
		pvm = vmonitor_by_index(data.mon_info.number,
		    &virtual_monitor_output);
		if (pvm == NULL ||
		    data.mon_info.amp < -31 ||
		    data.mon_info.amp > 31) {
			error = CUSE_ERR_INVALID;
			break;
		}
		pvm->src_chan = data.mon_info.src_chan;
		pvm->dst_chan = data.mon_info.dst_chan;
		pvm->pol = data.mon_info.pol ? 1 : 0;
		pvm->mute = data.mon_info.mute ? 1 : 0;
		pvm->shift = data.mon_info.amp;
		break;
	case VIRTUAL_OSS_GET_DEV_PEAK:
		pvp = vprofile_by_index(data.dev_peak.number);
		if (pvp == NULL ||
		    data.dev_peak.channel < 0 ||
		    data.dev_peak.channel >= (int)pvp->channels) {
			error = CUSE_ERR_INVALID;
			break;
		}
		strlcpy(data.dev_peak.name, pvp->name, sizeof(data.dev_peak.name));
		chan = data.dev_peak.channel;
		data.dev_peak.rx_peak_value = pvp->rx_peak_value[chan];
		pvp->rx_peak_value[chan] = 0;
		data.dev_peak.tx_peak_value = pvp->tx_peak_value[chan];
		pvp->tx_peak_value[chan] = 0;
		data.dev_peak.bits = pvp->bits;
		break;
	case VIRTUAL_OSS_GET_INPUT_MON_PEAK:
		pvm = vmonitor_by_index(data.mon_peak.number,
		    &virtual_monitor_input);
		if (pvm == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.mon_peak.peak_value = pvm->peak_value;
		data.mon_peak.bits = voss_dsp_bits;
		pvm->peak_value = 0;
		break;
	case VIRTUAL_OSS_GET_OUTPUT_MON_PEAK:
		pvm = vmonitor_by_index(data.mon_peak.number,
		    &virtual_monitor_output);
		if (pvm == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.mon_peak.peak_value = pvm->peak_value;
		data.mon_peak.bits = voss_dsp_bits;
		pvm->peak_value = 0;
		break;
	case VIRTUAL_OSS_ADD_INPUT_MON:
		pvm = vmonitor_alloc(&data.val,
		    &virtual_monitor_input);
		if (pvm == NULL)
			error = CUSE_ERR_INVALID;
		break;
	case VIRTUAL_OSS_ADD_OUTPUT_MON:
		pvm = vmonitor_alloc(&data.val,
		    &virtual_monitor_output);
		if (pvm == NULL)
			error = CUSE_ERR_INVALID;
		break;
	case VIRTUAL_OSS_SET_OUTPUT_CHN_GRP:
		if (data.out_chg.channel < 0 ||
		    data.out_chg.channel >= (int)voss_dsp_channels ||
		    data.out_chg.group < 0 || 
		    data.out_chg.group >= VMAX_CHAN) {
			error = CUSE_ERR_INVALID;
			break;
		}
		voss_output_group[data.out_chg.channel] = data.out_chg.group;
		break;
	case VIRTUAL_OSS_GET_OUTPUT_CHN_GRP:
		if (data.out_chg.channel < 0 ||
		    data.out_chg.channel >= (int)voss_dsp_channels) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.out_chg.group = voss_output_group[data.out_chg.channel];
		break;
	case VIRTUAL_OSS_SET_OUTPUT_LIMIT:
		if (data.out_lim.group < 0 ||
		    data.out_lim.group >= VMAX_CHAN ||
		    data.out_lim.limit < 0 ||
		    data.out_lim.limit >= VIRTUAL_OSS_LIMITER_MAX) {
			error = CUSE_ERR_INVALID;
			break;
		}
		voss_output_limiter[data.out_lim.group] = data.out_lim.limit;
		break;
	case VIRTUAL_OSS_GET_OUTPUT_LIMIT:
		if (data.out_lim.group < 0 ||
		    data.out_lim.group >= VMAX_CHAN) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.out_lim.limit = voss_output_limiter[data.out_lim.group];
		break;
	case VIRTUAL_OSS_SET_DEV_LIMIT:
		pvp = vprofile_by_index(data.dev_peak.number);
		if (pvp == NULL ||
		    data.dev_lim.limit < 0 ||
		    data.dev_lim.limit >= VIRTUAL_OSS_LIMITER_MAX) {
			error = CUSE_ERR_INVALID;
			break;
		}
		pvp->limiter = data.dev_lim.limit;
		break;
	case VIRTUAL_OSS_GET_DEV_LIMIT:
		pvp = vprofile_by_index(data.dev_peak.number);
		if (pvp == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.dev_lim.limit = pvp->limiter;
		break;
	case VIRTUAL_OSS_GET_OUTPUT_PEAK:
		chan = data.out_peak.channel;
		if (chan < 0 ||
		    chan >= (int)voss_dsp_channels) {
			error = CUSE_ERR_INVALID;
			break;
		}
		data.out_peak.bits = voss_dsp_bits;
		data.out_peak.peak_value = voss_output_peak[chan];
		voss_output_peak[chan] = 0;
		break;
	default:
		error = CUSE_ERR_INVALID;
		break;
	}

	atomic_unlock();

	if (error == 0) {
		if (cmd & IOC_OUT)
			error = cuse_copy_out(&data, peer_data, len);
	}
	return (error);
}

const struct cuse_methods vctl_methods = {
	.cm_open = vctl_open,
	.cm_close = vctl_close,
	.cm_ioctl = vctl_ioctl,
};
