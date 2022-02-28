/*-
 * Copyright (c) 2012-2022 Hans Petter Selasky
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <assert.h>

#include <sys/queue.h>
#include <sys/types.h>

#include "virtual_int.h"
#include "virtual_backend.h"

static uint64_t
virtual_oss_delay(void)
{
	uint64_t delay;

	delay = voss_dsp_samples;
	delay *= 1000000000ULL;
	delay /= voss_dsp_sample_rate;

	return (delay);
}

uint64_t
virtual_oss_timestamp(void)
{
	struct timespec ts;
	uint64_t nsec;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	nsec = ((unsigned)ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
	return (nsec);
}

static size_t
vclient_read_linear(struct virtual_client *pvc, struct virtual_ring *pvr,
    int64_t *dst, size_t total)
{
	size_t total_read = 0;

	pvc->sync_busy = 1;
	while (1) {
		size_t read = vring_read_linear(pvr, (uint8_t *)dst, 8 * total) / 8;

		total_read += read;
		dst += read;
		total -= read;

		if (!pvc->profile->synchronized || pvc->sync_wakeup ||
		    total == 0) {
			/* fill rest of buffer with silence, if any */
			if (total_read != 0 && total != 0)
				memset(dst, 0, 8 * total);
			break;
		}
		atomic_wait();
	}
	pvc->sync_busy = 0;
	if (pvc->sync_wakeup)
		atomic_wakeup();

	vclient_tx_equalizer(pvc, dst - total_read, total_read);

	return (total_read);
}

static size_t
vclient_write_linear(struct virtual_client *pvc, struct virtual_ring *pvr,
    int64_t *src, size_t total)
{
	size_t total_written = 0;

	vclient_rx_equalizer(pvc, src, total);

	pvc->sync_busy = 1;
	while (1) {
		size_t written = vring_write_linear(pvr, (uint8_t *)src, total * 8) / 8;

		total_written += written;
		src += written;
		total -= written;

		if (!pvc->profile->synchronized || pvc->sync_wakeup ||
		    total == 0)
			break;
		atomic_wait();
	}
	pvc->sync_busy = 0;
	if (pvc->sync_wakeup)
		atomic_wakeup();

	return (total_written);
}

void   *
virtual_oss_process(void *arg)
{
	vprofile_t *pvp;
	vclient_t *pvc;
	vmonitor_t *pvm;
	struct voss_backend *rx_be = voss_rx_backend;
	struct voss_backend *tx_be = voss_tx_backend;
	int rx_fmt;
	int tx_fmt;
	int rx_chn;
	int tx_chn;
	int off;
	int src_chans;
	int dst_chans;
	int src;
	int len;
	int samples;
	int shift;
	int shift_orig;
	int shift_fmt;
	int buffer_dsp_max_size;
	int buffer_dsp_half_size;
	int buffer_dsp_rx_sample_size;
	int buffer_dsp_rx_size;
	int buffer_dsp_tx_size_ref;
	int buffer_dsp_tx_size;
	uint64_t nice_timeout = 0;
	uint64_t last_timestamp;
	int blocks;
	int volume;
	int x_off;
	int x;
	int y;

	uint8_t *buffer_dsp;
	int64_t *buffer_monitor;
	int64_t *buffer_temp;
	int64_t *buffer_data;
	int64_t *buffer_local;
	int64_t *buffer_orig;

	bool need_delay = false;
	
	buffer_dsp_max_size = voss_dsp_samples *
	    voss_dsp_max_channels * (voss_dsp_bits / 8);
	buffer_dsp_half_size = (voss_dsp_samples / 2) *
	    voss_dsp_max_channels * (voss_dsp_bits / 8);

	buffer_dsp = malloc(buffer_dsp_max_size);
	buffer_temp = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_monitor = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_local = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_data = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_orig = malloc(voss_dsp_samples * voss_max_channels * 8);

	if (buffer_dsp == NULL || buffer_temp == NULL ||
	    buffer_monitor == NULL || buffer_local == NULL ||
	    buffer_data == NULL || buffer_orig == NULL)
		errx(1, "Cannot allocate buffer memory");

	while (1) {
		rx_be->close(rx_be);
		tx_be->close(tx_be);

		if (need_delay)
			sleep(2);

		voss_dsp_rx_refresh = 0;
		voss_dsp_tx_refresh = 0;

		rx_be = voss_rx_backend;
		tx_be = voss_tx_backend;

		rx_fmt = voss_dsp_rx_fmt;
		rx_chn = voss_dsp_max_channels;

		if (rx_be->open(rx_be, voss_dsp_rx_device, voss_dsp_sample_rate,
		    buffer_dsp_half_size, &rx_chn, &rx_fmt) < 0) {
			need_delay = true;
			continue;
		}

		buffer_dsp_rx_sample_size = rx_chn * (voss_dsp_bits / 8);
		buffer_dsp_rx_size = voss_dsp_samples * buffer_dsp_rx_sample_size;

		tx_fmt = voss_dsp_tx_fmt;
		tx_chn = voss_dsp_max_channels;
		if (tx_be->open(tx_be, voss_dsp_tx_device, voss_dsp_sample_rate,
		    buffer_dsp_max_size, &tx_chn, &tx_fmt) < 0) {
			need_delay = true;
			continue;
		}

		buffer_dsp_tx_size_ref = voss_dsp_samples *
		    tx_chn * (voss_dsp_bits / 8);

		/* reset compressor gain */
		for (x = 0; x != VMAX_CHAN; x++)
			voss_output_compressor_gain[x] = 1.0;

		/* reset local buffer */
		memset(buffer_local, 0, 8 * voss_dsp_samples * voss_max_channels);

		while (1) {
			uint64_t delta_time;

			/* Check if DSP device should be re-opened */
			if (voss_dsp_rx_refresh || voss_dsp_tx_refresh) {
				need_delay = false;
				break;
			}
			delta_time = nice_timeout - virtual_oss_timestamp();

			/* Don't service more than 2x sample rate */
			nice_timeout = virtual_oss_delay() / 2;
			if (delta_time >= 1000 && delta_time <= nice_timeout) {
				/* convert from ns to us */
				usleep(delta_time / 1000);
			}
			/* Compute next timeout */
			nice_timeout += virtual_oss_timestamp();

			/* Read in samples */
			len = rx_be->transfer(rx_be, buffer_dsp, buffer_dsp_rx_size);
			if (len < 0 || (len % buffer_dsp_rx_sample_size) != 0) {
				need_delay = true;
				break;
			}
			if (len == 0)
				continue;

			/* Convert to 64-bit samples */
			format_import(rx_fmt, buffer_dsp, len, buffer_data);

			samples = len / buffer_dsp_rx_sample_size;
			src_chans = voss_mix_channels;

			/* Compute master input peak values */
			format_maximum(buffer_data, voss_input_peak, rx_chn, samples, 0);

			/* Remix format */
			format_remix(buffer_data, rx_chn, src_chans, samples);

			/* Refresh timestamp */
			last_timestamp = virtual_oss_timestamp();

			atomic_lock();

			if (TAILQ_FIRST(&virtual_monitor_input) != NULL) {
				/* make a copy of the input data, in case of remote monitoring */
				memcpy(buffer_monitor, buffer_data, 8 * samples * src_chans);
			}

			/* (0) Check for local monitoring of output data */

			TAILQ_FOREACH(pvm, &virtual_monitor_local, entry) {

				int64_t val;

				if (pvm->mute != 0 || pvm->src_chan >= src_chans ||
				    pvm->dst_chan >= src_chans)
					continue;

				src = pvm->src_chan;
				shift = pvm->shift;
				x = pvm->dst_chan;

				if (pvm->pol) {
					if (shift < 0) {
						shift = -shift;
						for (y = 0; y != samples; y++) {
							val = -(buffer_local[(y * src_chans) + src] >> shift);
							buffer_data[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					} else {
						for (y = 0; y != samples; y++) {
							val = -(buffer_local[(y * src_chans) + src] << shift);
							buffer_data[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					}
				} else {
					if (shift < 0) {
						shift = -shift;
						for (y = 0; y != samples; y++) {
							val = (buffer_local[(y * src_chans) + src] >> shift);
							buffer_data[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					} else {
						for (y = 0; y != samples; y++) {
							val = (buffer_local[(y * src_chans) + src] << shift);
							buffer_data[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					}
				}
			}

			/* make a copy of the input data */
			memcpy(buffer_orig, buffer_data, 8 * samples * src_chans);

			/* (1) Distribute input samples to all clients */

			TAILQ_FOREACH(pvp, &virtual_profile_client_head, entry) {

			    if (TAILQ_FIRST(&pvp->head) == NULL)
				continue;

			    /* check if compressor should be applied */
			    voss_compressor(buffer_data, pvp->rx_compressor_gain,
			        &pvp->rx_compressor_param, samples * src_chans,
				src_chans, (1ULL << (pvp->bits - 1)) - 1ULL);

			    TAILQ_FOREACH(pvc, &pvp->head, entry) {

				dst_chans = pvc->channels;

				if (dst_chans > voss_max_channels)
					continue;

				shift_fmt = pvp->bits - (vclient_sample_bytes(pvc) * 8);

				for (x = 0; x != dst_chans; x++) {
					src = pvp->rx_src[x];
					shift = pvp->rx_shift[x] - shift_fmt;

					if (pvp->rx_mute[x] || src >= src_chans) {
						for (y = 0; y != samples; y++) {
							buffer_temp[(y * dst_chans) + x] = 0;
						}
					} else {
						if (pvp->rx_pol[x]) {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * dst_chans) + x] =
									    -(buffer_data[(y * src_chans) + src] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * dst_chans) + x] =
									    -(buffer_data[(y * src_chans) + src] << shift);
								}
							}
						} else {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * dst_chans) + x] =
									    (buffer_data[(y * src_chans) + src] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * dst_chans) + x] =
									    (buffer_data[(y * src_chans) + src] << shift);
								}
							}
						}
					}
				}

				format_maximum(buffer_temp, pvp->rx_peak_value,
				    dst_chans, samples, shift_fmt);

				/* check if recording is disabled */
				if (pvc->rx_enabled == 0 ||
				    (voss_is_recording == 0 && pvc->type != VTYPE_OSS_DAT))
					continue;

				pvc->rx_timestamp = last_timestamp;
				pvc->rx_samples += samples * dst_chans;

				/* store data into ring buffer */
				vclient_write_linear(pvc, &pvc->rx_ring[0],
				    buffer_temp, samples * dst_chans);
			    }

			    /* restore buffer, if any */
			    if (pvp->rx_compressor_param.enabled)
				memcpy(buffer_data, buffer_orig, 8 * samples * src_chans);
			}

			/* fill main output buffer with silence */

			memset(buffer_temp, 0, sizeof(buffer_temp[0]) *
			    samples * src_chans);

			/* (2) Run audio delay locator */

			if (voss_ad_enabled != 0) {
				y = (samples * voss_mix_channels);
				for (x = 0; x != y; x += voss_mix_channels) {
					buffer_temp[x + voss_ad_output_channel] +=
					    voss_ad_getput_sample(buffer_data
					    [x + voss_ad_input_channel]);
				}
			}

			/* (3) Load output samples from all clients */

			TAILQ_FOREACH(pvp, &virtual_profile_client_head, entry) {
			    TAILQ_FOREACH(pvc, &pvp->head, entry) {

				if (pvc->tx_enabled == 0)
					continue;

				dst_chans = pvc->channels;

				if (dst_chans > voss_max_channels)
					continue;

				/* update counters regardless of data presence */
				pvc->tx_timestamp = last_timestamp;
				pvc->tx_samples += samples * dst_chans;

				/* read data from ring buffer */
				if (vclient_read_linear(pvc, &pvc->tx_ring[0],
				    buffer_data, samples * dst_chans) == 0)
					continue;

				shift_fmt = pvp->bits - (vclient_sample_bytes(pvc) * 8);

				format_maximum(buffer_data, pvp->tx_peak_value,
				    dst_chans, samples, shift_fmt);

				for (x = x_off = 0; x != pvp->channels; x++, x_off++) {
					src = pvp->tx_dst[x];
					shift_orig = pvp->tx_shift[x] + shift_fmt;
					shift = shift_orig - 7;
					volume = pvc->tx_volume;

					if (pvp->tx_mute[x] || src >= src_chans) {
						continue;
					} else {
						if (x_off >= dst_chans)
							x_off -= dst_chans;

						if (pvp->tx_pol[x]) {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) << shift);
								}
							}
						} else {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    ((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    ((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) << shift);
								}
							}
						}
						if (shift_orig > 0) {
							buffer_temp[(y * src_chans) + src] +=
							    vclient_noise(pvc, volume, shift_orig);
						}
					}
				}
			    }
			}

			/* (4) Load output samples from all loopbacks */

			TAILQ_FOREACH(pvp, &virtual_profile_loopback_head, entry) {
			    TAILQ_FOREACH(pvc, &pvp->head, entry) {

				if (pvc->tx_enabled == 0)
					continue;

				dst_chans = pvc->channels;

				if (dst_chans > voss_max_channels)
					continue;

				/* read data from ring buffer */
				if (vclient_read_linear(pvc, &pvc->tx_ring[0],
				    buffer_data, samples * dst_chans) == 0)
					continue;

				pvc->tx_timestamp = last_timestamp;
				pvc->tx_samples += samples * dst_chans;

				shift_fmt = pvp->bits - (vclient_sample_bytes(pvc) * 8);

				format_maximum(buffer_data, pvp->tx_peak_value,
				    dst_chans, samples, shift_fmt);

				for (x = x_off = 0; x != pvp->channels; x++, x_off++) {
					src = pvp->tx_dst[x];
					shift_orig = pvp->tx_shift[x] + shift_fmt;
					shift = shift_orig - 7;
					volume = pvc->tx_volume;

					if (pvp->tx_mute[x] || src >= src_chans) {
						continue;
					} else {
						if (x_off >= dst_chans)
							x_off -= dst_chans;

						if (pvp->tx_pol[x]) {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) << shift);
								}
							}
						} else {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    ((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    ((buffer_data[(y * dst_chans) + x_off] *
									    (int64_t)volume) << shift);
								}
							}
						}
						if (shift_orig > 0) {
							buffer_temp[(y * src_chans) + src] +=
							    vclient_noise(pvc, volume, shift_orig);
						}
					}
				}
			    }
			}

			/* (5) Check for input monitoring */

			TAILQ_FOREACH(pvm, &virtual_monitor_input, entry) {

				int64_t val;

				if (pvm->mute != 0 || pvm->src_chan >= src_chans ||
				    pvm->dst_chan >= src_chans)
					continue;

				src = pvm->src_chan;
				shift = pvm->shift;
				x = pvm->dst_chan;

				if (pvm->pol) {
					if (shift < 0) {
						shift = -shift;
						for (y = 0; y != samples; y++) {
							val = -(buffer_monitor[(y * src_chans) + src] >> shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					} else {
						for (y = 0; y != samples; y++) {
							val = -(buffer_monitor[(y * src_chans) + src] << shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					}
				} else {
					if (shift < 0) {
						shift = -shift;
						for (y = 0; y != samples; y++) {
							val = (buffer_monitor[(y * src_chans) + src] >> shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					} else {
						for (y = 0; y != samples; y++) {
							val = (buffer_monitor[(y * src_chans) + src] << shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					}
				}
			}

			if (TAILQ_FIRST(&virtual_monitor_output) != NULL) {
				memcpy(buffer_monitor, buffer_temp,
				    8 * samples * src_chans);
			}

			/* (6) Check for output monitoring */

			TAILQ_FOREACH(pvm, &virtual_monitor_output, entry) {

				int64_t val;

				if (pvm->mute != 0 || pvm->src_chan >= src_chans ||
				    pvm->dst_chan >= src_chans)
					continue;

				src = pvm->src_chan;
				shift = pvm->shift;
				x = pvm->dst_chan;

				if (pvm->pol) {
					if (shift < 0) {
						shift = -shift;
						for (y = 0; y != samples; y++) {
							val = -(buffer_monitor[(y * src_chans) + src] >> shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					} else {
						for (y = 0; y != samples; y++) {
							val = -(buffer_monitor[(y * src_chans) + src] << shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					}
				} else {
					if (shift < 0) {
						shift = -shift;
						for (y = 0; y != samples; y++) {
							val = (buffer_monitor[(y * src_chans) + src] >> shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					} else {
						for (y = 0; y != samples; y++) {
							val = (buffer_monitor[(y * src_chans) + src] << shift);
							buffer_temp[(y * src_chans) + x] += val;
							if (val < 0)
								val = -val;
							if (val > pvm->peak_value)
								pvm->peak_value = val;
						}
					}
				}
			}

			/* make a copy of the output data */
			memcpy(buffer_data, buffer_temp, 8 * samples * src_chans);

			/* make a copy for local monitoring, if any */
			if (TAILQ_FIRST(&virtual_monitor_local) != NULL) {
				const int end = src_chans * (voss_dsp_samples - samples);
				const int off = src_chans * samples;

				assert(end >= 0);

				/* shift down samples */
				for (int x = 0; x != end; x++)
					buffer_local[x] = buffer_local[x + off];
				/* copy in new ones */
				memcpy(buffer_local + end, buffer_temp, 8 * samples * src_chans);
			}

			/* (7) Check for output recording */

			TAILQ_FOREACH(pvp, &virtual_profile_loopback_head, entry) {

			    if (TAILQ_FIRST(&pvp->head) == NULL)
				continue;

			    /* check if compressor should be applied */
			    voss_compressor(buffer_temp, pvp->rx_compressor_gain,
				&pvp->rx_compressor_param, samples,
			        samples * src_chans, (1ULL << (pvp->bits - 1)) - 1ULL);

			    TAILQ_FOREACH(pvc, &pvp->head, entry) {

				dst_chans = pvc->channels;

				if (dst_chans > voss_max_channels)
					continue;

				shift_fmt = pvp->bits - (vclient_sample_bytes(pvc) * 8);

				for (x = 0; x != dst_chans; x++) {
					src = pvp->rx_src[x];
					shift = pvp->rx_shift[x] - shift_fmt;

					if (pvp->rx_mute[x] || src >= src_chans) {
						for (y = 0; y != samples; y++) {
							buffer_monitor[(y * dst_chans) + x] = 0;
						}
					} else {
						if (pvp->rx_pol[x]) {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_monitor[(y * dst_chans) + x] =
									    -(buffer_temp[(y * src_chans) + src] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_monitor[(y * dst_chans) + x] =
									    -(buffer_temp[(y * src_chans) + src] << shift);
								}
							}
						} else {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_monitor[(y * dst_chans) + x] =
									    (buffer_temp[(y * src_chans) + src] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_monitor[(y * dst_chans) + x] =
									    (buffer_temp[(y * src_chans) + src] << shift);
								}
							}
						}
					}
				}

				format_maximum(buffer_monitor, pvp->rx_peak_value,
				    dst_chans, samples, shift_fmt);

				/* check if recording is disabled */
				if (pvc->rx_enabled == 0 ||
				    (voss_is_recording == 0 && pvc->type != VTYPE_OSS_DAT))
					continue;

				pvc->rx_timestamp = last_timestamp;
				pvc->rx_samples += samples * dst_chans;
				
				/* store data into ring buffer */
				vclient_write_linear(pvc, &pvc->rx_ring[0],
				    buffer_monitor, samples * dst_chans);
			    }

			    /* restore buffer, if any */
			    if (pvp->rx_compressor_param.enabled)
				memcpy(buffer_temp, buffer_data, 8 * samples * src_chans);
			}

			atomic_wakeup();

			format_remix(buffer_temp, voss_mix_channels, tx_chn, samples);

			/* Compute master output peak values */

			format_maximum(buffer_temp, voss_output_peak,
			    tx_chn, samples, 0);

			/* Apply compressor, if any */

			voss_compressor(buffer_temp, voss_output_compressor_gain,
			    &voss_output_compressor_param, samples * tx_chn,
			    tx_chn, format_max(tx_fmt));

			/* Recompute buffer DSP transmit size according to received number of samples */

			buffer_dsp_tx_size = samples * tx_chn * (voss_dsp_bits / 8);

			/* Export and transmit resulting audio */

			format_export(tx_fmt, buffer_temp, buffer_dsp,
			    buffer_dsp_tx_size);

			atomic_unlock();

			/* Get output delay in bytes */
			tx_be->delay(tx_be, &blocks);

			/*
			 * Simple fix for jitter: Repeat data when too
			 * little. Skip data when too much. This
			 * should not happen during normal operation.
			 */
			if (blocks == 0) {
				blocks = 2;	/* buffer is empty */
				voss_jitter_up++;
			} else if (blocks >= (3 * buffer_dsp_tx_size_ref)) {
				blocks = 0;	/* too much data */
				voss_jitter_down++;
			} else {
				blocks = 1;	/* normal */
			}

			len = 0;
			while (blocks--) {
				off = 0;
				while (off < (int)buffer_dsp_tx_size) {
					len = tx_be->transfer(tx_be, buffer_dsp + off,
					    buffer_dsp_tx_size - off);
					if (len <= 0)
						break;
					off += len;
				}
				if (len <= 0)
					break;
			}

			/* check for error only */
			if (len < 0) {
				need_delay = true;
				break;
			}
		}
	}
	return (NULL);
}
