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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <time.h>

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

	int64_t fmt_max;
	uint8_t fmt_limit[VMAX_CHAN];

	bool need_delay = false;
	
	buffer_dsp_max_size = voss_dsp_samples *
	    voss_dsp_max_channels * (voss_dsp_bits / 8);
	buffer_dsp_half_size = (voss_dsp_samples / 2) *
	    voss_dsp_max_channels * (voss_dsp_bits / 8);

	buffer_dsp = malloc(buffer_dsp_max_size);
	buffer_temp = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_monitor = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_data = malloc(voss_dsp_samples * voss_max_channels * 8);

	if (buffer_dsp == NULL || buffer_temp == NULL ||
	    buffer_monitor == NULL || buffer_data == NULL)
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

		buffer_dsp_tx_size = voss_dsp_samples *
		    tx_chn * (voss_dsp_bits / 8);

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
				memcpy(buffer_monitor, buffer_data,
				    8 * samples * src_chans);
			}
			/*
			 * -- 1 -- Distribute input samples to all
			 * client devices
			 */
			TAILQ_FOREACH(pvc, &virtual_client_head, entry) {

				dst_chans = pvc->channels;

				if (dst_chans > src_chans)
					continue;

				shift_fmt = pvc->profile->bits - (vclient_sample_bytes(pvc) * 8);

				for (x = 0; x != dst_chans; x++) {
					src = pvc->profile->rx_src[x];
					shift = pvc->profile->rx_shift[x] - shift_fmt;

					if (pvc->profile->rx_mute[x] || src >= src_chans) {
						for (y = 0; y != samples; y++) {
							buffer_temp[(y * dst_chans) + x] = 0;
						}
					} else {
						if (pvc->profile->rx_pol[x]) {
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

				format_maximum(buffer_temp, pvc->profile->rx_peak_value,
				    pvc->channels, samples, shift_fmt);

				/* Update limiter */
				fmt_max = (1LL << (pvc->profile->bits - 1)) - 1LL;
				for (x = 0; x != VMAX_CHAN; x++) {
					while ((pvc->profile->rx_peak_value[x] >>
					    pvc->profile->limiter) > fmt_max) {
						pvc->profile->limiter++;
					}
				}
				if (pvc->rx_enabled == 0)
					continue;

				pvc->rx_timestamp = last_timestamp;
				pvc->rx_samples += samples * dst_chans;

				/* store data into ring buffer */
				vclient_write_linear(pvc, &pvc->rx_ring[0],
				    buffer_temp, samples * dst_chans);
			}

			/* fill main output buffer with silence */

			memset(buffer_temp, 0, sizeof(buffer_temp[0]) *
			    samples * src_chans);

			/* -- 2.0 -- Run audio delay locator */

			if (voss_ad_enabled != 0) {
				y = (samples * voss_mix_channels);
				for (x = 0; x != y; x += voss_mix_channels) {
					buffer_temp[x + voss_ad_output_channel] +=
					    voss_ad_getput_sample(buffer_data
					    [x + voss_ad_input_channel]);
				}
			}
			/*
			 * -- 2.1 -- Load output samples from all client
			 * devices
			 */
			TAILQ_FOREACH(pvc, &virtual_client_head, entry) {

				if (pvc->tx_enabled == 0)
					continue;

				dst_chans = pvc->channels;

				/* read data from ring buffer */
				if (vclient_read_linear(pvc, &pvc->tx_ring[0],
				    buffer_data, samples * dst_chans) == 0)
					continue;

				pvc->tx_timestamp = last_timestamp;
				pvc->tx_samples += samples * dst_chans;

				shift_fmt = pvc->profile->bits - (vclient_sample_bytes(pvc) * 8);

				format_maximum(buffer_data, pvc->profile->tx_peak_value,
				    dst_chans, samples, shift_fmt);

				for (x = x_off = 0; x != pvc->profile->channels; x++, x_off++) {
					src = pvc->profile->tx_dst[x];
					shift_orig = pvc->profile->tx_shift[x] + shift_fmt;
					shift = shift_orig - 7;
					volume = pvc->tx_volume;

					if (pvc->profile->tx_mute[x] || src >= src_chans) {
						continue;
					} else {
						if (x_off >= dst_chans)
							x_off -= dst_chans;

						if (pvc->profile->tx_pol[x]) {
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

			/*
			 * -- 2.2 -- Load output samples from all loopback
			 * devices
			 */
			TAILQ_FOREACH(pvc, &virtual_loopback_head, entry) {

				if (pvc->tx_enabled == 0)
					continue;

				dst_chans = pvc->channels;

				/* read data from ring buffer */
				if (vclient_read_linear(pvc, &pvc->tx_ring[0],
				    buffer_data, samples * dst_chans) == 0)
					continue;

				pvc->tx_timestamp = last_timestamp;
				pvc->tx_samples += samples * dst_chans;

				shift_fmt = pvc->profile->bits - (vclient_sample_bytes(pvc) * 8);

				format_maximum(buffer_data, pvc->profile->tx_peak_value,
				    dst_chans, samples, shift_fmt);

				for (x = x_off = 0; x != pvc->profile->channels; x++, x_off++) {
					src = pvc->profile->tx_dst[x];
					shift_orig = pvc->profile->tx_shift[x] + shift_fmt;
					shift = shift_orig - 7;
					volume = pvc->tx_volume;

					if (pvc->profile->tx_mute[x] || src >= src_chans) {
						continue;
					} else {
						if (x_off >= dst_chans)
							x_off -= dst_chans;

						if (pvc->profile->tx_pol[x]) {
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

			/* -- 3 -- Check for input monitoring */

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
			/* -- 4 -- Check for output monitoring */

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

			/* -- 5 -- Check for output recording */

			TAILQ_FOREACH(pvc, &virtual_loopback_head, entry) {

				dst_chans = pvc->channels;

				if (dst_chans > src_chans)
					continue;

				shift_fmt = pvc->profile->bits - (vclient_sample_bytes(pvc) * 8);

				for (x = 0; x != dst_chans; x++) {
					src = pvc->profile->rx_src[x];
					shift = pvc->profile->rx_shift[x] - shift_fmt;

					if (pvc->profile->rx_mute[x] || src >= src_chans) {
						for (y = 0; y != samples; y++) {
							buffer_monitor[(y * dst_chans) + x] = 0;
						}
					} else {
						if (pvc->profile->rx_pol[x]) {
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

				format_maximum(buffer_monitor, pvc->profile->rx_peak_value,
				    pvc->channels, samples, shift_fmt);

				/* Update limiter */
				fmt_max = (1LL << (pvc->profile->bits - 1)) - 1LL;
				for (x = 0; x != VMAX_CHAN; x++) {
					while ((pvc->profile->rx_peak_value[x] >>
					    pvc->profile->limiter) > fmt_max) {
						pvc->profile->limiter++;
					}
				}
				if (pvc->rx_enabled == 0)
					continue;

				pvc->rx_timestamp = last_timestamp;
				pvc->rx_samples += samples * dst_chans;
				
				/* store data into ring buffer */
				vclient_write_linear(pvc, &pvc->rx_ring[0],
				    buffer_monitor, samples * dst_chans);
			}

			atomic_wakeup();

			format_remix(buffer_temp, voss_mix_channels, tx_chn, samples);

			/* Compute master output peak values */

			format_maximum(buffer_temp, voss_output_peak,
			    tx_chn, samples, 0);

			/* Update limiter */
			fmt_max = format_max(tx_fmt);

			for (x = 0; x != VMAX_CHAN; x++) {
				y = voss_output_group[x];
				while ((voss_output_peak[x] >> voss_output_limiter[y]) > fmt_max)
					voss_output_limiter[y]++;
				fmt_limit[x] = voss_output_limiter[y];
			}

			/* Export and transmit resulting audio */

			format_export(tx_fmt, buffer_temp, buffer_dsp,
			    buffer_dsp_tx_size, fmt_limit, tx_chn);

			atomic_unlock();

			/* Get output delay in bytes */
			tx_be->delay(tx_be, &blocks);

			/*
			 * Simple fix for jitter: Repeat data when too
			 * little. Skip data when too much. This
			 * should not happen during normal operation.
			 */
			if (blocks == 0)
				blocks = 2;	/* buffer is empty */
			else if (blocks > (4 * buffer_dsp_tx_size))
				blocks = 0;	/* too much data */
			else
				blocks = 1;	/* normal */

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
