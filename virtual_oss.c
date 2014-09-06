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
#include <fcntl.h>
#include <unistd.h>
#include <err.h>

#include <sys/soundcard.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/filio.h>

#include "virtual_int.h"

void   *
virtual_oss_process(void *arg)
{
	vclient_t *pvc;
	vblock_t *pvb;
	vmonitor_t *pvm;
	int fd_rx = -1;
	int fd_tx = -1;
	int off;
	int afmt;
	int src_chans;
	int dst_chans;
	int src;
	int len;
	int samples;
	int shift;
	int buffer_dsp_max_size;
	int buffer_dsp_rx_size;
	int buffer_dsp_tx_size;
	int blocks;
	int x;
	int y;

	uint8_t *buffer_dsp;
	int64_t *buffer_monitor;
	int64_t *buffer_temp;
	int64_t *buffer_data;

	int64_t fmt_max;
	uint8_t fmt_limit[VMAX_CHAN];

	buffer_dsp_max_size = voss_dsp_samples *
	    voss_dsp_max_channels * (voss_dsp_bits / 8);

	afmt = voss_dsp_fmt;

	buffer_dsp = malloc(buffer_dsp_max_size);
	buffer_temp = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_monitor = malloc(voss_dsp_samples * voss_max_channels * 8);
	buffer_data = malloc(voss_dsp_samples * voss_max_channels * 8);

	if (buffer_dsp == NULL || buffer_temp == NULL ||
	    buffer_monitor == NULL || buffer_data == NULL)
		errx(1, "Cannot allocate buffer memory");

	while (1) {
		if (fd_rx > -1) {
			close(fd_rx);
			sleep(1);
		}
		if (fd_tx > -1) {
			close(fd_tx);
			sleep(1);
		}
		fd_rx = open(voss_dsp_rx_device, O_RDONLY);
		if (fd_rx < 0) {
			warn("Could not open %s", voss_dsp_rx_device);
			sleep(1);
			continue;
		}
		fd_tx = open(voss_dsp_tx_device, O_WRONLY);
		if (fd_tx < 0) {
			warn("Could not open %s", voss_dsp_tx_device);
			sleep(1);
			continue;
		}

		blocks = 0;
		len = ioctl(fd_rx, FIONBIO, &blocks);
		if (len < 0) {
			warn("Could not set blocking mode on DSP");
			continue;
		}
		blocks = 0;
		len = ioctl(fd_tx, FIONBIO, &blocks);
		if (len < 0) {
			warn("Could not set blocking mode on DSP");
			continue;
		}
		blocks = voss_dsp_fmt;
		len = ioctl(fd_rx, SNDCTL_DSP_SETFMT, &blocks);
		if (len < 0) {
			warn("Could not set FMT=0x%08x", blocks);
			continue;
		}
		blocks = voss_dsp_fmt;
		len = ioctl(fd_tx, SNDCTL_DSP_SETFMT, &blocks);
		if (len < 0) {
			warn("Could not set FMT=0x%08x", blocks);
			continue;
		}
		blocks = voss_dsp_max_channels;
		len = ioctl(fd_tx, SOUND_PCM_WRITE_CHANNELS, &blocks);
		if (len < 0 || (unsigned)blocks > voss_dsp_max_channels) {
			warn("Could not set TX CHANNELS=%d/%d", blocks, (int)voss_dsp_max_channels);
			continue;
		}
		voss_dsp_tx_channels = blocks;
		buffer_dsp_tx_size = voss_dsp_samples *
		    voss_dsp_tx_channels * (voss_dsp_bits / 8);

		blocks = voss_dsp_max_channels;
		len = ioctl(fd_rx, SOUND_PCM_READ_CHANNELS, &blocks);
		if (len < 0 || (unsigned)blocks > voss_dsp_max_channels) {
			warn("Could not set RX CHANNELS=%d/%d", blocks, (int)voss_dsp_max_channels);
			continue;
		}
		voss_dsp_rx_channels = blocks;
		buffer_dsp_rx_size = voss_dsp_samples *
		    voss_dsp_rx_channels * (voss_dsp_bits / 8);

		blocks = voss_dsp_sample_rate;
		len = ioctl(fd_rx, SNDCTL_DSP_SPEED, &blocks);
		if (len < 0) {
			warn("Could not set SPEED=%d Hz", blocks);
			continue;
		}
		blocks = voss_dsp_sample_rate;
		len = ioctl(fd_tx, SNDCTL_DSP_SPEED, &blocks);
		if (len < 0) {
			warn("Could not set SPEED=%d Hz", blocks);
			continue;
		}
		while (1) {

			off = 0;
			len = 0;

			while (off < (int)buffer_dsp_rx_size) {
				len = read(fd_rx, buffer_dsp + off,
				    buffer_dsp_rx_size - off);
				if (len <= 0)
					break;
				off += len;
			}
			if (len <= 0)
				break;

			format_import(afmt, buffer_dsp,
			    buffer_dsp_rx_size, buffer_data);

			/* Compute master input peak values */

			format_maximum(buffer_data, voss_input_peak,
			    voss_dsp_rx_channels, voss_dsp_samples);

			format_remix(buffer_data,
			    voss_dsp_rx_channels,
			    voss_mix_channels,
			    voss_dsp_samples);

			samples = voss_dsp_samples;
			src_chans = voss_mix_channels;

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

				dst_chans = pvc->profile->channels;
				pvb = vblock_peek(&pvc->rx_free);

				if (dst_chans > src_chans)
					continue;

				for (x = 0; x != dst_chans; x++) {
					src = pvc->profile->rx_src[x];
					shift = pvc->profile->rx_shift[x];

					if (pvc->profile->rx_mute[x] ||
					    src >= src_chans) {
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
				    pvc->profile->channels, samples);

				/* Update limiter */
				fmt_max = (1LL << (pvc->profile->bits - 1)) - 1LL;
				for (x = 0; x != VMAX_CHAN; x++) {
					while ((pvc->profile->rx_peak_value[x] >>
					    pvc->profile->limiter) > fmt_max) {
						pvc->profile->limiter++;
					}
				}
				for (x = 0; x != VMAX_CHAN; x++)
					fmt_limit[x] = pvc->profile->limiter;

				if (pvb == NULL || pvc->rx_enabled == 0 || voss_is_recording == 0)
					continue;

				format_export(pvc->format, buffer_temp,
				    pvb->buf_start, pvb->buf_size,
				    fmt_limit, pvc->profile->channels);

				vblock_remove(pvb, &pvc->rx_free);
				vblock_insert(pvb, &pvc->rx_ready);
			}

			/* fill main output buffer with silence */

			memset(buffer_temp, 0, sizeof(buffer_temp[0]) *
			    samples * src_chans);

			/* -- 2.0 -- Run audio delay locator */

			if (voss_ad_enabled != 0) {
				y = (voss_dsp_samples * voss_mix_channels);
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

				pvb = vblock_peek(&pvc->tx_ready);

				if (pvb == NULL || pvc->tx_enabled == 0)
					continue;

				format_import(pvc->format, pvb->buf_start, pvb->buf_size, buffer_data);

				format_maximum(buffer_data, pvc->profile->tx_peak_value,
				    pvc->profile->channels, samples);

				dst_chans = pvc->profile->channels;

				for (x = 0; x != dst_chans; x++) {
					src = pvc->profile->tx_dst[x];
					shift = pvc->profile->tx_shift[x];

					if (pvc->profile->tx_mute[x] || src >= src_chans) {
						continue;
					} else {
						if (pvc->profile->tx_pol[x]) {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -(buffer_data[(y * dst_chans) + x] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -(buffer_data[(y * dst_chans) + x] << shift);
								}
							}
						} else {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    (buffer_data[(y * dst_chans) + x] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    (buffer_data[(y * dst_chans) + x] << shift);
								}
							}
						}
					}
				}

				vblock_remove(pvb, &pvc->tx_ready);
				vblock_insert(pvb, &pvc->tx_free);
			}

			/*
			 * -- 2.2 -- Load output samples from all loopback
			 * devices
			 */

			TAILQ_FOREACH(pvc, &virtual_loopback_head, entry) {

				pvb = vblock_peek(&pvc->tx_ready);

				if (pvb == NULL || pvc->tx_enabled == 0)
					continue;

				format_import(pvc->format, pvb->buf_start, pvb->buf_size, buffer_data);

				format_maximum(buffer_data, pvc->profile->tx_peak_value,
				    pvc->profile->channels, samples);

				dst_chans = pvc->profile->channels;

				for (x = 0; x != dst_chans; x++) {
					src = pvc->profile->tx_dst[x];
					shift = pvc->profile->tx_shift[x];

					if (pvc->profile->tx_mute[x] || src >= src_chans) {
						continue;
					} else {
						if (pvc->profile->tx_pol[x]) {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -(buffer_data[(y * dst_chans) + x] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    -(buffer_data[(y * dst_chans) + x] << shift);
								}
							}
						} else {
							if (shift < 0) {
								shift = -shift;
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    (buffer_data[(y * dst_chans) + x] >> shift);
								}
							} else {
								for (y = 0; y != samples; y++) {
									buffer_temp[(y * src_chans) + src] +=
									    (buffer_data[(y * dst_chans) + x] << shift);
								}
							}
						}
					}
				}

				vblock_remove(pvb, &pvc->tx_ready);
				vblock_insert(pvb, &pvc->tx_free);
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

				dst_chans = pvc->profile->channels;
				pvb = vblock_peek(&pvc->rx_free);

				if (dst_chans > src_chans)
					continue;

				for (x = 0; x != dst_chans; x++) {
					src = pvc->profile->rx_src[x];
					shift = pvc->profile->rx_shift[x];

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
				    pvc->profile->channels, samples);

				/* Update limiter */
				fmt_max = (1LL << (pvc->profile->bits - 1)) - 1LL;
				for (x = 0; x != VMAX_CHAN; x++) {
					while ((pvc->profile->rx_peak_value[x] >>
					    pvc->profile->limiter) > fmt_max) {
						pvc->profile->limiter++;
					}
				}
				for (x = 0; x != VMAX_CHAN; x++)
					fmt_limit[x] = pvc->profile->limiter;

				if (pvb == NULL || pvc->rx_enabled == 0 || voss_is_recording == 0)
					continue;

				format_export(pvc->format, buffer_monitor,
				    pvb->buf_start, pvb->buf_size,
				    fmt_limit, pvc->profile->channels);

				vblock_remove(pvb, &pvc->rx_free);
				vblock_insert(pvb, &pvc->rx_ready);
			}

			atomic_wakeup();

			format_remix(buffer_temp,
			    voss_mix_channels,
			    voss_dsp_tx_channels,
			    voss_dsp_samples);

			/* Compute master output peak values */

			format_maximum(buffer_temp, voss_output_peak,
			    voss_dsp_tx_channels, voss_dsp_samples);

			/* Update limiter */
			fmt_max = format_max(afmt);

			for (x = 0; x != VMAX_CHAN; x++) {
				y = voss_output_group[x];
				while ((voss_output_peak[x] >> voss_output_limiter[y]) > fmt_max)
					voss_output_limiter[y]++;
				fmt_limit[x] = voss_output_limiter[y];
			}

			/* Export and transmit resulting audio */

			format_export(afmt, buffer_temp, buffer_dsp,
			    buffer_dsp_tx_size, fmt_limit, voss_dsp_tx_channels);

			atomic_unlock();

			blocks = 0;

			ioctl(fd_tx, SNDCTL_DSP_GETODELAY, &blocks);

			blocks /= (int)buffer_dsp_tx_size;

			/*
			 * Simple fix for jitter: Repeat data when too
			 * little. Skip data when too much. This
			 * should not happen during normal operation.
			 */
			if (blocks < 1)
				blocks = 2;
			else if (blocks > 2)
				blocks = 0;
			else
				blocks = 1;

			while (blocks--) {
				off = 0;
				while (off < (int)buffer_dsp_tx_size) {
					len = write(fd_tx, buffer_dsp + off,
					    (buffer_dsp_tx_size - off));
					if (len <= 0)
						break;
					off += len;
				}
			}
		}
	}
	return (NULL);
}
