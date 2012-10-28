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
	int fd = -1;
	int off;
	int afmt;
	int src_chans;
	int dst_chans;
	int src;
	int len;
	int samples;
	int shift;
	int buffer_dsp_size;
	int blocks;
	int x;
	int y;

	uint8_t *buffer_dsp;
	int64_t *buffer_monitor;
	int64_t *buffer_temp;
	int64_t *buffer_data;

	buffer_dsp_size = voss_dsp_samples *
	    voss_dsp_channels * (voss_dsp_bits / 8);

	afmt = voss_dsp_fmt;

	buffer_dsp = malloc(buffer_dsp_size * 2);
	buffer_temp = malloc(voss_dsp_samples * voss_dsp_channels * 8 * 2);
	buffer_monitor = malloc(voss_dsp_samples * voss_dsp_channels * 8 * 2);
	buffer_data = malloc(voss_dsp_samples * voss_dsp_channels * 8 * 2);

	if (buffer_dsp == NULL || buffer_temp == NULL ||
	    buffer_monitor == NULL || buffer_data == NULL)
		errx(1, "Cannot allocate buffer memory");

	while (1) {
		if (fd > -1) {
			close(fd);
			sleep(1);
		}
		fd = open(voss_dsp_device, O_RDWR);
		if (fd < 0) {
			warn("Could not open %s", voss_dsp_device);
			sleep(1);
			continue;
		}
		blocks = 0;
		len = ioctl(fd, FIONBIO, &blocks);
		if (len < 0) {
			warn("Could not set blocking mode on DSP");
			continue;
		}
		blocks = voss_dsp_fmt;
		len = ioctl(fd, SNDCTL_DSP_SETFMT, &blocks);
		if (len < 0) {
			warn("Could not set FMT=0x%08x", blocks);
			continue;
		}
		blocks = voss_dsp_channels;
		len = ioctl(fd, SOUND_PCM_WRITE_CHANNELS, &blocks);
		if (len < 0) {
			warn("Could not set CHANNELS=%d", blocks);
			continue;
		}
		blocks = voss_dsp_sample_rate;
		len = ioctl(fd, SNDCTL_DSP_SPEED, &blocks);
		if (len < 0) {
			warn("Could not set SPEED=%d Hz", blocks);
			continue;
		}
		while (1) {

			off = 0;
			len = 0;

			while (off < (int)buffer_dsp_size) {
				len = read(fd, buffer_dsp + off,
				    buffer_dsp_size - off);
				if (len <= 0)
					break;
				off += len;
			}
			if (len <= 0)
				break;

			format_import(afmt, buffer_dsp,
			    buffer_dsp_size, buffer_data);

			samples = voss_dsp_samples;
			src_chans = voss_dsp_channels;

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

				if (pvc->rx_enabled == 0 ||
				    dst_chans > src_chans)
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

				if (pvb == NULL)
					continue;

				format_export(pvc->format, buffer_temp,
				    pvb->buf_start, pvb->buf_size);

				vblock_remove(pvb, &pvc->rx_free);
				vblock_insert(pvb, &pvc->rx_ready);
			}

			/* fill main output buffer with silence */

			memset(buffer_temp, 0, sizeof(buffer_temp[0]) *
			    samples * src_chans);

			/*
			 * -- 2 -- Load output samples from all client
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

				/* dump any written data */

				pvb = vblock_peek(&pvc->tx_ready);
				vblock_remove(pvb, &pvc->tx_ready);
				vblock_insert(pvb, &pvc->tx_free);

				dst_chans = pvc->profile->channels;
				pvb = vblock_peek(&pvc->rx_free);

				if (pvb == NULL || pvc->rx_enabled == 0 || dst_chans > src_chans)
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

				format_export(pvc->format, buffer_monitor,
				    pvb->buf_start, pvb->buf_size);

				vblock_remove(pvb, &pvc->rx_free);
				vblock_insert(pvb, &pvc->rx_ready);
			}

			atomic_wakeup();

			atomic_unlock();

			/* Export and transmit resulting audio */

			format_export(afmt, buffer_temp, buffer_dsp,
			    buffer_dsp_size);

			blocks = 0;

			ioctl(fd, SNDCTL_DSP_GETODELAY, &blocks);

			blocks /= (int)buffer_dsp_size;

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
				while (off < (int)buffer_dsp_size) {
					len = write(fd, buffer_dsp + off,
					    (buffer_dsp_size - off));
					if (len <= 0)
						break;
					off += len;
				}
			}
		}
	}
	return (NULL);
}
