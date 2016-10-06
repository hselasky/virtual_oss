/*-
 * Copyright (c) 2012-2015 Hans Petter Selasky. All rights reserved.
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sysexits.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/soundcard.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/filio.h>
#include <sys/rtprio.h>

#ifdef HAVE_CUSE
#include <cuse.h>
#else
#include <cuse4bsd.h>
#endif
#include <pthread.h>

#include "virtual_int.h"
#include "virtual_oss.h"
#include "virtual_backend.h"

static pthread_mutex_t atomic_mtx;
static pthread_cond_t atomic_cv;

static void
atomic_init(void)
{
	pthread_mutex_init(&atomic_mtx, NULL);
	pthread_cond_init(&atomic_cv, NULL);
}

void
atomic_lock(void)
{
	pthread_mutex_lock(&atomic_mtx);
}

void
atomic_unlock(void)
{
	pthread_mutex_unlock(&atomic_mtx);
}

void
atomic_wait(void)
{
	pthread_cond_wait(&atomic_cv, &atomic_mtx);
}

void
atomic_wakeup(void)
{
	pthread_cond_broadcast(&atomic_cv);
	cuse_poll_wakeup();
}

static vblock_t *
vblock_alloc(uint32_t size)
{
	vblock_t *pvb;

	pvb = malloc(sizeof(*pvb) + size);
	if (pvb == NULL)
		return (NULL);

	pvb->buf_start = (uint8_t *)(pvb + 1);
	pvb->buf_pos = 0;
	pvb->buf_size = size;

	return (pvb);
}

static void
vblock_init(vblock_head_t *phead)
{
	TAILQ_INIT(phead);
}

static int
vblock_fill(vblock_head_t *phead,
    uint32_t count, uint32_t bufsize)
{
	vblock_t *pvb;

	while (count--) {
		pvb = vblock_alloc(bufsize);
		if (pvb == NULL)
			return (1);
		TAILQ_INSERT_TAIL(phead, pvb, entry);
	}
	return (0);
}

static void
vblock_free(vblock_head_t *phead)
{
	vblock_t *pvb;

	while ((pvb = TAILQ_FIRST(phead)) != NULL) {
		TAILQ_REMOVE(phead, pvb, entry);
		free(pvb);
	}

	TAILQ_INIT(phead);
}

void
vblock_insert(vblock_t *pvb, vblock_head_t *phead)
{
	pvb->buf_pos = 0;
	TAILQ_INSERT_TAIL(phead, pvb, entry);
}

void
vblock_remove(vblock_t *pvb, vblock_head_t *phead)
{
	TAILQ_REMOVE(phead, pvb, entry);
}

static void
vblock_move(vblock_head_t *from, vblock_head_t *to)
{
	vblock_t *ptr;

	while ((ptr = TAILQ_FIRST(from)) != NULL) {
		vblock_remove(ptr, from);
		vblock_insert(ptr, to);
	}
}

uint32_t
vclient_sample_bytes(vclient_t *pvc)
{
	uint32_t fmt = pvc->format;

	if (fmt & (AFMT_S16_BE | AFMT_S16_LE | AFMT_U16_BE | AFMT_U16_LE)) {
		return (2);
	} else if (fmt & (AFMT_S24_BE | AFMT_S24_LE | AFMT_U24_BE | AFMT_U24_LE)) {
		return (3);
	} else if (fmt & (AFMT_S32_BE | AFMT_S32_LE | AFMT_U32_BE | AFMT_U32_LE)) {
		return (4);
	} else if (fmt & (AFMT_U8 | AFMT_S8)) {
		return (1);
	} else {
		return (0);
	}
}

uint32_t
vclient_bufsize_internal(vclient_t *pvc)
{
	return (pvc->channels * voss_dsp_samples * vclient_sample_bytes(pvc));
}

uint32_t
vclient_bufsize_scaled(vclient_t *pvc)
{
	uint32_t samples_scaled = ((uint64_t)voss_dsp_samples *
	    (uint64_t)pvc->sample_rate) / (uint64_t)voss_dsp_sample_rate;
	if (samples_scaled == 0)
		samples_scaled = 1;
	return (pvc->channels * samples_scaled * vclient_sample_bytes(pvc));
}

static int
vblock_count_bufs(vblock_head_t *phead)
{
	vblock_t *pvb;
	int retval = 0;

	TAILQ_FOREACH(pvb, phead, entry) {
		if (pvb->buf_pos == 0)
			retval++;
	}
	return (retval);
}

vblock_t *
vblock_peek(vblock_head_t *phead)
{
	return (TAILQ_FIRST(phead));
}

vmonitor_t *
vmonitor_alloc(int *pid, vmonitor_head_t *phead)
{
	int id = 0;
	vmonitor_t *pvm;

	TAILQ_FOREACH(pvm, phead, entry)
	    id++;

	if (id >= 64) {
		*pid = 0;
		return (NULL);
	}
	pvm = malloc(sizeof(*pvm));
	if (pvm == NULL) {
		*pid = 0;
		return (NULL);
	}
	memset(pvm, 0, sizeof(*pvm));

	pvm->mute = 1;

	TAILQ_INSERT_TAIL(phead, pvm, entry);

	*pid = id;
	return (pvm);
}

int64_t
vclient_noise(vclient_t *pvc, int64_t volume, int8_t shift)
{
	const uint32_t prime = 0xFFFF1DU;
	int64_t temp;

	/* compute next noise sample */
	temp = pvc->noise_rem;
	if (temp & 1)
		temp += prime;
	temp /= 2;
	pvc->noise_rem = temp;

	/* unsigned to signed conversion */
	temp ^= 0x800000ULL;
	if (temp & 0x800000U)
		temp |= -0x800000ULL;

	/* properly amplify */
	temp *= volume;

	/* properly shift noise */
	if (shift > (23 + 7))
		temp <<= (shift - (23 + 7));
	else
		temp >>= ((23 + 7) - shift);

	return (temp);
}

static void
vresample_free(vresample_t *pvr)
{
	if (pvr->state != NULL)
		src_delete(pvr->state);
	free(pvr->data.data_in);
	free(pvr->data.data_out);
	free(pvr->scratch_in_buf);
	free(pvr->scratch_out_buf);
	memset(pvr, 0, sizeof(*pvr));
}

static int
vresample_setup(vclient_t *pvc, vresample_t *pvr,
    uint32_t in_samples, uint32_t out_samples)
{
	int samples = in_samples > out_samples ? in_samples : out_samples;
	int code = 0;

	if (pvr->state != NULL)
		return (0);
	pvr->state = src_new(SRC_SINC_BEST_QUALITY, pvc->channels, &code);
	if (pvr->state == NULL)
		goto error;
	pvr->data.data_in = malloc(sizeof(float) * in_samples);
	if (pvr->data.data_in == NULL)
		goto error;
	pvr->data.data_out = malloc(sizeof(float) * out_samples);
	if (pvr->data.data_out == NULL)
		goto error;
	pvr->scratch_in_buf = malloc(sizeof(int64_t) * samples);
	if (pvr->scratch_in_buf == NULL)
		goto error;
	pvr->scratch_out_buf = malloc(sizeof(int64_t) * samples);
	if (pvr->scratch_out_buf == NULL)
		goto error;
	pvr->in_offset = 0;
	return (0);
error:
	return (CUSE_ERR_NO_MEMORY);
}

static void
vclient_free(vclient_t *pvc)
{
	vresample_free(&pvc->rx_resample);
	vresample_free(&pvc->tx_resample);

	vblock_free(&pvc->rx_ready);
	vblock_free(&pvc->rx_free);
	vblock_free(&pvc->tx_ready);
	vblock_free(&pvc->tx_free);

	free(pvc);
}

static vclient_t *
vclient_alloc(void)
{
	vclient_t *pvc;

	pvc = malloc(sizeof(*pvc));
	if (pvc == NULL)
		return (NULL);

	memset(pvc, 0, sizeof(*pvc));

	pvc->tx_volume = 128;
	pvc->noise_rem = 1;

	vblock_init(&pvc->rx_ready);
	vblock_init(&pvc->rx_free);
	vblock_init(&pvc->tx_ready);
	vblock_init(&pvc->tx_free);

	return (pvc);
}

static int
vclient_get_default_fmt(vprofile_t *pvp)
{
	int retval;

	switch (pvp->bits) {
	case 16:
		retval = AFMT_S16_NE;
		break;
	case 24:
		retval = AFMT_S24_NE;
		break;
	case 32:
		retval = AFMT_S32_NE;
		break;
	default:
		retval = AFMT_S8;
		break;
	}
	return (retval);
}

static int
vclient_setup_buffers(vclient_t *pvc, int size, int frags,
    int channels, int format, int sample_rate)
{
	int bufsize;
	int frags_internal;

	/* check we are not busy */
	if (pvc->rx_busy || pvc->tx_busy)
		return (CUSE_ERR_BUSY);

	/* free existing buffers */
	vblock_free(&pvc->rx_ready);
	vblock_free(&pvc->rx_free);
	vblock_free(&pvc->tx_ready);
	vblock_free(&pvc->tx_free);

	/* reset resampler */
	vresample_free(&pvc->rx_resample);
	vresample_free(&pvc->tx_resample);

	if (sample_rate > 0)
		pvc->sample_rate = sample_rate;
	if (format != 0)
		pvc->format = format;
	if (channels > 0)
		pvc->channels = channels;

	if (size > 0) {
		pvc->buffer_size = size;
		pvc->buffer_size_set = 1;
	} else if (pvc->buffer_size_set == 0)
		pvc->buffer_size = vclient_bufsize_scaled(pvc);

	if (frags > 0) {
		pvc->buffer_frags = frags;
		pvc->buffer_frags_set = 1;
	} else if (pvc->buffer_frags_set == 0)
		pvc->buffer_frags = 2;

	/* sanity checks */
	if (frags < 0 || size < 0)
		return (CUSE_ERR_INVALID);
	if (pvc->format == 0)
		return (CUSE_ERR_INVALID);
	if (pvc->buffer_frags <= 0 || pvc->buffer_frags >= 1024)
		return (CUSE_ERR_INVALID);
	if (pvc->buffer_size <= 0 || pvc->buffer_size >= (1024 * 1024))
		return (CUSE_ERR_INVALID);
	if ((pvc->buffer_size * pvc->buffer_frags) >= (128 * 1024 * 1024))
		return (CUSE_ERR_INVALID);
	if (pvc->channels <= 0 || channels > pvc->profile->channels)
		return (CUSE_ERR_INVALID);

	/* get number of internal fragments */
	bufsize = vclient_bufsize_scaled(pvc);
	frags_internal = (pvc->buffer_size * pvc->buffer_frags +
	    bufsize - 1) / bufsize;

	if (frags_internal < 2)
		frags_internal = 2;

	/* get internal buffer size */
	bufsize = vclient_bufsize_internal(pvc);

	/* allocate new RX buffers */
	if (vblock_fill(&pvc->rx_free, frags_internal, bufsize)) {
	  	vblock_free(&pvc->rx_free);
		return (CUSE_ERR_NO_MEMORY);
	}

	/* allocate new TX buffers */
	if (vblock_fill(&pvc->tx_free, frags_internal, bufsize)) {
	  	vblock_free(&pvc->tx_free);
		vblock_free(&pvc->rx_free);
		return (CUSE_ERR_NO_MEMORY);
	}

	pvc->start_block = voss_dsp_blocks;

	return (0);
}

static int
vclient_open_sub(struct cuse_dev *pdev, int fflags, int type)
{
	vclient_t *pvc;
	vprofile_t *pvp;
	int error;

	pvp = cuse_dev_get_priv0(pdev);

	pvc = vclient_alloc();
	if (pvc == NULL)
		return (CUSE_ERR_NO_MEMORY);

	pvc->profile = pvp;

	/* setup buffers */
	error = vclient_setup_buffers(pvc, 0, 0, pvp->channels,
	    vclient_get_default_fmt(pvp), voss_dsp_sample_rate);
	if (error != 0) {
		vclient_free(pvc);
		return (error);
	}

	pvc->type = type;

	cuse_dev_set_per_file_handle(pdev, pvc);

	atomic_lock();
	TAILQ_INSERT_TAIL(pvc->profile->pvc_head, pvc, entry);
	atomic_unlock();

	return (0);
}

static int
vclient_open_wav(struct cuse_dev *pdev, int fflags)
{
	return (vclient_open_sub(pdev, fflags, VTYPE_WAV_HDR));
}

static int
vclient_open_oss(struct cuse_dev *pdev, int fflags)
{
	return (vclient_open_sub(pdev, fflags, VTYPE_OSS_DAT));
}

static int
vclient_close(struct cuse_dev *pdev, int fflags)
{
	vclient_t *pvc;

	pvc = cuse_dev_get_per_file_handle(pdev);
	if (pvc == NULL)
		return (CUSE_ERR_INVALID);

	atomic_lock();
	TAILQ_REMOVE(pvc->profile->pvc_head, pvc, entry);
	atomic_unlock();

	vclient_free(pvc);

	return (0);
}

static int
vclient_read_copy_out(vclient_t *pvc, void *src, void *peer_ptr,
    int *pin_len, int *pout_len)
{
	int error;
	int delta_out;
	int delta_in;

	delta_out = *pout_len;
	delta_in = *pin_len;

	if (pvc->sample_rate == voss_dsp_sample_rate) {
		/* compute smallest transferrable amount */
		if (delta_out > delta_in)
			delta_out = delta_in;
		else
			delta_in = delta_out;

		pvc->rx_busy = 1;
		atomic_unlock();
		error = cuse_copy_out(src, peer_ptr, delta_out);
	} else {
		vresample_t *pvr = &pvc->tx_resample;
		uint8_t plimit[pvc->channels];
		int samp_size = vclient_sample_bytes(pvc);
		int frame_size = pvc->channels * samp_size;
		int samp_inp = vclient_bufsize_internal(pvc) / frame_size;
		int samp_out = vclient_bufsize_scaled(pvc) / frame_size;
		int max_in;
		int x;
		int y;
		int z;

		if (vresample_setup(pvc, pvr, samp_inp * pvc->channels,
		    samp_out * pvc->channels) != 0)
			return (CUSE_ERR_NO_MEMORY);

		max_in = (samp_inp - pvr->in_offset) * frame_size;
		if (delta_in > max_in)
			delta_in = max_in;

		if ((delta_in % frame_size) || (delta_out % frame_size))
			return (CUSE_ERR_INVALID);

		/* import samples */
		format_import(pvc->format, src, delta_in,
		    pvr->scratch_out_buf + pvr->in_offset * pvc->channels);
		pvr->in_offset += delta_in / frame_size;

		/* compute total number of samples */
		y = pvr->in_offset * pvc->channels;
		for (x = 0; x != y; x++)
			pvr->data.data_in[x] = pvr->scratch_out_buf[x] / (8.0 * 0x10000000);

		/* setup parameters for transform */
		pvr->data.input_frames = pvr->in_offset;
		pvr->data.output_frames = delta_out / frame_size;
		pvr->data.src_ratio = (float)pvc->sample_rate / (float)voss_dsp_sample_rate;

		error = src_process(pvr->state, &pvr->data);
		if (error != 0)
			return (CUSE_ERR_INVALID);

		/* compute total number of output samples */
		y = pvr->data.output_frames_gen * pvc->channels;
		for (x = 0; x != y; x++)
			pvr->scratch_in_buf[x] = pvr->data.data_out[x] * (8.0 * 0x10000000);

		/* compute total number of output bytes */
		delta_out = y * samp_size;

		/* put remaining input data at the beginning */
		pvr->in_offset -= pvr->data.input_frames_used;
		y = pvr->in_offset * pvc->channels;
		z = pvr->data.input_frames_used * pvc->channels;
		for (x = 0; x != y; x++)
			pvr->scratch_out_buf[x] = pvr->scratch_out_buf[z + x];

		/* don't shift output */
		memset(plimit, 0, sizeof(plimit));

		/* make sure we don't touch the source buffer */
		src = alloca(delta_out);

		/* export resulting samples into buffer */
		format_export(pvc->format, pvr->scratch_in_buf,
		    src, delta_out, plimit, pvc->channels);

		pvc->rx_busy = 1;
		atomic_unlock();
		error = cuse_copy_out(src, peer_ptr, delta_out);
	}
	atomic_lock();
	pvc->rx_busy = 0;
	*pout_len = delta_out;
	*pin_len = delta_in;

	return (error);
}

static int
vclient_read_silence_locked(struct cuse_dev *pdev, void *peer_ptr, int len, vclient_t *pvc)
{
	int delta_in;
	int delta_out;
	int sample_size;
	int retval = 0;
	int error;
	uint8_t buffer[vclient_sample_bytes(pvc) * pvc->channels * 1024] __aligned(4);

	while (len > 0) {
		delta_in = pvc->profile->rec_delay - pvc->rec_delay;
		if (delta_in > sizeof(buffer))
			delta_in = sizeof(buffer);
		if (delta_in < 1)
			break;

		delta_out = len;

		/* fill buffer with silence */
		format_silence(pvc->format, buffer, delta_in);

		error = vclient_read_copy_out(pvc, buffer,
		    peer_ptr, &delta_in, &delta_out);
		if (error != 0) {
			retval = error;
			break;
		}
		peer_ptr = (uint8_t *)peer_ptr + delta_out;
		len -= delta_out;
		retval += delta_out;
		pvc->rec_delay += delta_in;
	}
	return (retval);
}

static int
vclient_generate_wav_header_locked(vclient_t *pvc)
{
	vblock_t *pvb;
	uint8_t *ptr;
	uint32_t len;

	pvb = vblock_peek(&pvc->rx_free);
	if (pvb == NULL)
		return (CUSE_ERR_NO_MEMORY);

	ptr = pvb->buf_start;
	len = vclient_bufsize_internal(pvc);
	if (len < 44)
		return (CUSE_ERR_INVALID);

	vblock_remove(pvb, &pvc->rx_free);
	vblock_insert(pvb, &pvc->rx_ready);

	/* clear block */
	memset(ptr, 0, len);

	/* fill out data header */
	ptr[len - 8] = 'd';
	ptr[len - 7] = 'a';
	ptr[len - 6] = 't';
	ptr[len - 5] = 'a';

	/* magic for unspecified length */
	ptr[len - 4] = 0x00;
	ptr[len - 3] = 0xF0;
	ptr[len - 2] = 0xFF;
	ptr[len - 1] = 0x7F;

	/* fill out header */
	*ptr++ = 'R';
	*ptr++ = 'I';
	*ptr++ = 'F';
	*ptr++ = 'F';

	/* total chunk size - unknown */

	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;

	*ptr++ = 'W';
	*ptr++ = 'A';
	*ptr++ = 'V';
	*ptr++ = 'E';
	*ptr++ = 'f';
	*ptr++ = 'm';
	*ptr++ = 't';
	*ptr++ = ' ';

	/* make sure header fits in PCM block */
	len -= 28;

	*ptr++ = len;
	*ptr++ = len >> 8;
	*ptr++ = len >> 16;
	*ptr++ = len >> 24;

	/* audioformat = PCM */

	*ptr++ = 0x01;
	*ptr++ = 0x00;

	/* number of channels */

	len = pvc->channels;

	*ptr++ = len;
	*ptr++ = len >> 8;

	/* sample rate */

	len = pvc->sample_rate;

	*ptr++ = len;
	*ptr++ = len >> 8;
	*ptr++ = len >> 16;
	*ptr++ = len >> 24;

	/* byte rate */

	len = pvc->sample_rate * pvc->channels * vclient_sample_bytes(pvc);

	*ptr++ = len;
	*ptr++ = len >> 8;
	*ptr++ = len >> 16;
	*ptr++ = len >> 24;

	/* block align */

	len = pvc->channels * vclient_sample_bytes(pvc);

	*ptr++ = len;
	*ptr++ = len >> 8;

	/* bits per sample */

	len = vclient_sample_bytes(pvc) * 8;

	*ptr++ = len;
	*ptr++ = len >> 8;

	return (0);
}

static int
vclient_read(struct cuse_dev *pdev, int fflags,
    void *peer_ptr, int len)
{
	vclient_t *pvc;
	vblock_t *pvb;

	int delta_in;
	int delta_out;
	int error;
	int retval;

	pvc = cuse_dev_get_per_file_handle(pdev);
	if (pvc == NULL)
		return (CUSE_ERR_INVALID);

	atomic_lock();

	if (pvc->rx_busy) {
		atomic_unlock();
		return (CUSE_ERR_BUSY);
	}
	pvc->rx_enabled = 1;

	if (pvc->type == VTYPE_WAV_HDR) {
		retval = vclient_generate_wav_header_locked(pvc);
		if (retval != 0) {
			atomic_unlock();
			return (retval);
		}
		/* only write header once */
		pvc->type = VTYPE_WAV_DAT;
	}
	retval = vclient_read_silence_locked(pdev, peer_ptr, len, pvc);
	if (retval != 0) {
		atomic_unlock();
		return (retval);
	}
	while (len > 0) {
		pvb = vblock_peek(&pvc->rx_ready);
		if (pvb == NULL) {
			/* out of data */
			if (fflags & CUSE_FFLAG_NONBLOCK) {
				if (retval == 0)
					retval = CUSE_ERR_WOULDBLOCK;
				break;
			}
			atomic_wait();
			if (cuse_got_peer_signal() == 0) {
				if (retval == 0)
					retval = CUSE_ERR_SIGNAL;
				break;
			}
			continue;
		}
		delta_in = vclient_bufsize_internal(pvc) - pvb->buf_pos;
		if (delta_in == 0) {
			vblock_remove(pvb, &pvc->rx_ready);
			vblock_insert(pvb, &pvc->rx_free);
			continue;
		}
		delta_out = len;

		error = vclient_read_copy_out(pvc,
		    pvb->buf_start + pvb->buf_pos,
		    peer_ptr, &delta_in, &delta_out);
		if (error != 0) {
			retval = error;
			break;
		}
		peer_ptr = ((uint8_t *)peer_ptr) + delta_out;
		retval += delta_out;
		len -= delta_out;
		pvb->buf_pos += delta_in;
	}
	atomic_unlock();

	return (retval);
}

static int
vclient_write_oss(struct cuse_dev *pdev, int fflags,
    const void *peer_ptr, int len)
{
	vclient_t *pvc;
	vblock_t *pvb;

	int delta;
	int error;
	int retval;

	pvc = cuse_dev_get_per_file_handle(pdev);
	if (pvc == NULL)
		return (CUSE_ERR_INVALID);

	retval = 0;

	atomic_lock();

	if (pvc->tx_busy) {
		atomic_unlock();
		return (CUSE_ERR_BUSY);
	}
	pvc->tx_enabled = 1;

	while (len > 0) {
		/* make sure send is synchronous when not blocking */
		if ((fflags & CUSE_FFLAG_NONBLOCK) == 0 &&
		    vblock_peek(&pvc->tx_ready) != NULL)
			pvb = NULL;
		else
			pvb = vblock_peek(&pvc->tx_free);

		if (pvb == NULL) {
			/* out of data */
			if (fflags & CUSE_FFLAG_NONBLOCK) {
				if (retval == 0)
					retval = CUSE_ERR_WOULDBLOCK;
				break;
			}
			atomic_wait();
			if (cuse_got_peer_signal() == 0) {
				if (retval == 0)
					retval = CUSE_ERR_SIGNAL;
				break;
			}
			continue;
		}
		delta = vclient_bufsize_internal(pvc) - pvb->buf_pos;
		if (delta == 0) {
			vblock_remove(pvb, &pvc->tx_free);
			vblock_insert(pvb, &pvc->tx_ready);
			continue;
		}
		if (pvc->sample_rate == voss_dsp_sample_rate) {
			if (delta > len)
				delta = len;
			pvc->tx_busy = 1;
			atomic_unlock();
			error = cuse_copy_in(peer_ptr,
			    pvb->buf_start + pvb->buf_pos, delta);
			atomic_lock();
			pvc->tx_busy = 0;

			if (error != 0) {
				retval = error;
				break;
			}
			/* update local buffer position */
			pvb->buf_pos += delta;

			/* update remote buffer position */
			peer_ptr = ((const uint8_t *)peer_ptr) + delta;
			retval += delta;
			len -= delta;
		} else {
			vresample_t *pvr = &pvc->rx_resample;
			uint8_t plimit[pvc->channels];
			int samp_size = vclient_sample_bytes(pvc);
			int frame_size = pvc->channels * samp_size;
			int samp_inp = vclient_bufsize_scaled(pvc) / frame_size;
			int samp_out = vclient_bufsize_internal(pvc) / frame_size;
			int max_in;
			int x;
			int y;
			int z;

			if (vresample_setup(pvc, pvr, samp_inp * pvc->channels,
			    samp_out * pvc->channels) != 0) {
				retval = CUSE_ERR_NO_MEMORY;
				break;
			}
			max_in = (samp_inp - pvr->in_offset) * frame_size;
			if (max_in > len)
				max_in = len;

			if ((max_in % frame_size) || (delta % frame_size)) {
				retval = CUSE_ERR_INVALID;
				break;
			}
			pvc->tx_busy = 1;
			atomic_unlock();
			error = cuse_copy_in(peer_ptr, pvr->scratch_in_buf, max_in);
			atomic_lock();
			pvc->tx_busy = 0;

			if (error != 0) {
				retval = error;
				break;
			}
			/* update remote buffer position */
			peer_ptr = ((const uint8_t *)peer_ptr) + max_in;
			retval += max_in;
			len -= max_in;

			/* import samples */
			format_import(pvc->format, (void *)pvr->scratch_in_buf, max_in,
			    pvr->scratch_out_buf + pvr->in_offset * pvc->channels);
			pvr->in_offset += max_in / frame_size;

			/* compute total number of samples */
			y = pvr->in_offset * pvc->channels;
			for (x = 0; x != y; x++)
				pvr->data.data_in[x] = pvr->scratch_out_buf[x] / (8.0 * 0x10000000);

			/* setup parameters for transform */
			pvr->data.input_frames = pvr->in_offset;
			pvr->data.output_frames = delta / frame_size;
			pvr->data.src_ratio = (float)voss_dsp_sample_rate / (float)pvc->sample_rate;

			error = src_process(pvr->state, &pvr->data);
			if (error != 0) {
				retval = CUSE_ERR_INVALID;
				break;
			}
			/* compute total number of output samples */
			y = pvr->data.output_frames_gen * pvc->channels;
			for (x = 0; x != y; x++)
				pvr->scratch_in_buf[x] = pvr->data.data_out[x] * (8.0 * 0x10000000);

			/* compute total number of output bytes */
			delta = y * samp_size;

			/* put remaining input data at the beginning */
			pvr->in_offset -= pvr->data.input_frames_used;
			y = pvr->in_offset * pvc->channels;
			z = pvr->data.input_frames_used * pvc->channels;
			for (x = 0; x != y; x++)
				pvr->scratch_out_buf[x] = pvr->scratch_out_buf[z + x];

			/* don't shift output */
			memset(plimit, 0, sizeof(plimit));

			/* export resulting samples into buffer */
			format_export(pvc->format, pvr->scratch_in_buf,
			    pvb->buf_start + pvb->buf_pos, delta,
			    plimit, pvc->channels);

			/* update buffer position */
			pvb->buf_pos += delta;
		}
	}
	atomic_unlock();

	return (retval);
}

static int
vclient_write_wav(struct cuse_dev *pdev, int fflags,
    const void *peer_ptr, int len)
{
	return (CUSE_ERR_INVALID);
}

static int
vclient_set_channels(vclient_t *pvc, int channels)
{
	if (pvc->channels == channels)
		return (0);
	return (vclient_setup_buffers(pvc, 0, 0, channels, 0, 0));
}

static int
vclient_ioctl_oss(struct cuse_dev *pdev, int fflags,
    unsigned long cmd, void *peer_data)
{
	union {
		int	val;
		unsigned long long lval;
		oss_sysinfo sysinfo;
		oss_card_info card_info;
		oss_audioinfo audioinfo;
		audio_buf_info buf_info;
		oss_count_t oss_count;
		count_info oss_count_info;
		audio_errinfo errinfo;
		oss_label_t label;
		oss_longname_t longname;
	}     data;

	vclient_t *pvc;
	vblock_t *pvb;

	uint64_t rem;
	uint64_t div;

	int len;
	int error;
	int temp;

	pvc = cuse_dev_get_per_file_handle(pdev);
	if (pvc == NULL)
		return (CUSE_ERR_INVALID);

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
	case OSS_GETVERSION:
		data.val = SOUND_VERSION;
		break;
	case SNDCTL_SYSINFO:
		memset(&data.sysinfo, 0, sizeof(data.sysinfo));
		strcpy(data.sysinfo.product, "VOSS");
		strcpy(data.sysinfo.version, "1.0");
		data.sysinfo.versionnum = SOUND_VERSION;
		data.sysinfo.numaudios = 1;
		data.sysinfo.numcards = 1;
		data.sysinfo.numaudioengines = 1;
		strcpy(data.sysinfo.license, "BSD");
		memset(data.sysinfo.filler, -1, sizeof(data.sysinfo.filler));
		break;
	case SNDCTL_CARDINFO:
		memset(&data.card_info, 0, sizeof(data.card_info));
		strlcpy(data.card_info.shortname, pvc->profile->oss_name,
		    sizeof(data.card_info.shortname));
		break;
	case SNDCTL_AUDIOINFO:
	case SNDCTL_AUDIOINFO_EX:
	case SNDCTL_ENGINEINFO:
		memset(&data.audioinfo, 0, sizeof(data.audioinfo));
		strlcpy(data.audioinfo.name, pvc->profile->oss_name,
		    sizeof(data.audioinfo.name));
		data.audioinfo.caps = DSP_CAP_INPUT | DSP_CAP_OUTPUT;
		data.audioinfo.iformats = VSUPPORTED_AFMT;
		data.audioinfo.oformats = VSUPPORTED_AFMT;
		data.audioinfo.enabled = 1;
		data.audioinfo.min_rate = (int)8000;
		data.audioinfo.max_rate = (int)voss_dsp_sample_rate;
		/* range check */
		if (voss_libsamplerate_enable == 0 ||
		    data.audioinfo.min_rate > data.audioinfo.max_rate)
			data.audioinfo.min_rate = data.audioinfo.max_rate;
		data.audioinfo.nrates = 1;
		data.audioinfo.rates[0] = (int)voss_dsp_sample_rate;
		if (voss_libsamplerate_enable != 0 &&
		    96000 != voss_dsp_sample_rate)
			data.audioinfo.rates[data.audioinfo.nrates++] = 96000;
		if (voss_libsamplerate_enable != 0 &&
		    48000 != voss_dsp_sample_rate)
			data.audioinfo.rates[data.audioinfo.nrates++] = 48000;
		if (voss_libsamplerate_enable != 0 &&
		    44100 != voss_dsp_sample_rate)
			data.audioinfo.rates[data.audioinfo.nrates++] = 44100;
		if (voss_libsamplerate_enable != 0 &&
		    24000 != voss_dsp_sample_rate)
			data.audioinfo.rates[data.audioinfo.nrates++] = 24000;
		if (voss_libsamplerate_enable != 0 &&
		    16000 != voss_dsp_sample_rate)
			data.audioinfo.rates[data.audioinfo.nrates++] = 16000;
		if (voss_libsamplerate_enable != 0 &&
		    8000 != voss_dsp_sample_rate)
			data.audioinfo.rates[data.audioinfo.nrates++] = 8000;
		data.audioinfo.latency = -1;
		break;
	case FIONREAD:
		data.val = vblock_count_bufs(&pvc->rx_ready) *
		    vclient_bufsize_scaled(pvc);
		break;
	case FIOASYNC:
	case SNDCTL_DSP_NONBLOCK:
	case FIONBIO:
		break;
	case SNDCTL_DSP_SETBLKSIZE:
	case _IOWR('P', 4, int):
		error = vclient_setup_buffers(pvc, data.val, 0, 0, 0, 0);
		/* FALLTHROUGH */
	case SNDCTL_DSP_GETBLKSIZE:
		data.val = pvc->buffer_size;
		break;
	case SNDCTL_DSP_SETFRAGMENT:
		if ((data.val & 0xFFFF) < 4 || (data.val & 0xFFFF) > 24) {
			error = CUSE_ERR_INVALID;
			break;
		}
		error = vclient_setup_buffers(pvc,
		    (1 << (data.val & 0xFFFF)), (data.val >> 16), 0, 0, 0);
		break;
	case SNDCTL_DSP_RESET:
		break;
	case SNDCTL_DSP_SYNC:
		break;
	case SNDCTL_DSP_SPEED:
		if (data.val >= 8000 && data.val <= 96000 &&
		    voss_libsamplerate_enable != 0) {
			error = vclient_setup_buffers(pvc, 0, 0, 0, 0, data.val);
		}
		/* return current speed */
		data.val = (int)pvc->sample_rate;
		break;
	case SOUND_PCM_READ_RATE:
		data.val = (int)pvc->sample_rate;
		break;
	case SNDCTL_DSP_STEREO:
		if (data.val != 0) {
			error = vclient_set_channels(pvc, 2);
		} else {
			error = vclient_set_channels(pvc, 1);
		}
		data.val = (pvc->channels == 2);
		break;
	case SOUND_PCM_WRITE_CHANNELS:
		if (data.val < 0) {
			data.val = 0;
			error = CUSE_ERR_INVALID;
			break;
		}
		if (data.val == 0) {
			data.val = pvc->channels;
		} else {
			error = vclient_set_channels(pvc, data.val);
		}
		break;
	case SOUND_PCM_READ_CHANNELS:
		data.val = pvc->channels;
		break;
	case AIOGFMT:
	case SNDCTL_DSP_GETFMTS:
		data.val = VSUPPORTED_AFMT | AFMT_FULLDUPLEX |
		    (pvc->profile->channels > 1 ? AFMT_STEREO : 0);
		break;
	case AIOSFMT:
	case SNDCTL_DSP_SETFMT:
		if (data.val != AFMT_QUERY) {
			temp = data.val & VSUPPORTED_AFMT;
			if (temp == 0 || (temp & (temp - 1)) != 0) {
				error = CUSE_ERR_INVALID;
			} else {
				error = vclient_setup_buffers(pvc, 0, 0, 0, temp, 0);
			}
		} else {
			data.val = pvc->format;
		}
		break;
	case SNDCTL_DSP_GETISPACE:
		memset(&data.buf_info, 0, sizeof(data.buf_info));
		data.buf_info.fragsize = pvc->buffer_size;
		data.buf_info.fragstotal = pvc->buffer_frags;
		temp = vblock_count_bufs(&pvc->rx_ready) *
		    vclient_bufsize_scaled(pvc);
		temp = temp / pvc->buffer_size;
		if (temp > data.buf_info.fragstotal)
			temp = data.buf_info.fragstotal;
		data.buf_info.fragments = temp;
		data.buf_info.bytes = temp * pvc->buffer_size;
		break;
	case SNDCTL_DSP_GETOSPACE:
		memset(&data.buf_info, 0, sizeof(data.buf_info));
		data.buf_info.fragsize = pvc->buffer_size;
		data.buf_info.fragstotal = pvc->buffer_frags;
		temp = vblock_count_bufs(&pvc->tx_free) *
		    vclient_bufsize_scaled(pvc);
		temp = temp / pvc->buffer_size;
		if (temp > data.buf_info.fragstotal)
			temp = data.buf_info.fragstotal;
		data.buf_info.fragments = temp;
		data.buf_info.bytes = temp * pvc->buffer_size;
		break;
	case SNDCTL_DSP_GETCAPS:
		data.val = PCM_CAP_REALTIME | PCM_CAP_DUPLEX |
		    PCM_CAP_INPUT | PCM_CAP_OUTPUT | PCM_CAP_TRIGGER |
		    PCM_CAP_VIRTUAL;
		break;
	case SOUND_PCM_READ_BITS:
		data.val = vclient_sample_bytes(pvc) * 8;
		break;
	case SNDCTL_DSP_SETTRIGGER:
		if (data.val & PCM_ENABLE_INPUT) {
			pvc->rx_enabled = 1;
		} else {
			pvc->rx_enabled = 0;
			vblock_move(&pvc->rx_free, &pvc->rx_ready);
			vblock_move(&pvc->rx_ready, &pvc->rx_free);
		}

		if (data.val & PCM_ENABLE_OUTPUT) {
			pvc->tx_enabled = 1;
		} else {
			pvc->tx_enabled = 0;
			vblock_move(&pvc->tx_free, &pvc->tx_ready);
			vblock_move(&pvc->tx_ready, &pvc->tx_free);
		}
		break;
	case SNDCTL_DSP_GETTRIGGER:
		data.val = 0;
		if (pvc->rx_enabled)
			data.val |= PCM_ENABLE_INPUT;
		if (pvc->tx_enabled)
			data.val |= PCM_ENABLE_OUTPUT;
		break;
	case SNDCTL_DSP_GETODELAY:
		data.val = vblock_count_bufs(&pvc->tx_ready) *
		    vclient_bufsize_scaled(pvc);
		pvb = vblock_peek(&pvc->tx_free);
		if (pvb != NULL) {
			temp = ((uint64_t)pvb->buf_pos *
			    (uint64_t)pvc->sample_rate) /
			    (uint64_t)voss_dsp_sample_rate;
			temp = temp -
			    (temp % (pvc->channels * vclient_sample_bytes(pvc)));
			data.val += temp;
		}
		break;
	case SNDCTL_DSP_POST:
		break;
	case SNDCTL_DSP_SETDUPLEX:
		break;
	case SNDCTL_DSP_GETRECVOL:
		data.val = 128 | (128 << 8);
		break;
	case SNDCTL_DSP_GETPLAYVOL:
		temp = (pvc->tx_volume * 100) / 128;
		data.val = (temp & 0x00FF) |
		    ((temp << 8) & 0xFF00);
		break;
	case SNDCTL_DSP_SETPLAYVOL:
		pvc->tx_volume = ((data.val & 0xFF) * 128) / 100;
		break;
	case SNDCTL_DSP_CURRENT_IPTR:
	case SNDCTL_DSP_CURRENT_OPTR:
		memset(&data.oss_count, 0, sizeof(data.oss_count));
		/* compute sample ratio */
		rem = voss_dsp_sample_rate % pvc->sample_rate;
		div = voss_dsp_sample_rate / pvc->sample_rate;
		/* compute division error */
		rem *= (voss_dsp_blocks - pvc->start_block);
		rem /= pvc->sample_rate;
		/* compute output samples */
		data.oss_count.samples = (voss_dsp_blocks - pvc->start_block - rem) *
		    (voss_dsp_samples / div) * pvc->channels;
		break;
	case SNDCTL_DSP_GETOPTR:
	case SNDCTL_DSP_GETIPTR:
		memset(&data.oss_count_info, 0, sizeof(data.oss_count_info));
		/* compute sample ratio */
		rem = voss_dsp_sample_rate % pvc->sample_rate;
		div = voss_dsp_sample_rate / pvc->sample_rate;
		/* compute division error */
		rem *= (voss_dsp_blocks - pvc->start_block);
		rem /= pvc->sample_rate;
		/* compute output samples */
		rem = (voss_dsp_blocks - pvc->start_block - rem) *
		    (voss_dsp_samples / div) * pvc->channels * vclient_sample_bytes(pvc);
		data.oss_count_info.bytes = rem;
		data.oss_count_info.blocks = rem / pvc->buffer_size;
		data.oss_count_info.ptr = rem;
		break;
	case SNDCTL_DSP_HALT_OUTPUT:
		pvc->tx_enabled = 0;
		break;
	case SNDCTL_DSP_HALT_INPUT:
		pvc->rx_enabled = 0;
		break;
	case SNDCTL_DSP_LOW_WATER:
		break;
	case SNDCTL_DSP_GETERROR:
		memset(&data.errinfo, 0, sizeof(data.errinfo));
		break;
	case SNDCTL_DSP_SYNCGROUP:
	case SNDCTL_DSP_SYNCSTART:
		break;
	case SNDCTL_DSP_POLICY:
		break;
	case SNDCTL_DSP_COOKEDMODE:
		break;
	case SNDCTL_DSP_GET_CHNORDER:
		data.lval = CHNORDER_NORMAL;
		break;
	case SNDCTL_DSP_GETCHANNELMASK:
		data.val = DSP_BIND_FRONT;
		break;
	case SNDCTL_DSP_BIND_CHANNEL:
		break;
	case SNDCTL_GETLABEL:
		memset(&data.label, 0, sizeof(data.label));
		break;
	case SNDCTL_SETLABEL:
		break;
	case SNDCTL_GETSONG:
		memset(&data.longname, 0, sizeof(data.longname));
		break;
	case SNDCTL_SETSONG:
		break;
	case SNDCTL_SETNAME:
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

static int
vclient_ioctl_wav(struct cuse_dev *pdev, int fflags,
    unsigned long cmd, void *peer_data)
{
	union {
		int	val;
	}     data;

	vclient_t *pvc;
	vblock_t *pvb;

	int temp;
	int len;
	int error;

	pvc = cuse_dev_get_per_file_handle(pdev);
	if (pvc == NULL)
		return (CUSE_ERR_INVALID);

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
	case FIONREAD:
		data.val = vblock_count_bufs(&pvc->rx_ready) *
		    vclient_bufsize_scaled(pvc);
		break;
	case FIOASYNC:
	case SNDCTL_DSP_NONBLOCK:
	case FIONBIO:
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

static int
vclient_poll(struct cuse_dev *pdev, int fflags, int events)
{
	vclient_t *pvc;

	int retval = CUSE_POLL_NONE;

	pvc = cuse_dev_get_per_file_handle(pdev);
	if (pvc == NULL)
		return (retval);

	atomic_lock();
	if (events & CUSE_POLL_READ) {
		uint32_t temp = vblock_count_bufs(&pvc->rx_ready) *
		    vclient_bufsize_scaled(pvc);

		pvc->rx_enabled = 1;
		if (temp >= pvc->buffer_size)
			retval |= CUSE_POLL_READ;
	}
	if (events & CUSE_POLL_WRITE) {
		uint32_t temp = vblock_count_bufs(&pvc->tx_free) *
		    vclient_bufsize_scaled(pvc);

		if (temp >= pvc->buffer_size)
			retval |= CUSE_POLL_WRITE;
	}
	atomic_unlock();

	return (retval);
}

static const struct cuse_methods vclient_oss_methods = {
	.cm_open = vclient_open_oss,
	.cm_close = vclient_close,
	.cm_read = vclient_read,
	.cm_write = vclient_write_oss,
	.cm_ioctl = vclient_ioctl_oss,
	.cm_poll = vclient_poll,
};

static const struct cuse_methods vclient_wav_methods = {
	.cm_open = vclient_open_wav,
	.cm_close = vclient_close,
	.cm_read = vclient_read,
	.cm_write = vclient_write_wav,
	.cm_ioctl = vclient_ioctl_wav,
	.cm_poll = vclient_poll,
};

vprofile_head_t virtual_profile_client_head;
vprofile_head_t virtual_profile_loopback_head;

vclient_head_t virtual_client_head;
vclient_head_t virtual_loopback_head;

vmonitor_head_t virtual_monitor_input;
vmonitor_head_t virtual_monitor_output;

uint32_t voss_max_channels;
uint32_t voss_mix_channels;
uint32_t voss_dsp_samples;
uint32_t voss_dsp_max_channels;
uint32_t voss_dsp_sample_rate;
uint32_t voss_dsp_bits;
uint32_t voss_dsp_rx_fmt;
uint32_t voss_dsp_tx_fmt;
uint64_t voss_dsp_blocks;
uint8_t	voss_libsamplerate_enable;
int	voss_is_recording = 1;

static int voss_dsp_perm = 0666;

uint32_t voss_dsp_rx_refresh;
uint32_t voss_dsp_tx_refresh;
char voss_dsp_rx_device[VMAX_STRING];
char voss_dsp_tx_device[VMAX_STRING];
char voss_ctl_device[VMAX_STRING];
char voss_sta_device[VMAX_STRING];

struct voss_backend *voss_rx_backend;
struct voss_backend *voss_tx_backend;

static int voss_dups;

static void
voss_rx_backend_refresh(void)
{
  	/* setup RX backend */
	if (strcmp(voss_dsp_rx_device, "/dev/null") == 0) {
		voss_rx_backend = &voss_backend_null_rec;
#ifdef HAVE_BLUETOOTH
	} else if (strstr(voss_dsp_rx_device, "/dev/bluetooth/") == voss_dsp_rx_device) {
		voss_rx_backend = &voss_backend_bt_rec;
#endif
	} else {
		voss_rx_backend = &voss_backend_oss_rec;
	}
}

static void
voss_tx_backend_refresh(void)
{
  	/* setup TX backend */
	if (strcmp(voss_dsp_tx_device, "/dev/null") == 0) {
		voss_tx_backend = &voss_backend_null_play;
#ifdef HAVE_BLUETOOTH
	} else if (strstr(voss_dsp_tx_device, "/dev/bluetooth/") == voss_dsp_tx_device) {
		voss_tx_backend = &voss_backend_bt_play;
#endif
	} else {
		voss_tx_backend = &voss_backend_oss_play;
	}
}

static void
usage(void)
{
	fprintf(stderr, "Usage: virtual_oss [options...] [device] \\\n"
	    "\t" "-C 2 -c 2 -r 48000 -b 16 -s 1024 -f /dev/dsp3 \\\n"
	    "\t" "-P /dev/dsp3 -R /dev/dsp1 \\\n"
	    "\t" "-T /dev/sndstat \\\n"
	    "\t" "-c 1 -m 0,0 [-w wav.0] -d dsp100.0 \\\n"
	    "\t" "-c 1 -m 0,0 [-w wav.0] -d vdsp.0 \\\n"
	    "\t" "-c 2 -m 0,0,1,1 [-w wav.1] -d vdsp.1 \\\n"
	    "\t" "-c 2 -m 0,0,1,1 [-w wav.loopback] -l vdsp.loopback \\\n"
	    "\t" "-s <samples> \\\n"
	    "\t" "-S \\\n"
	    "\t" "-b <bits> \\\n"
	    "\t" "-r <rate> \\\n"
	    "\t" "-i <rtprio> \\\n"
	    "\t" "-a <amp -63..63> \\\n"
	    "\t" "-g <ch0grp,ch1grp...chnNgrp> \\\n"
	    "\t" "-p <pol 0..1> \\\n"
	    "\t" "-e <rxtx_mute 0..1> \\\n"
	    "\t" "-e <rx_mute 0..1>,<tx_mute 0..1> \\\n"
	    "\t" "-m <mapping> \\\n"
	    "\t" "-m <rx0,tx0,rx1,tx1...rxN,txN> \\\n"
	    "\t" "-C <mixchans>\\\n"
	    "\t" "-c <dspchans> \\\n"
	    "\t" "-M <monitorfilter> \\\n"
	    "\t" "-M i,<src>,<dst>,<pol>,<mute>,<amp> \\\n"
	    "\t" "-M o,<src>,<dst>,<pol>,<mute>,<amp> \\\n"
	    "\t" "-t vdsp.ctl \n"
	    "\t" "Left channel = 0\n"
	    "\t" "Right channel = 1\n"
	    "\t" "Max channels = %d\n", VMAX_CHAN);

	exit(EX_USAGE);
}

static const char *
dup_profile(vprofile_t *pvp, int amp, int pol, int rx_mute, int tx_mute)
{
	vprofile_t *ptr;
	struct cuse_dev *pdev;
	int x;

	rx_mute = rx_mute ? 1 : 0;
	tx_mute = tx_mute ? 1 : 0;
	pol = pol ? 1 : 0;

	if (amp < -63)
		amp = -63;
	else if (amp > 63)
		amp = 63;

	ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return ("Out of memory");

	memcpy(ptr, pvp, sizeof(*ptr));

	ptr->fd_sta = -1;

	for (x = 0; x != ptr->channels; x++) {
		ptr->tx_mute[x] = tx_mute;
		ptr->rx_mute[x] = rx_mute;
		ptr->tx_shift[x] = amp;
		ptr->rx_shift[x] = -amp;
		ptr->tx_pol[x] = pol;
		ptr->rx_pol[x] = pol;
	}

	/* create DSP device */
	if (ptr->oss_name[0] != 0) {
		/*
		 * Detect /dev/dsp creation and try to disable system
		 * basename cloning automatically:
		 */
		if (strcmp(ptr->oss_name, "dsp") == 0)
			system("sysctl hw.snd.basename_clone=0");

		/* create DSP character device */
		pdev = cuse_dev_create(&vclient_oss_methods, ptr, NULL,
		    0, 0, voss_dsp_perm, ptr->oss_name);
		if (pdev == NULL) {
			free(ptr);
			return ("Could not create CUSE DSP device");
		}

		/* register sndstat, if any */
		if (voss_sta_device[0] != 0) {
			ptr->fd_sta = open(voss_sta_device, O_WRONLY);
			if (ptr->fd_sta < 0) {
				warn("Could not open '%s'", voss_sta_device);
			} else {
				char temp[128];
				int unit;
				if (sscanf(ptr->oss_name, "dsp%d", &unit) == 1) {
					snprintf(temp, sizeof(temp),
					    "pcm%d: <Virtual OSS> (play/rec)\n"
					    "%s: <Virtual OSS> (play/rec)\n",
					    unit, ptr->oss_name);
				} else {
					snprintf(temp, sizeof(temp),
					    "%s: <Virtual OSS> (play/rec)\n",
					    ptr->oss_name);
				}
				if (write(ptr->fd_sta, temp, strlen(temp)) != strlen(temp)) {
					warn("Could not register virtual OSS device");
					close(ptr->fd_sta);
					ptr->fd_sta = -1;
				}
			}
		}
	}
	/* create WAV device */
	if (ptr->wav_name[0] != 0) {
		pdev = cuse_dev_create(&vclient_wav_methods, ptr, NULL,
		    0, 0, voss_dsp_perm, ptr->wav_name);
		if (pdev == NULL) {
			free(ptr);
			return ("Could not create CUSE WAV device");
		}
	}
	atomic_lock();
	if (ptr->pvc_head == &virtual_client_head) {
		TAILQ_INSERT_TAIL(&virtual_profile_client_head, ptr, entry);
	} else if (ptr->pvc_head == &virtual_loopback_head) {
		TAILQ_INSERT_TAIL(&virtual_profile_loopback_head, ptr, entry);
	}
	atomic_unlock();

	voss_dups++;

	/* need new names next time */
	memset(pvp->oss_name, 0, sizeof(pvp->oss_name));
	memset(pvp->wav_name, 0, sizeof(pvp->wav_name));

	return (NULL);
}

static void
virtual_pipe(int sig)
{
	voss_dsp_tx_refresh = 1;
	voss_dsp_rx_refresh = 1;
}

static void
virtual_cuse_hup(int sig)
{
	atomic_wakeup();
}

static void *
virtual_cuse_process(void *arg)
{
	signal(SIGHUP, &virtual_cuse_hup);

	while (1) {
		if (cuse_wait_and_process() != 0)
			break;
	}
	return (NULL);
}

static void
virtual_cuse_init_profile(struct virtual_profile *pvp, int clear)
{
	int x;

	if (clear != 0)
		memset(pvp, 0, sizeof(*pvp));
	for (x = 0; x != VMAX_CHAN; x++) {
		pvp->rx_src[x] = x;
		pvp->tx_dst[x] = x;
	}
}

static const char * const
parse_options(int narg, char **pparg, int is_main)
{
	const char *ptr;
	int c;
	int val;
	int idx;
	int type;
	int opt_mute[2] = {0, 0};
	int opt_amp = 0;
	int opt_pol = 0;
	const char *optstr;
	struct virtual_profile profile;
	struct rtprio rtp;

	if (is_main)
		optstr = "w:e:p:a:C:c:r:b:f:g:i:m:M:d:l:s:t:h?P:R:ST:";
	else
		optstr = "w:e:p:a:c:b:f:g:m:M:d:l:s:P:R:";

	virtual_cuse_init_profile(&profile, 1);

	/* reset getopt parsing */
	optreset = 1;
	optind = 1;

	while ((c = getopt(narg, pparg, optstr)) != -1) {
		switch (c) {
		case 'C':
			if (voss_mix_channels != 0) {
				return ("The -C argument may only be used once");
			}
			voss_mix_channels = atoi(optarg);
			if (voss_mix_channels >= VMAX_CHAN) {
				return ("Number of mixing channels is too high");
			}
			break;
		case 'a':
			opt_amp = atoi(optarg);
			break;
		case 'e':
			idx = 0;
			ptr = optarg;
			memset(opt_mute, 0, sizeof(opt_mute));
			while (1) {
				c = *ptr++;
				if (c == ',' || c == 0) {
					idx++;
					if (c == 0)
						break;
					continue;
				}
				if (idx < 2 && c >= '0' && c <= '1') {
					opt_mute[idx] = c - '0';
				} else {
					return ("Invalid -e parameter");
				}
			}
			switch (idx) {
			case 1:
				opt_mute[1] = opt_mute[0];
				break;
			case 2:
				break;
			default:
				return ("Invalid -e parameter");
			}
			break;
		case 'p':
			opt_pol = atoi(optarg);
			break;
		case 'c':
			profile.channels = atoi(optarg);
			if (profile.channels == 0)
				return ("Number of channels is zero");
			if (profile.channels >= VMAX_CHAN)
				return ("Number of channels is too high");
			break;
		case 'r':
			voss_dsp_sample_rate = atoi(optarg);
			if (voss_dsp_sample_rate < 8000)
				return ("Sample rate is too low, 8000 Hz");
			if (voss_dsp_sample_rate > 0xFFFFFF)
				return ("Sample rate is too high");
			break;
		case 'i':
			memset(&rtp, 0, sizeof(rtp));
			rtp.type = RTP_PRIO_REALTIME;
			rtp.prio = atoi(optarg);
			if (rtprio(RTP_SET, getpid(), &rtp) != 0)
				printf("Cannot set realtime priority\n");
			break;
		case 'b':
			profile.bits = atoi(optarg);
			switch (profile.bits) {
			case 8:
			case 16:
			case 24:
			case 32:
				break;
			default:
				return ("Invalid number of sample bits");
			}
			break;
		case 'g':
			ptr = optarg;
			val = 0;
			idx = 0;
			while (1) {
				c = *ptr++;
				if (c == ',' || c == 0) {
					if (idx >= VMAX_CHAN)
						return ("Too many channel groups");
					voss_output_group[idx] = val;
					if (c == 0)
						break;
					val = 0;
					idx++;
					continue;
				}
				if (c >= '0' && c <= '9') {
					val *= 10;
					val += c - '0';
				}
			}
			break;
		case 'f':
		case 'P':
		case 'R':
			if (voss_dsp_sample_rate == 0 || voss_dsp_samples == 0)
				return ("Missing -r or -s parameters");
			if (voss_dsp_bits == 0) {
				if (profile.bits == 0)
					return ("Missing -b parameter");
				voss_dsp_bits = profile.bits;
			}
			if (voss_dsp_max_channels == 0) {
				if (profile.channels == 0)
					return ("Missing -c parameter");
				voss_dsp_max_channels = profile.channels;
			}
			switch (voss_dsp_bits) {
			case 8:
				voss_dsp_rx_fmt =
				    voss_dsp_tx_fmt =
				    AFMT_S8 | AFMT_U8;
				break;
			case 16:
				voss_dsp_rx_fmt =
				    voss_dsp_tx_fmt =
				    AFMT_S16_BE | AFMT_S16_LE |
				    AFMT_U16_BE | AFMT_U16_LE;
				break;
			case 24:
				voss_dsp_rx_fmt =
				    voss_dsp_tx_fmt =
				    AFMT_S24_BE | AFMT_S24_LE |
				    AFMT_U24_BE | AFMT_U24_LE;
				break;
			case 32:
				voss_dsp_rx_fmt =
				    voss_dsp_tx_fmt =
				    AFMT_S32_BE | AFMT_S32_LE |
				    AFMT_U32_BE | AFMT_U32_LE;
				break;
			default:
				return ("Invalid number of sample bits");
			}
			if (c == 'f' || c == 'R') {
				if (strlen(optarg) > VMAX_STRING - 1)
					return ("Device name too long");
				strncpy(voss_dsp_rx_device, optarg, sizeof(voss_dsp_rx_device));
				voss_rx_backend_refresh();
				voss_dsp_rx_refresh = 1;
			}
			if (c == 'f' || c == 'P') {
				if (strlen(optarg) > VMAX_STRING - 1)
					return ("Device name too long");
				strncpy(voss_dsp_tx_device, optarg, sizeof(voss_dsp_tx_device));
				voss_tx_backend_refresh();
				voss_dsp_tx_refresh = 1;
			}
			break;
		case 'w':
			if (strlen(optarg) > VMAX_STRING - 1)
				return ("Device name too long");
			strncpy(profile.wav_name, optarg, sizeof(profile.wav_name));
			break;
		case 'd':
			if (strlen(optarg) > VMAX_STRING - 1)
				return ("Device name too long");
			strncpy(profile.oss_name, optarg, sizeof(profile.oss_name));
			profile.pvc_head = &virtual_client_head;

			if (profile.bits == 0 || voss_dsp_sample_rate == 0 ||
			    profile.channels == 0 || voss_dsp_samples == 0)
				return ("Missing -b, -r, -c or -s parameters");

			val = (voss_dsp_samples *
			    profile.bits * profile.channels) / 8;
			if (val <= 0 || val >= (1024 * 1024))
				return ("-s option value is too big");

			ptr = dup_profile(&profile, opt_amp, opt_pol, opt_mute[0], opt_mute[1]);
			if (ptr != NULL)
				return (ptr);
			break;
		case 'l':
			if (strlen(optarg) > VMAX_STRING - 1)
				return ("Device name too long");
			strncpy(profile.oss_name, optarg, sizeof(profile.oss_name));
			profile.pvc_head = &virtual_loopback_head;

			if (profile.bits == 0 || voss_dsp_sample_rate == 0 ||
			    profile.channels == 0 || voss_dsp_samples == 0)
				return ("Missing -b, -r, -r or -s parameters");

			val = (voss_dsp_samples *
			    profile.bits * profile.channels) / 8;
			if (val <= 0 || val >= (1024 * 1024))
				return ("-s option value is too big");

			ptr = dup_profile(&profile, opt_amp, opt_pol, opt_mute[0], opt_mute[1]);
			if (ptr != NULL)
				return (ptr);
			break;
		case 'S':
			voss_libsamplerate_enable = 1;
			break;
		case 's':
			if (voss_dsp_samples != 0)
				return ("-s option may only be used once");
			if (profile.bits == 0 || profile.channels == 0)
				return ("-s option requires -b and -c options");
			voss_dsp_samples = atoi(optarg);
			if (voss_dsp_samples >= (1U << 24))
				return ("-s option requires a non-zero positive value");
			break;
		case 'T':
			if (voss_sta_device[0])
				return ("-T parameter may only be used once");

			strncpy(voss_sta_device, optarg, sizeof(voss_sta_device));
			break;
		case 't':
			if (voss_ctl_device[0])
				return ("-t parameter may only be used once");

			strncpy(voss_ctl_device, optarg, sizeof(voss_ctl_device));
			break;
		case 'm':
			ptr = optarg;
			val = 0;
			idx = 0;
			virtual_cuse_init_profile(&profile, 0);
			while (1) {
				c = *ptr++;
				if (c == ',' || c == 0) {
					if (idx >= (2 * VMAX_CHAN))
						return ("Too many channels in mask");
					if (idx & 1)
						profile.tx_dst[idx / 2] = val;
					else
						profile.rx_src[idx / 2] = val;
					if (c == 0)
						break;
					val = 0;
					idx++;
					continue;
				}
				if (c >= '0' && c <= '9') {
					val *= 10;
					val += c - '0';
				}
			}
			break;
		case 'M':
			ptr = optarg;
			type = *ptr;
			if (type == 'i' || type == 'o') {
				vmonitor_t *pvm;

				int src = 0;
				int dst = 0;
				int pol = 0;
				int mute = 0;
				int amp = 0;
				int neg;

				ptr++;
				if (*ptr == ',')
					ptr++;

				val = 0;
				neg = 0;
				idx = 0;
				while (1) {
					c = *ptr++;
					if (c == '-') {
						neg = 1;
						continue;
					}
					if (c == ',' || c == 0) {
						switch (idx) {
						case 0:
							src = val;
							break;
						case 1:
							dst = val;
							break;
						case 2:
							pol = val ? 1 : 0;
							break;
						case 3:
							mute = val ? 1 : 0;
							break;
						case 4:
							if (val > 31) {
								return ("Absolute amplitude "
								    "for -M parameter "
								    "cannot exceed 31");
							}
							amp = neg ? -val : val;
							break;
						default:
							break;
						}
						if (c == 0)
							break;
						val = 0;
						neg = 0;
						idx++;
						continue;
					}
					if (c >= '0' && c <= '9') {
						val *= 10;
						val += c - '0';
					}
				}
				if (idx < 4)
					return ("Too few parameters for -M");

				pvm = vmonitor_alloc(&idx,
				    (type == 'i') ? &virtual_monitor_input :
				    &virtual_monitor_output);

				if (pvm == NULL)
					return ("Out of memory");

				pvm->src_chan = src;
				pvm->dst_chan = dst;
				pvm->pol = pol;
				pvm->mute = mute;
				pvm->shift = amp;
			} else {
				return ("Invalid -M parameter");
			}
			break;
		default:
			if (is_main)
				usage();
			else
				return ("Invalid option detected");
			break;
		}
	}
	return (NULL);
}

static void
create_threads(void)
{
	int idx;

	/* Give each DSP device 4 threads */

	for (idx = 0; idx != (voss_dups * 4); idx++) {
		pthread_t td;

		pthread_create(&td, NULL, &virtual_cuse_process, NULL);
	}

	/* Reset until next time called */
	voss_dups = 0;
}

void
voss_add_options(char *str)
{
	const char sep[] = "\t ";
	const char *ptrerr;
	char *parg[64];
	char *word;
	char *brkt;
	int narg = 0;

	parg[narg++] = "virtual_oss";

	for (word = strtok_r(str, sep, &brkt); word != NULL;
	     word = strtok_r(NULL, sep, &brkt)) {
		if (narg >= 64) {
			ptrerr = "Too many arguments";
			goto done;
		}
		parg[narg++] = word;
	}
	ptrerr = parse_options(narg, parg, 0);
done:
	if (ptrerr != NULL) {
		strlcpy(str, ptrerr, VIRTUAL_OSS_OPTIONS_MAX);
	} else {
		str[0] = 0;
		create_threads();
	}
}

int
main(int argc, char **argv)
{
	const char *ptrerr;

	TAILQ_INIT(&virtual_profile_client_head);
	TAILQ_INIT(&virtual_profile_loopback_head);

	TAILQ_INIT(&virtual_client_head);
	TAILQ_INIT(&virtual_loopback_head);

	TAILQ_INIT(&virtual_monitor_input);
	TAILQ_INIT(&virtual_monitor_output);

	atomic_init();

	if (cuse_init() != 0)
		errx(EX_USAGE, "Could not connect to cuse module");

	signal(SIGPIPE, &virtual_pipe);

	ptrerr = parse_options(argc, argv, 1);
	if (ptrerr != NULL)
		errx(EX_USAGE, "%s", ptrerr);

	if (voss_dsp_rx_device[0] == 0 || voss_dsp_tx_device[0] == 0)
		errx(EX_USAGE, "Missing -f argument");

	/* use DSP channels as default */
	if (voss_mix_channels == 0)
		voss_mix_channels = voss_dsp_max_channels;

	if (voss_mix_channels > voss_dsp_max_channels)
		voss_max_channels = voss_mix_channels;
	else
		voss_max_channels = voss_dsp_max_channels;

	if (voss_dsp_samples > (voss_dsp_sample_rate / 4))
		errx(EX_USAGE, "Too many buffer samples given by -s argument");

	/* setup audio delay unit */
	voss_ad_init(voss_dsp_sample_rate);

	/* Create CTL device */

	if (voss_ctl_device[0] != 0) {
		struct cuse_dev *pdev;

		pdev = cuse_dev_create(&vctl_methods, NULL, NULL,
		    0, 0, voss_dsp_perm, voss_ctl_device);
		if (pdev == NULL)
			errx(EX_USAGE, "Could not create '/dev/%s'", voss_ctl_device);

		voss_dups++;
	}

	/* Create worker threads */

	create_threads();
	
	/* Run DSP threads */

	virtual_oss_process(NULL);

	return (0);
}
