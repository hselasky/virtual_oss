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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sysexits.h>
#include <signal.h>

#include <sys/soundcard.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/filio.h>

#include <cuse4bsd.h>
#include <pthread.h>

#include "virtual_int.h"

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

static int
vblock_count_bytes(vblock_head_t *phead, int is_tx)
{
	vblock_t *pvb;
	int retval = 0;

	TAILQ_FOREACH(pvb, phead, entry) {
		if (is_tx)
			retval += pvb->buf_pos;
		else
			retval += pvb->buf_size - pvb->buf_pos;
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

static void
vclient_free(vclient_t *pvc)
{
	vblock_free(&pvc->rx_ready);
	vblock_free(&pvc->rx_free);
	vblock_free(&pvc->tx_ready);
	vblock_free(&pvc->tx_free);

	free(pvc);
}

static vclient_t *
vclient_alloc(uint32_t bufsize)
{
	vclient_t *pvc;

	pvc = malloc(sizeof(*pvc));
	if (pvc == NULL)
		return (NULL);

	memset(pvc, 0, sizeof(*pvc));

	vblock_init(&pvc->rx_ready);
	vblock_init(&pvc->rx_free);
	vblock_init(&pvc->tx_ready);
	vblock_init(&pvc->tx_free);

	if (vblock_fill(&pvc->rx_free, VMAX_FRAGS, bufsize)) {
		vclient_free(pvc);
		return (NULL);
	}
	if (vblock_fill(&pvc->tx_free, VMAX_FRAGS, bufsize)) {
		vclient_free(pvc);
		return (NULL);
	}
	return (pvc);
}

static int
vclient_get_fmts(vclient_t *pvc)
{
	int retval;

	switch (pvc->profile->bits) {
	case 16:
		retval = AFMT_FULLDUPLEX
		    | AFMT_S16_BE
		    | AFMT_S16_LE
		    | AFMT_U16_BE
		    | AFMT_U16_LE;
		break;
	case 24:
		retval = AFMT_FULLDUPLEX
		    | AFMT_S24_BE
		    | AFMT_S24_LE
		    | AFMT_U24_BE
		    | AFMT_U24_LE;
		break;

	case 32:
		retval = AFMT_FULLDUPLEX
		    | AFMT_S32_BE
		    | AFMT_S32_LE
		    | AFMT_U32_BE
		    | AFMT_U32_LE;
		break;
	default:
		retval =
		    AFMT_FULLDUPLEX
		    | AFMT_U8
		    | AFMT_S8;
		break;
	}
	return (retval);
}

static int
vclient_open(struct cuse_dev *pdev, int fflags)
{
	vclient_t *pvc;
	vprofile_t *pvp;

	pvp = cuse_dev_get_priv0(pdev);

	pvc = vclient_alloc(pvp->bufsize);

	if (pvc == NULL)
		return (CUSE_ERR_NO_MEMORY);

	pvc->profile = pvp;

	pvc->format = vclient_get_fmts(pvc) &
	    (AFMT_S8 | AFMT_S16_LE | AFMT_S24_LE | AFMT_S32_LE);

	cuse_dev_set_per_file_handle(pdev, pvc);

	atomic_lock();
	TAILQ_INSERT_TAIL(pvc->profile->pvc_head, pvc, entry);
	atomic_unlock();

	return (0);
}

static int
vclient_close(struct cuse_dev *pdev, int fflags)
{
	vclient_t *pvc;

	pvc = cuse_dev_get_per_file_handle(pdev);

	atomic_lock();
	TAILQ_REMOVE(pvc->profile->pvc_head, pvc, entry);
	atomic_unlock();

	vclient_free(pvc);

	return (0);
}

static int
vclient_read(struct cuse_dev *pdev, int fflags,
    void *peer_ptr, int len)
{
	vclient_t *pvc;
	vblock_t *pvb;

	int delta;
	int error;
	int retval;

	pvc = cuse_dev_get_per_file_handle(pdev);
	retval = 0;

	atomic_lock();

	if (pvc->rx_busy) {
		atomic_unlock();
		return (CUSE_ERR_BUSY);
	}
	pvc->rx_enabled = 1;

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
		delta = pvb->buf_size - pvb->buf_pos;
		if (delta == 0) {
			vblock_remove(pvb, &pvc->rx_ready);
			vblock_insert(pvb, &pvc->rx_free);
			continue;
		}
		if (delta > len)
			delta = len;

		pvc->rx_busy = 1;
		atomic_unlock();

		error = cuse_copy_out(pvb->buf_start + pvb->buf_pos,
		    peer_ptr, delta);

		atomic_lock();
		pvc->rx_busy = 0;

		if (error != 0) {
			retval = error;
			break;
		}
		pvb->buf_pos += delta;
		peer_ptr = ((uint8_t *)peer_ptr) + delta;
		retval += delta;
		len -= delta;

		delta = pvb->buf_size - pvb->buf_pos;
		if (delta == 0) {
			vblock_remove(pvb, &pvc->rx_ready);
			vblock_insert(pvb, &pvc->rx_free);
		}
	}
	atomic_unlock();

	return (retval);
}

static int
vclient_write(struct cuse_dev *pdev, int fflags,
    const void *peer_ptr, int len)
{
	vclient_t *pvc;
	vblock_t *pvb;

	int delta;
	int error;
	int retval;

	pvc = cuse_dev_get_per_file_handle(pdev);
	retval = 0;

	atomic_lock();

	if (pvc->tx_busy) {
		atomic_unlock();
		return (CUSE_ERR_BUSY);
	}
	pvc->tx_enabled = 1;

	while (len > 0) {
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
		delta = pvb->buf_size - pvb->buf_pos;
		if (delta == 0) {
			vblock_remove(pvb, &pvc->tx_free);
			vblock_insert(pvb, &pvc->tx_ready);
			continue;
		}
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
		pvb->buf_pos += delta;
		peer_ptr = ((const uint8_t *)peer_ptr) + delta;
		retval += delta;
		len -= delta;

		delta = pvb->buf_size - pvb->buf_pos;
		if (delta == 0) {
			vblock_remove(pvb, &pvc->tx_free);
			vblock_insert(pvb, &pvc->tx_ready);
		}
	}
	atomic_unlock();

	return (retval);
}

static int
vclient_ioctl(struct cuse_dev *pdev, int fflags,
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
		audio_errinfo errinfo;
		oss_label_t label;
		oss_longname_t longname;
	}     data;

	vclient_t *pvc;
	vblock_t *pvb;

	int len;
	int error;

	pvc = cuse_dev_get_per_file_handle(pdev);

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
		strlcpy(data.card_info.shortname, pvc->profile->name, sizeof(data.card_info.shortname));
		break;
	case SNDCTL_AUDIOINFO:
	case SNDCTL_AUDIOINFO_EX:
	case SNDCTL_ENGINEINFO:
		memset(&data.audioinfo, 0, sizeof(data.audioinfo));
		strlcpy(data.audioinfo.name, pvc->profile->name, sizeof(data.audioinfo.name));
		data.audioinfo.caps = DSP_CAP_INPUT | DSP_CAP_OUTPUT;
		data.audioinfo.iformats = vclient_get_fmts(pvc);
		data.audioinfo.oformats = vclient_get_fmts(pvc);
		data.audioinfo.enabled = 1;
		data.audioinfo.min_rate = (int)pvc->profile->rate;
		data.audioinfo.max_rate = (int)pvc->profile->rate;
		data.audioinfo.nrates = 1;
		data.audioinfo.rates[0] = (int)pvc->profile->rate;
		data.audioinfo.latency = -1;
		break;
	case FIONREAD:
		pvb = vblock_peek(&pvc->rx_ready);
		if (pvb != NULL)
			data.val = pvb->buf_size - pvb->buf_pos;
		else
			data.val = 0;
		break;
	case FIOASYNC:
	case SNDCTL_DSP_NONBLOCK:
	case FIONBIO:
		break;
	case _IOWR('P', 4, int):
	case SNDCTL_DSP_GETBLKSIZE:
		data.val = pvc->profile->bufsize;
		break;
	case SNDCTL_DSP_SETBLKSIZE:
		break;
	case SNDCTL_DSP_RESET:
		break;
	case SNDCTL_DSP_SYNC:
		break;
	case SNDCTL_DSP_SPEED:
		if (data.val != (int)pvc->profile->rate)
			error = CUSE_ERR_INVALID;
		break;
	case SOUND_PCM_READ_RATE:
		data.val = (int)pvc->profile->rate;
		break;
	case SNDCTL_DSP_STEREO:
		pvc->mono = (data.val == 0);
		break;
	case SOUND_PCM_WRITE_CHANNELS:
		if (data.val < 0) {
			data.val = 0;
			error = CUSE_ERR_INVALID;
			break;
		}
		if (data.val == 0) {
			if (pvc->mono != 0)
				data.val = 1;
			else
				data.val = pvc->profile->channels;
		} else if (data.val == 1) {
			pvc->mono = 1;
		} else if (pvc->profile->channels == data.val) {
			pvc->mono = 0;
		} else {
			error = CUSE_ERR_INVALID;
		}
		break;
	case SOUND_PCM_READ_CHANNELS:
		if (pvc->mono != 0)
			data.val = 1;
		else
			data.val = pvc->profile->channels;
		break;
	case AIOGFMT:
	case SNDCTL_DSP_GETFMTS:
		data.val = vclient_get_fmts(pvc);
		break;
	case AIOSFMT:
	case SNDCTL_DSP_SETFMT:
		if (data.val != AFMT_QUERY) {
			data.val &= vclient_get_fmts(pvc);
			if (data.val != 0) {
				pvc->format = data.val & ~(data.val - 1);
			} else {
				error = CUSE_ERR_INVALID;
			}
		} else {
			data.val = pvc->format;
		}
		break;
	case SNDCTL_DSP_GETISPACE:
		data.buf_info.bytes =
		    vblock_count_bytes(&pvc->rx_ready, 0);
		data.buf_info.fragments = data.buf_info.bytes / pvc->profile->bufsize;
		data.buf_info.fragstotal = VMAX_FRAGS;
		data.buf_info.fragsize = pvc->profile->bufsize;
		break;
	case SNDCTL_DSP_GETOSPACE:
		data.buf_info.bytes =
		    vblock_count_bytes(&pvc->tx_free, 0);
		data.buf_info.fragments = data.buf_info.bytes / pvc->profile->bufsize;
		data.buf_info.fragstotal = VMAX_FRAGS;
		data.buf_info.fragsize = pvc->profile->bufsize;
		break;
	case SNDCTL_DSP_GETCAPS:
		data.val = PCM_CAP_REALTIME | PCM_CAP_DUPLEX;
		break;
	case SOUND_PCM_READ_BITS:
		data.val = pvc->profile->bits;
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
		data.val = vblock_count_bytes(&pvc->tx_ready, 0) +
		    vblock_count_bytes(&pvc->tx_free, 1);
		break;
	case SNDCTL_DSP_POST:
		break;
	case SNDCTL_DSP_SETDUPLEX:
		break;
	case SNDCTL_DSP_GETRECVOL:
	case SNDCTL_DSP_GETPLAYVOL:
		data.val = 255;
		break;
	case SNDCTL_DSP_CURRENT_OPTR:
		memset(&data.oss_count, 0, sizeof(data.oss_count));
		data.oss_count.samples = ((16 *
		    pvc->profile->bufsize) / pvc->profile->bits);
		data.oss_count.fifo_samples = (8 * (vblock_count_bytes(&pvc->tx_ready, 0) +
		    vblock_count_bytes(&pvc->tx_free, 1))) / pvc->profile->bits;
		break;
	case SNDCTL_DSP_CURRENT_IPTR:
		memset(&data.oss_count, 0, sizeof(data.oss_count));
		data.oss_count.samples = ((16 *
		    pvc->profile->bufsize) / pvc->profile->bits);
		data.oss_count.fifo_samples = (8 * (vblock_count_bytes(&pvc->rx_ready, 0) +
		    vblock_count_bytes(&pvc->rx_free, 0)) / pvc->profile->bits);
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
vclient_poll(struct cuse_dev *pdev, int fflags, int events)
{
	vclient_t *pvc;

	int retval = CUSE_POLL_NONE;

	pvc = cuse_dev_get_per_file_handle(pdev);

	atomic_lock();

	if (events & CUSE_POLL_READ) {
		if (vblock_peek(&pvc->rx_ready))
			retval |= CUSE_POLL_READ;
	}
	if (events & CUSE_POLL_WRITE) {
		if (vblock_peek(&pvc->tx_free))
			retval |= CUSE_POLL_WRITE;
	}
	atomic_unlock();

	return (retval);
}

static const struct cuse_methods vclient_methods = {
	.cm_open = vclient_open,
	.cm_close = vclient_close,
	.cm_read = vclient_read,
	.cm_write = vclient_write,
	.cm_ioctl = vclient_ioctl,
	.cm_poll = vclient_poll,
};

vprofile_head_t virtual_profile_head;

vclient_head_t virtual_client_head;
vclient_head_t virtual_loopback_head;

vmonitor_head_t virtual_monitor_input;
vmonitor_head_t virtual_monitor_output;

uint32_t voss_dsp_samples;
uint32_t voss_dsp_channels;
uint32_t voss_dsp_sample_rate;
uint32_t voss_dsp_bits;
uint32_t voss_dsp_fmt;

static int voss_dsp_perm = 0666;

const char *voss_dsp_device;
const char *voss_ctl_device;

int	voss_dups;

static void
usage(void)
{
	fprintf(stderr, "Usage: virtual_oss [options...] [device] \\\n"
	    "\t" "-c 2 -r 48000 -b 16 -s 1024 -f /dev/dsp3 \\\n"
	    "\t" "-c 1 -m 0,0 -d vdsp.0 \\\n"
	    "\t" "-c 2 -m 0,0,1,1 -d vdsp.1 \\\n"
	    "\t" "-c 2 -m 0,0,1,1 -l vdsp.loopback \\\n"
	    "\t" "-M i,<src>,<dst>,<pol>,<mute>,<amp> \\\n"
	    "\t" "-M o,<src>,<dst>,<pol>,<mute>,<amp> \\\n"
	    "\t" "-t vdsp.ctl \n"
	    "\t" "Left channel = 0\n"
	    "\t" "Right channel = 1\n"
	    "\t" "Mapping = rx0,tx0,rx1,tx1\n"
	    "\t" "Max channels = %d\n", VMAX_CHAN);

	exit(EX_USAGE);
}

static void
dup_profile(const vprofile_t *pvp)
{
	vprofile_t *ptr;
	struct cuse_dev *pdev;

	ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		errx(EX_USAGE, "Out of memory");

	memcpy(ptr, pvp, sizeof(*ptr));

	pdev = cuse_dev_create(&vclient_methods, ptr, NULL,
	    0, 0, voss_dsp_perm, ptr->name);
	if (pdev == NULL)
		errx(EX_USAGE, "Could not create '/dev/%s'", ptr->name);

	atomic_lock();
	TAILQ_INSERT_TAIL(&virtual_profile_head, ptr, entry);
	atomic_unlock();

	voss_dups++;
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

int
main(int argc, char **argv)
{
	int c;
	const char *ptr;
	int val;
	int idx;
	int type;
	int samples = 0;
	const char *optstr = "c:r:b:f:m:M:d:l:s:t:h?";
	struct virtual_profile profile;

	memset(&profile, 0, sizeof(profile));

	TAILQ_INIT(&virtual_profile_head);

	TAILQ_INIT(&virtual_client_head);
	TAILQ_INIT(&virtual_loopback_head);

	TAILQ_INIT(&virtual_monitor_input);
	TAILQ_INIT(&virtual_monitor_output);

	atomic_init();

	if (cuse_init() != 0)
		errx(EX_USAGE, "Could not connect to cuse module");

	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 'c':
			profile.channels = atoi(optarg);
			if (profile.channels == 0)
				errx(EX_USAGE, "Number of channels is zero");
			if (profile.channels >= VMAX_CHAN)
				errx(EX_USAGE, "Number of channels is too high");
			break;
		case 'r':
			profile.rate = atoi(optarg);
			if (profile.rate < 8000)
				errx(EX_USAGE, "Sample rate is too low, 8000 Hz");
			if (profile.rate > 0xFFFFFF)
				errx(EX_USAGE, "Sample rate is too high");
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
				errx(EX_USAGE, "Invalid number of sample bits");
				break;
			}
			break;
		case 'f':
			if (profile.bits == 0 || profile.rate == 0 ||
			    profile.channels == 0 || samples == 0)
				errx(EX_USAGE, "Missing -b, -r, -c or -s parameters");

			if (voss_dsp_channels != 0)
				errx(EX_USAGE, "The -f argument may only be used once");

			voss_dsp_channels = profile.channels;
			voss_dsp_sample_rate = profile.rate;
			voss_dsp_bits = profile.bits;
			switch (voss_dsp_bits) {
			case 8:
				voss_dsp_fmt = AFMT_S8;
				break;
			case 16:
				voss_dsp_fmt = AFMT_S16_LE;
				break;
			case 24:
				voss_dsp_fmt = AFMT_S24_LE;
				break;
			case 32:
				voss_dsp_fmt = AFMT_S32_LE;
				break;
			default:
				errx(EX_USAGE, "Invalid number of sample bits");
				break;
			}
			voss_dsp_samples = samples;
			voss_dsp_device = optarg;
			break;
		case 'd':
			profile.name = optarg;
			profile.pvc_head = &virtual_client_head;

			if (profile.bits == 0 || profile.rate == 0 ||
			    profile.channels == 0 || samples == 0)
				errx(EX_USAGE, "Missing -b, -r, -c or -s parameters");

			profile.bufsize = (samples *
			    profile.bits * profile.channels) / 8;
			if (profile.bufsize >= (1024 * 1024))
				errx(EX_USAGE, "-s option value is too big");

			dup_profile(&profile);
			break;
		case 'l':
			profile.name = optarg;
			profile.pvc_head = &virtual_loopback_head;

			if (profile.bits == 0 || profile.rate == 0 ||
			    profile.channels == 0 || samples == 0)
				errx(EX_USAGE, "Missing -b, -r, -r or -s parameters");

			profile.bufsize = (samples *
			    profile.bits * profile.channels) / 8;
			if (profile.bufsize >= (1024 * 1024))
				errx(EX_USAGE, "-s option value is too big");

			dup_profile(&profile);
			break;
		case 's':
			if (samples != 0)
				errx(EX_USAGE, "-s option may only be used once");
			if (profile.bits == 0 || profile.channels == 0)
				errx(EX_USAGE, "-s option requires -b and -c options");

			samples = atoi(optarg);
			if (samples <= 0)
				errx(EX_USAGE, "-s option requires a non-zero positive value");
			break;
		case 't':
			if (voss_ctl_device != NULL)
				errx(EX_USAGE, "-t parameter may only be used once");

			voss_ctl_device = optarg;
			break;
		case 'm':
			ptr = optarg;
			val = 0;
			idx = 0;
			memset(profile.tx_dst, 0, sizeof(profile.tx_dst));
			memset(profile.rx_src, 0, sizeof(profile.rx_src));
			while (1) {
				c = *ptr++;
				if (c == ',' || c == 0) {
					if (idx >= (2 * VMAX_CHAN))
						errx(EX_USAGE, "Too many channels in mask");
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
				val *= 10;
				val += c - '0';
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
							if (val > 31)
								errx(EX_USAGE,
								    "Absolute amplitude for "
								    "-M parameter cannot exceed 31");
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
					val *= 10;
					val += c - '0';
				}
				if (idx < 4)
					errx(EX_USAGE, "Too few parameters for -M");

				pvm = vmonitor_alloc(&idx,
				    (type == 'i') ? &virtual_monitor_input :
				    &virtual_monitor_output);

				if (pvm == NULL)
					errx(EX_USAGE, "Out of memory");

				pvm->src_chan = src;
				pvm->dst_chan = dst;
				pvm->pol = pol;
				pvm->mute = mute;
				pvm->shift = amp;
			} else {
				errx(EX_USAGE, "Invalid -M parameter");
			}
			break;
		default:
			usage();
			break;
		}
	}

	if (voss_dsp_device == NULL)
		errx(EX_USAGE, "Missing -f argument");

	/* Create CTL device */

	if (voss_ctl_device != NULL) {
		struct cuse_dev *pdev;

		pdev = cuse_dev_create(&vctl_methods, NULL, NULL,
		    0, 0, voss_dsp_perm, voss_ctl_device);
		if (pdev == NULL)
			errx(EX_USAGE, "Could not create '/dev/%s'", voss_ctl_device);

		voss_dups++;
	}
	/* Give each DSP device 4 threads */

	for (idx = 0; idx != (voss_dups * 4); idx++) {
		pthread_t td;

		pthread_create(&td, NULL, &virtual_cuse_process, NULL);
	}

	/* Run DSP threads */

	virtual_oss_process(NULL);

	return (0);
}
