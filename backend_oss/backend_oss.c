/*-
 * Copyright (c) 2015 Hans Petter Selasky. All rights reserved.
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

#include <sys/queue.h>
#include <sys/filio.h>
#include <sys/soundcard.h>

#include "../virtual_int.h"
#include "../virtual_backend.h"

static int
oss_set_format(int fd, int *format)
{
	int value[6];
	int error;
	int i;

	value[0] = *format & VPREFERRED_SNE_AFMT;
	value[1] = *format & VPREFERRED_UNE_AFMT;
	value[2] = *format & VPREFERRED_SLE_AFMT;
	value[3] = *format & VPREFERRED_SBE_AFMT;
	value[4] = *format & VPREFERRED_ULE_AFMT;
	value[5] = *format & VPREFERRED_UBE_AFMT;

	for (i = 0; i != 6; i++) {
		if (value[i] == 0)
			continue;
		error = ioctl(fd, SNDCTL_DSP_SETFMT, value + i);
		if (error == 0) {
			*format = value[i];
			return (0);
		}
	}
	return (-1);
}

static void
oss_close(struct voss_backend *pbe)
{
	if (pbe->fd > -1) {
		close(pbe->fd);
		pbe->fd = -1;
	}
}

static int
oss_open(struct voss_backend *pbe, const char *devname, int samplerate, int *pchannels, int *pformat, int attr)
{
	int temp;
	int err;

	pbe->fd = open(devname, attr);
	if (pbe->fd < 0) {
		warn("Could not open DSP device '%s'", devname);
		return (-1);
	}
	temp = 0;
	err = ioctl(pbe->fd, FIONBIO, &temp);
	if (err < 0) {
		warn("Could not set blocking mode on DSP");
		goto error;
	}
	err = oss_set_format(pbe->fd, pformat);
	if (err < 0) {
		warn("Could not set sample format 0x%08x", *pformat);
		goto error;
	}
	temp = *pchannels;
	do {
		err = ioctl(pbe->fd, SOUND_PCM_WRITE_CHANNELS, &temp);
	} while (err < 0 && --temp > 0);

	err = ioctl(pbe->fd, SOUND_PCM_READ_CHANNELS, &temp);
	if (err < 0 || temp <= 0 || temp > *pchannels) {
		warn("Could not set DSP channels: %d / %d", temp, *pchannels);
		goto error;
	}
	*pchannels = temp;

	temp = samplerate;
	err = ioctl(pbe->fd, SNDCTL_DSP_SPEED, &temp);
	if (err < 0 || temp != samplerate) {
		warn("Could not set sample rate to %d / %d Hz", temp, samplerate);
		goto error;
	}
	return (0);
error:
	close(pbe->fd);
	pbe->fd = -1;
	return (-1);
}

static int
oss_rec_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat)
{
	return (oss_open(pbe, devname, samplerate, pchannels, pformat, O_RDONLY));
}

static int
oss_play_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat)
{
	return (oss_open(pbe, devname, samplerate, pchannels, pformat, O_WRONLY));
}

static int
oss_rec_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	return (read(pbe->fd, ptr, len));
}

static int
oss_play_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	return (write(pbe->fd, ptr, len));
}

static void
oss_rec_delay(struct voss_backend *pbe, int *pdelay)
{
	if (ioctl(pbe->fd, FIONREAD, pdelay) != 0)
		*pdelay = -1;
}

static void
oss_play_delay(struct voss_backend *pbe, int *pdelay)
{
	if (ioctl(pbe->fd, SNDCTL_DSP_GETODELAY, pdelay) != 0)
		*pdelay = -1;
}

struct voss_backend voss_backend_oss_rec = {
	.open = oss_rec_open,
	.close = oss_close,
	.transfer = oss_rec_transfer,
	.delay = oss_rec_delay,
	.fd = -1,
};

struct voss_backend voss_backend_oss_play = {
	.open = oss_play_open,
	.close = oss_close,
	.transfer = oss_play_transfer,
	.delay = oss_play_delay,
	.fd = -1,
};
