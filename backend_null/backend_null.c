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
#include <time.h>

#include <sys/queue.h>
#include <sys/filio.h>
#include <sys/soundcard.h>

#include "../virtual_int.h"
#include "../virtual_backend.h"

static void
null_close(struct voss_backend *pbe)
{
}

static int
null_open(struct voss_backend *pbe, const char *devname,
    int samplerate, int bufsize, int *pchannels, int *pformat)
{
	int value[3];
	int i;

	value[0] = *pformat & VPREFERRED_SNE_AFMT;
	value[1] = *pformat & VPREFERRED_SLE_AFMT;
	value[2] = *pformat & VPREFERRED_SBE_AFMT;

	for (i = 0; i != 3; i++) {
		if (value[i] == 0)
			continue;
		*pformat = value[i];
		return (0);
	}
	return (-1);
}

static void
null_wait(void)
{
	struct timespec ts;
	uint64_t delay;
	uint64_t nsec;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	nsec = ((unsigned)ts.tv_sec) * 1000000000ULL + ts.tv_nsec;

	delay = voss_dsp_samples;
	delay *= 1000000000ULL;
	delay /= voss_dsp_sample_rate;

	usleep((delay - (nsec % delay)) / 1000);
}

static int
null_rec_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	if (!voss_has_synchronization)
		null_wait();
	memset(ptr, 0, len);
	return (len);
}

static int
null_play_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	return (len);
}

static void
null_delay(struct voss_backend *pbe, int *pdelay)
{
	*pdelay = -1;
}

struct voss_backend voss_backend_null_rec = {
	.open = null_open,
	.close = null_close,
	.transfer = null_rec_transfer,
	.delay = null_delay,
};

struct voss_backend voss_backend_null_play = {
	.open = null_open,
	.close = null_close,
	.transfer = null_play_transfer,
	.delay = null_delay,
};
