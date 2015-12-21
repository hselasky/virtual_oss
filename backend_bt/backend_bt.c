/* $NetBSD$ */

/*-
 * Copyright (c) 2015 Hans Petter Selasky. All rights reserved.
 * Copyright (c) 2015 Nathanial Sloss <nathanialsloss@yahoo.com.au>.
 * All rights reserved.
 * Copyright (c) 2006 Itronix Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of Itronix Inc. may not be used to endorse
 *    or promote products derived from this software without specific
 *    prior written permission.
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

/* This was based upon bta2dpd.c which was based upon bthset.c */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <bluetooth.h>
#include <sdp.h>

#include <sys/queue.h>
#include <sys/filio.h>
#include <sys/soundcard.h>

#include "../virtual_int.h"
#include "../virtual_backend.h"

#include "avdtp_signal.h"
#include "sbc_encode.h"

struct l2cap_info {
	bdaddr_t laddr;
	bdaddr_t raddr;
};

static struct sbc_encode sbc_encode;

static struct avdtp_sepInfo mySepInfo;

static int
bt_set_format(int *format)
{
	int value;

	value = *format & AFMT_S16_NE;
	if (value != 0) {
		*format = value;
		return (0);
	}
	return (-1);
}

static void
bt_close(struct voss_backend *pbe)
{
	if (pbe->hc > -1) {
		avdtpAbort(pbe->hc, pbe->hc, mySepInfo.sep);
		avdtpClose(pbe->hc, pbe->hc, mySepInfo.sep);
		close(pbe->hc);
		pbe->hc = -1;
	}
	if (pbe->fd > -1) {
		close(pbe->fd);
		pbe->fd = -1;
	}
}

static const uint32_t bt_attrs[] =
{
	SDP_ATTR_RANGE(SDP_ATTR_PROTOCOL_DESCRIPTOR_LIST,
	    SDP_ATTR_PROTOCOL_DESCRIPTOR_LIST),
};

#define	BT_NUM_VALUES 32
#define	BT_BUF_SIZE 32

static int
bt_find_psm(const uint8_t *start, const uint8_t *end)
{
	uint32_t type;
	uint32_t len;
	int protover = 0;
	int psm = -1;

	if ((end - start) < 2)
		return (-1);

	SDP_GET8(type, start);
	switch (type) {
	case SDP_DATA_SEQ8:
		SDP_GET8(len, start);
		break;

	case SDP_DATA_SEQ16:
		SDP_GET16(len, start);
		break;

	case SDP_DATA_SEQ32:
		SDP_GET32(len, start);
		break;

	default:
		return (-1);
	}

	while (start < end) {
		SDP_GET8(type, start);
		switch (type) {
		case SDP_DATA_SEQ8:
			SDP_GET8(len, start);
			break;

		case SDP_DATA_SEQ16:
			SDP_GET16(len, start);
			break;

		case SDP_DATA_SEQ32:
			SDP_GET32(len, start);
			break;

		default:
			return (-1);
		}
		/* check range */
		if (len > (end - start))
			break;

		if (len >= 6) {
			const uint8_t *ptr = start;

			SDP_GET8(type, ptr);
			if (type == SDP_DATA_UUID16) {
				uint16_t temp;

				SDP_GET16(temp, ptr);
				switch (temp) {
				case SDP_UUID_PROTOCOL_L2CAP:
					SDP_GET8(type, ptr);
					SDP_GET16(psm, ptr);
					break;
				case SDP_UUID_PROTOCOL_AVDTP:
					SDP_GET8(type, ptr);
					SDP_GET16(protover, ptr);
					break;
				default:
					break;
				}
			}
		}
		start += len;

		if (protover >= 0x0100 && psm > -1)
			return (htole16(psm));
	}
	return (-1);
}

static int
bt_query(struct l2cap_info *info, uint16_t service_class)
{
	sdp_attr_t values[BT_NUM_VALUES];
	uint8_t buffer[BT_NUM_VALUES][BT_BUF_SIZE];
	void *ss;
	int psm = -1;
	int n;

	memset(buffer, 0, sizeof(buffer));
	memset(values, 0, sizeof(values));

	ss = sdp_open(&info->laddr, &info->raddr);
	if (sdp_error(ss) != 0) {
		warn("Could not open SDP");
		return (psm);
	}
	/* Initialize attribute values array */
	for (n = 0; n != BT_NUM_VALUES; n++) {
		values[n].flags = SDP_ATTR_INVALID;
		values[n].vlen = BT_BUF_SIZE;
		values[n].value = buffer[n];
	}

	/* Do SDP Service Search Attribute Request */
	n = sdp_search(ss, 1, &service_class, 1, bt_attrs, BT_NUM_VALUES, values);
	if (n != 0)
		goto done;

	/* Print attributes values */
	for (n = 0; n != BT_NUM_VALUES; n++) {
		if (values[n].flags != SDP_ATTR_OK)
			break;
		if (values[n].attr != SDP_ATTR_PROTOCOL_DESCRIPTOR_LIST)
			continue;
		psm = bt_find_psm(values[n].value, values[n].value + values[n].vlen);
		if (psm > -1)
			break;
	}
done:
	sdp_close(ss);
	return (psm);
}

static int
bt_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat, struct sbc_config *sbcfg,
    int service_class)
{
	struct sockaddr_l2cap addr;
	struct l2cap_info info;
	socklen_t mtusize = sizeof(uint16_t);
	int tmpbitpool;
	int l2cap_psm;
	int temp;
	int err;

	memset(&info, 0, sizeof(info));

	if (strstr(devname, "/dev/bluetooth/") != devname) {
		warn("Invalid device name '%s'", devname);
		goto error;
	}
	/* skip prefix */
	devname += sizeof("/dev/bluetooth/") - 1;

	if (!bt_aton(devname, &info.raddr)) {
		struct hostent *he = NULL;

		if ((he = bt_gethostbyname(optarg)) == NULL) {
			warn("Could not get host by name");
			goto error;
		}
		bdaddr_copy(&info.raddr, (bdaddr_t *)he->h_addr);
	}
#if 0
	if (!bt_devaddr(XXX, &info.laddr))
		warn("Could not get local device address");
#endif
	switch (samplerate) {
	case 16000:
		sbcfg->freq = FREQ_16K;
		break;
	case 32000:
		sbcfg->freq = FREQ_32K;
		break;
	case 44100:
		sbcfg->freq = FREQ_44_1K;
		break;
	case 48000:
		sbcfg->freq = FREQ_48K;
		break;
	default:
		warn("Invalid samplerate %d", samplerate);
		goto error;
	}
	sbcfg->bands = BANDS_8;
	sbcfg->bitpool = 0;

	switch (*pchannels) {
	case 1:
		*pchannels = 1;
		sbcfg->chmode = MODE_MONO;
		break;
	default:
		*pchannels = 2;
		sbcfg->chmode = MODE_STEREO;
		break;
	}

	sbcfg->allocm = ALLOC_LOUDNESS;

	if (sbcfg->chmode == MODE_MONO || sbcfg->chmode == MODE_DUAL)
		tmpbitpool = 16;
	else
		tmpbitpool = 32;

	if (sbcfg->bands == BANDS_8)
		tmpbitpool *= 8;
	else
		tmpbitpool *= 4;

	if (tmpbitpool > DEFAULT_MAXBPOOL)
		tmpbitpool = DEFAULT_MAXBPOOL;

	sbcfg->bitpool = tmpbitpool;

	if (bt_set_format(pformat)) {
		warn("Unsupported sample format");
		goto error;
	}
	l2cap_psm = bt_query(&info, service_class);
	if (l2cap_psm < 0) {
		warn("PSM not found");
		goto error;
	}
	pbe->hc = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (pbe->hc < 0) {
		warn("Could not create BT socket");
		goto error;
	}
	memset(&addr, 0, sizeof(addr));
	addr.l2cap_len = sizeof(addr);
	addr.l2cap_family = AF_BLUETOOTH;
	bdaddr_copy(&addr.l2cap_bdaddr, &info.laddr);

	if (bind(pbe->hc, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		warn("Could not bind to HC");
		goto error;
	}
	bdaddr_copy(&addr.l2cap_bdaddr, &info.raddr);
	addr.l2cap_psm = l2cap_psm;
	if (connect(pbe->hc, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		warn("Could not connect to HC");
		goto error;
	}
	if (avdtpDiscover(pbe->hc, pbe->hc, &mySepInfo)) {
		warn("DISCOVER FAILED");
		goto error;
	}
	if (avdtpAutoConfig(pbe->hc, pbe->hc, mySepInfo.sep, sbcfg)) {
		warn("AUTOCONFIG FAILED");
		goto error;
	}
	if (avdtpOpen(pbe->hc, pbe->hc, mySepInfo.sep)) {
		warn("OPEN FAILED");
		goto error;
	}
	pbe->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (pbe->fd < 0) {
		warn("Could not create BT socket");
		goto error;
	}
	memset(&addr, 0, sizeof(addr));

	addr.l2cap_len = sizeof(addr);
	addr.l2cap_family = AF_BLUETOOTH;
	bdaddr_copy(&addr.l2cap_bdaddr, &info.laddr);

	if (bind(pbe->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		warn("Could not bind");
		goto error;
	}
	bdaddr_copy(&addr.l2cap_bdaddr, &info.raddr);
	addr.l2cap_psm = l2cap_psm;
	if (connect(pbe->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		warn("Could not connect");
		goto error;
	}
	getsockopt(pbe->fd, SOL_L2CAP, SO_L2CAP_OMTU, &sbcfg->mtu, &mtusize);

	temp = sbcfg->mtu * 2;
	if (setsockopt(pbe->fd, SOL_SOCKET, SO_SNDBUF, &temp, sizeof(temp)) == -1) {
		warn("Could not set send buffer size");
		goto error;
	}
	temp = sbcfg->mtu;
	if (setsockopt(pbe->fd, SOL_SOCKET, SO_SNDLOWAT, &temp, sizeof(temp)) == -1) {
		warn("Could not set low water mark");
		goto error;
	}
	if (avdtpStart(pbe->hc, pbe->hc, mySepInfo.sep)) {
		warn("START FAILED");
		goto error;
	}
	return (0);

error:
	if (pbe->fd > -1) {
		close(pbe->fd);
		pbe->fd = -1;
	}
	if (pbe->hc > -1) {
		close(pbe->hc);
		pbe->hc = -1;
	}
	return (-1);
}

static int
bt_rec_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat)
{
	return (bt_open(pbe, devname, samplerate, pchannels, pformat,
	    NULL, SDP_SERVICE_CLASS_AUDIO_SOURCE));
}

static int
bt_play_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat)
{
	memset(&sbc_encode, 0, sizeof(sbc_encode));

	return (bt_open(pbe, devname, samplerate, pchannels, pformat,
	    &sbc_encode.cfg, SDP_SERVICE_CLASS_AUDIO_SINK));
}

static int
bt_rec_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	return (-1);
}

static int
bt_play_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	int rem_size = 1;
	int old_len = len;
	int err = 0;

	switch (sbc_encode.cfg.blocks) {
	case BLOCKS_4:
		sbc_encode.blocks = 4;
		rem_size *= 4;
		break;
	case BLOCKS_8:
		sbc_encode.blocks = 8;
		rem_size *= 8;
		break;
	case BLOCKS_12:
		sbc_encode.blocks = 12;
		rem_size *= 12;
		break;
	default:
		sbc_encode.blocks = 16;
		rem_size *= 16;
		break;
	}

	switch (sbc_encode.cfg.bands) {
	case BANDS_4:
		rem_size *= 4;
		sbc_encode.bands = 4;
		break;
	default:
		rem_size *= 8;
		sbc_encode.bands = 8;
		break;
	}

	/* store number of samples per frame */
	sbc_encode.framesamples = rem_size;

	if (sbc_encode.cfg.chmode != MODE_MONO) {
		rem_size *= 2;
		sbc_encode.channels = 2;
	} else {
		sbc_encode.channels = 1;
	}

	rem_size *= 2;			/* 16-bit samples */

	while (len > 0) {
		int delta = len;

		if (delta > (int)(rem_size - sbc_encode.rem_len))
			delta = (int)(rem_size - sbc_encode.rem_len);

		/* copy in samples */
		memcpy((char *)sbc_encode.music_data +
		    sbc_encode.rem_len, ptr, delta);

		ptr = (char *)ptr + delta;
		len -= delta;
		sbc_encode.rem_len += delta;

		/* check if buffer is full */
		if (sbc_encode.rem_len == rem_size) {
			if (sbc_encode_stream(&sbc_encode, pbe->fd)) {
				err = -1;
				break;
			}
			sbc_encode.rem_len = 0;
		}
	}
	if (err == 0)
		return (old_len);
	return (err);
}

static void
bt_rec_delay(struct voss_backend *pbe, int *pdelay)
{
	*pdelay = -1;
}

static void
bt_play_delay(struct voss_backend *pbe, int *pdelay)
{
	/* TODO */
	*pdelay = -1;
}

struct voss_backend voss_backend_bt_rec = {
	.open = bt_rec_open,
	.close = bt_close,
	.transfer = bt_rec_transfer,
	.delay = bt_rec_delay,
	.fd = -1,
	.hc = -1,
};

struct voss_backend voss_backend_bt_play = {
	.open = bt_play_open,
	.close = bt_close,
	.transfer = bt_play_transfer,
	.delay = bt_play_delay,
	.fd = -1,
	.hc = -1,
};
