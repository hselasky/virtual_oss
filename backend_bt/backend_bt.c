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

#include <stdio.h>
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
#include "backend_bt.h"

#define	DPRINTF(...) printf("backend_bt: " __VA_ARGS__)

struct l2cap_info {
	bdaddr_t laddr;
	bdaddr_t raddr;
};

static struct bt_config bt_play_cfg;
static struct bt_config bt_rec_cfg;

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

static void
bt_play_close(struct voss_backend *pbe)
{
  	struct bt_config *cfg = &bt_play_cfg;

	switch (cfg->codec) {
	case CODEC_SBC:
		if (cfg->handle.sbc_enc == NULL)
			break;
		free(cfg->handle.sbc_enc);
		cfg->handle.sbc_enc = NULL;
		break;
	case CODEC_AAC:
		if (cfg->handle.aac_enc == NULL)
			break;
		faacEncClose(cfg->handle.aac_enc);
		cfg->handle.aac_enc = NULL;
		free(cfg->rem_in_data);
		free(cfg->rem_out_data);
		break;
	default:
		break;
	}
	return (bt_close(pbe));
}

static void
bt_rec_close(struct voss_backend *pbe)
{
	/* setup codec */
	switch (bt_rec_cfg.codec) {
	case CODEC_SBC:
		break;
	case CODEC_AAC:
		break;
	default:
		break;
	}
	return (bt_close(pbe));
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
		DPRINTF("Could not open SDP\n");
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
	if (n != 0) {
		DPRINTF("SDP search failed\n");
		goto done;
	}

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
    int *pchannels, int *pformat, struct bt_config *cfg,
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
		printf("Invalid device name '%s'", devname);
		goto error;
	}
	/* skip prefix */
	devname += sizeof("/dev/bluetooth/") - 1;

	if (!bt_aton(devname, &info.raddr)) {
		struct hostent *he = NULL;

		if ((he = bt_gethostbyname(optarg)) == NULL) {
			DPRINTF("Could not get host by name\n");
			goto error;
		}
		bdaddr_copy(&info.raddr, (bdaddr_t *)he->h_addr);
	}
#if 0
	if (!bt_devaddr(XXX, &info.laddr))
		DPRINTF("Could not get local device address\n");
#endif
retry:
	switch (samplerate) {
	case 8000:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0x80;
		cfg->aacMode2 = 0x0C;
		break;
	case 11025:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0x40;
		cfg->aacMode2 = 0x0C;
		break;
	case 12000:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0x20;
		cfg->aacMode2 = 0x0C;
		break;
	case 16000:
		cfg->freq = FREQ_16K;
		cfg->aacMode1 = 0x10;
		cfg->aacMode2 = 0x0C;
		break;
	case 22050:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0x08;
		cfg->aacMode2 = 0x0C;
		break;
	case 24000:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0x04;
		cfg->aacMode2 = 0x0C;
		break;
	case 32000:
		cfg->freq = FREQ_32K;
		cfg->aacMode1 = 0x02;
		cfg->aacMode2 = 0x0C;
		break;
	case 44100:
		cfg->freq = FREQ_44_1K;
		cfg->aacMode1 = 0x01;
		cfg->aacMode2 = 0x0C;
		break;
	case 48000:
		cfg->freq = FREQ_48K;
		cfg->aacMode1 = 0;
		cfg->aacMode2 = 0x8C;
		break;
	case 64000:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0;
		cfg->aacMode2 = 0x4C;
		break;
	case 88200:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0;
		cfg->aacMode2 = 0x2C;
		break;
	case 96000:
		cfg->freq = FREQ_UNDEFINED;
		cfg->aacMode1 = 0;
		cfg->aacMode2 = 0x1C;
		break;
	default:
		DPRINTF("Invalid samplerate %d", samplerate);
		goto error;
	}
	cfg->bands = BANDS_8;
	cfg->bitpool = 0;

	switch (*pchannels) {
	case 1:
		cfg->aacMode2 &= 0xF8;
		cfg->chmode = MODE_MONO;
		break;
	default:
		cfg->aacMode2 &= 0xF4;
		cfg->chmode = MODE_STEREO;
		break;
	}

	cfg->allocm = ALLOC_LOUDNESS;

	if (cfg->chmode == MODE_MONO || cfg->chmode == MODE_DUAL)
		tmpbitpool = 16;
	else
		tmpbitpool = 32;

	if (cfg->bands == BANDS_8)
		tmpbitpool *= 8;
	else
		tmpbitpool *= 4;

	if (tmpbitpool > DEFAULT_MAXBPOOL)
		tmpbitpool = DEFAULT_MAXBPOOL;

	cfg->bitpool = tmpbitpool;

	if (bt_set_format(pformat)) {
		DPRINTF("Unsupported sample format\n");
		goto error;
	}
	l2cap_psm = bt_query(&info, service_class);
	if (l2cap_psm < 0) {
		DPRINTF("PSM not found\n");
		goto error;
	}
	pbe->hc = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (pbe->hc < 0) {
		DPRINTF("Could not create BT socket\n");
		goto error;
	}
	memset(&addr, 0, sizeof(addr));
	addr.l2cap_len = sizeof(addr);
	addr.l2cap_family = AF_BLUETOOTH;
	bdaddr_copy(&addr.l2cap_bdaddr, &info.laddr);

	if (bind(pbe->hc, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DPRINTF("Could not bind to HC\n");
		goto error;
	}
	bdaddr_copy(&addr.l2cap_bdaddr, &info.raddr);
	addr.l2cap_psm = l2cap_psm;
	if (connect(pbe->hc, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DPRINTF("Could not connect to HC\n");
		goto error;
	}
	if (avdtpDiscover(pbe->hc, pbe->hc, &mySepInfo)) {
		DPRINTF("DISCOVER FAILED\n");
		goto error;
	}
	if (avdtpAutoConfig(pbe->hc, pbe->hc, mySepInfo.sep, cfg)) {
		DPRINTF("AUTOCONFIG FAILED\n");
		goto error;
	}
	if (avdtpOpen(pbe->hc, pbe->hc, mySepInfo.sep)) {
		DPRINTF("OPEN FAILED\n");
		goto error;
	}
	pbe->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (pbe->fd < 0) {
		DPRINTF("Could not create BT socket\n");
		goto error;
	}
	memset(&addr, 0, sizeof(addr));

	addr.l2cap_len = sizeof(addr);
	addr.l2cap_family = AF_BLUETOOTH;
	bdaddr_copy(&addr.l2cap_bdaddr, &info.laddr);

	if (bind(pbe->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DPRINTF("Could not bind\n");
		goto error;
	}
	bdaddr_copy(&addr.l2cap_bdaddr, &info.raddr);
	addr.l2cap_psm = l2cap_psm;
	if (connect(pbe->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DPRINTF("Could not connect\n");
		goto error;
	}
	getsockopt(pbe->fd, SOL_L2CAP, SO_L2CAP_OMTU, &cfg->mtu, &mtusize);

	temp = cfg->mtu * 2;
	if (setsockopt(pbe->fd, SOL_SOCKET, SO_SNDBUF, &temp, sizeof(temp)) == -1) {
		DPRINTF("Could not set send buffer size\n");
		goto error;
	}
	temp = cfg->mtu;
	if (setsockopt(pbe->fd, SOL_SOCKET, SO_SNDLOWAT, &temp, sizeof(temp)) == -1) {
		DPRINTF("Could not set low water mark\n");
		goto error;
	}
	if (avdtpStart(pbe->hc, pbe->hc, mySepInfo.sep)) {
		DPRINTF("START FAILED\n");
		goto error;
	}
	switch (cfg->chmode) {
	case MODE_MONO:
		*pchannels = 1;
		break;
	default:
		*pchannels = 2;
		break;
	}
	return (0);

error:
	if (pbe->hc > -1) {
		close(pbe->hc);
		pbe->hc = -1;
	}
	if (pbe->fd > -1) {
		close(pbe->fd);
		pbe->fd = -1;
	}
	return (-1);
}

static int
bt_rec_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat)
{
  	struct bt_config *cfg = &bt_rec_cfg;
	int retval;

	memset(cfg, 0, sizeof(*cfg));

	retval = bt_open(pbe, devname, samplerate, pchannels, pformat,
	    cfg, SDP_SERVICE_CLASS_AUDIO_SOURCE);
	if (retval != 0)
		return (retval);
	return (0);
}

static int
bt_play_open(struct voss_backend *pbe, const char *devname, int samplerate,
    int *pchannels, int *pformat)
{
	struct bt_config *cfg = &bt_play_cfg;
	int retval;

	memset(cfg, 0, sizeof(*cfg));

	retval = bt_open(pbe, devname, samplerate, pchannels, pformat,
	    cfg, SDP_SERVICE_CLASS_AUDIO_SINK);
	if (retval != 0)
		return (retval);

	/* setup codec */
	switch (cfg->codec) {
		unsigned long aacFrameSamples = 0;
		unsigned long aacFrameBytes = 0;
		faacEncConfigurationPtr aac_cfg;

	case CODEC_SBC:
		cfg->handle.sbc_enc =
		    malloc(sizeof(*cfg->handle.sbc_enc));
		if (cfg->handle.sbc_enc == NULL)
			return (-1);
		memset(cfg->handle.sbc_enc, 0, sizeof(*cfg->handle.sbc_enc));
		break;
	case CODEC_AAC:
		cfg->handle.aac_enc =
		    faacEncOpen(samplerate, *pchannels,
		    &aacFrameSamples,
		    &aacFrameBytes);
		if (cfg->handle.aac_enc == NULL)
			return (-1);

		aac_cfg = faacEncGetCurrentConfiguration(cfg->handle.aac_enc);
		aac_cfg->inputFormat = FAAC_INPUT_16BIT;
		aac_cfg->mpegVersion = MPEG2;
		aac_cfg->outputFormat = 1;	/* RAW data */
		aac_cfg->useTns = 1;
		aac_cfg->useLfe = 0;
		aac_cfg->aacObjectType = LOW;
		aac_cfg->shortctl = SHORTCTL_NORMAL;
		aac_cfg->quantqual = 100;
		aac_cfg->bandWidth = 0;
		aac_cfg->bitRate = 0;
		if (faacEncSetConfiguration(cfg->handle.aac_enc, aac_cfg) == 0) {
			faacEncClose(cfg->handle.aac_enc);
			cfg->handle.aac_enc = NULL;
			return (-1);
		}
		cfg->rem_in_size = aacFrameSamples * 2;
		cfg->rem_in_data = malloc(cfg->rem_in_size);
		if (cfg->rem_in_data == NULL) {
			faacEncClose(cfg->handle.aac_enc);
			cfg->handle.aac_enc = NULL;
			return (-1);
		}
		cfg->rem_out_size = aacFrameBytes;
		cfg->rem_out_data = malloc(cfg->rem_out_size);
		if (cfg->rem_out_data == NULL) {
			free(cfg->rem_in_data);
			faacEncClose(cfg->handle.aac_enc);
			cfg->handle.aac_enc = NULL;
			return (-1);
		}
		break;
	default:
		break;
	}
	return (0);
}

static int
bt_rec_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	struct bt_config *cfg = &bt_rec_cfg;
	int err;
	int i;

	do {
		err = read(pbe->fd, cfg->mtu_data, cfg->mtu);
	} while (err < 0 && errno == EAGAIN);

	if (err < 0)
		return (-1);

	return (-1);
}

static int
bt_play_sbc_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	struct bt_config *cfg = &bt_play_cfg;
	struct sbc_encode *sbc = cfg->handle.sbc_enc;
	int rem_size = 1;
	int old_len = len;
	int err = 0;

	switch (cfg->blocks) {
	case BLOCKS_4:
		sbc->blocks = 4;
		rem_size *= 4;
		break;
	case BLOCKS_8:
		sbc->blocks = 8;
		rem_size *= 8;
		break;
	case BLOCKS_12:
		sbc->blocks = 12;
		rem_size *= 12;
		break;
	default:
		sbc->blocks = 16;
		rem_size *= 16;
		break;
	}

	switch (cfg->bands) {
	case BANDS_4:
		rem_size *= 4;
		sbc->bands = 4;
		break;
	default:
		rem_size *= 8;
		sbc->bands = 8;
		break;
	}

	/* store number of samples per frame */
	sbc->framesamples = rem_size;

	if (cfg->chmode != MODE_MONO) {
		rem_size *= 2;
		sbc->channels = 2;
	} else {
		sbc->channels = 1;
	}

	rem_size *= 2;			/* 16-bit samples */

	while (len > 0) {
		int delta = len;

		if (delta > (int)(rem_size - sbc->rem_len))
			delta = (int)(rem_size - sbc->rem_len);

		/* copy in samples */
		memcpy((char *)sbc->music_data +
		    sbc->rem_len, ptr, delta);

		ptr = (char *)ptr + delta;
		len -= delta;
		sbc->rem_len += delta;

		/* check if buffer is full */
		if (sbc->rem_len == rem_size) {
			struct sbc_header *phdr = (struct sbc_header *)cfg->mtu_data;
			uint32_t pkt_len;
			uint32_t rem;

			if (cfg->chmode == MODE_MONO)
				sbc->channels = 1;
			else
				sbc->channels = 2;

			pkt_len = sbc_make_frame(cfg);

	retry:
			if (cfg->mtu_offset == 0) {
				phdr->id = 0x80;	/* RTP v2 */
				phdr->id2 = 0x60;	/* payload type 96. */
				phdr->seqnumMSB = (uint8_t)(cfg->mtu_seqnumber >> 8);
				phdr->seqnumLSB = (uint8_t)(cfg->mtu_seqnumber);
				phdr->ts3 = (uint8_t)(cfg->mtu_timestamp >> 24);
				phdr->ts2 = (uint8_t)(cfg->mtu_timestamp >> 16);
				phdr->ts1 = (uint8_t)(cfg->mtu_timestamp >> 8);
				phdr->ts0 = (uint8_t)(cfg->mtu_timestamp);
				phdr->reserved0 = 0x01;
				phdr->numFrames = 0;

				cfg->mtu_seqnumber++;
				cfg->mtu_offset += sizeof(*phdr);
			}
			/* compute bytes left */
			rem = cfg->mtu - cfg->mtu_offset;

			if (phdr->numFrames == 255 || rem < pkt_len) {
				int xlen;

				if (phdr->numFrames == 0)
					return (-1);
				do {
					xlen = write(pbe->fd, cfg->mtu_data, cfg->mtu_offset);
				} while (xlen < 0 && errno == EAGAIN);

				if (xlen < 0)
					return (-1);

				cfg->mtu_offset = 0;
				goto retry;
			}
			memcpy(cfg->mtu_data + cfg->mtu_offset, sbc->data, pkt_len);
			memset(sbc->data, 0, pkt_len);
			cfg->mtu_offset += pkt_len;
			cfg->mtu_timestamp += sbc->framesamples;
			phdr->numFrames++;

			sbc->rem_len = 0;
		}
	}
	if (err == 0)
		return (old_len);
	return (err);
}

static int
bt_play_aac_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	struct bt_config *cfg = &bt_play_cfg;
	faacEncHandle *aac = cfg->handle.aac_enc;
	struct aac_header {
		uint8_t	id;
		uint8_t	id2;
		uint8_t	seqnumMSB;
		uint8_t	seqnumLSB;
		uint8_t	ts3;
		uint8_t	ts2;
		uint8_t	ts1;
		uint8_t	ts0;
		uint8_t	sync3;
		uint8_t	sync2;
		uint8_t	sync1;
		uint8_t	sync0;
	};

	int old_len = len;
	int pkt_len;
	int err = 0;

	while (len > 0) {
		int delta = len;
		int rem;

		if (delta > (int)(cfg->rem_in_size - cfg->rem_in_len))
			delta = (int)(cfg->rem_in_size - cfg->rem_in_len);

		/* copy in samples */
		memcpy(cfg->rem_in_data + cfg->rem_in_len, ptr, delta);

		ptr = (char *)ptr + delta;
		len -= delta;
		cfg->rem_in_len += delta;

		/* check if buffer is full */
		if (cfg->rem_in_len == cfg->rem_in_size) {
			struct aac_header *phdr = (struct aac_header *)cfg->mtu_data;
			int i;

			pkt_len = faacEncEncode(cfg->handle.aac_enc,
			    (int *)cfg->rem_in_data, cfg->rem_in_size / 2,
			    cfg->rem_out_data, cfg->rem_out_size);
			if (pkt_len < 1) {
				/* reset remaining length */
				cfg->rem_in_len = 0;
				continue;
			}
	retry:
			if (cfg->mtu_offset == 0) {
				phdr->id = 0x80;	/* RTP v2 */
				phdr->id2 = 0x60;	/* payload type 96. */
				phdr->seqnumMSB = (uint8_t)(cfg->mtu_seqnumber >> 8);
				phdr->seqnumLSB = (uint8_t)(cfg->mtu_seqnumber);
				phdr->ts3 = (uint8_t)(cfg->mtu_timestamp >> 24);
				phdr->ts2 = (uint8_t)(cfg->mtu_timestamp >> 16);
				phdr->ts1 = (uint8_t)(cfg->mtu_timestamp >> 8);
				phdr->ts0 = (uint8_t)(cfg->mtu_timestamp);
				phdr->sync3 = 0;
				phdr->sync2 = 0;
				phdr->sync1 = 0;
				phdr->sync0 = 0;

				cfg->mtu_seqnumber++;
				cfg->mtu_offset += sizeof(*phdr);
			}
			/* compute bytes left */
			rem = cfg->mtu - cfg->mtu_offset;

			if (rem >= pkt_len) {
				int xlen;

				memcpy(cfg->mtu_data + cfg->mtu_offset, cfg->rem_out_data, pkt_len);
				cfg->mtu_offset += pkt_len;
				if (cfg->chmode != MODE_MONO)
					cfg->mtu_timestamp += cfg->rem_in_size / 4;
				else
					cfg->mtu_timestamp += cfg->rem_in_size / 2;
				do {
					xlen = write(pbe->fd, cfg->mtu_data, cfg->mtu_offset);
				} while (xlen < 0 && errno == EAGAIN);

				if (xlen < 0)
					return (-1);
			}
			/* reset MTU offset */
			cfg->mtu_offset = 0;		

			/* reset remaining length */
			cfg->rem_in_len = 0;
		}
	}
	if (err == 0)
		return (old_len);
	return (err);
}

static int
bt_play_transfer(struct voss_backend *pbe, void *ptr, int len)
{
	struct bt_config *cfg = &bt_play_cfg;

	switch (cfg->codec) {
	case CODEC_SBC:
		return (bt_play_sbc_transfer(pbe, ptr, len));
	case CODEC_AAC:
		return (bt_play_aac_transfer(pbe, ptr, len));
	default:
		return (-1);
	}
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
	.close = bt_rec_close,
	.transfer = bt_rec_transfer,
	.delay = bt_rec_delay,
	.fd = -1,
	.hc = -1,
};

struct voss_backend voss_backend_bt_play = {
	.open = bt_play_open,
	.close = bt_play_close,
	.transfer = bt_play_transfer,
	.delay = bt_play_delay,
	.fd = -1,
	.hc = -1,
};
