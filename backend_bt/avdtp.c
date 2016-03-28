/* $NetBSD$ */

/*-
 * Copyright (c) 2015-2016 Nathanial Sloss <nathanialsloss@yahoo.com.au>
 * Copyright (c) 2016 Hans Petter Selasky <hps@selasky.org>
 * All rights reserved.
 *
 *		This software is dedicated to the memory of -
 *	   Baron James Anlezark (Barry) - 1 Jan 1949 - 13 May 2012.
 *
 *		Barry was a man who loved his music.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/uio.h>

#include "avdtp_signal.h"
#include "backend_bt.h"

#define	DPRINTF(...) printf("backend_bt: " __VA_ARGS__)

struct avdtpGetResponseInfo {
	uint8_t	buffer_data[512];
	uint16_t buffer_len;
	uint8_t	trans;
	uint8_t	signalId;
};

static int
avdtpGetResponse(int fd, struct avdtpGetResponseInfo *info)
{
	int len;

	memset(info, 0, sizeof(*info));

	len = read(fd, &info->buffer_data, sizeof(info->buffer_data));

	if (len < AVDTP_LEN_SUCCESS)
		return (255);

	info->trans = (info->buffer_data[0] & TRANSACTIONLABEL) >> TRANSACTIONLABEL_S;
	info->signalId = (info->buffer_data[1] & SIGNALID_MASK);
	info->buffer_len = len;

	return (info->buffer_data[0] & MESSAGETYPE);
}

static int
avdtpSendSyncCommand(int fd, struct avdtpGetResponseInfo *info,
    uint8_t command, uint8_t type, uint8_t *data0, int datasize0,
    uint8_t *data1, int datasize1)
{
	static uint8_t transLabel;
	struct iovec iov[3];
	uint8_t header[2];
	uint8_t trans;
	int retval;

	trans = (transLabel++) & 0xF;

	/* fill out command header */
	header[0] = (trans << 4) | (type & 3);
	if (command != 0)
		header[1] = command & 0x3f;
	else
		header[1] = 3;

	iov[0].iov_base = header;
	iov[0].iov_len = 2;
	iov[1].iov_base = data0;
	iov[1].iov_len = datasize0;
	iov[2].iov_base = data1;
	iov[2].iov_len = datasize1;

	alarm(8);			/* set timeout */

	retval = writev(fd, iov, 3);
	if (retval != (2 + datasize0 + datasize1)) {
		retval = EINVAL;
		goto done;
	}
retry:
	switch (avdtpGetResponse(fd, info)) {
	case RESPONSEACCEPT:
		if (info->trans != trans)
			goto retry;
		retval = 0;
		break;
	case RESPONSEREJECT:
		if (info->trans != trans)
			goto retry;
		retval = EINVAL;
		goto done;
	case COMMAND:
		goto retry;
	default:
		retval = ENXIO;
		break;
	}
done:
	alarm(0);			/* clear timeout */

	return (retval);
}

static int
avdtpSendDescResponse(int fd, int trans, int mySep)
{
	uint8_t data[4];
	int retval;

	data[0] = trans << 4 | RESPONSEACCEPT;
	data[1] = AVDTP_DISCOVER;
	data[2] = mySep << 2;
	data[3] = 0x6 << 4;

	retval = write(fd, data, sizeof(data));
	if (retval != sizeof(data))
		return (ENXIO);

	return (0);
}

int
avdtpSendCapabilitiesResponseSBC(int fd, int trans, uint8_t mySep,
    struct bt_config *cfg)
{
	uint8_t data[12];
	int retval;

	data[0] = (uint8_t)(trans << 4 | RESPONSEACCEPT);
	data[1] = AVDTP_GET_CAPABILITIES;
	data[2] = mediaTransport;
	data[3] = 0;
	data[4] = mediaCodec;
	data[5] = 0x6;
	data[6] = mediaTypeAudio;
	data[7] = SBC_CODEC_ID;
	data[8] =
	    (1 << (3 - MODE_STEREO)) |
	    (1 << (3 - MODE_MONO)) |
	    (1 << (3 - cfg->freq + 4));
	data[9] =
	    (1 << (3 - cfg->blocks + 4)) |
	    (1 << (1 - cfg->bands + 2)) |
	    (1 << cfg->allocm);
	data[10] = MIN_BITPOOL;
	data[11] = DEFAULT_MAXBPOOL;

	retval = write(fd, data, sizeof(data));
	if (retval != sizeof(data))
		return (ENXIO);

	return (0);
}

int
avdtpSendAccept(int fd, uint8_t trans, uint8_t myCommand)
{
	uint8_t data[2];
	int retval;

	data[0] = (uint8_t)(trans << 4 | RESPONSEACCEPT);
	data[1] = myCommand;;

	retval = write(fd, data, sizeof(data));
	if (retval != sizeof(data))
		return (ENXIO);

	return (0);
}

int
avdtpSendReject(int fd, uint8_t trans, uint8_t myCommand)
{
	uint8_t data[4];
	int retval;

	data[0] = (uint8_t)(trans << 4 | RESPONSEREJECT);
	data[1] = myCommand;
	data[2] = 0;

	retval = write(fd, data, sizeof(data));
	if (retval != sizeof(data))
		return (ENXIO);

	return (0);
}

int
avdtpSendDiscResponseAudio(int fd, uint8_t trans,
    uint8_t mySep, uint8_t is_sink)
{
	uint8_t data[4];
	int retval;

	data[0] = (uint8_t)(trans << 4 | RESPONSEACCEPT);
	data[1] = AVDTP_DISCOVER;
	data[2] = (uint8_t)(mySep << 2);
	data[3] = is_sink ? (1 << 3) : 0;

	retval = write(fd, data, sizeof(data));
	if (retval != sizeof(data))
		return (ENXIO);

	return (0);
}

int
avdtpDiscover(int fd, struct bt_config *cfg)
{
	struct avdtpGetResponseInfo info;
	uint16_t offset;
	int retval;

	retval = avdtpSendSyncCommand(fd, &info, AVDTP_DISCOVER, 0,
	    NULL, 0, NULL, 0);
	if (retval)
		return (retval);
	for (offset = 2; offset + 2 <= info.buffer_len; offset += 2) {
		cfg->sep = info.buffer_data[offset] >> 2;
		cfg->media_Type = info.buffer_data[offset + 1] >> 4;
		if (!(info.buffer_data[offset] & DISCOVER_SEP_IN_USE))
			return (0);
	}
	return (ENOMEM);
}

static int
avdtpGetCapabilities(int fd, uint8_t sep, struct avdtpGetResponseInfo *info)
{
	uint8_t address = (sep << 2);

	return (avdtpSendSyncCommand(fd, info,
	    AVDTP_GET_CAPABILITIES, 0, &address, 1, NULL, 0));
}

int
avdtpSetConfiguration(int fd, uint8_t sep, uint8_t *data, int datasize)
{
	struct avdtpGetResponseInfo info;
	uint8_t configAddresses[2];

	configAddresses[0] = sep << 2;
	configAddresses[1] = INTSEP << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_SET_CONFIGURATION, 0,
	    configAddresses, 2, data, datasize));
}

int
avdtpOpen(int fd, uint8_t sep)
{
	struct avdtpGetResponseInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_OPEN, 0,
	    &address, 1, NULL, 0));
}

int
avdtpStart(int fd, uint8_t sep)
{
	struct avdtpGetResponseInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_START, 0,
	    &address, 1, NULL, 0));
}

int
avdtpClose(int fd, uint8_t sep)
{
	struct avdtpGetResponseInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_CLOSE, 0,
	    &address, 1, NULL, 0));
}

int
avdtpSuspend(int fd, uint8_t sep)
{
	struct avdtpGetResponseInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_SUSPEND, 0,
	    &address, 1, NULL, 0));
}

int
avdtpAbort(int fd, uint8_t sep)
{
	struct avdtpGetResponseInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_ABORT, 0,
	    &address, 1, NULL, 0));
}

int
avdtpAutoConfig(int fd, uint8_t sep, struct bt_config *cfg)
{
	struct avdtpGetResponseInfo info;
	uint8_t freqmode;
	uint8_t blk_len_sb_alloc;
	uint8_t availFreqMode = 0;
	uint8_t availConfig = 0;
	uint8_t supBitpoolMin = 0;
	uint8_t supBitpoolMax = 0;
	uint8_t aacMode1 = 0;
	uint8_t aacMode2 = 0;
	uint8_t aacBitrate3 = 0;
	uint8_t aacBitrate4 = 0;
	uint8_t aacBitrate5 = 0;
	int retval;
	int i;

	retval = avdtpGetCapabilities(fd, sep, &info);
	if (retval) {
		DPRINTF("Cannot get capabilities\n");
		return (retval);
	}
retry:
	for (i = 2; (i + 1) < info.buffer_len;) {
#if 0
		DPRINTF("0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
		    info.buffer_data[i + 0],
		    info.buffer_data[i + 1],
		    info.buffer_data[i + 2],
		    info.buffer_data[i + 3],
		    info.buffer_data[i + 4],
		    info.buffer_data[i + 5]);
#endif
		if (i + 2 + info.buffer_data[i + 1] > info.buffer_len)
			break;
		switch (info.buffer_data[i]) {
		case mediaTransport:
			break;
		case mediaCodec:
			if (info.buffer_data[i + 1] < 2)
				break;
			/* check codec */
			switch (info.buffer_data[i + 3]) {
			case 0:	/* SBC */
				if (info.buffer_data[i + 1] < 6)
					break;
				availFreqMode = info.buffer_data[i + 4];
				availConfig = info.buffer_data[i + 5];
				supBitpoolMin = info.buffer_data[i + 6];
				supBitpoolMax = info.buffer_data[i + 7];
				break;
			case 2:	/* MPEG2/4 AAC */
				if (info.buffer_data[i + 1] < 8)
					break;
				aacMode1 = info.buffer_data[i + 5];
				aacMode2 = info.buffer_data[i + 6];
				aacBitrate3 = info.buffer_data[i + 7];
				aacBitrate4 = info.buffer_data[i + 8];
				aacBitrate5 = info.buffer_data[i + 9];
				break;
			default:
				break;
			}
		}
		/* jump to next information element */
		i += 2 + info.buffer_data[i + 1];
	}
	aacMode1 &= cfg->aacMode1;
	aacMode2 &= cfg->aacMode2;

	/* Try AAC first */
	if (aacMode1 == cfg->aacMode1 &&
	    aacMode2 == cfg->aacMode2) {
#ifdef HAVE_FFMPEG
		uint8_t config[12] = {mediaTransport, 0x0, mediaCodec,
			0x8, 0x0, 0x02, 0x80, aacMode1, aacMode2, aacBitrate3,
		aacBitrate4, aacBitrate5};

		if (avdtpSetConfiguration(fd, sep, config, sizeof(config)) == 0) {
			cfg->codec = CODEC_AAC;
			return (0);
		}
#endif
	}
	/* Try SBC second */
	if (cfg->freq == FREQ_UNDEFINED)
		goto auto_config_failed;

	freqmode = (1 << (3 - cfg->freq + 4)) |
	    (1 << (3 - cfg->chmode));

	if ((availFreqMode & freqmode) != freqmode) {
		DPRINTF("No frequency and mode match\n");
		goto auto_config_failed;
	}
	for (i = 0; i != 4; i++) {
		blk_len_sb_alloc = (1 << (i + 4)) |
		    (1 << (1 - cfg->bands + 2)) |
		    (1 << cfg->allocm);

		if ((availConfig & blk_len_sb_alloc) == blk_len_sb_alloc)
			break;
	}
	if (i == 4) {
		DPRINTF("No bands available\n");
		goto auto_config_failed;
	}
	cfg->blocks = (3 - i);

	if (cfg->allocm == ALLOC_SNR)
		supBitpoolMax &= ~1;

	if (cfg->chmode == MODE_DUAL || cfg->chmode == MODE_MONO)
		supBitpoolMax /= 2;

	if (cfg->bands == BANDS_4)
		supBitpoolMax /= 2;

	if (supBitpoolMax > cfg->bitpool)
		supBitpoolMax = cfg->bitpool;
	else
		cfg->bitpool = supBitpoolMax;

	do {
		uint8_t config[10] = {mediaTransport, 0x0, mediaCodec, 0x6,
		0x0, 0x0, freqmode, blk_len_sb_alloc, supBitpoolMin, supBitpoolMax};

		if (avdtpSetConfiguration(fd, sep, config, sizeof(config)) == 0) {
			cfg->codec = CODEC_SBC;
			return (0);
		}
	} while (0);

auto_config_failed:
	if (cfg->chmode == MODE_STEREO) {
		cfg->chmode = MODE_MONO;
		cfg->aacMode2 ^= 0x0C;
		goto retry;
	}
	return (EINVAL);
}
