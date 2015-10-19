/* $NetBSD$ */

/*-
 * Copyright (c) 2015 Nathanial Sloss <nathanialsloss@yahoo.com.au>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "avdtp_signal.h"
#include "sbc_encode.h"

int	avdtpSendDescResponse(int, int, int, int);

static uint8_t transLabel = 1;
int
avdtpSendCommand(int fd, uint8_t command, uint8_t type, uint8_t *data,
    size_t datasize)
{
#define	SINGLE_PACKET 0
#define	START_PACKET 1
#define	CONTINUE_PACKET 2
#define	END_PACKET 3
#define	signalID 3

	uint8_t header[64];
	size_t extra_size = 0;
	const uint8_t packetType = (SINGLE_PACKET & 3) << 2;
	const uint8_t messageType = (type & 3);

	transLabel &= 0xf;

	header[0] = (transLabel << 4) | packetType | messageType;
	if (command != 0)
		header[1] = command & 0x3f;
	else
		header[1] = signalID & 0x3f;	/* Bits 7/6 Reserved */

	transLabel++;
	if (data != NULL) {
		extra_size = datasize;
		memcpy(header + 2, data, extra_size);
	}
	write(fd, &header, extra_size + 2);

	return (transLabel - 1);
}

int
avdtpCheckResponse(int recvfd, int *trans, int signalId,
    int *pkt_type, uint8_t *data, size_t *datasize)
{
	uint8_t buffer[64];
	int len;

	len = read(recvfd, &buffer, sizeof(buffer));

	if (datasize)
		*datasize = 0;

	if (len < AVDTP_LEN_SUCCESS)
		goto response_invalid;

	if ((buffer[0] & MESSAGETYPE) == COMMAND) {
		*trans = (buffer[0] & TRANSACTIONLABEL) >> TRANSACTIONLABEL_S;
		if (datasize)
			*datasize = buffer[1] & SIGNALID_MASK;
		return (1);
	}
	if ((buffer[0] & TRANSACTIONLABEL) >> TRANSACTIONLABEL_S == *trans &&
	    (buffer[1] & SIGNALID_MASK) == signalId) {
		if (len == AVDTP_LEN_ERROR)
			return (buffer[2]);
		else if ((len % AVDTP_LEN_SUCCESS) == 0 &&
		    buffer[0] & RESPONSEACCEPT) {
			if (len == AVDTP_LEN_SUCCESS)
				return (0);
			else if (datasize && data && len > AVDTP_LEN_SUCCESS) {
				memcpy(data, buffer + 2, len - 2);
				*datasize = len - 2;

				return (0);
			}
		}
	}
response_invalid:
	return (EINVAL);
}

int
avdtpSendDescResponse(int fd, int recvfd, int trans, int mySep)
{
	uint8_t data[4];

	data[0] = trans << 4 | RESPONSEACCEPT;
	data[1] = AVDTP_DISCOVER;
	data[2] = mySep << 2;
	data[3] = 0x6 << 4;

	write(fd, data, sizeof(data));

	return (0);
}

int
avdtpDiscover(int fd, int recvfd, struct avdtp_sepInfo *sepInfo)
{
	int sentINT = 0;
	int sepRECV = 0;
	size_t len;
	size_t offset;
	size_t recvsize;
	int trans;
	int pkt;
	int tmptrans;
	uint8_t buffer[64];

	tmptrans = trans = avdtpSendCommand(fd, AVDTP_DISCOVER, 0, NULL, 0);
	while (1) {
		len = avdtpCheckResponse(fd, &trans, AVDTP_DISCOVER, &pkt,
		    buffer, &recvsize);

		if (len == 1) {
			avdtpSendDescResponse(fd, fd, trans, INTSEP);
			sentINT = 1;
			trans = tmptrans;
			transLabel++;
		}
		if (len == EINVAL)
			return (EINVAL);

		if (len == 0 && recvsize >= 2) {
			for (offset = 0; offset <= len; offset += 2) {
				sepInfo->sep = buffer[offset] >> 2;
				sepInfo->media_Type = buffer[offset + 1] >> 4;
				if (buffer[offset] & DISCOVER_SEP_IN_USE)
					continue;
				else
					break;
			}
			if (offset > recvsize)
				return (EINVAL);
			sepRECV = 1;
		}
		sentINT = sepRECV;
		if (sepRECV && sentINT)
			break;
	}
	return (0);
}

int
avdtpGetCapabilities(int fd, int recvfd, uint8_t sep, uint8_t *data,
    size_t *datasize)
{
	uint8_t address = sep << 2;
	int trans;
	int pkt;

	trans = avdtpSendCommand(fd, AVDTP_GET_CAPABILITIES, 0, &address, 1);

	return (avdtpCheckResponse(fd, &trans, AVDTP_GET_CAPABILITIES, &pkt,
	    data, datasize));
}

int
avdtpSetConfiguration(int fd, int recvfd, uint8_t sep, uint8_t *data,
    size_t datasize)
{
	uint8_t configAddresses[2];
	uint8_t *configData;
	int trans;
	int pkt;

	if (data == NULL || datasize == 0)
		return (EINVAL);

	configData = malloc(datasize + 2);
	if (configData == NULL)
		return (ENOMEM);
	configAddresses[0] = sep << 2;
	configAddresses[1] = INTSEP << 2;

	memcpy(configData, configAddresses, 2);
	memcpy(configData + 2, data, datasize);

	trans = avdtpSendCommand(fd, AVDTP_SET_CONFIGURATION, 0,
	    configData, datasize + 2);
	free(configData);

	return (avdtpCheckResponse(fd, &trans, AVDTP_SET_CONFIGURATION,
	    &pkt, NULL, NULL));

}

int
avdtpOpen(int fd, int recvfd, uint8_t sep)
{
	uint8_t address = sep << 2;
	int trans;
	int pkt;

	trans = avdtpSendCommand(fd, AVDTP_OPEN, 0, &address, 1);

	return (avdtpCheckResponse(fd, &trans, AVDTP_OPEN, &pkt,
	    NULL, NULL));
}

int
avdtpStart(int fd, int recvfd, uint8_t sep)
{
	uint8_t address;
	int trans;
	int pkt;

	address = sep << 2;
	trans = avdtpSendCommand(fd, AVDTP_START, 0, &address, 1);

	return (avdtpCheckResponse(fd, &trans, AVDTP_START, &pkt,
	    NULL, NULL));
}

int
avdtpClose(int fd, int recvfd, uint8_t sep)
{
	uint8_t address = sep << 2;
	int trans;
	int pkt;

	trans = avdtpSendCommand(fd, AVDTP_CLOSE, 0, &address, 1);

	return (avdtpCheckResponse(fd, &trans, AVDTP_CLOSE, &pkt,
	    NULL, NULL));
}

int
avdtpSuspend(int fd, int recvfd, uint8_t sep)
{
	uint8_t address = sep << 2;
	int trans;
	int pkt;

	trans = avdtpSendCommand(fd, AVDTP_SUSPEND, 0, &address, 1);

	return (avdtpCheckResponse(fd, &trans, AVDTP_SUSPEND, &pkt,
	    NULL, NULL));
}

int
avdtpAbort(int fd, int recvfd, uint8_t sep)
{
	uint8_t address = sep << 2;
	int trans;
	int pkt;

	trans = avdtpSendCommand(fd, AVDTP_ABORT, 0, &address, 1);

	return (avdtpCheckResponse(fd, &trans, AVDTP_ABORT, &pkt,
	    NULL, NULL));
}

int
avdtpAutoConfig(int fd, int recvfd, uint8_t sep, int freq, int mode,
    int *alloc_method, int *bitpool, int *bands, int *blocks)
{
	uint8_t capabilities[128];
	uint8_t freqmode;
	uint8_t blk_len_sb_alloc;
	uint8_t availFreqMode;
	uint8_t availConfig;
	uint8_t supBitpoolMin;
	uint8_t supBitpoolMax;
	size_t cap_len;
	size_t i;

	if (avdtpGetCapabilities(fd, fd, sep, capabilities, &cap_len))
		return (ENOTSUP);

	for (i = 0; i < cap_len; i++) {
		if (capabilities[i] == mediaTransport &&
		    capabilities[i + 1] == 0 &&
		    capabilities[i + 2] == mediaCodec &&
		    capabilities[i + 3] == SBC_CODEC_ID)
			break;
	}
	if (i >= cap_len)
		goto auto_config_failed;

	availFreqMode = capabilities[i + 6];
	availConfig = capabilities[i + 7];
	supBitpoolMin = capabilities[i + 8];
	supBitpoolMax = capabilities[i + 9];

	freqmode = (1 << (3 - freq + 4)) |
	    (1 << (3 - mode));

	if ((availFreqMode & freqmode) != freqmode)
		goto auto_config_failed;

	for (i = 0; i != 4; i++) {
		blk_len_sb_alloc = (1 << (3 - i + 4)) |
		    (1 << (2 - *bands + 1)) | (1 << *alloc_method);

		if ((availConfig & blk_len_sb_alloc) == blk_len_sb_alloc)
			break;
	}
	if (i == 4)
		goto auto_config_failed;
	*blocks = i;

	if (*alloc_method == ALLOC_SNR)
		supBitpoolMax &= ~1;

	if (mode == MODE_DUAL || mode == MODE_MONO)
		supBitpoolMax /= 2;

	if (*bands == BANDS_4)
		supBitpoolMax /= 2;

	if (supBitpoolMax > *bitpool)
		supBitpoolMax = *bitpool;
	else
		*bitpool = supBitpoolMax;

	do {
		uint8_t config[10] = {mediaTransport, 0x0, mediaCodec, SBC_CODEC_ID,
		0x0, 0x0, freqmode, blk_len_sb_alloc, supBitpoolMin, supBitpoolMax};

		if (avdtpSetConfiguration(fd, fd, sep, config, sizeof(config)) == 0)
			return (0);
	} while (0);

auto_config_failed:
	return (EINVAL);
}
