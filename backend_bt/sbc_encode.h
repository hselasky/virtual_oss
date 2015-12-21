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

#ifndef _SBC_ENCODE_H_
#define	_SBC_ENCODE_H_

#define	SBC_CODEC_ID	0x6
#define	DEFAULT_MAXBPOOL 80
#define	SBC_MAX_MTU	65536

struct sbc_config {
	uint8_t	chmode;
#define	MODE_STEREO	2
#define	MODE_JOINT	3
#define	MODE_DUAL	1
#define	MODE_MONO	0
	uint8_t	allocm;
#define	ALLOC_LOUDNESS	0
#define	ALLOC_SNR 	1
	uint8_t	bitpool;
	uint8_t	bands;
#define	BANDS_4		0
#define	BANDS_8		1
	uint8_t	blocks;
#define	BLOCKS_4	0
#define	BLOCKS_8	1
#define	BLOCKS_12	2
#define	BLOCKS_16	3
	uint8_t	freq;
#define	FREQ_16K	0
#define	FREQ_32K	1
#define	FREQ_44_1K	2
#define	FREQ_48K	3
	uint16_t mtu;
};

struct sbc_encode {
	uint8_t	pkt_data[SBC_MAX_MTU];
	int32_t	output[256];
	int16_t	music_data[256];
	uint8_t	data[1024];
	int	bits[2][8];
	int32_t	left[80];
	int32_t	right[80];
	int32_t	samples[16][2][8];
	uint32_t rem_len;
	uint32_t bitoffset;
	uint32_t maxoffset;
	uint32_t pktoffset;
	uint32_t crc;
	uint32_t timestamp;
	uint16_t seqnumber;
	uint16_t framesamples;
	uint8_t	scalefactor[2][8];
	uint8_t	channels;
	uint8_t	bands;
	uint8_t	blocks;
	struct sbc_config cfg;
};

int	sbc_encode_stream(struct sbc_encode *, int);

#endif					/* _SBC_ENCODE_H_ */
