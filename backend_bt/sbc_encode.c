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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sbc_coeffs.h"
#include "sbc_crc.h"
#include "sbc_encode.h"

static uint8_t make_crc(uint8_t);
uint8_t	Crc8(uint8_t, uint8_t *, size_t, size_t);
static size_t make_frame(uint8_t *, int16_t *);
static void calc_scalefactors(int32_t samples[16][2][8]);
static uint8_t calc_scalefactors_joint(int32_t sb_sample[16][2][8]);
static size_t sbc_encode(int16_t *, uint32_t *);
static void calc_bitneed(void);
static size_t move_bits(uint8_t *, int, uint32_t);
static size_t move_bits_crc(uint8_t *, int, uint32_t);

uint32_t scalefactor[2][8];
int	bits[2][8];
int	global_bitpool = 32;
int	global_mode = MODE_STEREO;
int	global_alloc = ALLOC_LOUDNESS;
int	global_freq = FREQ_44_1K;
int	global_chan = 2;
int	global_bands = 8;
int	global_bands_config = BANDS_8;
int	global_block_config = BLOCKS_16;
int	global_blocks = 16;
int	join = 0;

#define	SYNCWORD	0x9c
#define	ABS(x)		(((x) < 0) ? -(x) : (x))
#define	BIT30		(1U << 30)
#define	BM(x)		((1U << (x)) - 1U)

struct a2dp_frame_header {
	uint8_t	syncword;
	uint8_t	config;
	uint8_t	bitpool;
	uint8_t	crc;
};

struct a2dp_frame_header_joint {
	uint8_t	syncword;
	uint8_t	config;
	uint8_t	bitpool;
	uint8_t	crc;
	uint8_t	joint;
};


struct a2dp_frame_mono {
	struct a2dp_frame_header header;
	uint8_t	scale[4];
	uint8_t	samples[256];
};

struct a2dp_frame_joint {
	struct a2dp_frame_header_joint header;
	uint8_t	scale[8];
	uint8_t	samples[256];
};

struct a2dp_frame {
	struct a2dp_frame_header header;
	uint8_t	scale[8];
	uint8_t	samples[256];
};

struct rtpHeader {
	uint8_t	id;			/* Just random number. */
	uint8_t	id2;
	uint8_t	seqnumMSB;		/* Packet sequence number most
					 * significant byte. */
	uint8_t	seqnumLSB;
	uint8_t	ts3;			/* Timestamp most significant byte. */
	uint8_t	ts2;
	uint8_t	ts1;
	uint8_t	ts0;			/* Timestamp least significant byte. */
	uint8_t	reserved3;
	uint8_t	reserved2;
	uint8_t	reserved1;
	uint8_t	reserved0;		/* Reseverd least significant byte set
					 * to 1. */
	uint8_t	numFrames;		/* Number of sbc frames in this
					 * packet. */
};

/* Loudness offset allocations. */
int	loudnessoffset8[4][8] = {
	{-2, 0, 0, 0, 0, 0, 0, 1},
	{-3, 0, 0, 0, 0, 0, 1, 2},
	{-4, 0, 0, 0, 0, 0, 1, 2},
	{-4, 0, 0, 0, 0, 0, 1, 2},
};

int	loudnessoffset4[4][4] = {
	{-1, 0, 0, 0},
	{-2, 0, 0, 1},
	{-2, 0, 0, 1},
	{-2, 0, 0, 1}
};

uint8_t
calc_scalefactors_joint(int32_t sb_sample[16][2][8])
{
	int64_t sb_j[16][2];
	uint32_t x, y;
	int32_t ax;
	int block, sb, lz;
	uint8_t joint;

	joint = 0;
	for (sb = 0; sb < global_bands - 1; sb++) {
		for (block = 0; block < global_blocks; block++) {
			sb_j[block][0] = (sb_sample[block][0][sb]) +
			    (sb_sample[block][1][sb]);
			sb_j[block][1] = (sb_sample[block][0][sb]) -
			    (sb_sample[block][1][sb]);
		}

		x = 1 << 15;
		y = 1 << 15;
		for (block = 0; block < global_blocks; block++) {
			ax = ABS(sb_j[block][0] / 2);
			if (ax)
				x |= ax;
			ax = ABS(sb_j[block][1] / 2);
			if (ax)
				y |= ax;
		}

		lz = 1;
		while (!(x & BIT30)) {
			lz++;
			x <<= 1;
		}
		x = 16 - lz;

		lz = 1;
		while (!(y & BIT30)) {
			lz++;
			y <<= 1;
		}
		y = 16 - lz;

		if ((scalefactor[0][sb] + scalefactor[1][sb]) > x + y) {
			joint |= 1 << (global_bands - sb - 1);
			scalefactor[0][sb] = x;
			scalefactor[1][sb] = y;
			for (block = 0; block < global_blocks; block++) {
				sb_sample[block][0][sb] = sb_j[block][0] / 2;
				sb_sample[block][1][sb] = sb_j[block][1] / 2;
			}
		}
	}

	return joint;
}

void
calc_scalefactors(int32_t samples[16][2][8])
{
	uint32_t x;
	int32_t ax;
	size_t lz;
	int ch, sb, block;

	for (ch = 0; ch < global_chan; ch++) {
		for (sb = 0; sb < global_bands; sb++) {
			x = 1 << 16;
			for (block = 0; block < global_blocks; block++) {
				ax = ABS(samples[block][ch][sb]);
				if (ax)
					x |= ax;
			}

			lz = 1;
			while (!(x & BIT30)) {
				lz++;
				x <<= 1;
			}
			scalefactor[ch][sb] = 16 - lz;
		}
	}
}

void
calc_bitneed()
{
	int32_t bitneed[2][8];
	int32_t max_bitneed, bitcount;
	int32_t slicecount, bitslice;
	int32_t loudness;
	int ch, sb, start_chan = 0;

	if (global_mode == MODE_DUAL)
		global_chan = 1;
next_chan:
	max_bitneed = 0;
	bitcount = 0;
	slicecount = 0;

	if (global_alloc == ALLOC_SNR) {
		for (ch = start_chan; ch < global_chan; ch++) {
			for (sb = 0; sb < global_bands; sb++) {
				bitneed[ch][sb] = scalefactor[ch][sb];

				if (bitneed[ch][sb] > max_bitneed)
					max_bitneed = bitneed[ch][sb];
			}
		}
	} else {
		for (ch = start_chan; ch < global_chan; ch++) {
			for (sb = 0; sb < global_bands; sb++) {
				if (scalefactor[ch][sb] == 0)
					bitneed[ch][sb] = -5;
				else {
					if (global_bands == 8)
						loudness = scalefactor[ch][sb] -
						    loudnessoffset8[global_freq][sb];
					else
						loudness = scalefactor[ch][sb] -
						    loudnessoffset4[global_freq][sb];
					if (loudness > 0)
						bitneed[ch][sb] = loudness / 2;
					else
						bitneed[ch][sb] = loudness;
				}
				if (bitneed[ch][sb] > max_bitneed)
					max_bitneed = bitneed[ch][sb];
			}
		}
	}

	slicecount = bitcount = 0;
	bitslice = max_bitneed + 1;
	do {
		bitslice--;
		bitcount += slicecount;
		slicecount = 0;
		for (ch = start_chan; ch < global_chan; ch++) {
			for (sb = 0; sb < global_bands; sb++) {
				if ((bitneed[ch][sb] > bitslice + 1) &&
				    (bitneed[ch][sb] < bitslice + 16))
					slicecount++;
				else if (bitneed[ch][sb] == bitslice + 1)
					slicecount += 2;
			}
		}
	} while (bitcount + slicecount < global_bitpool);
	if (bitcount + slicecount == global_bitpool) {
		bitcount += slicecount;
		bitslice--;
	}
	for (ch = start_chan; ch < global_chan; ch++) {
		for (sb = 0; sb < global_bands; sb++) {
			if (bitneed[ch][sb] < bitslice + 2)
				bits[ch][sb] = 0;
			else {
				bits[ch][sb] = bitneed[ch][sb] - bitslice;
				if (bits[ch][sb] > 16)
					bits[ch][sb] = 16;
			}
		}
	}

	if (global_mode == MODE_DUAL)
		ch = start_chan;
	else
		ch = 0;
	sb = 0;
	while (bitcount < global_bitpool && sb < global_bands) {
		if ((bits[ch][sb] >= 2) && (bits[ch][sb] < 16)) {
			bits[ch][sb]++;
			bitcount++;
		} else if ((bitneed[ch][sb] == bitslice + 1) &&
		    (global_bitpool > bitcount + 1)) {
			bits[ch][sb] = 2;
			bitcount += 2;
		}
		if (global_chan == 1 || start_chan == 1)
			sb++;
		else if (ch == 1) {
			ch = 0;
			sb++;
		} else
			ch = 1;
	}

	if (global_mode == MODE_DUAL)
		ch = start_chan;
	else
		ch = 0;
	sb = 0;
	while (bitcount < global_bitpool && sb < global_bands) {
		if (bits[ch][sb] < 16) {
			bits[ch][sb]++;
			bitcount++;
		}
		if (global_chan == 1 || start_chan == 1)
			sb++;
		else if (ch == 1) {
			ch = 0;
			sb++;
		} else
			ch = 1;
	}

	if (global_mode == MODE_DUAL && start_chan == 0) {
		start_chan = 1;
		global_chan = 2;
		goto next_chan;
	}
}

size_t
move_bits(uint8_t *data, int numbits, uint32_t sample)
{
	static uint16_t cache = 0;
	static int cache_pos = 0;
	uint8_t tmp_cache;
	size_t written = 0;

	if (numbits == 0) {
		if (cache_pos > 8) {
			cache_pos -= 8;
			tmp_cache = cache >> cache_pos;
			*data++ = tmp_cache;
			written++;
		}
		if (cache_pos) {
			*data = (cache & BM(cache_pos + 1)) << (8 - cache_pos);
			written++;
		}
		cache = cache_pos = 0;
	} else {
		cache_pos += numbits;
		cache <<= numbits;
		cache |= sample & BM(numbits + 1);
		if (cache_pos >= 8) {
			cache_pos -= 8;
			tmp_cache = cache >> cache_pos;
			*data = tmp_cache;
			written++;
		}
	}
	return written;
}

size_t
move_bits_crc(uint8_t *data, int numbits, uint32_t sample)
{
	static uint16_t cache = 0;
	static int cache_pos = 0;
	uint8_t tmp_cache;
	size_t written = 0;

	if (numbits > 8 || numbits < 0)
		return 0;

	if (numbits == 0) {
		if (cache_pos > 8) {
			cache_pos -= 8;
			tmp_cache = cache >> cache_pos;
			*data++ = tmp_cache;
			written++;
		}
		if (cache_pos) {
			*data = (cache & BM(cache_pos + 1)) << (8 - cache_pos);
			written++;
		}
		cache = cache_pos = 0;
	} else {
		cache_pos += numbits;
		cache <<= numbits;
		cache |= sample & BM(numbits + 1);
		if (cache_pos >= 8) {
			cache_pos -= 8;
			tmp_cache = cache >> cache_pos;
			*data = tmp_cache;
			written++;
		}
	}
	return written;
}

size_t
sbc_encode(int16_t *input, uint32_t *samples)
{
	int64_t delta[2][8], levels[2][8], S[80];
	static int32_t L[80], R[80];
	int32_t *X, Z[80], Y[80];
	int32_t output[16][2][8];
	int32_t audioout;
	int16_t left[8], right[8], *data;
	size_t numsamples;
	int i, k, block, chan, sb;

	for (block = 0; block < global_blocks; block++) {

		k = 0;
		for (i = 0; i < global_bands; i++) {
			left[i] = input[k++];
			if (global_chan == 2)
				right[i] = input[k++];
		}
		input += k;

		for (chan = 0; chan < global_chan; chan++) {
			if (chan == 0) {
				X = L;
				data = left;
			} else {
				X = R;
				data = right;
			}

			for (i = (global_bands * 10) - 1; i > global_bands - 1; i--)
				X[i] = X[i - global_bands];
			k = 0;
			for (i = global_bands - 1; i >= 0; i--)
				X[i] = data[k++];
			for (i = 0; i < global_bands * 10; i++) {
				if (global_bands == 8)
					Z[i] = sbc_coeffs8[i] * X[i];
				else
					Z[i] = sbc_coeffs4[i] * X[i];
			}
			for (i = 0; i < global_bands * 2; i++) {
				Y[i] = 0;
				for (k = 0; k < 5; k++)
					Y[i] += Z[i + k * global_bands * 2];
			}
			for (i = 0; i < global_bands; i++) {
				S[i] = 0;
				for (k = 0; k < global_bands * 2; k++) {
					if (global_bands == 8) {
						S[i] += (int64_t)cosdata8[i][k] *
						    (int64_t)Y[k];
					} else
						S[i] += (int64_t)cosdata4[i][k] *
						    (int64_t)Y[k];
				}
				output[block][chan][i] = S[i] / SIMULTI;
			}
		}
	}

	calc_scalefactors(output);
	if (global_mode == MODE_JOINT)
		join = calc_scalefactors_joint(output);

	calc_bitneed();

	for (chan = 0; chan < global_chan; chan++) {
		for (sb = 0; sb < global_bands; sb++) {
			levels[chan][sb] = BM(bits[chan][sb]) <<
			    (15 - scalefactor[chan][sb]);
			delta[chan][sb] = 1 << (scalefactor[chan][sb] + 16);
		}
	}

	numsamples = 0;
	for (block = 0; block < global_blocks; block++) {
		for (chan = 0; chan < global_chan; chan++) {
			for (sb = 0; sb < global_bands; sb++) {
				if (bits[chan][sb] == 0)
					continue;

				audioout = (levels[chan][sb] * (delta[chan][sb]
				    + (int32_t)output[block][chan][sb])) >> 32;

				samples[numsamples++] = audioout;
			}
		}
	}
	return numsamples;
}

uint8_t
Crc8(uint8_t inCrc, uint8_t *inData, size_t numbits, size_t inBytes)
{
	uint8_t data;
	int i;

	for (i = 0; i < (int)inBytes; i++) {
		data = inCrc ^ inData[i];

		if (numbits == 8)
			data = sbc_crc8[data];
		else if (numbits == 4)
			data = sbc_crc4[data];

		inCrc = data;
	}
	return inCrc;
}

uint8_t
make_crc(uint8_t config)
{
	uint8_t crc, data[11];
	int i, j;
	uint8_t *dataStart = data;
	uint8_t *crcData = data;


	crcData += move_bits_crc(crcData, 8, config);
	crcData += move_bits_crc(crcData, 8, global_bitpool);
	if (global_mode == MODE_JOINT) {
		if (global_bands == 8)
			crcData += move_bits_crc(crcData, 8, join);
		else
			crcData += move_bits_crc(crcData, 4, join);
	}
	for (i = 0; i < global_chan; i++) {
		for (j = 0; j < global_bands; j++)
			crcData += move_bits_crc(crcData, 4, scalefactor[i][j]);
	}

	crc = Crc8(0xf, data, 8, crcData - dataStart);

	if (global_mode == MODE_JOINT && global_bands == 4) {
		move_bits_crc(crcData, 0, 0);
		crc = Crc8(crc, crcData, 4, 1);
	}
	return crc;
}

size_t
make_frame(uint8_t *frame, int16_t *input)
{
	static uint32_t samples[256 * 2];
	uint8_t config, crc;
	int block, chan, sb, j, i;

	uint8_t *frameStart = frame;

	config = (global_freq << 6) | (global_block_config << 4) |
	    (global_mode << 2) | (global_alloc << 1) | global_bands_config;

	sbc_encode(input, samples);

	crc = make_crc(config);

	frame += move_bits(frame, 8, SYNCWORD);
	frame += move_bits(frame, 8, config);
	frame += move_bits(frame, 8, global_bitpool);
	frame += move_bits(frame, 8, crc);

	if (global_mode == MODE_JOINT && global_bands == 8)
		frame += move_bits(frame, 8, join);
	else if (global_mode == MODE_JOINT && global_bands == 4)
		frame += move_bits(frame, 4, join);

	for (i = 0; i < global_chan; i++) {
		for (j = 0; j < global_bands; j++)
			frame += move_bits(frame, 4, scalefactor[i][j]);
	}

	i = 0;
	for (block = 0; block < global_blocks; block++) {
		for (chan = 0; chan < global_chan; chan++) {
			for (sb = 0; sb < global_bands; sb++) {
				if (bits[chan][sb] == 0)
					continue;

				frame += move_bits(frame, bits[chan][sb], samples[i++]);
			}
		}
	}
	frame += move_bits(frame, 0, 0);

	return (uint8_t *)frame - frameStart;
}

int
stream(int16_t *music_data, size_t music_samp, int outfd, int mode, int freq, int bands, int blocks,
    int alloc_method, size_t bitpool, size_t mtu)
{
	struct rtpHeader myHeader;
	struct iovec iov[2];
	uint8_t frameData[mtu];
	size_t totalSize;
	size_t pkt_len;
	size_t readsize;
	size_t offset;
	size_t next_pkt;
	static uint32_t ts = 0;
	static uint16_t seqnumber = 0;
	int len;
	int numpkts;

	global_mode = mode;
	global_bitpool = bitpool;
	global_alloc = alloc_method;
	global_freq = freq;

	global_bands_config = bands;
	if (bands == BANDS_8)
		global_bands = 8;
	else
		global_bands = 4;

	if (blocks == BLOCKS_4)
		global_blocks = 4;
	else if (blocks == BLOCKS_8)
		global_blocks = 8;
	else if (blocks == BLOCKS_12)
		global_blocks = 12;
	else {
		blocks = BLOCKS_16;
		global_blocks = 16;
	}

	global_block_config = blocks;

	global_chan = 2;
	if (global_mode == MODE_MONO)
		global_chan = 1;

	readsize = 0;

	while (music_samp >= 256 / 4) {
		memset(&myHeader, 0, sizeof(myHeader));
		myHeader.id = 0x80;	/* RTP v2 */
		myHeader.id2 = 0x60;	/* payload type 96. */
		myHeader.seqnumMSB = (uint8_t)(seqnumber >> 8);
		myHeader.seqnumLSB = (uint8_t)seqnumber;
		myHeader.ts3 = (uint8_t)(ts >> 24);
		myHeader.ts2 = (uint8_t)(ts >> 16);
		myHeader.ts1 = (uint8_t)(ts >> 8);
		myHeader.ts0 = (uint8_t)ts;
		myHeader.reserved0 = 0x01;

		totalSize = sizeof(myHeader);

		numpkts = next_pkt = len = 0;

		pkt_len = 80;
		while (totalSize + (pkt_len * 2) <= mtu && music_samp >= 256 / 4) {
			pkt_len = make_frame(frameData + next_pkt, music_data);
			next_pkt += pkt_len;
			totalSize += pkt_len;
			numpkts++;
			music_data += 256 / 4;
			music_samp -= 256 / 4;
			readsize += 512 / 4;
			if (numpkts == 255)
				break;
		}
		myHeader.numFrames = numpkts;

		/* setup I/O vector */
		iov[0].iov_base = &myHeader;
		iov[0].iov_len = sizeof(myHeader);
		iov[1].iov_base = frameData;
		iov[1].iov_len = next_pkt;

		do {
			len = writev(outfd, iov, 2);
		} while (len < 0 && errno == EAGAIN);

		if (len < 0)
			return (-1);

		seqnumber++;
		ts += (readsize / (global_chan * sizeof(int16_t))) * numpkts;
	}
	return (0);
}
