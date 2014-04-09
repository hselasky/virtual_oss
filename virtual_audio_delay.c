/*-
 * Copyright (c) 2014 Hans Petter Selasky. All rights reserved.
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
#include <math.h>
#include <sysexits.h>

#include <sys/queue.h>

#include "virtual_int.h"

static uint32_t voss_ad_last;

static struct voss_ad {
	double *sin_a;
	double *cos_a;

	double *sin_b;
	double *cos_b;

	double *sin_c;
	double *cos_c;

	double sum_sin_a;
	double sum_cos_a;

	double sum_sin_b;
	double sum_cos_b;

	double sum_sin_c;
	double sum_cos_c;

	uint32_t len_a;
	uint32_t len_b;
	uint32_t len_c;

	uint32_t offset_a;
	uint32_t offset_b;
	uint32_t offset_c;

	uint32_t inv_ab;
	uint32_t inv_ac;
	uint32_t inv_bc;
} voss_ad;

static void
voss_ad_next_prime(int *p)
{
	int val = *p | 1;
	int x;
	int y;
repeat:
	for (x = 3; x < val; x += 2) {
		if ((val % x) == 0) {
			val += 2;
			goto repeat;
		}
	}
	*p = val;
}

void
voss_ad_init(uint32_t rate)
{
	int samples_a;
	int samples_b;
	int samples_c;
	int x;

	samples_a = rate / 440;
	voss_ad_next_prime(&samples_a);
	samples_b = samples_a + 2;
	voss_ad_next_prime(&samples_b);
	samples_c = samples_b + 2;
	voss_ad_next_prime(&samples_c);

	for (x = 1; x != samples_b; x++) {
		if (((x * samples_a) % samples_b) == 1)
			break;
	}
	voss_ad.inv_ab = x;

	for (x = 1; x != samples_c; x++) {
		if (((x * samples_a) % samples_c) == 1)
			break;
	}
	voss_ad.inv_ac = x;

	for (x = 1; x != samples_c; x++) {
		if (((x * samples_b) % samples_c) == 1)
			break;
	}
	voss_ad.inv_bc = x;

	voss_ad.sin_a = malloc(sizeof(voss_ad.sin_a[0]) * samples_a);
	voss_ad.cos_a = malloc(sizeof(voss_ad.cos_a[0]) * samples_a);

	voss_ad.sin_b = malloc(sizeof(voss_ad.sin_b[0]) * samples_b);
	voss_ad.cos_b = malloc(sizeof(voss_ad.cos_b[0]) * samples_b);

	voss_ad.sin_c = malloc(sizeof(voss_ad.sin_c[0]) * samples_c);
	voss_ad.cos_c = malloc(sizeof(voss_ad.cos_c[0]) * samples_c);

	if (voss_ad.sin_a == NULL || voss_ad.sin_b == NULL ||
	    voss_ad.cos_a == NULL || voss_ad.cos_b == NULL ||
	    voss_ad.cos_c == NULL || voss_ad.cos_c == NULL)
		errx(EX_SOFTWARE, "Out of memory");

	voss_ad.len_a = samples_a;
	voss_ad.len_b = samples_b;
	voss_ad.len_c = samples_c;

	for (x = 0; x != samples_a; x++) {
		voss_ad.sin_a[x] = sin(2.0 * M_PI * ((double)x) / ((double)samples_a));
		voss_ad.cos_a[x] = cos(2.0 * M_PI * ((double)x) / ((double)samples_a));
	}
	for (x = 0; x != samples_b; x++) {
		voss_ad.sin_b[x] = sin(2.0 * M_PI * ((double)x) / ((double)samples_b));
		voss_ad.cos_b[x] = cos(2.0 * M_PI * ((double)x) / ((double)samples_b));
	}
	for (x = 0; x != samples_c; x++) {
		voss_ad.sin_c[x] = sin(2.0 * M_PI * ((double)x) / ((double)samples_c));
		voss_ad.cos_c[x] = cos(2.0 * M_PI * ((double)x) / ((double)samples_c));
	}

	printf("VOSS AD: %d %d %d %d\n", voss_ad.len_a, voss_ad.len_b, voss_ad.len_c, voss_ad.inv_ab);

}

static double
voss_add_decode_offset(double x /* cos */, double y /* sin */)
{
	double r = sqrt((x * x) + (y * y));
	uint32_t v;
	if (r == 0.0)
		return (0);

	x /= r;
	y /= r;

	v = 0;

	if (y < 0) {
		v |= 1;
		y = -y;
	}
	if (x < 0) {
		v |= 2;
		x = -x;
	}

	if (y < x) {
		r = acos(y);
	} else {
		r = asin(x);
	}

	switch (v) {
	case 0:
		r = (2.0 * M_PI) - r;
		break;
	case 1:
		r = M_PI + r;
		break;
	case 3:
		r = M_PI - r;
		break;
	default:
		break;
	}
	return (r);
}

double
voss_ad_getput_sample(double sample)
{
	uint32_t xa = voss_ad.offset_a;
	uint32_t xb = voss_ad.offset_b;
	uint32_t xc = voss_ad.offset_c;

	double retval;

	retval = (voss_ad.sin_a[xa] + voss_ad.sin_b[xb] + voss_ad.sin_c[xc]) / 3.0;

	voss_ad.sum_sin_a += voss_ad.sin_a[xa] * sample;
	voss_ad.sum_cos_a += voss_ad.cos_a[xa] * sample;

	voss_ad.sum_sin_b += voss_ad.sin_b[xb] * sample;
	voss_ad.sum_cos_b += voss_ad.cos_b[xb] * sample;

	voss_ad.sum_sin_c += voss_ad.sin_c[xc] * sample;
	voss_ad.sum_cos_c += voss_ad.cos_c[xc] * sample;

	xa++;
	xb++;
	xc++;

	if (xa == voss_ad.len_a)
		xa = 0;
	if (xb == voss_ad.len_b)
		xb = 0;
	if (xc == voss_ad.len_c)
		xc = 0;

	voss_ad.offset_a = xa;
	voss_ad.offset_b = xb;
	voss_ad.offset_c = xc;

	if (xa == 0 && xb == 0 && xc == 0) {
		double off;

		off = voss_add_decode_offset(voss_ad.sum_cos_a, voss_ad.sum_sin_a);
		off = (off * ((double)voss_ad.len_a)) / (2.0 * M_PI);

		xa = round(off);

		if (xa < 0 || xa >= voss_ad.len_a)
			xa = 0;

 		off = voss_add_decode_offset(voss_ad.sum_cos_b, voss_ad.sum_sin_b);
		off = (off * ((double)voss_ad.len_b)) / (2.0 * M_PI);

		xb = round(off);
		if (xb < 0 || xb >= voss_ad.len_b)
			xb = 0;

 		off = voss_add_decode_offset(voss_ad.sum_cos_c, voss_ad.sum_sin_c);
		off = (off * ((double)voss_ad.len_c)) / (2.0 * M_PI);

		xc = round(off);
		if (xc < 0 || xc >= voss_ad.len_c)
			xc = 0;

		printf("%d %d %d\n", xb, xa, xc);

		xb = ((voss_ad.len_b + xb - xa) * voss_ad.inv_ab) % voss_ad.len_b;
		xc = ((voss_ad.len_c + xc - xa) * voss_ad.inv_ac) % voss_ad.len_c;

		xc = ((voss_ad.len_c + xc - xb) * voss_ad.inv_bc) % voss_ad.len_c;

		voss_ad_last = (xc * voss_ad.len_a * voss_ad.len_b) +
		  (xb * voss_ad.len_a) + xa;

		printf("OFF = %d\n", voss_ad_last);

		voss_ad.sum_sin_a = 0;
		voss_ad.sum_cos_a = 0;

		voss_ad.sum_sin_b = 0;
		voss_ad.sum_cos_b = 0;

		voss_ad.sum_sin_c = 0;
		voss_ad.sum_cos_c = 0;
	}

	return (retval);
}
