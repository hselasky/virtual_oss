/*-
 * Copyright (c) 2015 - 2016 Nathanial Sloss <nathanialsloss@yahoo.com.au>
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

#include <math.h>
#include <stdio.h>
#include <stdint.h>

static const double sbc8_coeffs[] = {
	0.00000000e+00, 1.56575398e-04, 3.43256425e-04, 5.54620202e-04,
	8.23919506e-04, 1.13992507e-03, 1.47640169e-03, 1.78371725e-03,
	2.01182542e-03, 2.10371989e-03, 1.99454554e-03, 1.61656283e-03,
	9.02154502e-04, -1.78805361e-04, -1.64973098e-03, -3.49717454e-03,
	5.65949473e-03, 8.02941163e-03, 1.04584443e-02, 1.27472335e-02,
	1.46525263e-02, 1.59045603e-02, 1.62208471e-02, 1.53184106e-02,
	1.29371806e-02, 8.85757540e-03, 2.92408442e-03, -4.91578024e-03,
	-1.46404076e-02, -2.61098752e-02, -3.90751381e-02, -5.31873032e-02,
	6.79989431e-02, 8.29847578e-02, 9.75753918e-02, 1.11196689e-01,
	1.23264548e-01, 1.33264415e-01, 1.40753505e-01, 1.45389847e-01,
	1.46955068e-01, 1.45389847e-01, 1.40753505e-01, 1.33264415e-01,
	1.23264548e-01, 1.11196689e-01, 9.75753918e-02, 8.29847578e-02,
	-6.79989431e-02, -5.31873032e-02, -3.90751381e-02, -2.61098752e-02,
	-1.46404076e-02, -4.91578024e-03, 2.92408442e-03, 8.85757540e-03,
	1.29371806e-02, 1.53184106e-02, 1.62208471e-02, 1.59045603e-02,
	1.46525263e-02, 1.27472335e-02, 1.04584443e-02, 8.02941163e-03,
	-5.65949473e-03, -3.49717454e-03, -1.64973098e-03, -1.78805361e-04,
	9.02154502e-04, 1.61656283e-03, 1.99454554e-03, 2.10371989e-03,
	2.01182542e-03, 1.78371725e-03, 1.47640169e-03, 1.13992507e-03,
	8.23919506e-04, 5.54620202e-04, 3.43256425e-04, 1.56575398e-04,
};

static const double sbc4_coeffs[] = {
	0.00000000e+00, 5.36548976e-04, 1.49188357e-03, 2.73370904e-03,
	3.83720193e-03, 3.89205149e-03, 1.86581691e-03, -3.06012286e-03,
	1.09137620e-02, 2.04385087e-02, 2.88757392e-02, 3.21939290e-02,
	2.58767811e-02, 6.13245186e-03, -2.88217274e-02, -7.76463494e-02,
	1.35593274e-01, 1.94987841e-01, 2.46636662e-01, 2.81828203e-01,
	2.94315332e-01, 2.81828203e-01, 2.46636662e-01, 1.94987841e-01,
	-1.35593274e-01, -7.76463494e-02, -2.88217274e-02, 6.13245186e-03,
	2.58767811e-02, 3.21939290e-02, 2.88757392e-02, 2.04385087e-02,
	-1.09137620e-02, -3.06012286e-03, 1.86581691e-03, 3.89205149e-03,
	3.83720193e-03, 2.73370904e-03, 1.49188357e-03, 5.36548976e-04,
};

#define	AC(x)  (int)(sizeof(x) / sizeof((x)[0]))

int
main(int argc, char **argv)
{
	float S[8][16];
	int i;
	int k;
	int count = 0;

	printf("/* sbc_coeffs.h - Automatically generated by cosdata.c. */\n"
	    "\n");

	printf("static const float sbc_coeffs8[] = {\n    ");
	for (k = 0; k < AC(sbc8_coeffs); k++) {
		if ((count % 8) == 0 && count != 0)
			printf("\n    ");
		printf("%0.12ff, ", (float)sbc8_coeffs[k]);
		count++;
	}
	printf("\n};\n");

	count = 0;
	printf("static const float sbc_coeffs4[] = {\n    ");
	for (k = 0; k < AC(sbc4_coeffs); k++) {
		if ((count % 8) == 0 && count != 0)
			printf("\n    ");
		printf("%0.12ff, ", (float)sbc4_coeffs[k]);
		count++;
	}
	printf("\n};\n");

	count = 0;
	printf("static const float cosdata8[8][16] = {\n    ");
	for (i = 0; i < 8; i++) {
		for (k = 0; k < 16; k++) {
			S[i][k] = cosf((float)((i + 0.5) * (k - 4) * (M_PI / 8.0)));

			if ((count % 8) == 0 && count != 0)
				printf("\n    ");
			if (k == 0)
				printf("{ ");
			printf("%0.12ff, ", S[i][k]);
			if (k == 15)
				printf("},");
			count++;
		}
	}
	printf("\n};\n");

	count = 0;
	printf("static const float cosdata4[4][8] = {\n    ");
	for (i = 0; i < 4; i++) {
		for (k = 0; k < 8; k++) {
			S[i][k] = cosf((float)((i + 0.5) * (k - 2) * (M_PI / 4.0)));

			if ((count % 8) == 0 && count != 0)
				printf("\n    ");
			if (k == 0)
				printf("{ ");
			printf("%0.12ff, ", S[i][k]);
			if (k == 7)
				printf("},");
			count++;
		}
	}
	printf("\n};\n");

	count = 0;
	printf("static const float cosdecdata8[8][16] = {\n    ");
	for (i = 0; i < 8; i++) {
		for (k = 0; k < 16; k++) {
			S[i][k] = cosf((float)((i + 0.5) * (k + 4) * (M_PI / 8.0)));

			if ((count % 8) == 0 && count != 0)
				printf("\n    ");
			if (k == 0)
				printf("{ ");
			printf("%0.12ff, ", S[i][k]);
			if (k == 15)
				printf("},");
			count++;
		}
	}
	printf("\n};\n");

	count = 0;
	printf("static const float cosdecdata4[4][8] = {\n    ");
	for (i = 0; i < 4; i++) {
		for (k = 0; k < 8; k++) {
			S[i][k] = cosf((float)((i + 0.5) * (k + 2) * (M_PI / 4.0)));

			if ((count % 8) == 0 && count != 0)
				printf("\n    ");
			if (k == 0)
				printf("{ ");
			printf("%0.12ff, ", S[i][k]);
			if (k == 7)
				printf("},");
			count++;
		}
	}
	printf("\n};\n");

	return (0);
}
