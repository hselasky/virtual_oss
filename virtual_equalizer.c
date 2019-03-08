/*-
 * Copyright (c) 2019 Google LLC, written by Richard Kralovic <riso@google.com>
 * All rights reserved.
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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fftw3.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/soundcard.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static int in_background = 0;
static int need_dump = 0;

#define BACKLOG_BLOCKS 512

static void
message(const char *fmt,...)
{
	va_list list;
	if (in_background) return;
	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	va_end(list);
}

static void
dump(int signal __attribute__((unused)))
{
	need_dump = 1;
}

/* Masking window value for -1 < x < 1. Window must be symmetric, thus, this
 * function is queried for x >= 0 only.
 * Currently a Hann window. */
static double
get_window(double x)
{
	return 0.5 + 0.5 * cos(M_PI * x);
}

struct equalizer {
	double	rate;
	int block_size;  /* size of one IO block */
	int channels;
	int bytes;  /* per sample */

	uint8_t* io_buffer;  /* channels * block_size * 2 elements */
	int dump_index;
	uint8_t* backlog_buffer;

	/* guarded by guard: */
	double* filter;  /* block_size * 2 elements, half-complex format */
	double* fftw_time;  /* block_size * 2 elements, time domain */
	double* fftw_freq;  /* block_size * 2 elements, half-complex, freq domain */
	fftw_plan forward;
	fftw_plan inverse;
	pthread_mutex_t guard;
};

/* lock required: e->guard */
static int
load_frequency_amplification(struct equalizer* e, const char* config)
{
	double prev_f = 0.0;
	double prev_amp = 1.0;
	double next_f = 0.0;
	double next_amp = 1.0;

	for (int i = 0; i <= e->block_size; ++i) {
		double f = e->rate / (2 * e->block_size) * i;
		while (f >= next_f) {
			prev_f = next_f;
			prev_amp = next_amp;
			if (*config == 0) {
				next_f = e->rate;
				next_amp = prev_amp;
			} else {
				int len;
				if (sscanf(config, "%lf %lf %n", &next_f, &next_amp, &len) == 2) {
					config += len;
					if (next_f <= prev_f) {
						message("Parse error: Nonincreasing sequence of frequencies.\n");
						return 0;
					}
				} else {
					message("Parse error.\n");
					return 0;
				}
			}
		}
		e->fftw_freq[i] =
		    ((f - prev_f) / (next_f - prev_f)) * (next_amp - prev_amp) + prev_amp;
	}
	return 1;
}

static void
equalizer_init(struct equalizer* e, double rate, int block_size,
    int channels, int bits)
{
	e->rate = rate;
	e->block_size = block_size;
	e->channels = channels;
	if (bits % 8 || bits <= 0 || bits >= 64) {
		errx(EX_SOFTWARE, "Wrong bit depth");
	}
	e->bytes = bits / 8;
	int io_buffer_size = e->bytes * channels * block_size * 3;
	e->io_buffer = (uint8_t*)malloc(io_buffer_size);
	memset(e->io_buffer, 0, io_buffer_size);

	e->dump_index = 0;
	e->backlog_buffer = (uint8_t*)malloc(e->bytes * channels * block_size *
	    BACKLOG_BLOCKS);
	memset(e->backlog_buffer, 0, e->bytes * channels * block_size *
	    BACKLOG_BLOCKS);

	int buffer_size = sizeof(double) * e->block_size * 2;
	e->filter = (double*)malloc(buffer_size);
	e->fftw_time = (double*)malloc(buffer_size);
	e->fftw_freq = (double*)malloc(buffer_size);

	e->forward = fftw_plan_r2r_1d(2 * block_size, e->fftw_time, e->fftw_freq,
	    FFTW_R2HC, FFTW_MEASURE);
	e->inverse = fftw_plan_r2r_1d(2 * block_size, e->fftw_freq, e->fftw_time,
	    FFTW_HC2R, FFTW_MEASURE);
	if (pthread_mutex_init(&e->guard, NULL)) {
		errx(EX_SOFTWARE, "Mutex error at init");
	}
}

/* Can be called at any time */
static int
equalizer_load(struct equalizer* e, const char* config)
{
	if (pthread_mutex_lock(&e->guard)) {
		errx(EX_SOFTWARE, "Mutex error at lock");
	}

	int retval = 0;
	int N = 2 * e->block_size;
	int shift = e->block_size / 2;
	int buffer_size = sizeof(double) * N;

	memset(e->fftw_freq, 0, buffer_size);
	message("\n\nReloading amplification specifications:\n%s\n", config);
	if (!load_frequency_amplification(e, config)) goto end;
	memcpy(e->filter, e->fftw_freq, buffer_size);

	fftw_execute(e->inverse);
	/* Multiply by symmetric window */
	double window_zero = get_window(0.0);
	e->fftw_time[0] *= window_zero;
	for (int i = 1; i < shift; ++i) {
		double weight = get_window(i / (double)shift);
		e->fftw_time[N - i] = e->fftw_time[i] *= weight;
	}
	e->fftw_time[shift] = e->fftw_time[N - shift] = 0;
	/* Shift */
	for (int i = e->block_size - 1; i >= 0; --i) {
		e->fftw_time[i] = e->fftw_time[(i + N - shift) % N];
	}

	/* Outside of the window is 0 */
	memset(e->fftw_time + e->block_size, 0, sizeof(double) * e->block_size);

	fftw_execute(e->forward);
	for (int i = 0; i < N; ++i) {
		e->fftw_freq[i] /= (double)N * N; // window_zero;
	}

	/* Debug output */
	for (int i = 0; i <= e->block_size; ++i) {
		double f = (e->rate / N) * i;
		double a = sqrt(pow(e->fftw_freq[i], 2.0) +
		    ((i > 0 && i < e->block_size) ? pow(e->fftw_freq[N - i], 2.0) : 0));
		a *= N;
		double r = e->filter[i];
		message("%3.1lf Hz: requested %2.2lf, got %2.7lf (log10 = %.2lf), %3.7lfdb\n",
		    f, r, a, log(a)/log(10), (log(a / r) / log(10.0)) * 10.0);
	}
	/* End of debug */

	memcpy(e->filter, e->fftw_freq, buffer_size);
	retval = 1;

end:
	if (pthread_mutex_unlock(&e->guard)) {
		errx(EX_SOFTWARE, "Mutex error at unlock");
	}
	return retval;
}

static void
equalizer_done(struct equalizer* e)
{
	pthread_mutex_destroy(&e->guard);
	fftw_destroy_plan(e->forward);
	fftw_destroy_plan(e->inverse);
	free(e->io_buffer);
	free(e->filter);
	free(e->fftw_time);
	free(e->fftw_freq);
	free(e->backlog_buffer);
}

static int
safe_read(int fd, int64_t len, void* data)
{
	while (len > 0) {
		int64_t r = read(fd, data, len);
		if (r < 0) {
			if (errno == EINTR) continue;
			return 0;
		}
		len -= r;
		data += r;
	}
	return 1;
}

static int64_t
load_le(int bytes, const uint8_t* ptr)
{
	uint64_t value = 0;
	for (int i = 0; i < bytes; ++i) {
		value |= *(ptr++) << (i * 8);
	}
	int shift = (8 - bytes) * 8;
	value = value << shift;
	return ((int64_t)value) >> shift;
}

static void
store_le(int bytes, int64_t value, uint8_t* ptr)
{
	while (bytes-- > 0) {
		*(ptr++) = value & 0xFF;
		value = value >> 8;
	}
}

// Cannot be called from more than one threads concurrently.
static int
equalize_block(struct equalizer* e, int fd_in, int fd_out)
{
	int io_block = e->block_size * e->channels * e->bytes;
	if (need_dump) {
		char fn[256];
		sprintf(fn, "/tmp/virtual_equalizer_dump_%d", e->dump_index++);
		FILE* f = fopen(fn, "w");
		if (f != NULL) {
			fwrite(e->backlog_buffer, 1, io_block * BACKLOG_BLOCKS, f);
			fclose(f);
		}
		need_dump = 0;
	}

	if (pthread_mutex_lock(&e->guard)) {
		errx(EX_SOFTWARE, "Mutex error at lock");
	}
	int N = 2 * e->block_size;
	for (int ch = 0; ch < e->channels; ++ch) {
		for (int i = 0; i < N; ++i) {
			e->fftw_time[i] = load_le(e->bytes,
			    e->io_buffer + e->bytes * (e->channels * i + ch));
		}
		fftw_execute(e->forward);
		e->fftw_freq[0] *= e->filter[0];
		for (int i = 1; i < e->block_size; ++i) {
			double re = e->fftw_freq[i] * e->filter[i] -
			    e->fftw_freq[N - i] * e->filter[N - i];
			double im = e->fftw_freq[i] * e->filter[N - i] +
			    e->fftw_freq[N - i] * e->filter[i];
			e->fftw_freq[i] = re;
			e->fftw_freq[N - i] = im;
		}
		e->fftw_freq[e->block_size] *= e->filter[e->block_size];
		fftw_execute(e->inverse);
		for (int i = 0; i < e->block_size; ++i) {
			store_le(e->bytes, (int64_t)e->fftw_time[i + e->block_size], e->io_buffer +
			    e->bytes * (e->channels * i + ch));
		}
	}
	if (pthread_mutex_unlock(&e->guard)) {
		errx(EX_SOFTWARE, "Mutex error at unlock");
	}

	int v;
	if (ioctl(fd_out, SNDCTL_DSP_GETODELAY, &v) != -1) {
		message(", after equalize: %d", v);
		message("           \r", v);
	}

	memmove(e->backlog_buffer, e->backlog_buffer + io_block, io_block * (BACKLOG_BLOCKS - 1));
	memcpy(e->backlog_buffer + io_block * (BACKLOG_BLOCKS - 1), e->io_buffer,
	    io_block);

	memset(e->io_buffer + 2 * io_block, 0, io_block);
	for (int64_t i = 0; i < io_block; ) {
		int64_t w = write(fd_out, e->io_buffer + i, io_block - i);
		if (w < 0) {
			if (errno == EINTR) continue;
			return 0;
		}
		if (!safe_read(fd_in, w, e->io_buffer + 2 * io_block + i)) {
			return 0;
		}
		i += w;
	}
	memmove(e->io_buffer, e->io_buffer + io_block, 2 * io_block);
	return 1;
}

static struct option equalizer_opts[] = {
	{"device_input", required_argument, NULL, 'i'},
	{"device_output", required_argument, NULL, 'o'},
	{"rate", required_argument, NULL, 'r'},
	{"block", required_argument, NULL, 'b'},
	{"channels", required_argument, NULL, 'c'},
	{"background", no_argument, NULL, 'B'},
	{"config", required_argument, NULL, 's'},
};

static void
usage()
{
	message("Usage: equalizer \n"
	    "\t -i, --device_input [device]\n"
	    "\t -o, --device_output [device]\n"
	    "\t -r, --rate [rate in Hz, default 44100]\n"
	    "\t -b, --block [block size in samples, default 2048]\n"
	    "\t -c, --channels [channels, default 2]\n"
	    "\t -B, --background\n"
	    "\t -s, --config [equalizer configuration socket]\n");
	exit(EX_USAGE);
}

static int
setup_oss(int rate, int channels, int block, int fd)
{
	int v;
	v = AFMT_S24_LE;
	if (ioctl(fd, SNDCTL_DSP_SETFMT, &v) == -1) {
		message("Cannot set format");
		return -1;
	}
	v = channels;
	if (ioctl(fd, SNDCTL_DSP_CHANNELS, &v) == -1) {
		message("Cannot set channels");
		return -1;
	}
	v = rate;
	if (ioctl(fd, SNDCTL_DSP_SPEED, &v) == -1) {
		message("Cannot set rate");
		return -1;
	}
	// Estimate buffer of 1/4 of block size + 2 extra fragments.
	v = ((2 + channels * 3 * block / 4 / 1024) << 16) | 10;
	if (ioctl(fd, SNDCTL_DSP_SETFRAGMENT, &v) == -1) {
		message("Cannot set fragments");
		return -1;
	}
	return 0;
}

struct thread_cfg {
	const char* socket;
	struct equalizer* e;
};

static void*
control_thread(struct thread_cfg* cfg)
{
	unlink(cfg->socket);

	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		errx(EX_SOFTWARE, "Cannot create socket");
	}

	struct sockaddr_un name;
	memset(&name, 0, sizeof(struct sockaddr_un));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, cfg->socket, sizeof(name.sun_path) - 1);
	if (bind(s, (const struct sockaddr*)&name, sizeof(struct sockaddr_un))) {
		errx(EX_SOFTWARE, "Cannot bind socket");
	}
	while (1) {
		char buffer[65536];
		int len = read(s, buffer, sizeof(buffer) - 1);
		buffer[len] = 0;
		equalizer_load(cfg->e, buffer);
	}
	close(s);
	unlink(cfg->socket);
	return NULL;
}

int
equalizer_main(int argc, char** argv)
{
	signal(SIGINFO, &dump);
	struct equalizer e;
	double rate = 44100.0;
	int block = 2048;
	int channels = 2;
	const char* socket = "/tmp/equalizer.socket";
	const char* in_dsp = NULL;
	const char* out_dsp = NULL;
	int fd_in = 0;
	int fd_out = 1;
	int go_to_background = 0;

	int opt;
	while ((opt = getopt_long(argc, argv, "i:o:r:b:c:Bs:h", equalizer_opts, NULL))
	    != -1) {
		switch (opt) {
		case 'i':
			in_dsp = optarg;
			fd_in = -1;
			break;
		case 'o':
			out_dsp = optarg;
			fd_out = -1;
			break;
		case 'r':
			if (sscanf(optarg, "%lf", &rate) != 1) {
				message("Cannot parse rate\n");
				usage();
			}
			break;
		case 'b':
			block = strtol(optarg, NULL, 10);
			if (block == 0 || (block % 2)) {
				message("Wrong block size\n");
				usage();
			}
			break;
		case 'c':
			channels = strtol(optarg, NULL, 10);
			if (channels == 0) {
				message("Wrong number of channels\n");
				usage();
			}
			break;
		case 'B':
			go_to_background = 1;
			break;
		case 's':
			socket = optarg;
			break;
		default:
			usage();
		}
	}

	if (go_to_background) {
		in_background = 1;
		if (daemon(0, 0) != 0) {
			errx(EX_SOFTWARE, "Cannot go to background");
		}
	}

	equalizer_init(&e, rate, block, channels, 24);
	equalizer_load(&e, "");

	struct thread_cfg cfg;
	cfg.socket = socket;
	cfg.e = &e;
	pthread_t control_thread;
	if (pthread_create(&control_thread, NULL, (void*(*)(void*))&control_thread, &cfg)) {
		errx(EX_SOFTWARE, "Cannot create control thread");
	}

	while(1) {
		if (fd_out == -1) {
			fd_out = open(out_dsp, O_WRONLY);
			if (fd_out != -1 && setup_oss((int)rate, channels, block, fd_out) == -1) {
				fd_out = -1;
			}
		}
		if (fd_out == -1) {
			message("Output device is not ready.\n");
			if (fd_in > -1) {
				close(fd_in);
				fd_in = -1;
			}
			sleep(1);
			continue;
		}

		if (fd_in == -1) {
			fd_in = open(in_dsp, O_RDONLY);
			if (fd_in != -1 && setup_oss((int)rate, channels, block, fd_in) == -1) {
				fd_in = -1;
			}
		}
		if (fd_in == -1) {
			message("Input device is not ready.\n");
			sleep(1);
			continue;
		}

		{
			int v;
			ioctl(fd_out, SNDCTL_DSP_GETODELAY, &v);
			message("Output delay before equalize: %d, ", v);
		}

		if (!equalize_block(&e, fd_in, fd_out)) {
			if (fd_in != -1) close(fd_in);
			if (fd_out != -1) close(fd_out);
			fd_in = -1;
			fd_out = -1;
			message("Devices are not ready.\n");
			sleep(1);
		}
	}
	pthread_join(control_thread, NULL);
	equalizer_done(&e);
	return 0;
}
