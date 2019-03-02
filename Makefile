#
# Copyright (c) 2012 Hans Petter Selasky. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#
# Makefile for virtual_oss
#

.PATH: . backend_oss backend_bt backend_null

VERSION=1.2.1
PROG=virtual_oss
MAN=virtual_oss.8
PACKAGE=${PROG}-${VERSION}
PTHREAD_LIBS?= -lpthread
PREFIX?=        /usr/local
LOCALBASE?=     /usr/local
BINDIR=         ${PREFIX}/sbin
MANDIR=         ${PREFIX}/man/man
LIBDIR=         ${PREFIX}/lib

SRCS= \
virtual_audio_delay.c \
virtual_ctl.c \
virtual_format.c \
virtual_main.c \
virtual_oss.c \
virtual_ring.c \
backend_oss.c \
backend_null.c

.if defined(HAVE_BLUETOOTH)
SRCS += backend_bt.c avdtp.c sbc_encode.c bt_speaker.c
CFLAGS += -DHAVE_BLUETOOTH
LDFLAGS += -lbluetooth -lsdp
LINKS += ${BINDIR}/virtual_oss ${BINDIR}/virtual_bt_speaker
MAN += virtual_bt_speaker.8
.endif

.if defined(HAVE_FFMPEG)
CFLAGS += -DHAVE_FFMPEG
LDFLAGS += -lavdevice -lavutil -lavcodec -lavresample -lavformat
.endif

.if defined(HAVE_CUSE)
CFLAGS+= -DHAVE_CUSE
LDFLAGS+= -lcuse
.else
LDFLAGS+= -lcuse4bsd
.endif

CFLAGS += -I${LOCALBASE}/include
LDFLAGS += -L${LIBDIR} ${PTHREAD_LIBS} -lm -lsamplerate

.include <bsd.prog.mk>

help:
	@echo "Targets are: all, install, clean, package, help"

package: clean
	tar -cvf ${PACKAGE}.tar Makefile virtual*.[ch8] backend_*/*.[ch]
	rm -rf ${PACKAGE}
	mkdir ${PACKAGE}
	tar -xvf ${PACKAGE}.tar -C ${PACKAGE}
	rm -rf ${PACKAGE}.tar
	tar -jcvf ${PACKAGE}.tar.bz2 --uid 0 --gid 0 ${PACKAGE}

