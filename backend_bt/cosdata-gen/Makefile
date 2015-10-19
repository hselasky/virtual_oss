# $NetBSD$

USE_FORT?= yes	# network client
WARNS?=	4

PROG=		cosdata
SRCS=		cosdata.c
NO_MAN=		true

DPADD+=		${LIBMATH}
LDADD+=		-lm

.include <bsd.prog.mk>
