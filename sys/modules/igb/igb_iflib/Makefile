#$FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/e1000
KMOD    = if_igb
SRCS    = if_igb_stub.c

CFLAGS += -I${.CURDIR}/../../../dev/e1000 -DSMP

CFLAGS += -DIFLIB

.include <bsd.kmod.mk>
