# $FreeBSD$

.PATH:  ${SRCTOP}/sys/dev/ixgbe

KMOD    = if_ix
SRCS    = device_if.h bus_if.h pci_if.h pci_iov_if.h ifdi_if.h
SRCS    += opt_inet.h opt_inet6.h opt_rss.h opt_iflib.h
SRCS    += if_ix.c ix_txrx.c ixgbe_osdep.c ixgbe_sysctl.c

# Shared source
SRCS    += ixgbe_common.c ixgbe_api.c ixgbe_phy.c ixgbe_mbx.c ixgbe_vf.c
SRCS    += ixgbe_dcb.c ixgbe_dcb_82598.c ixgbe_dcb_82599.c
SRCS    += ixgbe_82598.c ixgbe_82599.c ixgbe_x540.c ixgbe_x550.c

CFLAGS+= -I${SRCTOP}/sys/dev/ixgbe -DSMP
CFLAGS+= -DIFLIB

.include <bsd.kmod.mk>
