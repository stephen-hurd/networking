#$FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/ixl

KMOD    = if_ixlv
SRCS    = device_if.h bus_if.h pci_if.h pci_iov_if.h
SRCS    += opt_inet.h opt_inet6.h opt_rss.h opt_bdg.h
SRCS    += if_ixlv.c ixlvc.c if_ixl_common.c ixl_txrx.c i40e_osdep.c

# Shared source
SRCS    += i40e_common.c i40e_nvm.c i40e_adminq.c

CFLAGS	+= -DSMP

# Add Flow Director support
# CFLAGS += -DIXL_FDIR
# Debug messages / sysctls
# CFLAGS += -DIXLE_DEBUG

.include <bsd.kmod.mk>
