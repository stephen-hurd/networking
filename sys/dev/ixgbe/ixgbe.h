/******************************************************************************

  Copyright (c) 2001-2017, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/* $FreeBSD$*/


#ifndef _IFLIB_IXGBE_H_
#define _IFLIB_IXGBE_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sockio.h>
#include <sys/eventhandler.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/if_types.h>
#include <net/if_vlan_var.h>
#include <net/iflib.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <sys/bus.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <machine/resource.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/clock.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/endian.h>
#include <sys/gtaskqueue.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <machine/smp.h>
#include <sys/sbuf.h>

 #ifdef PCI_IOV
#include <sys/nv.h>
#include <sys/iov_schema.h>
#include <dev/pci/pci_iov.h>
#endif

#include "ixgbe_api.h"
#include "ixgbe_common.h"
#include "ixgbe_phy.h"
#include "ixgbe_vf.h"

#ifdef PCI_IOV
#include "ixgbe_common.h"
#include "ixgbe_mbx.h"
#endif
#include "ixgbe_features.h"
#include "ixgbe_rss.h"
#include "ixgbe_fdir.h"

#define IXGBE_CORE_LOCK_ASSERT(a) (sx_assert(iflib_ctx_lock_get((a)->ctx), SX_XLOCKED))

/* Tunables */

/*
 * TxDescriptors Valid Range: 64-4096 Default Value: 256 This value is the
 * number of transmit descriptors allocated by the driver. Increasing this
 * value allows the driver to queue more transmits. Each descriptor is 16
 * bytes. Performance tests have show the 2K value to be optimal for top
 * performance.
 */
#define DEFAULT_TXD     1024
#define PERFORM_TXD     2048
#define MAX_TXD         4096
#define MIN_TXD         64

/*
 * RxDescriptors Valid Range: 64-4096 Default Value: 256 This value is the
 * number of receive descriptors allocated for each RX queue. Increasing this
 * value allows the driver to buffer more incoming packets. Each descriptor
 * is 16 bytes.  A receive buffer is also allocated for each descriptor.
 *
 * Note: with 8 rings and a dual port card, it is possible to bump up
 *       against the system mbuf pool limit, you can tune nmbclusters
 *       to adjust for this.
 */
#define DEFAULT_RXD     1024
#define PERFORM_RXD     2048
#define MAX_RXD         4096
#define MIN_RXD         64

/* Alignment for rings */
#define DBA_ALIGN       128

/*
 * This is the max watchdog interval, ie. the time that can
 * pass between any two TX clean operations, such only happening
 * when the TX hardware is functioning.
 */
#define IXGBE_WATCHDOG  (10 * hz)

/*
 * This parameters control when the driver calls the routine to reclaim
 * transmit descriptors.
 */
#define IXGBE_TX_CLEANUP_THRESHOLD(_a)  ((_a)->num_tx_desc / 8)
#define IXGBE_TX_OP_THRESHOLD(_a)       ((_a)->num_tx_desc / 32)

/* These defines are used in MTU calculations */
#define IXGBE_MAX_FRAME_SIZE  9728
#define IXGBE_MTU_HDR         (ETHER_HDR_LEN + ETHER_CRC_LEN)
#define IXGBE_MTU_HDR_VLAN    (ETHER_HDR_LEN + ETHER_CRC_LEN + \
                               ETHER_VLAN_ENCAP_LEN)
#define IXGBE_MAX_MTU         (IXGBE_MAX_FRAME_SIZE - IXGBE_MTU_HDR)
#define IXGBE_MAX_MTU_VLAN    (IXGBE_MAX_FRAME_SIZE - IXGBE_MTU_HDR_VLAN)

/* Flow control constants */
#define IXGBE_FC_PAUSE        0xFFFF
#define IXGBE_FC_HI           0x20000
#define IXGBE_FC_LO           0x10000

/*
 * Used for optimizing small rx mbufs.  Effort is made to keep the copy
 * small and aligned for the CPU L1 cache.
 *
 * MHLEN is typically 168 bytes, giving us 8-byte alignment.  Getting
 * 32 byte alignment needed for the fast bcopy results in 8 bytes being
 * wasted.  Getting 64 byte alignment, which _should_ be ideal for
 * modern Intel CPUs, results in 40 bytes wasted and a significant drop
 * in observed efficiency of the optimization, 97.9% -> 81.8%.
 */
#if __FreeBSD_version < 1002000
#define MPKTHSIZE                 (sizeof(struct m_hdr) + sizeof(struct pkthdr))
#endif
#define IXGBE_RX_COPY_HDR_PADDED  ((((MPKTHSIZE - 1) / 32) + 1) * 32)
#define IXGBE_RX_COPY_LEN         (MSIZE - IXGBE_RX_COPY_HDR_PADDED)
#define IXGBE_RX_COPY_ALIGN       (IXGBE_RX_COPY_HDR_PADDED - MPKTHSIZE)

/* Keep older OS drivers building... */
#if !defined(SYSCTL_ADD_UQUAD)
#define SYSCTL_ADD_UQUAD SYSCTL_ADD_QUAD
#endif

/* Defines for printing debug information */
#define DEBUG_INIT  0
#define DEBUG_IOCTL 0
#define DEBUG_HW    0

#define INIT_DEBUGOUT(S)            if (DEBUG_INIT)  printf(S "\n")
#define INIT_DEBUGOUT1(S, A)        if (DEBUG_INIT)  printf(S "\n", A)
#define INIT_DEBUGOUT2(S, A, B)     if (DEBUG_INIT)  printf(S "\n", A, B)
#define IOCTL_DEBUGOUT(S)           if (DEBUG_IOCTL) printf(S "\n")
#define IOCTL_DEBUGOUT1(S, A)       if (DEBUG_IOCTL) printf(S "\n", A)
#define IOCTL_DEBUGOUT2(S, A, B)    if (DEBUG_IOCTL) printf(S "\n", A, B)
#define HW_DEBUGOUT(S)              if (DEBUG_HW) printf(S "\n")
#define HW_DEBUGOUT1(S, A)          if (DEBUG_HW) printf(S "\n", A)
#define HW_DEBUGOUT2(S, A, B)       if (DEBUG_HW) printf(S "\n", A, B)

#define MAX_NUM_MULTICAST_ADDRESSES     128
#define IXGBE_82598_SCATTER             100
#define IXGBE_82599_SCATTER             32
#define MSIX_82598_BAR                  3
#define MSIX_82599_BAR                  4
#define IXGBE_TSO_SIZE                  262140
#define IXGBE_RX_HDR                    128
#define IXGBE_VFTA_SIZE                 128
#define IXGBE_BR_SIZE                   4096
#define IXGBE_QUEUE_MIN_FREE            32
#define IXGBE_MAX_TX_BUSY               10
#define IXGBE_QUEUE_HUNG                0x80000000

#define IXGBE_EITR_DEFAULT              128

#define CSUM_OFFLOAD  (CSUM_IP_TSO|CSUM_IP6_TSO|CSUM_IP| \
                       CSUM_IP_UDP|CSUM_IP_TCP|CSUM_IP_SCTP| \
                       CSUM_IP6_UDP|CSUM_IP6_TCP|CSUM_IP6_SCTP)
/*
 * Interrupt Moderation parameters
 */
#define IXGBE_LOW_LATENCY   128
#define IXGBE_AVE_LATENCY   400
#define IXGBE_BULK_LATENCY  1200

/* Using 1FF (the max value), the interval is ~1.05ms */
#define IXGBE_LINK_ITR_QUANTA  0x1FF
#define IXGBE_LINK_ITR         ((IXGBE_LINK_ITR_QUANTA << 3) & \
                                IXGBE_EITR_ITR_INT_MASK)

/* MAC type macros */
#define IXGBE_IS_X550VF(_adapter) \
       ((_adapter->hw.mac.type == ixgbe_mac_X550_vf) || \
        (_adapter->hw.mac.type == ixgbe_mac_X550EM_x_vf))
 
#define IXGBE_IS_VF(_adapter) \
       (IXGBE_IS_X550VF(_adapter) || \
        (_adapter->hw.mac.type == ixgbe_mac_X540_vf) || \
        (_adapter->hw.mac.type == ixgbe_mac_82599_vf))
 
#ifdef PCI_IOV
#define IXGBE_VF_INDEX(vmdq)  ((vmdq) / 32)
#define IXGBE_VF_BIT(vmdq)    (1 << ((vmdq) % 32))

#define IXGBE_VT_MSG_MASK      0xFFFF

#define IXGBE_VT_MSGINFO(msg)  \
       (((msg) & IXGBE_VT_MSGINFO_MASK) >> IXGBE_VT_MSGINFO_SHIFT)

#define IXGBE_VF_GET_QUEUES_RESP_LEN   5

#define IXGBE_API_VER_1_0      0               
#define IXGBE_API_VER_2_0      1       /* Solaris API.  Not supported. */
#define IXGBE_API_VER_1_1      2
#define IXGBE_API_VER_UNKNOWN  UINT16_MAX

enum ixgbe_iov_mode {
       IXGBE_64_VM,
       IXGBE_32_VM,
       IXGBE_NO_VM
};
#endif /* PCI_IOV */

struct ixgbe_bp_data {
	u32 low;
	u32 high;
	u32 log;
};

/*
 * Bus dma allocation structure used by ixgbe_dma_malloc and ixgbe_dma_free
 */
struct ixgbe_dma_alloc {
	bus_addr_t        dma_paddr;
	caddr_t           dma_vaddr;
	bus_dma_tag_t     dma_tag;
	bus_dmamap_t      dma_map;
	bus_dma_segment_t dma_seg;
	bus_size_t        dma_size;
	int               dma_nseg;
};

struct ixgbe_mc_addr {
	u8  addr[IXGBE_ETH_LENGTH_OF_ADDRESS];
	u32 vmdq;
};

/*
 * The transmit ring, one per queue
 */
struct tx_ring {
	struct adapter		*adapter;
	qidx_t			*tx_rsq;
	qidx_t			tx_rs_cidx;
	qidx_t			tx_rs_pidx;
	qidx_t			tx_cidx_processed;
	u16			me;
	u32			tail;
	u32			busy;
	union ixgbe_adv_tx_desc	*tx_base;
	uint64_t tx_paddr;
#ifdef IXGBE_FDIR
	u16			atr_sample;
	u16			atr_count;
#endif
	u32			bytes;  /* used for AIM */
	u32			packets;
	/* Soft Stats */
	unsigned long   	tso_tx;
        u64			total_packets;
};


/*
 * The Receive ring, one per rx queue
 */
struct rx_ring {
	struct ix_rx_queue	*que;
	struct adapter		*adapter;
	u32			me;
	u32			tail;
	union ixgbe_adv_rx_desc	*rx_base;
	uint64_t rx_paddr;
	bool			hw_rsc;
	bool			vtag_strip;
	bus_dma_tag_t		ptag;

	u32			bytes; /* Used for AIM calc */
	u32			packets;

	/* Soft stats */
	u64                     rx_irq;
	u64                     rx_copies;
	u64                     rx_packets;
	u64                     rx_bytes;
	u64                     rx_discarded;
	u64                     rsc_num;

	/* Flow Director */
	u64                     flm;
};

/*
** Driver queue struct: this is the interrupt container
**  for the associated tx and rx ring.
*/
struct ix_rx_queue {
	struct adapter		*adapter;
	u32			msix;           /* This queue's MSIX vector */
	u32			eims;           /* This queue's EIMS bit */
	u32			eitr_setting;
	struct resource		*res;
	void			*tag;
	int			busy;
	struct rx_ring		rxr;
        struct if_irq           que_irq;
	u64			irqs;
};

struct ix_tx_queue {
	struct adapter		*adapter;
	u32			msix;           /* This queue's MSIX vector */
	struct tx_ring		txr;
};

#ifdef PCI_IOV
#define IXGBE_VF_CTS		(1 << 0) /* VF is clear to send. */
#define IXGBE_VF_CAP_MAC	(1 << 1) /* VF is permitted to change MAC. */
#define IXGBE_VF_CAP_VLAN	(1 << 2) /* VF is permitted to join vlans. */
#define IXGBE_VF_ACTIVE		(1 << 3) /* VF is active. */

#define IXGBE_MAX_VF_MC 30  /* Max number of multicast entries */

struct ixgbe_vf {
	u_int		pool;
	u_int		rar_index;
	u_int		maximum_frame_size;
	uint32_t	flags;
	uint8_t		ether_addr[ETHER_ADDR_LEN];
	uint16_t	mc_hash[IXGBE_MAX_VF_MC];
	uint16_t	num_mc_hashes;
	uint16_t	default_vlan;
	uint16_t	vlan_tag;
	uint16_t	api_ver;
};
#endif

/* Our adapter structure */
struct adapter {
	/* much of the code assumes this is first :< */
	struct ixgbe_hw		hw;
	struct ixgbe_osdep	osdep;
	if_ctx_t ctx;
	if_softc_ctx_t shared;
#define num_tx_queues shared->isc_ntxqsets
#define num_rx_queues shared->isc_nrxqsets
#define max_frame_size shared->isc_max_frame_size
#define intr_type shared->isc_intr
	struct ifnet		*ifp;
	struct device		*dev;
	struct resource		*pci_mem;

	/*
	 * Interrupt resources: this set is
	 * either used for legacy, or for Link
	 * when doing MSI-X
	 */
	struct if_irq           irq;
	void			*tag;
	struct resource 	*res;

	struct ifmedia		*media;
	int			msix;
	int			if_flags;

	u16			num_vlans;

	/*
	 * Shadow VFTA table, this is needed because
	 * the real vlan filter table gets cleared during
	 * a soft reset and the driver needs to be able
	 * to repopulate it.
	 */
	u32                     shadow_vfta[IXGBE_VFTA_SIZE];

	/* Info about the interface */
	u32			optics;
	u32			fc; /* local flow ctrl setting */
	int			advertise;  /* link speeds */
	bool			enable_aim; /* adaptive interrupt moderation */
	bool			link_active;
	u16			num_segs;
	u32			link_speed;
	bool			link_up;
	u32 			vector;
	u16			dmac;
	bool			eee_enabled;
	u32			phy_layer;

	/* Power management-related */
	bool                    wol_support;
	u32                     wufc;

	/* Support for pluggable optics */
	bool			sfp_probe;

	struct grouptask     	mod_task;   /* SFP tasklet */
	struct grouptask     	msf_task;   /* Multispeed Fiber */

#ifdef PCI_IOV
	struct grouptask		mbx_task;   /* VF -> PF mailbox interrupt */
	struct ixgbe_vf         *vfs;
#endif /* PCI_IOV */
#ifdef IXGBE_FDIR
	int			fdir_reinit;
	struct grouptask     	fdir_task;
#endif

	struct grouptask		phy_task;   /* PHY intr tasklet */

	/*
	** Queues: 
	**   This is the irq holder, it has
	**   and RX/TX pair or rings associated
	**   with it.
	*/
	struct ix_tx_queue	*tx_queues;
	struct ix_rx_queue	*rx_queues;
	u64			active_queues;

        u32                     tx_process_limit;
	u32			rx_process_limit;

	/* Multicast array memory */
	struct ixgbe_mc_addr    *mta;

	/* SR-IOV */
	int                     iov_mode;
	int                     num_vfs;
	int                     pool;

	/* Bypass */
	struct ixgbe_bp_data    bypass;

	/* Misc stats maintained by the driver */
        unsigned long           rx_mbuf_sz;
	unsigned long   	mbuf_header_failed;
	unsigned long   	mbuf_packet_failed;
	unsigned long   	watchdog_events;
	unsigned long		link_irq;
	union {
		struct ixgbe_hw_stats pf;
		struct ixgbevf_hw_stats vf;
	} stats;
#if __FreeBSD_version >= 1100036
	/* counter(9) stats */
	u64                     ipackets;
	u64                     ierrors;
	u64                     opackets;
	u64                     oerrors;
	u64                     ibytes;
	u64                     obytes;
	u64                     imcasts;
	u64                     omcasts;
	u64                     iqdrops;
	u64                     noproto;
#endif
	/* Feature capable/enabled flags.  See ixgbe_features.h */
	u32                     feat_cap;
	u32                     feat_en;
};

#include "ixgbe_bypass.h"
#include "ixgbe_sriov.h"

/* Precision Time Sync (IEEE 1588) defines */
#define ETHERTYPE_IEEE1588      0x88F7
#define PICOSECS_PER_TICK       20833
#define TSYNC_UDP_PORT          319 /* UDP port for the protocol */
#define IXGBE_ADVTXD_TSTAMP     0x00080000

/* For backward compatibility */
#if !defined(PCIER_LINK_STA)
#define PCIER_LINK_STA PCIR_EXPRESS_LINK_STA
#endif

/* Stats macros */
#if __FreeBSD_version >= 1100036
#define IXGBE_SET_IPACKETS(sc, count)    (sc)->ipackets = (count)
#define IXGBE_SET_IERRORS(sc, count)     (sc)->ierrors = (count)
#define IXGBE_SET_OPACKETS(sc, count)    (sc)->opackets = (count)
#define IXGBE_SET_OERRORS(sc, count)     (sc)->oerrors = (count)
#define IXGBE_SET_COLLISIONS(sc, count)
#define IXGBE_SET_IBYTES(sc, count)      (sc)->ibytes = (count)
#define IXGBE_SET_OBYTES(sc, count)      (sc)->obytes = (count)
#define IXGBE_SET_IMCASTS(sc, count)     (sc)->imcasts = (count)
#define IXGBE_SET_OMCASTS(sc, count)     (sc)->omcasts = (count)
#define IXGBE_SET_IQDROPS(sc, count)     (sc)->iqdrops = (count)
#else
#define IXGBE_SET_IPACKETS(sc, count)    (sc)->ifp->if_ipackets = (count)
#define IXGBE_SET_IERRORS(sc, count)     (sc)->ifp->if_ierrors = (count)
#define IXGBE_SET_OPACKETS(sc, count)    (sc)->ifp->if_opackets = (count)
#define IXGBE_SET_OERRORS(sc, count)     (sc)->ifp->if_oerrors = (count)
#define IXGBE_SET_COLLISIONS(sc, count)  (sc)->ifp->if_collisions = (count)
#define IXGBE_SET_IBYTES(sc, count)      (sc)->ifp->if_ibytes = (count)
#define IXGBE_SET_OBYTES(sc, count)      (sc)->ifp->if_obytes = (count)
#define IXGBE_SET_IMCASTS(sc, count)     (sc)->ifp->if_imcasts = (count)
#define IXGBE_SET_OMCASTS(sc, count)     (sc)->ifp->if_omcasts = (count)
#define IXGBE_SET_IQDROPS(sc, count)     (sc)->ifp->if_iqdrops = (count)
#endif

/* External PHY register addresses */
#define IXGBE_PHY_CURRENT_TEMP     0xC820
#define IXGBE_PHY_OVERTEMP_STATUS  0xC830

/* Sysctl help messages; displayed with sysctl -d */
#define IXGBE_SYSCTL_DESC_ADV_SPEED \
        "\nControl advertised link speed using these flags:\n" \
        "\t0x1 - advertise 100M\n" \
        "\t0x2 - advertise 1G\n" \
        "\t0x4 - advertise 10G\n" \
        "\t0x8 - advertise 10M\n\n" \
        "\t100M and 10M are only supported on certain adapters.\n"

#define IXGBE_SYSCTL_DESC_SET_FC \
        "\nSet flow control mode using these values:\n" \
        "\t0 - off\n" \
        "\t1 - rx pause\n" \
        "\t2 - tx pause\n" \
        "\t3 - tx and rx pause"

static inline bool
ixgbe_is_sfp(struct ixgbe_hw *hw)
{
       switch (hw->phy.type) {
       case ixgbe_phy_sfp_avago:
       case ixgbe_phy_sfp_ftl:
       case ixgbe_phy_sfp_intel:
       case ixgbe_phy_sfp_unknown:
       case ixgbe_phy_sfp_passive_tyco:
       case ixgbe_phy_sfp_passive_unknown:
       case ixgbe_phy_qsfp_passive_unknown:
       case ixgbe_phy_qsfp_active_unknown:
       case ixgbe_phy_qsfp_intel:
       case ixgbe_phy_qsfp_unknown:
               return TRUE;
       default:
               return FALSE;
       }
}

/*
** This checks for a zero mac addr, something that will be likely
** unless the Admin on the Host has created one.
*/
static inline bool
ixv_check_ether_addr(u8 *addr)
{
	bool status = TRUE;

	if ((addr[0] == 0 && addr[1]== 0 && addr[2] == 0 &&
	    addr[3] == 0 && addr[4]== 0 && addr[5] == 0))
		status = FALSE;

	return (status);
}

/* Shared Prototypes */

int	ixgbe_allocate_queues(struct adapter *);
int	ixgbe_allocate_transmit_buffers(struct tx_ring *);
int	ixgbe_setup_transmit_structures(struct adapter *);
void	ixgbe_free_transmit_structures(struct adapter *);
int	ixgbe_allocate_receive_buffers(struct rx_ring *);
int	ixgbe_setup_receive_structures(struct adapter *);
void	ixgbe_free_receive_structures(struct adapter *);

int	ixgbe_dma_malloc(struct adapter *,
	    bus_size_t, struct ixgbe_dma_alloc *, int);
void	ixgbe_dma_free(struct adapter *, struct ixgbe_dma_alloc *);
int	ixgbe_get_regs(SYSCTL_HANDLER_ARGS);

#ifdef PCI_IOV

static inline enum ixgbe_iov_mode
ixgbe_get_iov_mode(struct adapter *adapter)
{
	if (adapter->num_vfs == 0)
		return (IXGBE_NO_VM);
	if (adapter->num_tx_queues <= 2)
		return (IXGBE_64_VM);
	else if (adapter->num_tx_queues <= 4)
		return (IXGBE_32_VM);
	else
		return (IXGBE_NO_VM);
}

static inline u16
ixgbe_max_vfs(enum ixgbe_iov_mode mode)
{
	/*
	 * We return odd numbers below because we
	 * reserve 1 VM's worth of queues for the PF.
	 */
	switch (mode) {
	case IXGBE_64_VM:
		return (63);
	case IXGBE_32_VM:
		return (31);
	case IXGBE_NO_VM:
	default:
		return (0);
	}
}


static inline int
ixgbe_pf_que_index(enum ixgbe_iov_mode mode, int num)
{
	return (ixgbe_vf_que_index(mode, ixgbe_max_vfs(mode), num));
}


#endif /* PCI_IOV */
#endif /* _IXGBE_H_ */
