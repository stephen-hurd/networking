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


#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_rss.h"

#include "ixgbe.h"
#include "ifdi_if.h"

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <dev/netmap/netmap_kern.h>

/************************************************************************
 * Driver version
 ************************************************************************/
char ixgbe_driver_version[] = "3.2.12-k";


/************************************************************************
 * PCI Device ID Table
 *
 *   Used by probe to select devices to load on
 *   Last field stores an index into ixgbe_strings
 *   Last entry must be all 0s
 *
 *  { Vendor ID, Device ID, SubVendor ID, SubDevice ID, String Index }
 *********************************************************************/
static pci_vendor_info_t ixgbe_vendor_info_array[] =
{
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AF_DUAL_PORT,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AF_SINGLE_PORT,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598EB_CX4,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AT,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AT2,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_DA_DUAL_PORT,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_CX4_DUAL_PORT,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598EB_XF_LR,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_SR_DUAL_PORT_EM,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598EB_SFP_LOM,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_KX4,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_KX4_MEZZ,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_XAUI_LOM,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_CX4,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_T3_LOM,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_COMBO_BACKPLANE,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_BACKPLANE_FCOE,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_SF2,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_FCOE,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599EN_SFP,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_SF_QP,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_QSFP_SF_QP,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X540T,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X540T1,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550T,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550T1, "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_KR,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_KX4,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_10G_T,  "Intel(R) PRO/10GbE PCI-Express Network Driver"),
  PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_SFP, "Intel(R) PRO/10GbE PCI-Express Network Driver"),

	/* required last entry */
  PVID_END
};

/*********************************************************************
 *  Function prototypes
 *********************************************************************/
static void *ixgbe_register(device_t dev);
static int ixgbe_if_attach_pre(if_ctx_t ctx);
static int ixgbe_if_attach_post(if_ctx_t ctx);
static int ixgbe_if_detach(if_ctx_t ctx);
static int ixgbe_if_shutdown(if_ctx_t ctx);
static int ixgbe_if_suspend(if_ctx_t ctx);
static int ixgbe_if_resume(if_ctx_t ctx);

static void ixgbe_if_stop(if_ctx_t ctx);
static void ixgbe_if_init(if_ctx_t ctx);
void ixgbe_if_enable_intr(if_ctx_t ctx);
static void ixgbe_if_disable_intr(if_ctx_t ctx);
static int ixgbe_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t qid);
static int ixgbe_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t qid);
static void ixgbe_if_media_status(if_ctx_t ctx, struct ifmediareq * ifmr);
static int ixgbe_if_media_change(if_ctx_t ctx);
static int ixgbe_if_msix_intr_assign(if_ctx_t, int);
static int ixgbe_if_mtu_set(if_ctx_t ctx, uint32_t mtu);
static void ixgbe_if_crcstrip_set(if_ctx_t ctx, int onoff, int strip);
static void ixgbe_if_multi_set(if_ctx_t ctx);
static int ixgbe_if_promisc_set(if_ctx_t ctx, int flags);
static int ixgbe_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets);
static int ixgbe_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets);
static void ixgbe_if_queues_free(if_ctx_t ctx);
static void ixgbe_if_timer(if_ctx_t ctx, uint16_t);
static void ixgbe_if_update_admin_status(if_ctx_t ctx);
static void ixgbe_if_vlan_register(if_ctx_t ctx, u16 vtag);
static void ixgbe_if_vlan_unregister(if_ctx_t ctx, u16 vtag);

int ixgbe_intr(void *arg);

#if __FreeBSD_version >= 1100036
static uint64_t	ixgbe_if_get_counter(if_ctx_t, ift_counter);
#endif

static void ixgbe_enable_queue(struct adapter *adapter, u32 vector);
static void ixgbe_disable_queue(struct adapter *adapter, u32 vector);
static void ixgbe_add_device_sysctls(if_ctx_t ctx);
static int ixgbe_allocate_pci_resources(if_ctx_t ctx);
static int ixgbe_setup_low_power_mode(if_ctx_t ctx);

static void ixgbe_config_dmac(struct adapter *adapter);
static void ixgbe_configure_ivars(struct adapter *adapter);
static void ixgbe_set_ivar(struct adapter *adapter, u8 entry, u8 vector, s8 type);
static u8 * ixgbe_mc_array_itr(struct ixgbe_hw *, u8 **, u32 *);
static bool ixgbe_sfp_probe(if_ctx_t ctx);

static void ixgbe_identify_hardware(if_ctx_t ctx);
static void ixgbe_free_pci_resources(if_ctx_t ctx);

static int ixgbe_msix_link(void *arg);
static int ixgbe_msix_que(void *arg);
static void ixgbe_initialize_rss_mapping(struct adapter *adapter);
static void ixgbe_initialize_receive_units(if_ctx_t ctx);
static void ixgbe_initialize_transmit_units(if_ctx_t ctx);

static int ixgbe_interface_setup(if_ctx_t ctx);
static void ixgbe_add_media_types(if_ctx_t ctx);
static void ixgbe_update_stats_counters(struct adapter *adapter);
static void ixgbe_config_link(struct adapter *adapter);
static void ixgbe_get_slot_info(struct adapter *);
static void ixgbe_check_wol_support(struct adapter *adapter);
static void ixgbe_enable_rx_drop(struct adapter *);
static void ixgbe_disable_rx_drop(struct adapter *);

static void ixgbe_add_hw_stats(struct adapter *adapter);
static int ixgbe_set_flowcntl(struct adapter *, int);
static int ixgbe_set_advertise(struct adapter *, int);
static void ixgbe_setup_vlan_hw_support(if_ctx_t ctx);
static void ixgbe_setup_optics(struct adapter *adapter);
static void ixgbe_config_gpie(struct adapter *adapter);
static void ixgbe_config_delay_values(struct adapter *adapter);
static void ixgbe_rearm_queues(struct adapter *adapter, u64 queues);

/* Sysctl handlers */
static int ixgbe_sysctl_flowcntl(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_advertise(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_interrupt_rate_handler(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_thermal_test(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_dmac(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_phy_temp(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_phy_overtemp_occurred(SYSCTL_HANDLER_ARGS);
#ifdef IXGBE_DEBUG
static int      ixgbe_sysctl_power_state(SYSCTL_HANDLER_ARGS);
static int      ixgbe_sysctl_print_rss_config(SYSCTL_HANDLER_ARGS);
#endif
static int ixgbe_sysctl_rdh_handler(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_rdt_handler(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_tdt_handler(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_tdh_handler(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_wol_enable(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_wufc(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_eee_enable(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_eee_negotiated(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_eee_rx_lpi_status(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_eee_tx_lpi_status(SYSCTL_HANDLER_ARGS);
static int ixgbe_sysctl_eee_tx_lpi_delay(SYSCTL_HANDLER_ARGS);

/* Deferred interrupt tasklets */
static void	ixgbe_handle_msf(void *);
static void	ixgbe_handle_mod(void *);
static void	ixgbe_handle_phy(void *);

/**********************************************************************
 *  FreeBSD Device Interface Entry Points
 *********************************************************************/
static device_method_t ixgbe_methods[] = {
	/* Device interface */
	DEVMETHOD(device_register, ixgbe_register),
	DEVMETHOD(device_probe, iflib_device_probe),
	DEVMETHOD(device_attach, iflib_device_attach),
	DEVMETHOD(device_detach, iflib_device_detach),
	DEVMETHOD(device_shutdown, iflib_device_shutdown),
	DEVMETHOD(device_suspend, iflib_device_suspend),
	DEVMETHOD(device_resume, iflib_device_resume),
#ifdef PCI_IOV
	DEVMETHOD(pci_iov_init, ixgbe_init_iov),
	DEVMETHOD(pci_iov_uninit, ixgbe_uninit_iov),
	DEVMETHOD(pci_iov_add_vf, ixgbe_add_vf),
#endif /* PCI_IOV */
	DEVMETHOD_END
};

static driver_t ixgbe_driver = {
	"ix", ixgbe_methods, sizeof(struct adapter),
};

devclass_t ix_devclass;
DRIVER_MODULE(ix, pci, ixgbe_driver, ix_devclass, 0, 0);

MODULE_DEPEND(ix, pci, 1, 1, 1);
MODULE_DEPEND(ix, ether, 1, 1, 1);
MODULE_DEPEND(ix, iflib, 1, 1, 1);

static device_method_t ixgbe_if_methods[] = {
	DEVMETHOD(ifdi_attach_pre, ixgbe_if_attach_pre),
	DEVMETHOD(ifdi_attach_post, ixgbe_if_attach_post),
	DEVMETHOD(ifdi_detach, ixgbe_if_detach),
	DEVMETHOD(ifdi_shutdown, ixgbe_if_shutdown),
	DEVMETHOD(ifdi_suspend, ixgbe_if_suspend),
	DEVMETHOD(ifdi_resume, ixgbe_if_resume),
	DEVMETHOD(ifdi_init, ixgbe_if_init),
	DEVMETHOD(ifdi_stop, ixgbe_if_stop),
	DEVMETHOD(ifdi_msix_intr_assign, ixgbe_if_msix_intr_assign),
	DEVMETHOD(ifdi_intr_enable, ixgbe_if_enable_intr),
	DEVMETHOD(ifdi_intr_disable, ixgbe_if_disable_intr),
	DEVMETHOD(ifdi_rx_queue_intr_enable, ixgbe_if_rx_queue_intr_enable),
	DEVMETHOD(ifdi_tx_queue_intr_enable, ixgbe_if_tx_queue_intr_enable),
	DEVMETHOD(ifdi_tx_queues_alloc, ixgbe_if_tx_queues_alloc),
	DEVMETHOD(ifdi_rx_queues_alloc, ixgbe_if_rx_queues_alloc),
	DEVMETHOD(ifdi_queues_free, ixgbe_if_queues_free),
	DEVMETHOD(ifdi_update_admin_status, ixgbe_if_update_admin_status),
	DEVMETHOD(ifdi_multi_set, ixgbe_if_multi_set),
	DEVMETHOD(ifdi_mtu_set, ixgbe_if_mtu_set),
	DEVMETHOD(ifdi_crcstrip_set, ixgbe_if_crcstrip_set),
	DEVMETHOD(ifdi_media_status, ixgbe_if_media_status),
	DEVMETHOD(ifdi_media_change, ixgbe_if_media_change),
	DEVMETHOD(ifdi_promisc_set, ixgbe_if_promisc_set),
	DEVMETHOD(ifdi_timer, ixgbe_if_timer),
	DEVMETHOD(ifdi_vlan_register, ixgbe_if_vlan_register),
	DEVMETHOD(ifdi_vlan_unregister, ixgbe_if_vlan_unregister),
	DEVMETHOD(ifdi_get_counter, ixgbe_if_get_counter),
	DEVMETHOD_END
};

/*
 * note that if (adapter->msix_mem) is replaced by:
 * if (adapter->intr_type == IFLIB_INTR_MSIX)
 */

static driver_t ixgbe_if_driver = {
  "ixgbe_if", ixgbe_if_methods, sizeof(struct adapter)
};

/*
 * TUNEABLE PARAMETERS:
 */

static SYSCTL_NODE(_hw, OID_AUTO, ix, CTLFLAG_RD, 0, "IXGBE driver parameters");

/*
 * AIM: Adaptive Interrupt Moderation
 * which means that the interrupt rate
 * is varied over time based on the
 * traffic for that interrupt vector
 */
static int ixgbe_enable_aim = FALSE;
SYSCTL_INT(_hw_ix, OID_AUTO, enable_aim, CTLFLAG_RDTUN, &ixgbe_enable_aim, 0,
    "Enable adaptive interrupt moderation");

static int ixgbe_max_interrupt_rate = (4000000 / IXGBE_LOW_LATENCY);
SYSCTL_INT(_hw_ix, OID_AUTO, max_interrupt_rate, CTLFLAG_RDTUN,
    &ixgbe_max_interrupt_rate, 0, "Maximum interrupts per second");

/* Flow control setting, default to full */
static int ixgbe_flow_control = ixgbe_fc_full;
SYSCTL_INT(_hw_ix, OID_AUTO, flow_control, CTLFLAG_RDTUN,
    &ixgbe_flow_control, 0, "Default flow control used for all adapters");

/* Advertise Speed, default to 0 (auto) */
static int ixgbe_advertise_speed = 0;
SYSCTL_INT(_hw_ix, OID_AUTO, advertise_speed, CTLFLAG_RDTUN,
    &ixgbe_advertise_speed, 0, "Default advertised speed for all adapters");

/*
 * Smart speed setting, default to on
 * this only works as a compile option
 * right now as its during attach, set
 * this to 'ixgbe_smart_speed_off' to
 * disable.
 */
static int ixgbe_smart_speed = ixgbe_smart_speed_on;

/*
 * MSI-X should be the default for best performance,
 * but this allows it to be forced off for testing.
 */
static int ixgbe_enable_msix = 1;
SYSCTL_INT(_hw_ix, OID_AUTO, enable_msix, CTLFLAG_RDTUN, &ixgbe_enable_msix, 0,
    "Enable MSI-X interrupts");

/*
 * HW RSC control:
 *  this feature only works with
 *  IPv4, and only on 82599 and later.
 *  Also this will cause IP forwarding to
 *  fail and that can't be controlled by
 *  the stack as LRO can. For all these
 *  reasons I've deemed it best to leave
 *  this off and not bother with a tuneable
 *  interface, this would need to be compiled
 *  to enable.
 */
static bool ixgbe_rsc_enable = FALSE;

extern int iflib_crcstrip;

/*
 * Defining this on will allow the use
 * of unsupported SFP+ modules, note that
 * doing so you are on your own :)
 */
static int allow_unsupported_sfp = FALSE;
TUNABLE_INT("hw.ix.unsupported_sfp", &allow_unsupported_sfp);

static MALLOC_DEFINE(M_IXGBE, "ix", "ix driver allocations");

extern struct if_txrx ixgbe_txrx;

static struct if_shared_ctx ixgbe_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_q_align = PAGE_SIZE,/* max(DBA_ALIGN, PAGE_SIZE) */
	.isc_tx_maxsize = IXGBE_TSO_SIZE,

	.isc_tx_maxsegsize = PAGE_SIZE,

	.isc_rx_maxsize = PAGE_SIZE*4,
	.isc_rx_nsegments = 1,
	.isc_rx_maxsegsize = PAGE_SIZE*4,
	.isc_nfl = 1,
	.isc_ntxqs = 1,
	.isc_nrxqs = 1,

	.isc_admin_intrcnt = 1,
	.isc_vendor_info = ixgbe_vendor_info_array,
	.isc_driver_version = ixgbe_driver_version,
	.isc_driver = &ixgbe_if_driver,

	.isc_nrxd_min = {MIN_RXD},
	.isc_ntxd_min = {MIN_TXD},
	.isc_nrxd_max = {MAX_RXD},
	.isc_ntxd_max = {MAX_TXD},
	.isc_nrxd_default = {DEFAULT_RXD},
	.isc_ntxd_default = {DEFAULT_TXD},
};

if_shared_ctx_t ixgbe_sctx = &ixgbe_sctx_init;

static int
ixgbe_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ix_tx_queue *que;
	int i, error;
#ifdef PCI_IOV
	enum ixgbe_iov_mode mode;
#endif
	
	MPASS(adapter->num_tx_queues > 0);
	MPASS(adapter->num_tx_queues == ntxqsets);
	MPASS(ntxqs == 1);

	/* Allocate queue structure memory */
	if (!(adapter->tx_queues =
	      (struct ix_tx_queue *) malloc(sizeof(struct ix_tx_queue) *
					    ntxqsets, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate TX ring memory\n");
		return (ENOMEM);
	}

#ifdef PCI_IOV
	mode = ixgbe_get_iov_mode(adapter);
	adapter->pool = ixgbe_max_vfs(mode);
#else
	adapter->pool = 0;
#endif

	for (i = 0, que = adapter->tx_queues; i < ntxqsets; i++, que++) {
		struct tx_ring		*txr = &que->txr;

		if (!(txr->tx_rsq = (qidx_t *) malloc(sizeof(qidx_t) * scctx->isc_ntxd[0], M_DEVBUF, M_NOWAIT | M_ZERO))) {
			device_printf(iflib_get_dev(ctx), "failed to allocate qidx memory\n");
			error = ENOMEM;
			goto fail;
		}
#ifdef PCI_IOV
		txr->me = ixgbe_pf_que_index(mode, i);
#else
		txr->me = i;
#endif

		txr->adapter = que->adapter = adapter;
		adapter->active_queues |= (u64)1 << txr->me;

		/* get the virtual and physical address of the hardware queues */
		txr->tail = IXGBE_TDT(txr->me);
		txr->tx_base = (union ixgbe_adv_tx_desc *)vaddrs[i];
		txr->tx_paddr = paddrs[i];

		txr->bytes = 0;
		txr->total_packets = 0;

	}

	iflib_config_gtask_init(ctx, &adapter->mod_task, ixgbe_handle_mod, "mod_task");
	iflib_config_gtask_init(ctx, &adapter->msf_task, ixgbe_handle_msf, "msf_task");
	iflib_config_gtask_init(ctx, &adapter->phy_task, ixgbe_handle_phy, "phy_task");
#ifdef PCI_IOV
	iflib_config_gtask_init(ctx, &adapter->mbx_task, ixgbe_handle_mbx, "mbx_task");
#endif

	device_printf(iflib_get_dev(ctx), "allocated for %d queues\n", adapter->num_tx_queues);
	return (0);

 fail:
	ixgbe_if_queues_free(ctx);
	return (error);
} /* ixgbe_attach */


static int
ixgbe_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ix_rx_queue *que;
	int i;
#ifdef PCI_IOV
	enum ixgbe_iov_mode mode;
#endif

	MPASS(adapter->num_rx_queues > 0);
	MPASS(adapter->num_rx_queues == nrxqsets);
	MPASS(nrxqs == 1);

	/* Allocate queue structure memory */
	if (!(adapter->rx_queues =
	      (struct ix_rx_queue *) malloc(sizeof(struct ix_rx_queue)*nrxqsets , M_DEVBUF, M_NOWAIT | M_ZERO))) {
	  device_printf(iflib_get_dev(ctx), "Unable to allocate TX ring memory\n");
	  return (ENOMEM);
	}

#ifdef PCI_IOV
	mode = ixgbe_get_iov_mode(adapter);
	adapter->pool = ixgbe_max_vfs(mode);
#else
	adapter->pool = 0;
#endif

	for (i = 0, que = adapter->rx_queues; i < nrxqsets; i++, que++) {
		struct rx_ring 		*rxr = &que->rxr;

#ifdef PCI_IOV
	        rxr->me = ixgbe_pf_que_index(mode, i);
#else
		rxr->me = i;
#endif
		/* only do 1:1 but keep door open */
		MPASS(adapter->num_rx_queues == adapter->num_tx_queues);
		que->txq[0] = &adapter->tx_queues[i];
		rxr->adapter = que->adapter = adapter;

		/* get the virtual and physical address of the hardware queues */

		rxr->tail = IXGBE_RDT(rxr->me);
		rxr->rx_base = (union ixgbe_adv_rx_desc *)vaddrs[i];
		rxr->rx_paddr = paddrs[i];
		rxr->bytes = 0;
		rxr->que = que;
	}

	device_printf(iflib_get_dev(ctx), "allocated for %d rx queues\n", adapter->num_rx_queues);
	return (0);
}

static void
ixgbe_if_queues_free(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ix_tx_queue *tx_que = adapter->tx_queues;
	struct ix_rx_queue *rx_que = adapter->rx_queues;
        int i;

	if (tx_que == NULL && rx_que == NULL)
		return;

        for (i = 0; i < adapter->num_tx_queues; i++, tx_que++) {
		struct tx_ring		*txr = &tx_que->txr;

		if (txr->tx_rsq == NULL)
			break;

		free(txr->tx_rsq, M_DEVBUF);
		txr->tx_rsq = NULL;
	}
	
	free(adapter->tx_queues, M_DEVBUF);
	free(adapter->rx_queues, M_DEVBUF);
	adapter->rx_queues = NULL;
	adapter->tx_queues = NULL;
}

static void
ixgbe_initialize_rss_mapping(struct adapter *adapter)
{
	struct ixgbe_hw	*hw = &adapter->hw;
	u32 reta = 0, mrqc, rss_key[10];
	int queue_id, table_size, index_mult;
#ifdef	RSS
	u32 rss_hash_config;
#endif
#ifdef PCI_IOV
	enum ixgbe_iov_mode mode;
#endif

#ifdef	RSS
	/* Fetch the configured RSS key */
	rss_getkey((uint8_t *) &rss_key);
#else
	/* set up random bits */
	arc4rand(&rss_key, sizeof(rss_key), 0);
#endif

	/* Set multiplier for RETA setup and table size based on MAC */
	index_mult = 0x1;
	table_size = 128;
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
		index_mult = 0x11;
		break;
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
		table_size = 512;
		break;
	default:
		break;
	}

	/* Set up the redirection table */
	for (int i = 0, j = 0; i < table_size; i++, j++) {
		if (j == adapter->num_rx_queues) j = 0;
#ifdef	RSS
		/*
		 * Fetch the RSS bucket id for the given indirection entry.
		 * Cap it at the number of configured buckets (which is
		 * num_queues.)
		 */
		queue_id = rss_get_indirection_to_bucket(i);
		queue_id = queue_id % adapter->num_rx_queues;
#else
		queue_id = (j * index_mult);
#endif
		/*
		 * The low 8 bits are for hash value (n+0);
		 * The next 8 bits are for hash value (n+1), etc.
		 */
		reta = reta >> 8;
		reta = reta | ( ((uint32_t) queue_id) << 24);
		if ((i & 3) == 3) {
			if (i < 128)
				IXGBE_WRITE_REG(hw, IXGBE_RETA(i >> 2), reta);
			else
				IXGBE_WRITE_REG(hw, IXGBE_ERETA((i >> 2) - 32), reta);
			reta = 0;
		}
	}

	/* Now fill our hash function seeds */
	for (int i = 0; i < 10; i++)
		IXGBE_WRITE_REG(hw, IXGBE_RSSRK(i), rss_key[i]);

	/* Perform hash on these packet types */
#ifdef	RSS
	mrqc = IXGBE_MRQC_RSSEN;
	rss_hash_config = rss_gethashconfig();
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_UDP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4_EX)
		device_printf(adapter->dev,
		    "%s: RSS_HASHTYPE_RSS_UDP_IPV4_EX defined, "
		    "but not supported\n", __func__);
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_UDP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX_UDP;
#else
	/*
	 * Disable UDP - IP fragments aren't currently being handled
	 * and so we end up with a mix of 2-tuple and 4-tuple
	 * traffic.
	 */
	mrqc = IXGBE_MRQC_RSSEN
	     | IXGBE_MRQC_RSS_FIELD_IPV4
	     | IXGBE_MRQC_RSS_FIELD_IPV4_TCP
	     | IXGBE_MRQC_RSS_FIELD_IPV6_EX_TCP
	     | IXGBE_MRQC_RSS_FIELD_IPV6_EX
	     | IXGBE_MRQC_RSS_FIELD_IPV6
	     | IXGBE_MRQC_RSS_FIELD_IPV6_TCP
	;
#endif /* RSS */
#ifdef PCI_IOV
	mode = ixgbe_get_iov_mode(adapter);
	mrqc |= ixgbe_get_mrqc(mode);
#endif
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);
}

/************************************************************************
 * ixgbe_setup_hw_rsc
 *
 *   Initialize Hardware RSC (LRO) feature on 82599
 *   for an RX ring, this is toggled by the LRO capability
 *   even though it is transparent to the stack.
 *
 *   NOTE: Since this HW feature only works with IPv4 and
 *         testing has shown soft LRO to be as effective,
 *         this feature will be disabled by default.
 ************************************************************************/
static void
ixgbe_setup_hw_rsc(struct rx_ring *rxr)
{
	struct	adapter 	*adapter = rxr->adapter;
	struct	ixgbe_hw	*hw = &adapter->hw;
	u32			rscctrl, rdrxctl;

	/* If turning LRO/RSC off we need to disable it */
	if ((adapter->ifp->if_capenable & IFCAP_LRO) == 0) {
		rscctrl = IXGBE_READ_REG(hw, IXGBE_RSCCTL(rxr->me));
		rscctrl &= ~IXGBE_RSCCTL_RSCEN;
		return;
	}

	rdrxctl = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);
	rdrxctl &= ~IXGBE_RDRXCTL_RSCFRSTSIZE;
	if ((adapter->ifp->if_capenable & IFCAP_NETMAP && !iflib_crcstrip) ||
	    !(adapter->ifp->if_capenable & IFCAP_NETMAP))
		rdrxctl |= IXGBE_RDRXCTL_CRCSTRIP;
	IXGBE_WRITE_REG(hw, IXGBE_RDRXCTL, rdrxctl);

	rscctrl = IXGBE_READ_REG(hw, IXGBE_RSCCTL(rxr->me));
	rscctrl |= IXGBE_RSCCTL_RSCEN;
	/*
	** Limit the total number of descriptors that
	** can be combined, so it does not exceed 64K
	*/
	if (adapter->rx_mbuf_sz == MCLBYTES)
		rscctrl |= IXGBE_RSCCTL_MAXDESC_16;
	else if (adapter->rx_mbuf_sz == MJUMPAGESIZE)
		rscctrl |= IXGBE_RSCCTL_MAXDESC_8;
	else if (adapter->rx_mbuf_sz == MJUM9BYTES)
		rscctrl |= IXGBE_RSCCTL_MAXDESC_4;
	else  /* Using 16K cluster */
		rscctrl |= IXGBE_RSCCTL_MAXDESC_1;

	IXGBE_WRITE_REG(hw, IXGBE_RSCCTL(rxr->me), rscctrl);

	/* Enable TCP header recognition */
	IXGBE_WRITE_REG(hw, IXGBE_PSRTYPE(0),
	    (IXGBE_READ_REG(hw, IXGBE_PSRTYPE(0)) |
	    IXGBE_PSRTYPE_TCPHDR));

	/* Disable RSC for ACK packets */
	IXGBE_WRITE_REG(hw, IXGBE_RSCDBU,
	    (IXGBE_RSCDBU_RSCACKDIS | IXGBE_READ_REG(hw, IXGBE_RSCDBU)));

	rxr->hw_rsc = TRUE;
}

/*********************************************************************
 *
 *  Setup receive registers and features.
 *
 **********************************************************************/
#define IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT 2

#define BSIZEPKT_ROUNDUP ((1<<IXGBE_SRRCTL_BSIZEPKT_SHIFT)-1)

/************************************************************************
 * ixgbe_config_link
 ************************************************************************/
static void
ixgbe_initialize_receive_units(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ixgbe_hw	*hw = &adapter->hw;
	struct ifnet   *ifp = iflib_get_ifp(ctx);

	struct ix_rx_queue *que;
	u32		bufsz, fctrl, srrctl, rxcsum;
	u32		hlreg;
	int             i;

	/*
	 * Make sure receives are disabled while
	 * setting up the descriptor ring
	 */
	ixgbe_disable_rx(hw);

	/* Enable broadcasts */
	fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	fctrl |= IXGBE_FCTRL_BAM;
	if (adapter->hw.mac.type == ixgbe_mac_82598EB) {
		fctrl |= IXGBE_FCTRL_DPF;
		fctrl |= IXGBE_FCTRL_PMCF;
	}
	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);

	/* Set for Jumbo Frames? */
	hlreg = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	if (ifp->if_mtu > ETHERMTU)
		hlreg |= IXGBE_HLREG0_JUMBOEN;
	else
		hlreg &= ~IXGBE_HLREG0_JUMBOEN;
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hlreg);

	bufsz = (adapter->rx_mbuf_sz +
	    BSIZEPKT_ROUNDUP) >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;

	/* Setup the Base and Length of the Rx Descriptor Ring */
        for (i = 0, que = adapter->rx_queues; i < adapter->num_rx_queues; i++, que++) {
                struct rx_ring	   *rxr = &que->rxr;
		u64	           rdba = rxr->rx_paddr;
                int                   j = rxr->me;

		/* Setup the Base and Length of the Rx Descriptor Ring */
		IXGBE_WRITE_REG(hw, IXGBE_RDBAL(j),
			       (rdba & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_RDBAH(j), (rdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_RDLEN(j),
		     scctx->isc_nrxd[0] * sizeof(union ixgbe_adv_rx_desc));

		/* Set up the SRRCTL register */
		srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(j));
		srrctl &= ~IXGBE_SRRCTL_BSIZEHDR_MASK;
		srrctl &= ~IXGBE_SRRCTL_BSIZEPKT_MASK;
		srrctl |= bufsz;
		srrctl |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

		/*
		 * Set DROP_EN iff we have no flow control and >1 queue.
		 * Note that srrctl was cleared shortly before during reset,
		 * so we do not need to clear the bit, but do it just in case
		 * this code is moved elsewhere.
		 */
		if (adapter->num_rx_queues > 1 &&
		    adapter->hw.fc.requested_mode == ixgbe_fc_none) {
			srrctl |= IXGBE_SRRCTL_DROP_EN;
		} else {
			srrctl &= ~IXGBE_SRRCTL_DROP_EN;
		}

		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(j), srrctl);

		/* Setup the HW Rx Head and Tail Descriptor Pointers */
		IXGBE_WRITE_REG(hw, IXGBE_RDH(j), 0);
		IXGBE_WRITE_REG(hw, IXGBE_RDT(j), 0);

		/* Set the driver rx tail address */
		rxr->tail =  IXGBE_RDT(rxr->me);
		if (ixgbe_rsc_enable)
			ixgbe_setup_hw_rsc(rxr);
	}

	if (adapter->hw.mac.type != ixgbe_mac_82598EB) {
		u32 psrtype = IXGBE_PSRTYPE_TCPHDR |
			      IXGBE_PSRTYPE_UDPHDR |
			      IXGBE_PSRTYPE_IPV4HDR |
			      IXGBE_PSRTYPE_IPV6HDR;
		IXGBE_WRITE_REG(hw, IXGBE_PSRTYPE(0), psrtype);
	}

	rxcsum = IXGBE_READ_REG(hw, IXGBE_RXCSUM);

	ixgbe_initialize_rss_mapping(adapter);

	if (adapter->num_rx_queues > 1) {
		/* RSS and RX IPP Checksum are mutually exclusive */
		rxcsum |= IXGBE_RXCSUM_PCSD;
	}

	if (ifp->if_capenable & IFCAP_RXCSUM)
		rxcsum |= IXGBE_RXCSUM_PCSD;

	if (!(rxcsum & IXGBE_RXCSUM_PCSD))
		rxcsum |= IXGBE_RXCSUM_IPPCSE;

	IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, rxcsum);
}



/*********************************************************************
 *
 *  Enable transmit units.
 *
 **********************************************************************/
static void
ixgbe_initialize_transmit_units(if_ctx_t ctx)
{
  struct adapter *adapter = iflib_get_softc(ctx);
  if_softc_ctx_t scctx = adapter->shared;
  struct ixgbe_hw	*hw = &adapter->hw;
  struct ix_tx_queue *que;
  int i;

  /* Setup the Base and Length of the Tx Descriptor Ring */
  for (i = 0, que = adapter->tx_queues; i < adapter->num_tx_queues; i++, que++) {
                struct tx_ring	   *txr = &que->txr;
		u64	tdba = 	txr->tx_paddr;
		u32	txctrl = 0;
		int	j = txr->me;

		IXGBE_WRITE_REG(hw, IXGBE_TDBAL(j),
		       (tdba & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_TDBAH(j), (tdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_TDLEN(j),
		    scctx->isc_ntxd[0] * sizeof(union ixgbe_adv_tx_desc));

		/* Setup the HW Tx Head and Tail descriptor pointers */
		IXGBE_WRITE_REG(hw, IXGBE_TDH(j), 0);
		IXGBE_WRITE_REG(hw, IXGBE_TDT(j), 0);


		/*
		 * Note: for X550 series devices, these registers are actually
		 * prefixed with TPH_ isntead of DCA_, but the addresses and
		 * fields remain the same.
		 */
		/* Disable Head Writeback */
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			txctrl = IXGBE_READ_REG(hw, IXGBE_DCA_TXCTRL(j));
			break;
		default:
			txctrl = IXGBE_READ_REG(hw, IXGBE_DCA_TXCTRL_82599(j));
			break;
                }
		txctrl &= ~IXGBE_DCA_TXCTRL_DESC_WRO_EN;
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL(j), txctrl);
			break;
		default:
			IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL_82599(j), txctrl);
			break;
		}

	}

	if (hw->mac.type != ixgbe_mac_82598EB) {
		u32 dmatxctl, rttdcs;
#ifdef PCI_IOV
		enum ixgbe_iov_mode mode = ixgbe_get_iov_mode(adapter);
#endif
		dmatxctl = IXGBE_READ_REG(hw, IXGBE_DMATXCTL);
		dmatxctl |= IXGBE_DMATXCTL_TE;
		IXGBE_WRITE_REG(hw, IXGBE_DMATXCTL, dmatxctl);
		/* Disable arbiter to set MTQC */
		rttdcs = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
		rttdcs |= IXGBE_RTTDCS_ARBDIS;
		IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);
#ifdef PCI_IOV
		IXGBE_WRITE_REG(hw, IXGBE_MTQC, ixgbe_get_mtqc(mode));
#else
		IXGBE_WRITE_REG(hw, IXGBE_MTQC, IXGBE_MTQC_64Q_1PB);
#endif
		rttdcs &= ~IXGBE_RTTDCS_ARBDIS;
		IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);
	}
}


static void *
ixgbe_register(device_t dev)
{
	return (ixgbe_sctx);
}

 /*********************************************************************
 *  Device initialization routine
 *
 *  The attach entry point is called when the driver is being loaded.
 *  This routine identifies the type of hardware, allocates all resources
 *  and initializes the hardware.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/

#define IXGBE_CAPS  IFCAP_TSO4 | IFCAP_TSO6 | IFCAP_TXCSUM | IFCAP_TXCSUM_IPV6 | IFCAP_RXCSUM | IFCAP_RXCSUM_IPV6 | \
	IFCAP_VLAN_HWFILTER | IFCAP_WOL_MAGIC |	IFCAP_WOL_MCAST | IFCAP_WOL | IFCAP_VLAN_HWTSO | IFCAP_HWCSUM | \
	IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | IFCAP_LRO;

static int
ixgbe_if_attach_pre(if_ctx_t ctx)
{
	device_t dev;
	struct adapter *adapter;
	if_softc_ctx_t scctx;
	struct ixgbe_hw *hw;
	uint16_t csum;
	int error = 0;
  
	INIT_DEBUGOUT("ixgbe_attach: begin");

	/* Allocate, clear, and link in our adapter structure */
	dev = iflib_get_dev(ctx);
	adapter = iflib_get_softc(ctx);
	adapter->ctx = ctx;
	adapter->dev = dev;
	scctx = adapter->shared = iflib_get_softc_ctx(ctx);
	adapter->media = iflib_get_media(ctx);
	hw = &adapter->hw;

	/* Identify hardware revision */
	ixgbe_identify_hardware(ctx);

	if (adapter->hw.mac.type == ixgbe_mac_82598EB) {
		scctx->isc_tx_nsegments = IXGBE_82598_SCATTER;
		scctx->isc_msix_bar = PCIR_BAR(MSIX_82598_BAR);
	} else {
		hw->phy.smart_speed = ixgbe_smart_speed;
		scctx->isc_tx_nsegments = IXGBE_82599_SCATTER;
		scctx->isc_msix_bar = PCIR_BAR(MSIX_82599_BAR);
	}
	scctx->isc_txqsizes[0] = roundup2(scctx->isc_ntxd[0] * sizeof(union ixgbe_adv_tx_desc) + sizeof(u32), DBA_ALIGN),
	scctx->isc_rxqsizes[0] = roundup2(scctx->isc_nrxd[0] * sizeof(union ixgbe_adv_rx_desc), DBA_ALIGN);

	scctx->isc_tx_tso_segments_max = scctx->isc_tx_nsegments;
	scctx->isc_tx_tso_size_max = IXGBE_TSO_SIZE;
	scctx->isc_tx_tso_segsize_max = PAGE_SIZE;
	/* XXX */
	scctx->isc_ntxqsets_max = scctx->isc_nrxqsets_max = 32;

	/* Sysctls */
	ixgbe_add_device_sysctls(ctx);

	/* Do base PCI setup - map BAR0 */
	if (ixgbe_allocate_pci_resources(ctx)) {
		device_printf(dev, "Allocation of PCI resources failed\n");
		return (ENXIO);
	}

	/* Allocate multicast array memory. */
	adapter->mta = malloc(sizeof(*adapter->mta) *
						  MAX_NUM_MULTICAST_ADDRESSES, M_DEVBUF, M_NOWAIT);
	if (adapter->mta == NULL) {
		device_printf(dev, "Can not allocate multicast setup array\n");
		error = ENOMEM;
		goto err_pci;
	}

	/* Initialize the shared code */
	hw->allow_unsupported_sfp = allow_unsupported_sfp;
	error = ixgbe_init_shared_code(hw);
	if (error == IXGBE_ERR_SFP_NOT_PRESENT) {
		/*
		** No optics in this port, set up
		** so the timer routine will probe
		** for later insertion.
		*/
		adapter->sfp_probe = TRUE;
		error = 0;
	} else if (error == IXGBE_ERR_SFP_NOT_SUPPORTED) {
		device_printf(dev,"Unsupported SFP+ module detected!\n");
		error = EIO;
		goto err_late;
	} else if (error) {
		device_printf(dev,"Unable to initialize the shared code\n");
		error = EIO;
		goto err_late;
	}  
  
	/* Make sure we have a good EEPROM before we read from it */
	if (ixgbe_validate_eeprom_checksum(&adapter->hw, &csum) < 0) {
		device_printf(dev,"The EEPROM Checksum Is Not Valid\n");
		error = EIO;
		goto err_late;
	}

	error = ixgbe_init_hw(hw);

	switch (error) {
	case IXGBE_ERR_EEPROM_VERSION:
		device_printf(dev, "This device is a pre-production adapter/"
					  "LOM.  Please be aware there may be issues associated "
					  "with your hardware.\n If you are experiencing problems "
					  "please contact your Intel or hardware representative "
					  "who provided you with this hardware.\n");
		break;
	case IXGBE_ERR_SFP_NOT_SUPPORTED:
		device_printf(dev,"Unsupported SFP+ Module\n");
		error = EIO;
		goto err_late;
	case IXGBE_ERR_SFP_NOT_PRESENT:
		device_printf(dev,"No SFP+ Module found\n");
		/* falls thru */
	default:
		break;
	}

	iflib_set_mac(ctx, hw->mac.addr);
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
		scctx->isc_rss_table_size = 512;
		break;
	default:
		scctx->isc_rss_table_size = 128;
	}
	scctx->isc_txrx = &ixgbe_txrx;
	scctx->isc_tx_csum_flags = CSUM_IP | CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP | CSUM_IP6_UDP | CSUM_IP6_TSO;
	if (hw->mac.type != ixgbe_mac_82598EB)
		scctx->isc_tx_csum_flags |= CSUM_SCTP |CSUM_IP6_SCTP;

	scctx->isc_capenable = IXGBE_CAPS;
	return (0);
err_late:
	free(adapter->mta, M_DEVBUF);
err_pci:
	ixgbe_free_pci_resources(ctx);

	return (error);
}

static int
ixgbe_if_attach_post(if_ctx_t ctx)
{
	device_t dev;
	struct adapter  *adapter;
	struct ixgbe_hw *hw;
	int             error = 0;
	u32             ctrl_ext;

	dev = iflib_get_dev(ctx);
	adapter = iflib_get_softc(ctx);
	hw = &adapter->hw;


	/* hw.ix defaults init */
	ixgbe_set_advertise(adapter, ixgbe_advertise_speed);
	ixgbe_set_flowcntl(adapter, ixgbe_flow_control);
	adapter->enable_aim = ixgbe_enable_aim;

	/* Enable the optics for 82599 SFP+ fiber */
	ixgbe_enable_tx_laser(hw);

	/* Enable power to the phy. */
	ixgbe_set_phy_power(hw, TRUE);

#ifdef PCI_IOV
	ixgbe_initialize_iov(adapter);
#endif

	error = ixgbe_interface_setup(ctx);
	if (error) {
		device_printf(dev, "Interface setup failed: %d\n", error);
		goto err;
	}

	/* Initialize statistics */
	ixgbe_update_stats_counters(adapter);
	ixgbe_add_hw_stats(adapter);
  
	/* Check PCIE slot type/speed/width */
	ixgbe_get_slot_info(adapter);

	/* Set an initial default flow control & dmac value */
	adapter->fc = ixgbe_fc_full;
	adapter->dmac = 0;
	adapter->eee_enabled = 0;
#ifdef PCI_IOV
	if ((hw->mac.type != ixgbe_mac_82598EB) && (adapter->intr_type == IFLIB_INTR_MSIX)) {
		nvlist_t *pf_schema, *vf_schema;

		hw->mbx.ops.init_params(hw);
		pf_schema = pci_iov_schema_alloc_node();
		vf_schema = pci_iov_schema_alloc_node();
		pci_iov_schema_add_unicast_mac(vf_schema, "mac-addr", 0, NULL);
		pci_iov_schema_add_bool(vf_schema, "mac-anti-spoof",
								IOV_SCHEMA_HASDEFAULT, TRUE);
		pci_iov_schema_add_bool(vf_schema, "allow-set-mac",
								IOV_SCHEMA_HASDEFAULT, FALSE);
		pci_iov_schema_add_bool(vf_schema, "allow-promisc",
								IOV_SCHEMA_HASDEFAULT, FALSE);
		error = pci_iov_attach(dev, pf_schema, vf_schema);
		if (error != 0) {
			device_printf(dev,
						  "Error %d setting up SR-IOV\n", error);
		}
	} else {
		device_printf(dev, "PCI_IOV enabled but not configured: mac_type: %x intr_type: %d\n",
			      hw->mac.type, adapter->intr_type);
	}
#endif /* PCI_IOV */

	/* Check for certain supported features */
	ixgbe_check_wol_support(adapter);

	/* let hardware know driver is loaded */
	ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ctrl_ext |= IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);

	return (0);
err:
	ixgbe_if_detach(ctx);
	return (error);
}

/*
 * Checks whether the adapter's ports are capable of
 * Wake On LAN by reading the adapter's NVM.
 *
 * Sets each port's hw->wol_enabled value depending
 * on the value read here.
 */
static void
ixgbe_check_wol_support(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u16 dev_caps = 0;

	/* Find out WoL support for port */
	adapter->wol_support = hw->wol_enabled = 0;
	ixgbe_get_device_caps(hw, &dev_caps);
	if ((dev_caps & IXGBE_DEVICE_CAPS_WOL_PORT0_1) ||
	    ((dev_caps & IXGBE_DEVICE_CAPS_WOL_PORT0) &&
		 hw->bus.func == 0))
	    adapter->wol_support = hw->wol_enabled = 1;

	/* Save initial wake up filter configuration */
	adapter->wufc = IXGBE_READ_REG(hw, IXGBE_WUFC);

	return;
}
 
/*********************************************************************
 *
 *  Setup networking device structure and register an interface.
 *
 **********************************************************************/
#define IXGBE_IFCAPABILITIES			\
	(IFCAP_RXCSUM |  IFCAP_TXCSUM |  IFCAP_RXCSUM_IPV6 |  IFCAP_TXCSUM_IPV6 |  IFCAP_TSO4 |	\
	 IFCAP_TSO6 |  IFCAP_LRO |  IFCAP_VLAN_HWTAGGING |  IFCAP_VLAN_HWTSO | IFCAP_VLAN_HWCSUM | \
	 IFCAP_JUMBO_MTU | IFCAP_VLAN_MTU | IFCAP_HWSTATS)

static int
ixgbe_interface_setup(if_ctx_t ctx)
{
	struct ifnet   *ifp = iflib_get_ifp(ctx);
	struct adapter *adapter = iflib_get_softc(ctx);
	uint64_t cap;

	INIT_DEBUGOUT("ixgbe_interface_setup: begin");

	cap = IXGBE_IFCAPABILITIES;

	if_setifheaderlen(ifp, sizeof(struct ether_vlan_header));
	if_setcapabilitiesbit(ifp, cap, 0);
	if_setcapenable(ifp, if_getcapabilities(ifp));
	if_setbaudrate(ifp, 1000000000);

	adapter->max_frame_size =
	    ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;

	/*
	** Don't turn this on by default, if vlans are
	** created on another pseudo device (eg. lagg)
	** then vlan events are not passed thru, breaking
	** operation, but with HW FILTER off it works. If
	** using vlans directly on the ixgbe driver you can
	** enable this and get full hardware tag filtering.
	*/
	ifp->if_capabilities |= IFCAP_VLAN_HWFILTER;
	adapter->phy_layer = ixgbe_get_supported_physical_layer(&adapter->hw);

	ixgbe_add_media_types(ctx);

	/* Autoselect media by default */
	ifmedia_set(adapter->media, IFM_ETHER | IFM_AUTO);

	return (0);
}

static uint64_t
ixgbe_if_get_counter(if_ctx_t ctx, ift_counter cnt)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_t ifp = iflib_get_ifp(ctx);

	switch (cnt) {
	case IFCOUNTER_IPACKETS:
		return (adapter->ipackets);
	case IFCOUNTER_OPACKETS:
		return (adapter->opackets);
	case IFCOUNTER_IBYTES:
		return (adapter->ibytes);
	case IFCOUNTER_OBYTES:
		return (adapter->obytes);
	case IFCOUNTER_IMCASTS:
		return (adapter->imcasts);
	case IFCOUNTER_OMCASTS:
		return (adapter->omcasts);
	case IFCOUNTER_COLLISIONS:
		return (0);
	case IFCOUNTER_IQDROPS:
		return (adapter->iqdrops);
	case IFCOUNTER_OQDROPS:
		return (0);
	case IFCOUNTER_IERRORS:
		return (adapter->ierrors);
	default:
		return (if_get_counter_default(ifp, cnt));
	}
}

static void
ixgbe_add_media_types(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	device_t dev = iflib_get_dev(ctx);
	int layer;

	layer = adapter->phy_layer = ixgbe_get_supported_physical_layer(hw);

	/* Media types with matching FreeBSD media defines */
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_T)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_T, 0, NULL);
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_T)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_T, 0, NULL);
	if (layer & IXGBE_PHYSICAL_LAYER_100BASE_TX)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_100_TX, 0, NULL);
	
	if (layer & IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU ||
	    layer & IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_TWINAX, 0, NULL);

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_LR)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_LR, 0, NULL);
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_SR) {
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_SR, 0, NULL);
		if (hw->phy.multispeed_fiber)
			ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_SX, 0, NULL);
	} else if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_SX)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_SX, 0, NULL);
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_CX4)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_CX4, 0, NULL);
#ifdef IFM_ETH_XTYPE
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KR)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_KR, 0, NULL);
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KX4)
		ifmedia_add( adapter->media, IFM_ETHER | IFM_10G_KX4, 0, NULL);
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_KX)
		ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_KX, 0, NULL);
#else
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KR) {
		device_printf(dev, "Media supported: 10GbaseKR\n");
		device_printf(dev, "10GbaseKR mapped to 10GbaseSR\n");
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_SR, 0, NULL);
	}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KX4) {
		device_printf(dev, "Media supported: 10GbaseKX4\n");
		device_printf(dev, "10GbaseKX4 mapped to 10GbaseCX4\n");
		ifmedia_add(adapter->media, IFM_ETHER | IFM_10G_CX4, 0, NULL);
	}
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_KX) {
		device_printf(dev, "Media supported: 1000baseKX\n");
		device_printf(dev, "1000baseKX mapped to 1000baseCX\n");
		ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_CX, 0, NULL);
	}
#endif
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_BX) {
		/* Someday, someone will care about you... */
		device_printf(dev, "Media supported: 1000baseBX\n");
	}
	
	if (hw->device_id == IXGBE_DEV_ID_82598AT) {
		ifmedia_add(adapter->media,
					IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
		ifmedia_add(adapter->media,
					IFM_ETHER | IFM_1000_T, 0, NULL);
	}

	ifmedia_add(adapter->media, IFM_ETHER | IFM_AUTO, 0, NULL);
}

static void
ixgbe_config_link(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32	autoneg, err = 0;
	bool	sfp, negotiate;

	sfp = ixgbe_is_sfp(hw);

	if (sfp) { 
		GROUPTASK_ENQUEUE(&adapter->mod_task);
	} else {
		if (hw->mac.ops.check_link)
			err = ixgbe_check_link(hw, &adapter->link_speed,
								   &adapter->link_up, FALSE);
		if (err)
			return;
		autoneg = hw->phy.autoneg_advertised;
		if ((!autoneg) && (hw->mac.ops.get_link_capabilities))
			err  = hw->mac.ops.get_link_capabilities(hw,
				 &autoneg, &negotiate);
		if (err)
			return;
		if (hw->mac.ops.setup_link)
			err = hw->mac.ops.setup_link(hw,
										 autoneg, adapter->link_up);
	}

}

 
/**********************************************************************
 *
 *  Update the board statistics counters.
 *
 **********************************************************************/
static void
ixgbe_update_stats_counters(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 missed_rx = 0, bprc, lxon, lxoff, total;
	u64 total_missed_rx = 0;

	adapter->stats.pf.crcerrs += IXGBE_READ_REG(hw, IXGBE_CRCERRS);
	adapter->stats.pf.illerrc += IXGBE_READ_REG(hw, IXGBE_ILLERRC);
	adapter->stats.pf.errbc += IXGBE_READ_REG(hw, IXGBE_ERRBC);
	adapter->stats.pf.mspdc += IXGBE_READ_REG(hw, IXGBE_MSPDC);

	for (int i = 0; i < 16; i++) {
		adapter->stats.pf.qprc[i] += IXGBE_READ_REG(hw, IXGBE_QPRC(i));
		adapter->stats.pf.qptc[i] += IXGBE_READ_REG(hw, IXGBE_QPTC(i));
		adapter->stats.pf.qprdc[i] += IXGBE_READ_REG(hw, IXGBE_QPRDC(i));
	}
	adapter->stats.pf.mlfc += IXGBE_READ_REG(hw, IXGBE_MLFC);
	adapter->stats.pf.mrfc += IXGBE_READ_REG(hw, IXGBE_MRFC);
	adapter->stats.pf.rlec += IXGBE_READ_REG(hw, IXGBE_RLEC);

	/* Hardware workaround, gprc counts missed packets */
	adapter->stats.pf.gprc += IXGBE_READ_REG(hw, IXGBE_GPRC);
	adapter->stats.pf.gprc -= missed_rx;

	if (hw->mac.type != ixgbe_mac_82598EB) {
		adapter->stats.pf.gorc += IXGBE_READ_REG(hw, IXGBE_GORCL) +
		    ((u64)IXGBE_READ_REG(hw, IXGBE_GORCH) << 32);
		adapter->stats.pf.gotc += IXGBE_READ_REG(hw, IXGBE_GOTCL) +
		    ((u64)IXGBE_READ_REG(hw, IXGBE_GOTCH) << 32);
		adapter->stats.pf.tor += IXGBE_READ_REG(hw, IXGBE_TORL) +
		    ((u64)IXGBE_READ_REG(hw, IXGBE_TORH) << 32);
		adapter->stats.pf.lxonrxc += IXGBE_READ_REG(hw, IXGBE_LXONRXCNT);
		adapter->stats.pf.lxoffrxc += IXGBE_READ_REG(hw, IXGBE_LXOFFRXCNT);
	} else {
		adapter->stats.pf.lxonrxc += IXGBE_READ_REG(hw, IXGBE_LXONRXC);
		adapter->stats.pf.lxoffrxc += IXGBE_READ_REG(hw, IXGBE_LXOFFRXC);
		/* 82598 only has a counter in the high register */
		adapter->stats.pf.gorc += IXGBE_READ_REG(hw, IXGBE_GORCH);
		adapter->stats.pf.gotc += IXGBE_READ_REG(hw, IXGBE_GOTCH);
		adapter->stats.pf.tor += IXGBE_READ_REG(hw, IXGBE_TORH);
	}

	/*
	 * Workaround: mprc hardware is incorrectly counting
	 * broadcasts, so for now we subtract those.
	 */
	bprc = IXGBE_READ_REG(hw, IXGBE_BPRC);
	adapter->stats.pf.bprc += bprc;
	adapter->stats.pf.mprc += IXGBE_READ_REG(hw, IXGBE_MPRC);
	if (hw->mac.type == ixgbe_mac_82598EB)
		adapter->stats.pf.mprc -= bprc;

	adapter->stats.pf.prc64 += IXGBE_READ_REG(hw, IXGBE_PRC64);
	adapter->stats.pf.prc127 += IXGBE_READ_REG(hw, IXGBE_PRC127);
	adapter->stats.pf.prc255 += IXGBE_READ_REG(hw, IXGBE_PRC255);
	adapter->stats.pf.prc511 += IXGBE_READ_REG(hw, IXGBE_PRC511);
	adapter->stats.pf.prc1023 += IXGBE_READ_REG(hw, IXGBE_PRC1023);
	adapter->stats.pf.prc1522 += IXGBE_READ_REG(hw, IXGBE_PRC1522);

	lxon = IXGBE_READ_REG(hw, IXGBE_LXONTXC);
	adapter->stats.pf.lxontxc += lxon;
	lxoff = IXGBE_READ_REG(hw, IXGBE_LXOFFTXC);
	adapter->stats.pf.lxofftxc += lxoff;
	total = lxon + lxoff;

	adapter->stats.pf.gptc += IXGBE_READ_REG(hw, IXGBE_GPTC);
	adapter->stats.pf.mptc += IXGBE_READ_REG(hw, IXGBE_MPTC);
	adapter->stats.pf.ptc64 += IXGBE_READ_REG(hw, IXGBE_PTC64);
	adapter->stats.pf.gptc -= total;
	adapter->stats.pf.mptc -= total;
	adapter->stats.pf.ptc64 -= total;
	adapter->stats.pf.gotc -= total * ETHER_MIN_LEN;

	adapter->stats.pf.ruc += IXGBE_READ_REG(hw, IXGBE_RUC);
	adapter->stats.pf.rfc += IXGBE_READ_REG(hw, IXGBE_RFC);
	adapter->stats.pf.roc += IXGBE_READ_REG(hw, IXGBE_ROC);
	adapter->stats.pf.rjc += IXGBE_READ_REG(hw, IXGBE_RJC);
	adapter->stats.pf.mngprc += IXGBE_READ_REG(hw, IXGBE_MNGPRC);
	adapter->stats.pf.mngpdc += IXGBE_READ_REG(hw, IXGBE_MNGPDC);
	adapter->stats.pf.mngptc += IXGBE_READ_REG(hw, IXGBE_MNGPTC);
	adapter->stats.pf.tpr += IXGBE_READ_REG(hw, IXGBE_TPR);
	adapter->stats.pf.tpt += IXGBE_READ_REG(hw, IXGBE_TPT);
	adapter->stats.pf.ptc127 += IXGBE_READ_REG(hw, IXGBE_PTC127);
	adapter->stats.pf.ptc255 += IXGBE_READ_REG(hw, IXGBE_PTC255);
	adapter->stats.pf.ptc511 += IXGBE_READ_REG(hw, IXGBE_PTC511);
	adapter->stats.pf.ptc1023 += IXGBE_READ_REG(hw, IXGBE_PTC1023);
	adapter->stats.pf.ptc1522 += IXGBE_READ_REG(hw, IXGBE_PTC1522);
	adapter->stats.pf.bptc += IXGBE_READ_REG(hw, IXGBE_BPTC);
	adapter->stats.pf.xec += IXGBE_READ_REG(hw, IXGBE_XEC);
	adapter->stats.pf.fccrc += IXGBE_READ_REG(hw, IXGBE_FCCRC);
	adapter->stats.pf.fclast += IXGBE_READ_REG(hw, IXGBE_FCLAST);
	/* Only read FCOE on 82599 */
	if (hw->mac.type != ixgbe_mac_82598EB) {
		adapter->stats.pf.fcoerpdc += IXGBE_READ_REG(hw, IXGBE_FCOERPDC);
		adapter->stats.pf.fcoeprc += IXGBE_READ_REG(hw, IXGBE_FCOEPRC);
		adapter->stats.pf.fcoeptc += IXGBE_READ_REG(hw, IXGBE_FCOEPTC);
		adapter->stats.pf.fcoedwrc += IXGBE_READ_REG(hw, IXGBE_FCOEDWRC);
		adapter->stats.pf.fcoedwtc += IXGBE_READ_REG(hw, IXGBE_FCOEDWTC);
	}

	/* Fill out the OS statistics structure */
	IXGBE_SET_IPACKETS(adapter, adapter->stats.pf.gprc);
	IXGBE_SET_OPACKETS(adapter, adapter->stats.pf.gptc);
	IXGBE_SET_IBYTES(adapter, adapter->stats.pf.gorc);
	IXGBE_SET_OBYTES(adapter, adapter->stats.pf.gotc);
	IXGBE_SET_IMCASTS(adapter, adapter->stats.pf.mprc);
	IXGBE_SET_OMCASTS(adapter, adapter->stats.pf.mptc);
	IXGBE_SET_COLLISIONS(adapter, 0);
	IXGBE_SET_IQDROPS(adapter, total_missed_rx);
	IXGBE_SET_IERRORS(adapter, adapter->stats.pf.crcerrs
					  + adapter->stats.pf.rlec);
}

/*
 * Add sysctl variables, one per statistic, to the system.
 */
static void
ixgbe_add_hw_stats(struct adapter *adapter)
{
        device_t dev = iflib_get_dev(adapter->ctx);
        struct ix_rx_queue *rx_que;
        struct ix_tx_queue *tx_que;
	int i;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(dev);
	struct sysctl_oid_list *child = SYSCTL_CHILDREN(tree);
	struct ixgbe_hw_stats *stats = &adapter->stats.pf;

	struct sysctl_oid *stat_node, *queue_node;
	struct sysctl_oid_list *stat_list, *queue_list;

#define QUEUE_NAME_LEN 32
	char namebuf[QUEUE_NAME_LEN];

	/* Driver Statistics */
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "watchdog_events",
			CTLFLAG_RD, &adapter->watchdog_events,
			"Watchdog timeouts");
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "link_irq",
			CTLFLAG_RD, &adapter->link_irq,
			"Link MSIX IRQ Handled");

	for (i = 0, tx_que = adapter->tx_queues; i < adapter->num_tx_queues; i++, tx_que++) {
	        struct tx_ring *txr = &tx_que->txr;
		snprintf(namebuf, QUEUE_NAME_LEN, "queue%d", i);
		queue_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, namebuf,
					    CTLFLAG_RD, NULL, "Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "txd_head", 
				CTLTYPE_UINT | CTLFLAG_RD, txr, sizeof(txr),
				ixgbe_sysctl_tdh_handler, "IU",
				"Transmit Descriptor Head");
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "txd_tail", 
				CTLTYPE_UINT | CTLFLAG_RD, txr, sizeof(txr),
				ixgbe_sysctl_tdt_handler, "IU",
				"Transmit Descriptor Tail");
		SYSCTL_ADD_ULONG(ctx, queue_list, OID_AUTO, "tso_tx",
				CTLFLAG_RD, &txr->tso_tx,
				"TSO");
		SYSCTL_ADD_UQUAD(ctx, queue_list, OID_AUTO, "tx_packets",
				CTLFLAG_RD,  &txr->total_packets,
				"Queue Packets Transmitted");
	}

	for (i = 0, rx_que = adapter->rx_queues; i < adapter->num_rx_queues; i++, rx_que++) {
	        struct rx_ring *rxr = &rx_que->rxr;
		snprintf(namebuf, QUEUE_NAME_LEN, "queue%d", i);
		queue_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, namebuf, 
					    CTLFLAG_RD, NULL, "Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);

		snprintf(namebuf, QUEUE_NAME_LEN, "queue%d", i);
		queue_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, namebuf, 
					    CTLFLAG_RD, NULL, "Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);

		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "interrupt_rate",
				CTLTYPE_UINT | CTLFLAG_RW, &adapter->rx_queues[i],
				sizeof(&adapter->rx_queues[i]),
				ixgbe_sysctl_interrupt_rate_handler, "IU",
				"Interrupt Rate");
		SYSCTL_ADD_UQUAD(ctx, queue_list, OID_AUTO, "irqs",
				CTLFLAG_RD, &(adapter->rx_queues[i].irqs),
				"irqs on this queue");
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "rxd_head", 
				CTLTYPE_UINT | CTLFLAG_RD, rxr, sizeof(rxr),
				ixgbe_sysctl_rdh_handler, "IU",
				"Receive Descriptor Head");
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "rxd_tail", 
				CTLTYPE_UINT | CTLFLAG_RD, rxr, sizeof(rxr),
				ixgbe_sysctl_rdt_handler, "IU",
				"Receive Descriptor Tail");
		SYSCTL_ADD_UQUAD(ctx, queue_list, OID_AUTO, "rx_packets",
				CTLFLAG_RD, &rxr->rx_packets,
				"Queue Packets Received");
		SYSCTL_ADD_UQUAD(ctx, queue_list, OID_AUTO, "rx_bytes",
				CTLFLAG_RD, &rxr->rx_bytes,
				"Queue Bytes Received");
		SYSCTL_ADD_UQUAD(ctx, queue_list, OID_AUTO, "rx_copies",
				CTLFLAG_RD, &rxr->rx_copies,
				"Copied RX Frames");
	}

	/* MAC stats get the own sub node */

	stat_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "mac_stats", 
				    CTLFLAG_RD, NULL, "MAC Statistics");
	stat_list = SYSCTL_CHILDREN(stat_node);

	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "crc_errs",
			CTLFLAG_RD, &stats->crcerrs,
			"CRC Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "ill_errs",
			CTLFLAG_RD, &stats->illerrc,
			"Illegal Byte Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "byte_errs",
			CTLFLAG_RD, &stats->errbc,
			"Byte Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "short_discards",
			CTLFLAG_RD, &stats->mspdc,
			"MAC Short Packets Discarded");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "local_faults",
			CTLFLAG_RD, &stats->mlfc,
			"MAC Local Faults");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "remote_faults",
			CTLFLAG_RD, &stats->mrfc,
			"MAC Remote Faults");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rec_len_errs",
			CTLFLAG_RD, &stats->rlec,
			"Receive Length Errors");

	/* Flow Control stats */
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xon_txd",
			CTLFLAG_RD, &stats->lxontxc,
			"Link XON Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xon_recvd",
			CTLFLAG_RD, &stats->lxonrxc,
			"Link XON Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xoff_txd",
			CTLFLAG_RD, &stats->lxofftxc,
			"Link XOFF Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xoff_recvd",
			CTLFLAG_RD, &stats->lxoffrxc,
			"Link XOFF Received");

	/* Packet Reception Stats */
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "total_octets_rcvd",
			CTLFLAG_RD, &stats->tor,
			"Total Octets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_octets_rcvd",
			CTLFLAG_RD, &stats->gorc,
			"Good Octets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "total_pkts_rcvd",
			CTLFLAG_RD, &stats->tpr,
			"Total Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_pkts_rcvd",
			CTLFLAG_RD, &stats->gprc,
			"Good Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "mcast_pkts_rcvd",
			CTLFLAG_RD, &stats->mprc,
			"Multicast Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "bcast_pkts_rcvd",
			CTLFLAG_RD, &stats->bprc,
			"Broadcast Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_64",
			CTLFLAG_RD, &stats->prc64,
			"64 byte frames received ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_65_127",
			CTLFLAG_RD, &stats->prc127,
			"65-127 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_128_255",
			CTLFLAG_RD, &stats->prc255,
			"128-255 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_256_511",
			CTLFLAG_RD, &stats->prc511,
			"256-511 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_512_1023",
			CTLFLAG_RD, &stats->prc1023,
			"512-1023 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_1024_1522",
			CTLFLAG_RD, &stats->prc1522,
			"1023-1522 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_undersized",
			CTLFLAG_RD, &stats->ruc,
			"Receive Undersized");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_fragmented",
			CTLFLAG_RD, &stats->rfc,
			"Fragmented Packets Received ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_oversized",
			CTLFLAG_RD, &stats->roc,
			"Oversized Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_jabberd",
			CTLFLAG_RD, &stats->rjc,
			"Received Jabber");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "management_pkts_rcvd",
			CTLFLAG_RD, &stats->mngprc,
			"Management Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "management_pkts_drpd",
			CTLFLAG_RD, &stats->mngptc,
			"Management Packets Dropped");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "checksum_errs",
			CTLFLAG_RD, &stats->xec,
			"Checksum Errors");

	/* Packet Transmission Stats */
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_octets_txd",
			CTLFLAG_RD, &stats->gotc, 
			"Good Octets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "total_pkts_txd",
			CTLFLAG_RD, &stats->tpt,
			"Total Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_pkts_txd",
			CTLFLAG_RD, &stats->gptc,
			"Good Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "bcast_pkts_txd",
			CTLFLAG_RD, &stats->bptc,
			"Broadcast Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "mcast_pkts_txd",
			CTLFLAG_RD, &stats->mptc,
			"Multicast Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "management_pkts_txd",
			CTLFLAG_RD, &stats->mngptc,
			"Management Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_64",
			CTLFLAG_RD, &stats->ptc64,
			"64 byte frames transmitted ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_65_127",
			CTLFLAG_RD, &stats->ptc127,
			"65-127 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_128_255",
			CTLFLAG_RD, &stats->ptc255,
			"128-255 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_256_511",
			CTLFLAG_RD, &stats->ptc511,
			"256-511 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_512_1023",
			CTLFLAG_RD, &stats->ptc1023,
			"512-1023 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_1024_1522",
			CTLFLAG_RD, &stats->ptc1522,
			"1024-1522 byte frames transmitted");
}

/** ixgbe_sysctl_tdh_handler - Handler function
 *  Retrieves the TDH value from the hardware
 */
static int 
ixgbe_sysctl_tdh_handler(SYSCTL_HANDLER_ARGS)
{
	int error;

	struct tx_ring *txr = ((struct tx_ring *)oidp->oid_arg1);
	if (!txr) return 0;

	unsigned val = IXGBE_READ_REG(&txr->adapter->hw, IXGBE_TDH(txr->me));
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return error;
	return 0;
}

/** ixgbe_sysctl_tdt_handler - Handler function
 *  Retrieves the TDT value from the hardware
 */
static int 
ixgbe_sysctl_tdt_handler(SYSCTL_HANDLER_ARGS)
{
	int error;

	struct tx_ring *txr = ((struct tx_ring *)oidp->oid_arg1);
	if (!txr) return 0;

	unsigned val = IXGBE_READ_REG(&txr->adapter->hw, IXGBE_TDT(txr->me));
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return error;
	return 0;
}

/** ixgbe_sysctl_rdh_handler - Handler function
 *  Retrieves the RDH value from the hardware
 */
static int
ixgbe_sysctl_rdh_handler(SYSCTL_HANDLER_ARGS)
{
	int error;

	struct rx_ring *rxr = ((struct rx_ring *)oidp->oid_arg1);
	if (!rxr) return 0;

	unsigned val = IXGBE_READ_REG(&rxr->adapter->hw, IXGBE_RDH(rxr->me));
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return error;
	return 0;
}

/** ixgbe_sysctl_rdt_handler - Handler function
 *  Retrieves the RDT value from the hardware
 */
static int 
ixgbe_sysctl_rdt_handler(SYSCTL_HANDLER_ARGS)
{
	int error;

	struct rx_ring *rxr = ((struct rx_ring *)oidp->oid_arg1);
	if (!rxr) return 0;

	unsigned val = IXGBE_READ_REG(&rxr->adapter->hw, IXGBE_RDT(rxr->me));
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return error;
	return 0;
}

/*
** This routine is run via an vlan config EVENT,
** it enables us to use the HW Filter table since
** we can get the vlan id. This just creates the
** entry in the soft version of the VFTA, init will
** repopulate the real table.
*/
static void
ixgbe_if_vlan_register(if_ctx_t ctx, u16 vtag)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	u16            index, bit;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	adapter->shadow_vfta[index] |= (1 << bit);
	++adapter->num_vlans;
	ixgbe_setup_vlan_hw_support(ctx);
}

/*
** This routine is run via an vlan
** unconfig EVENT, remove our entry
** in the soft vfta.
*/
static void
ixgbe_if_vlan_unregister(if_ctx_t ctx, u16 vtag)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	u16		index, bit;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	adapter->shadow_vfta[index] &= ~(1 << bit);
	--adapter->num_vlans;
	/* Re-init to load the changes */
	ixgbe_setup_vlan_hw_support(ctx);
}

static void
ixgbe_setup_vlan_hw_support(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
        struct ifnet 	*ifp = iflib_get_ifp(ctx);
	struct rx_ring	*rxr;
	u32		ctrl;

	/* We get here thru init_locked, meaning
	** a soft reset, this has already cleared
	** the VFTA and other state, so if there
	** have been no vlan's registered do nothing.
	*/
	if (adapter->num_vlans == 0)
		return;

	/* Setup the queues for vlans */
	for (int i = 0; i < adapter->num_rx_queues; i++) {
		rxr = &adapter->rx_queues[i].rxr;
		/* On 82599 the VLAN enable is per/queue in RXDCTL */
		if (hw->mac.type != ixgbe_mac_82598EB) {
			ctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxr->me));
			ctrl |= IXGBE_RXDCTL_VME;
			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rxr->me), ctrl);
		}
		rxr->vtag_strip = TRUE;
	}

	if ((ifp->if_capenable & IFCAP_VLAN_HWFILTER) == 0)
		return;

	/* A soft reset zero's out the VFTA, so
	** we need to repopulate it now.
	*/
	for (int i = 0; i < IXGBE_VFTA_SIZE; i++)
		if (adapter->shadow_vfta[i] != 0)
			IXGBE_WRITE_REG(hw, IXGBE_VFTA(i),
							adapter->shadow_vfta[i]);

	ctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	/* Enable the Filter Table if enabled */
	if (ifp->if_capenable & IFCAP_VLAN_HWFILTER) {
		ctrl &= ~IXGBE_VLNCTRL_CFIEN;
		ctrl |= IXGBE_VLNCTRL_VFE;
	}
	if (hw->mac.type == ixgbe_mac_82598EB)
		ctrl |= IXGBE_VLNCTRL_VME;
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, ctrl);
} 
 
/*
** Get the width and transaction speed of
** the slot this adapter is plugged into.
*/
static void
ixgbe_get_slot_info(struct adapter *adapter)
{
	device_t		dev = iflib_get_dev(adapter->ctx);
	struct ixgbe_hw		*hw = &adapter->hw;
	struct ixgbe_mac_info	*mac = &hw->mac;
	u16			link;
	u32			offset;

	MPASS(hw->back != NULL);
	/* For most devices simply call the shared code routine */
	if (hw->device_id != IXGBE_DEV_ID_82599_SFP_SF_QP) {
		ixgbe_get_bus_info(hw);
		/* These devices don't use PCI-E */
		switch (hw->mac.type) {
		case ixgbe_mac_X550EM_x:
			return;
		default:
			goto display;
		}
	}
	/*
	** For the Quad port adapter we need to parse back
	** up the PCI tree to find the speed of the expansion
	** slot into which this adapter is plugged. A bit more work.
	*/
	dev = device_get_parent(device_get_parent(dev));
#ifdef IXGBE_DEBUG
	device_printf(dev, "parent pcib = %x,%x,%x\n",
				  pci_get_bus(dev), pci_get_slot(dev), pci_get_function(dev));
#endif
	dev = device_get_parent(device_get_parent(dev));
#ifdef IXGBE_DEBUG
	device_printf(dev, "slot pcib = %x,%x,%x\n",
				  pci_get_bus(dev), pci_get_slot(dev), pci_get_function(dev));
#endif
	/* Now get the PCI Express Capabilities offset */
	pci_find_cap(dev, PCIY_EXPRESS, &offset);
	/* ...and read the Link Status Register */
	link = pci_read_config(dev, offset + PCIER_LINK_STA, 2);
	switch (link & IXGBE_PCI_LINK_WIDTH) {
	case IXGBE_PCI_LINK_WIDTH_1:
		hw->bus.width = ixgbe_bus_width_pcie_x1;
		break;
	case IXGBE_PCI_LINK_WIDTH_2:
		hw->bus.width = ixgbe_bus_width_pcie_x2;
		break;
	case IXGBE_PCI_LINK_WIDTH_4:
		hw->bus.width = ixgbe_bus_width_pcie_x4;
		break;
	case IXGBE_PCI_LINK_WIDTH_8:
		hw->bus.width = ixgbe_bus_width_pcie_x8;
		break;
	default:
		hw->bus.width = ixgbe_bus_width_unknown;
		break;
	}
	switch (link & IXGBE_PCI_LINK_SPEED) {
	case IXGBE_PCI_LINK_SPEED_2500:
		hw->bus.speed = ixgbe_bus_speed_2500;
		break;
	case IXGBE_PCI_LINK_SPEED_5000:
		hw->bus.speed = ixgbe_bus_speed_5000;
		break;
	case IXGBE_PCI_LINK_SPEED_8000:
		hw->bus.speed = ixgbe_bus_speed_8000;
		break;
	default:
		hw->bus.speed = ixgbe_bus_speed_unknown;
		break;
	}

	mac->ops.set_lan_id(hw);

display:
	device_printf(dev,"PCI Express Bus: Speed %s %s\n",
				  ((hw->bus.speed == ixgbe_bus_speed_8000) ? "8.0GT/s":
				   (hw->bus.speed == ixgbe_bus_speed_5000) ? "5.0GT/s":
				   (hw->bus.speed == ixgbe_bus_speed_2500) ? "2.5GT/s":"Unknown"),
				  (hw->bus.width == ixgbe_bus_width_pcie_x8) ? "Width x8" :
				  (hw->bus.width == ixgbe_bus_width_pcie_x4) ? "Width x4" :
				  (hw->bus.width == ixgbe_bus_width_pcie_x1) ? "Width x1" :
				  ("Unknown"));

	if ((hw->device_id != IXGBE_DEV_ID_82599_SFP_SF_QP) &&
	    ((hw->bus.width <= ixgbe_bus_width_pcie_x4) &&
		 (hw->bus.speed == ixgbe_bus_speed_2500))) {
		device_printf(dev, "PCI-Express bandwidth available"
					  " for this card\n     is not sufficient for"
					  " optimal performance.\n");
		device_printf(dev, "For optimal performance a x8 "
					  "PCIE, or x4 PCIE Gen2 slot is required.\n");
	}
	if ((hw->device_id == IXGBE_DEV_ID_82599_SFP_SF_QP) &&
	    ((hw->bus.width <= ixgbe_bus_width_pcie_x8) &&
		 (hw->bus.speed < ixgbe_bus_speed_8000))) {
		device_printf(dev, "PCI-Express bandwidth available"
					  " for this card\n     is not sufficient for"
					  " optimal performance.\n");
		device_printf(dev, "For optimal performance a x8 "
					  "PCIE Gen3 slot is required.\n");
	}

	return;
}
 
/*********************************************************************
 *
 *  Setup MSIX Interrupt resources and handlers 
 *
 **********************************************************************/
static int
ixgbe_if_msix_intr_assign(if_ctx_t ctx, int msix)
{
	struct          adapter *adapter = iflib_get_softc(ctx);
	struct 		ix_rx_queue *rx_que = adapter->rx_queues;
	struct		ix_tx_queue *tx_que;
	int 		error, rid, vector = 0;
	int		cpu_id = 0;
	char buf[16];

	/* Admin Que is vector 0*/
	rid = vector + 1;
	for (int i = 0; i < adapter->num_rx_queues; i++, vector++, rx_que++) {
		rid = vector + 1;

		snprintf(buf, sizeof(buf), "rxq%d", i);
		error = iflib_irq_alloc_generic(ctx, &rx_que->que_irq, rid, IFLIB_INTR_RXTX,
										ixgbe_msix_que, rx_que, rx_que->rxr.me, buf);

		if (error) {
			device_printf(iflib_get_dev(ctx), "Failed to allocate que int %d err: %d", i, error);
			adapter->num_rx_queues = i + 1;
			goto fail;
		}

		rx_que->msix = vector;
		adapter->active_queues |= (u64)(1 << rx_que->msix);
#ifdef	RSS
		/*
		 * The queue ID is used as the RSS layer bucket ID.
		 * We look up the queue ID -> RSS CPU ID and select
		 * that.
		 */
		cpu_id = rss_getcpu(i % rss_getnumbuckets());
#else
		/*
		 * Bind the msix vector, and thus the
		 * rings to the corresponding cpu.
		 *
		 * This just happens to match the default RSS round-robin
		 * bucket -> queue -> CPU allocation.
		 */
		if (adapter->num_rx_queues > 1)
			cpu_id = i;
#endif

	}
	for (int i = 0, rid = 1; i < adapter->num_tx_queues; i++, rid++) {
		snprintf(buf, sizeof(buf), "txq%d", i);
		tx_que = &adapter->tx_queues[i];
		tx_que->msix = adapter->rx_queues[i % adapter->num_rx_queues].msix;
		rid = rman_get_start(adapter->rx_queues[i % adapter->num_rx_queues].que_irq.ii_res);
		iflib_softirq_alloc_generic(ctx, rid, IFLIB_INTR_TX, tx_que, tx_que->txr.me, buf);
	}
	rid = vector + 1;
	error = iflib_irq_alloc_generic(ctx, &adapter->irq, rid, IFLIB_INTR_ADMIN,
									ixgbe_msix_link, adapter, 0, "aq");
	if (error) {
		device_printf(iflib_get_dev(ctx), "Failed to register admin handler");
		return (error);
	}


	adapter->vector = vector;
	return (0);
fail:
	iflib_irq_free(ctx, &adapter->irq);
	rx_que = adapter->rx_queues;
	for (int i = 0; i < adapter->num_rx_queues; i++, rx_que++)
		iflib_irq_free(ctx, &rx_que->que_irq);
	return (error);
}

/*********************************************************************
 *
 *  MSIX Queue Interrupt Service routine
 *
 **********************************************************************/
static int
ixgbe_msix_que(void *arg)
{
	struct ix_rx_queue	*que = arg;
	struct adapter  *adapter = que->adapter;
	struct tx_ring	*txr;
	struct rx_ring	*rxr = &que->rxr;
	struct ifnet   *ifp = iflib_get_ifp(que->adapter->ctx);
	u32             newitr = 0;

	/* Protect against spurious interrupts */
	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
		return 0;

	ixgbe_disable_queue(adapter, que->msix);
        ++que->irqs;
	
	if (ixgbe_enable_aim == FALSE)
		goto no_calc;

	MPASS(adapter->num_rx_queues == adapter->num_tx_queues);
	txr = &que->txq[0]->txr;
	/*
	** Do Adaptive Interrupt Moderation:
	**  - Write out last calculated setting
	**  - Calculate based on average size over
	**    the last interval.
	*/
	if (que->eitr_setting) {
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EITR(que->msix), que->eitr_setting);
	}
 
	que->eitr_setting = 0;

	/* Idle, do nothing */
	if ((txr->bytes) && (txr->packets))
		newitr = txr->bytes/txr->packets;

	if ((rxr->bytes) && (rxr->packets))
		newitr = max(newitr,
					 (rxr->bytes / rxr->packets));
	newitr += 24; /* account for hardware frame, crc */

	/* set an upper boundary */
	newitr = min(newitr, 3000);

	/* Be nice to the mid range */
	if ((newitr > 300) && (newitr < 1200))
		newitr = (newitr / 3);
	else
		newitr = (newitr / 2);

	if (adapter->hw.mac.type == ixgbe_mac_82598EB)
		newitr |= newitr << 16;
	else
		newitr |= IXGBE_EITR_CNT_WDIS;
                 
	/* save for next interrupt */
	que->eitr_setting = newitr;

	/* Reset state */
	txr->bytes = 0;
	txr->packets = 0;
	rxr->bytes = 0;
	rxr->packets = 0;

no_calc:
	return (FILTER_SCHEDULE_THREAD);
}

/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called whenever the user queries the status of
 *  the interface using ifconfig.
 *
 **********************************************************************/
static void
ixgbe_if_media_status(if_ctx_t ctx, struct ifmediareq * ifmr)
{ 
	struct adapter *adapter = iflib_get_softc(ctx);
  	struct ixgbe_hw *hw = &adapter->hw;
	int layer;

	INIT_DEBUGOUT("ixgbe_if_media_status: begin");
	ixgbe_if_update_admin_status(ctx);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!adapter->link_active) {
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;
	layer = adapter->phy_layer;

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_T ||
	    layer & IXGBE_PHYSICAL_LAYER_1000BASE_T ||
	    layer & IXGBE_PHYSICAL_LAYER_100BASE_TX)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_100_FULL:
			ifmr->ifm_active |= IFM_100_TX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU ||
	    layer & IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_TWINAX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_LR)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_LR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_LX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_LRM)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_LRM | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_LX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_SR ||
	    layer & IXGBE_PHYSICAL_LAYER_1000BASE_SX)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_SR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_SX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_CX4)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_CX4 | IFM_FDX;
			break;
		}
	/*
	** XXX: These need to use the proper media types once
	** they're added.
	*/
#ifndef IFM_ETH_XTYPE
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KR)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_SR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_SX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_CX | IFM_FDX;
			break;
		}
	else if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KX4
			 || layer & IXGBE_PHYSICAL_LAYER_1000BASE_KX)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_CX4 | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_SX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_CX | IFM_FDX;
			break;
		}
#else
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KR)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_KR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_KX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_KX | IFM_FDX;
			break;
		}
	else if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KX4
	    || layer & IXGBE_PHYSICAL_LAYER_1000BASE_KX)
		switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_KX4 | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_KX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_KX | IFM_FDX;
			break;
		}
#endif
	/* If nothing is recognized... */
	if (IFM_SUBTYPE(ifmr->ifm_active) == 0)
		ifmr->ifm_active |= IFM_UNKNOWN;

	/* Display current flow control setting used on link */
	if (hw->fc.current_mode == ixgbe_fc_rx_pause ||
	    hw->fc.current_mode == ixgbe_fc_full)
		ifmr->ifm_active |= IFM_ETH_RXPAUSE;
	if (hw->fc.current_mode == ixgbe_fc_tx_pause ||
	    hw->fc.current_mode == ixgbe_fc_full)
		ifmr->ifm_active |= IFM_ETH_TXPAUSE;
} 

/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called when the user changes speed/duplex using
 *  media/mediopt option with ifconfig.
 *
 **********************************************************************/
static int
ixgbe_if_media_change(if_ctx_t ctx)
{
	struct adapter *adapter =  iflib_get_softc(ctx);
	struct ifmedia *ifm = iflib_get_media(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	ixgbe_link_speed speed = 0;

	INIT_DEBUGOUT("ixgbe_if_media_change: begin");

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	if (hw->phy.media_type == ixgbe_media_type_backplane)
		return (EPERM);

	/*
	** We don't actually need to check against the supported
	** media types of the adapter; ifmedia will take care of
	** that for us.
	*/
#ifndef IFM_ETH_XTYPE
	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
	case IFM_10G_T:
		speed |= IXGBE_LINK_SPEED_100_FULL;
	case IFM_10G_LRM:
	case IFM_10G_SR: /* KR, too */
	case IFM_10G_LR:
	case IFM_10G_CX4: /* KX4 */
		speed |= IXGBE_LINK_SPEED_1GB_FULL;
	case IFM_10G_TWINAX:
		speed |= IXGBE_LINK_SPEED_10GB_FULL;
		break;
	case IFM_1000_T:
		speed |= IXGBE_LINK_SPEED_100_FULL;
	case IFM_1000_LX:
	case IFM_1000_SX:
	case IFM_1000_CX: /* KX */
		speed |= IXGBE_LINK_SPEED_1GB_FULL;
		break;
	case IFM_100_TX:
		speed |= IXGBE_LINK_SPEED_100_FULL;
		break;
	default:
		goto invalid;
	}
#else
	switch (IFM_SUBTYPE(ifm->ifm_media)) {
		case IFM_AUTO:
		case IFM_10G_T:
			speed |= IXGBE_LINK_SPEED_100_FULL;
		case IFM_10G_LRM:
		case IFM_10G_KR:
		case IFM_10G_LR:
		case IFM_10G_KX4:
			speed |= IXGBE_LINK_SPEED_1GB_FULL;
		case IFM_10G_TWINAX:
			speed |= IXGBE_LINK_SPEED_10GB_FULL;
			break;
		case IFM_1000_T:
			speed |= IXGBE_LINK_SPEED_100_FULL;
		case IFM_1000_LX:
		case IFM_1000_SX:
		case IFM_1000_KX:
			speed |= IXGBE_LINK_SPEED_1GB_FULL;
			break;
		case IFM_100_TX:
			speed |= IXGBE_LINK_SPEED_100_FULL;
			break;
		default:
			goto invalid;
	}
#endif
	hw->mac.autotry_restart = TRUE;
	hw->mac.ops.setup_link(hw, speed, TRUE);
	adapter->advertise =
		((speed & IXGBE_LINK_SPEED_10GB_FULL) << 2) |
		((speed & IXGBE_LINK_SPEED_1GB_FULL) << 1) |
		((speed & IXGBE_LINK_SPEED_100_FULL) << 0);

	return (0);

invalid:
	device_printf(iflib_get_dev(ctx), "Invalid media type!\n");
	return (EINVAL);
}
 
static int
ixgbe_if_promisc_set(if_ctx_t ctx, int flags)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ifnet   *ifp = iflib_get_ifp(ctx);
	u_int32_t       reg_rctl;
	int		  mcnt = 0;

	reg_rctl = IXGBE_READ_REG(&adapter->hw, IXGBE_FCTRL);
	reg_rctl &= (~IXGBE_FCTRL_UPE);
	if (ifp->if_flags & IFF_ALLMULTI)
		mcnt = MAX_NUM_MULTICAST_ADDRESSES;
	else {
		mcnt = if_multiaddr_count(ifp, MAX_NUM_MULTICAST_ADDRESSES);
	}
	if (mcnt < MAX_NUM_MULTICAST_ADDRESSES)
		reg_rctl &= (~IXGBE_FCTRL_MPE);

	/* clear promiscuous mode and multicast filters before enabling */
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_FCTRL, reg_rctl);
  
	if (ifp->if_flags & IFF_PROMISC) {
		reg_rctl |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_FCTRL, reg_rctl);
	} else if (ifp->if_flags & IFF_ALLMULTI) {
		reg_rctl |= IXGBE_FCTRL_MPE;
		reg_rctl &= ~IXGBE_FCTRL_UPE;
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_FCTRL, reg_rctl);
	}
  
	return (0);
}

static int
ixgbe_msix_link(void *arg)
{
	struct adapter	*adapter = arg;
	struct ixgbe_hw *hw = &adapter->hw;
	u32		reg_eicr, mod_mask;

	++adapter->link_irq;

	/* First get the cause */
	reg_eicr = IXGBE_READ_REG(hw, IXGBE_EICS);

	/* Be sure the queue bits are not cleared */
	reg_eicr &= ~IXGBE_EICR_RTX_QUEUE;
	/* Clear interrupt with write */
	IXGBE_WRITE_REG(hw, IXGBE_EICR, reg_eicr);

        /* Link status change */
	if (reg_eicr & IXGBE_EICR_LSC)
	  iflib_admin_intr_deferred(adapter->ctx);
	
	if (adapter->hw.mac.type != ixgbe_mac_82598EB) {
#ifdef IXGBE_FDIR
		if (reg_eicr & IXGBE_EICR_FLOW_DIR) {
			/* This is probably overkill :) */
			if (atomic_cmpset_int(&adapter->fdir_reinit, 0, 1)) {
				/* Disable the interrupt */
				IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_EICR_FLOW_DIR);
				GROUPTASK_ENQUEUE(&adapter->fdir_task);
			}
			return (FILTER_HANDLED);
		} else
#endif
			if (reg_eicr & IXGBE_EICR_ECC) {
			  device_printf(iflib_get_dev(adapter->ctx), "\nCRITICAL: ECC ERROR!! "
							  "Please Reboot!!\n");
				IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_ECC);
			}

		/* Check for over temp condition */
		if (reg_eicr & IXGBE_EICR_TS) {
		  device_printf(iflib_get_dev(adapter->ctx), "\nCRITICAL: OVER TEMP!! "
						  "PHY IS SHUT DOWN!!\n");
		  device_printf(iflib_get_dev(adapter->ctx), "System shutdown required!\n");
			IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_TS);
		}
	}

#ifdef PCI_IOV
		if (reg_eicr & IXGBE_EICR_MAILBOX)
			GROUPTASK_ENQUEUE(&adapter->mbx_task);
#endif
	/* Pluggable optics-related interrupt */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_SFP)
		mod_mask = IXGBE_EICR_GPI_SDP0_X540;
	else
		mod_mask = IXGBE_EICR_GPI_SDP2_BY_MAC(hw);

	if (ixgbe_is_sfp(hw)) {
		if (reg_eicr & IXGBE_EICR_GPI_SDP1_BY_MAC(hw)) {
			IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP1_BY_MAC(hw));
			GROUPTASK_ENQUEUE(&adapter->msf_task);
		} else if (reg_eicr & mod_mask) {
			IXGBE_WRITE_REG(hw, IXGBE_EICR, mod_mask);
			GROUPTASK_ENQUEUE(&adapter->mod_task);
		}
	}

	/* Check for fan failure */
	if ((hw->device_id == IXGBE_DEV_ID_82598AT) &&
	    (reg_eicr & IXGBE_EICR_GPI_SDP1)) {
		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP1);
		device_printf(iflib_get_dev(adapter->ctx), "\nCRITICAL: FAN FAILURE!! "
					  "REPLACE IMMEDIATELY!!\n");
	}

	/* External PHY interrupt */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T &&
	    (reg_eicr & IXGBE_EICR_GPI_SDP0_X540)) {
		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP0_X540);
		GROUPTASK_ENQUEUE(&adapter->phy_task);
	}
 
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMS, IXGBE_EIMS_OTHER);
	return (FILTER_HANDLED);
}

static int
ixgbe_sysctl_interrupt_rate_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	struct ix_rx_queue *que = ((struct ix_rx_queue *)oidp->oid_arg1);
	unsigned int reg, usec, rate;

	reg = IXGBE_READ_REG(&que->adapter->hw, IXGBE_EITR(que->msix));
	usec = ((reg & 0x0FF8) >> 3);
	if (usec > 0)
		rate = 500000 / usec;
	else
		rate = 0;
	error = sysctl_handle_int(oidp, &rate, 0, req);
	if (error || !req->newptr)
		return error;
	reg &= ~0xfff; /* default, no limitation */
	ixgbe_max_interrupt_rate = 0;
	if (rate > 0 && rate < 500000) {
		if (rate < 1000)
			rate = 1000;
		ixgbe_max_interrupt_rate = rate;
		reg |= ((4000000/rate) & 0xff8 );
	}
	IXGBE_WRITE_REG(&que->adapter->hw, IXGBE_EITR(que->msix), reg);
	return 0;
}

static void
ixgbe_add_device_sysctls(if_ctx_t ctx)
{
        device_t dev = iflib_get_dev(ctx);
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	struct sysctl_oid_list *child;
	struct sysctl_ctx_list *ctx_list;

	ctx_list = device_get_sysctl_ctx(dev);
	child = SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	/* Sysctls for all devices */
	SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "fc",
					CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
					ixgbe_sysctl_flowcntl, "I", IXGBE_SYSCTL_DESC_SET_FC);

	SYSCTL_ADD_INT(ctx_list, child, OID_AUTO, "enable_aim",
				   CTLFLAG_RW,
				   &ixgbe_enable_aim, 1, "Interrupt Moderation");

	SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "advertise_speed",
					CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
					ixgbe_sysctl_advertise, "I", IXGBE_SYSCTL_DESC_ADV_SPEED);

	SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "thermal_test",
					CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
					ixgbe_sysctl_thermal_test, "I", "Thermal Test");

	SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "reg_dump",
			                 CTLTYPE_STRING | CTLFLAG_RD, adapter, 0,
			                 ixgbe_get_regs, "A", "Dump Registers");

#ifdef IXGBE_DEBUG
	/* testing sysctls (for all devices) */
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "power_state",
			CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
			ixgbe_sysctl_power_state, "I", "PCI Power State");

	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "print_rss_config",
			CTLTYPE_STRING | CTLFLAG_RD, adapter, 0,
			ixgbe_sysctl_print_rss_config, "A", "Prints RSS Configuration");
#endif
	/* for X550 series devices */
	if (hw->mac.type >= ixgbe_mac_X550)
		SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "dmac",
						CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
						ixgbe_sysctl_dmac, "I", "DMA Coalesce");

	/* for X552 backplane devices */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_KR) {
		struct sysctl_oid *eee_node;
		struct sysctl_oid_list *eee_list;

		eee_node = SYSCTL_ADD_NODE(ctx_list, child, OID_AUTO, "eee",
								   CTLFLAG_RD, NULL,
								   "Energy Efficient Ethernet sysctls");
		eee_list = SYSCTL_CHILDREN(eee_node);

		SYSCTL_ADD_PROC(ctx_list, eee_list, OID_AUTO, "enable",
						CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
						ixgbe_sysctl_eee_enable, "I",
						"Enable or Disable EEE");

		SYSCTL_ADD_PROC(ctx_list, eee_list, OID_AUTO, "negotiated",
						CTLTYPE_INT | CTLFLAG_RD, adapter, 0,
						ixgbe_sysctl_eee_negotiated, "I",
						"EEE negotiated on link");

		SYSCTL_ADD_PROC(ctx_list, eee_list, OID_AUTO, "tx_lpi_status",
						CTLTYPE_INT | CTLFLAG_RD, adapter, 0,
						ixgbe_sysctl_eee_tx_lpi_status, "I",
						"Whether or not TX link is in LPI state");

		SYSCTL_ADD_PROC(ctx_list, eee_list, OID_AUTO, "rx_lpi_status",
						CTLTYPE_INT | CTLFLAG_RD, adapter, 0,
						ixgbe_sysctl_eee_rx_lpi_status, "I",
						"Whether or not RX link is in LPI state");
		SYSCTL_ADD_PROC(ctx_list, eee_list, OID_AUTO, "tx_lpi_delay",
				CTLTYPE_INT | CTLFLAG_RD, adapter, 0,
				ixgbe_sysctl_eee_tx_lpi_delay, "I",
				"TX LPI entry delay in microseconds");
	}

	/* for WoL-capable devices */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T) {
		SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "wol_enable",
						CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
						ixgbe_sysctl_wol_enable, "I",
						"Enable/Disable Wake on LAN");

		SYSCTL_ADD_PROC(ctx_list, child, OID_AUTO, "wufc",
						CTLTYPE_INT | CTLFLAG_RW, adapter, 0,
						ixgbe_sysctl_wufc, "I",
						"Enable/Disable Wake Up Filters");
	}
	/* for X550EM 10GBaseT devices */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T) {
		struct sysctl_oid *phy_node;
		struct sysctl_oid_list *phy_list;

		phy_node = SYSCTL_ADD_NODE(ctx_list, child, OID_AUTO, "phy",
								   CTLFLAG_RD, NULL,
								   "External PHY sysctls");
		phy_list = SYSCTL_CHILDREN(phy_node);

		SYSCTL_ADD_PROC(ctx_list, phy_list, OID_AUTO, "temp",
						CTLTYPE_INT | CTLFLAG_RD, adapter, 0,
						ixgbe_sysctl_phy_temp, "I",
						"Current External PHY Temperature (Celsius)");

		SYSCTL_ADD_PROC(ctx_list, phy_list, OID_AUTO, "overtemp_occurred",
						CTLTYPE_INT | CTLFLAG_RD, adapter, 0,
						ixgbe_sysctl_phy_overtemp_occurred, "I",
						"External PHY High Temperature Event Occurred");
	}
}

/*********************************************************************
 *
 *  Determine hardware revision.
 *
 **********************************************************************/
static void
ixgbe_identify_hardware(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
        device_t dev = iflib_get_dev(ctx);
	struct ixgbe_hw *hw = &adapter->hw;

	/* Save off the information about this board */
	hw->vendor_id = pci_get_vendor(dev);
	hw->device_id = pci_get_device(dev);
	hw->revision_id = pci_read_config(dev, PCIR_REVID, 1);
	hw->subsystem_vendor_id =
	    pci_read_config(dev, PCIR_SUBVEND_0, 2);
	hw->subsystem_device_id =
	    pci_read_config(dev, PCIR_SUBDEV_0, 2);

	/* We need this here to set the num_segs in the code that follows */
	ixgbe_set_mac_type(hw);
}

/*********************************************************************
 *
 *  Determine optic type
 *
 **********************************************************************/
static void
ixgbe_setup_optics(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int		layer;

	layer = adapter->phy_layer = ixgbe_get_supported_physical_layer(hw);

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_T) {
		adapter->optics = IFM_10G_T;
		return;
	}

	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_T) {
		adapter->optics = IFM_1000_T;
		return;

	}

	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_SX) {
		adapter->optics = IFM_1000_SX;
		return;
	}

	if (layer & (IXGBE_PHYSICAL_LAYER_10GBASE_LR |
				 IXGBE_PHYSICAL_LAYER_10GBASE_LRM)) {
		adapter->optics = IFM_10G_LR;
		return;
	}

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_SR) {
		adapter->optics = IFM_10G_SR;
		return;
	}

	if (layer & IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU) {
		adapter->optics = IFM_10G_TWINAX;
		return;
	}

	if (layer & (IXGBE_PHYSICAL_LAYER_10GBASE_KX4 |
				 IXGBE_PHYSICAL_LAYER_10GBASE_CX4)) {
		adapter->optics = IFM_10G_CX4;
		return;
	}

	/* If we get here just set the default */
	adapter->optics = IFM_ETHER | IFM_AUTO;
}
 
static int
ixgbe_allocate_pci_resources(if_ctx_t ctx)
{
	int             rid;
	struct adapter *adapter = iflib_get_softc(ctx);
	device_t        dev = iflib_get_dev(ctx);

	rid = PCIR_BAR(0);
	adapter->pci_mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
						  &rid, RF_ACTIVE);

	if (!(adapter->pci_mem)) {
		device_printf(dev,"Unable to allocate bus resource: memory\n");
		return (ENXIO);
	}

	adapter->osdep.mem_bus_space_tag =
		rman_get_bustag(adapter->pci_mem);
	adapter->osdep.mem_bus_space_handle =
		rman_get_bushandle(adapter->pci_mem);
	adapter->hw.hw_addr = (u8 *) &adapter->osdep.mem_bus_space_handle;
	adapter->hw.back = adapter;
	return (0);
}

/*********************************************************************
 *  Device removal routine
 *
 *  The detach entry point is called when the driver is being removed.
 *  This routine stops the adapter and deallocates all the resources
 *  that were allocated for driver operation.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/
static int
ixgbe_if_detach(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	u32 ctrl_ext;
#ifdef PCI_IOV
	device_t dev = iflib_get_dev(ctx);
#endif

	INIT_DEBUGOUT("ixgbe_detach: begin");

#ifdef PCI_IOV
	if (pci_iov_detach(dev) != 0) {
		device_printf(dev, "SR-IOV in use; detach first.\n");
		return (EBUSY);
	}
#endif /* PCI_IOV */

	iflib_config_gtask_deinit(&adapter->mod_task);
	iflib_config_gtask_deinit(&adapter->msf_task);
	iflib_config_gtask_deinit(&adapter->phy_task);
#ifdef PCI_IOV
	iflib_config_gtask_deinit(&adapter->mbx_task);
#endif

	ixgbe_setup_low_power_mode(ctx);

	/* let hardware know driver is unloading */
	ctrl_ext = IXGBE_READ_REG(&adapter->hw, IXGBE_CTRL_EXT);
	ctrl_ext &= ~IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_CTRL_EXT, ctrl_ext);
  
	ixgbe_free_pci_resources(ctx);
	free(adapter->mta, M_DEVBUF);
  
	return (0);
}

static int
ixgbe_setup_low_power_mode(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	device_t dev = iflib_get_dev(ctx);
	s32 error = 0;

	if (!hw->wol_enabled)
		ixgbe_set_phy_power(hw, FALSE);

	/* Limit power management flow to X550EM baseT */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T
		&& hw->phy.ops.enter_lplu) {
		/* Turn off support for APM wakeup. (Using ACPI instead) */
		IXGBE_WRITE_REG(hw, IXGBE_GRC,
						IXGBE_READ_REG(hw, IXGBE_GRC) & ~(u32)2);
    
		/*
		 * Clear Wake Up Status register to prevent any previous wakeup
		 * events from waking us up immediately after we suspend.
		 */
		IXGBE_WRITE_REG(hw, IXGBE_WUS, 0xffffffff);
    
		/*
		 * Program the Wakeup Filter Control register with user filter
		 * settings
		 */
		IXGBE_WRITE_REG(hw, IXGBE_WUFC, adapter->wufc);
    
		/* Enable wakeups and power management in Wakeup Control */
		IXGBE_WRITE_REG(hw, IXGBE_WUC,
						IXGBE_WUC_WKEN | IXGBE_WUC_PME_EN);
    
		/* X550EM baseT adapters need a special LPLU flow */
		hw->phy.reset_disable = true;
		error = hw->phy.ops.enter_lplu(hw);
		if (error)
			device_printf(dev,
						  "Error entering LPLU: %d\n", error);
		hw->phy.reset_disable = false;
	} 
  
	return error;
}

/*********************************************************************
 *
 *  Shutdown entry point
 *
 **********************************************************************/
static int
ixgbe_if_shutdown(if_ctx_t ctx)
{
	int error = 0;

	INIT_DEBUGOUT("ixgbe_shutdown: begin");

	error = ixgbe_setup_low_power_mode(ctx);
	return (error);
}

static int
ixgbe_if_suspend(if_ctx_t ctx)
{
	int error = 0;

	INIT_DEBUGOUT("ixgbe_suspend: begin");

	error = ixgbe_setup_low_power_mode(ctx);

	return (error);
}

static int
ixgbe_if_resume(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	device_t dev  = iflib_get_dev(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	u32 wus;

	INIT_DEBUGOUT("ixgbe_resume: begin");

	/* Read & clear WUS register */
	wus = IXGBE_READ_REG(hw, IXGBE_WUS);
	if (wus)
		device_printf(dev, "Woken up by (WUS): %#010x\n",
					  IXGBE_READ_REG(hw, IXGBE_WUS));
	IXGBE_WRITE_REG(hw, IXGBE_WUS, 0xffffffff);
	/* And clear WUFC until next low-power transition */
	IXGBE_WRITE_REG(hw, IXGBE_WUFC, 0);

	/*
	 * Required after D3->D0 transition;
	 * will re-advertise all previous advertised speeds
	 */
	if (ifp->if_flags & IFF_UP)
		ixgbe_if_init(ctx);

	INIT_DEBUGOUT("ixgbe_resume: end");
	return (0);
}

/*********************************************************************          
 *  Ioctl mtu entry point                                                       
 *                                                                              
 *                                                                              
 *  return 0 on success, EINVAL on failure                                      
 **********************************************************************/
static int
ixgbe_if_mtu_set(if_ctx_t ctx, uint32_t mtu)
{
	int error = 0;
	struct adapter *adapter = iflib_get_softc(ctx);

	IOCTL_DEBUGOUT("ioctl: SIOCIFMTU (Set Interface MTU)");

	if (mtu > IXGBE_MAX_MTU) {
		error = EINVAL;
	} else {
		adapter->max_frame_size = mtu + IXGBE_MTU_HDR;
	}
    
	return error;
}

static void
ixgbe_if_crcstrip_set(if_ctx_t ctx, int onoff, int crcstrip)
{
	struct adapter *sc = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &sc->hw;
	/* crc stripping is set in two places:
	 * IXGBE_HLREG0 (modified on init_locked and hw reset)
	 * IXGBE_RDRXCTL (set by the original driver in
	 *	ixgbe_setup_hw_rsc() called in init_locked.
	 *	We disable the setting when netmap is compiled in).
	 * We update the values here, but also in ixgbe.c because
	 * init_locked sometimes is called outside our control.
	 */
	uint32_t hl, rxc;

	hl = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	rxc = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);
	if (netmap_verbose)
		D("%s read  HLREG 0x%x rxc 0x%x",
		  onoff ? "enter" : "exit", hl, rxc);
	/* hw requirements ... */
	rxc &= ~IXGBE_RDRXCTL_RSCFRSTSIZE;
	rxc |= IXGBE_RDRXCTL_RSCACKC;
	if (onoff && !crcstrip) {
		/* keep the crc. Fast rx */
		hl &= ~IXGBE_HLREG0_RXCRCSTRP;
		rxc &= ~IXGBE_RDRXCTL_CRCSTRIP;
	} else {
		/* reset default mode */
		hl |= IXGBE_HLREG0_RXCRCSTRP;
		rxc |= IXGBE_RDRXCTL_CRCSTRIP;
	}
#ifdef DEV_NETMAP
	if (netmap_verbose)
		D("%s write HLREG 0x%x rxc 0x%x",
		  onoff ? "enter" : "exit", hl, rxc);
#endif	
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hl);
	IXGBE_WRITE_REG(hw, IXGBE_RDRXCTL, rxc);
}

/*********************************************************************
 *  Init entry point
 *
 *  This routine is used in two ways. It is used by the stack as
 *  init entry point in network interface structure. It is also used
 *  by the driver as a hw/sw initialization routine to get to a
 *  consistent state.
 *
 *  return 0 on success, positive on failure
 **********************************************************************/
#define IXGBE_MHADD_MFS_SHIFT 16

static void
ixgbe_if_init(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ifnet   *ifp = iflib_get_ifp(ctx);
	device_t 	dev = iflib_get_dev(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	struct ix_rx_queue *rx_que;
	struct ix_tx_queue *tx_que;

	u32		txdctl, mhadd;
	u32		rxdctl, rxctrl;
        int             i, err;

#ifdef PCI_IOV
	enum ixgbe_iov_mode mode;
#endif

	INIT_DEBUGOUT("ixgbe_if_init: begin");

#ifdef PCI_IOV
	mode = ixgbe_get_iov_mode(adapter);
	adapter->pool = ixgbe_max_vfs(mode);
	/* Queue indices may change with IOV mode */
	for (int i = 0; i < adapter->num_rx_queues; i++) {
		adapter->rx_queues[i].rxr.me = ixgbe_pf_que_index(mode, i);
		adapter->tx_queues[i].txr.me = ixgbe_pf_que_index(mode, i);
	}
#endif
	/* reprogram the RAR[0] in case user changed it. */
	ixgbe_set_rar(hw, 0, hw->mac.addr, adapter->pool, IXGBE_RAH_AV);

	/* Get the latest mac address, User can use a LAA */
	bcopy(IF_LLADDR(ifp), hw->mac.addr, IXGBE_ETH_LENGTH_OF_ADDRESS);
	ixgbe_set_rar(hw, 0, hw->mac.addr, adapter->pool, 1);
	hw->addr_ctrl.rar_used_count = 1;

	ixgbe_init_hw(hw);

#ifdef PCI_IOV
	ixgbe_initialize_iov(adapter);
#endif

	ixgbe_initialize_transmit_units(ctx);

	/* Setup Multicast table */
	ixgbe_if_multi_set(ctx);

	/*
	** Determine the correct mbuf pool
	** for doing jumbo frames
	*/
	if (adapter->max_frame_size <= MCLBYTES)
		adapter->rx_mbuf_sz = MCLBYTES;
	else
		adapter->rx_mbuf_sz = MJUMPAGESIZE;

	/* Configure RX settings */
	ixgbe_initialize_receive_units(ctx);
	
	/* Enable SDP & MSIX interrupts based on adapter */
	ixgbe_config_gpie(adapter);

	/* Set MTU size */
	if (ifp->if_mtu > ETHERMTU) {
		/* aka IXGBE_MAXFRS on 82599 and newer */
		mhadd = IXGBE_READ_REG(hw, IXGBE_MHADD);
		mhadd &= ~IXGBE_MHADD_MFS_MASK;
		mhadd |= adapter->max_frame_size << IXGBE_MHADD_MFS_SHIFT;
		IXGBE_WRITE_REG(hw, IXGBE_MHADD, mhadd);
	}

	/* Now enable all the queues */
	for (i = 0, tx_que = adapter->tx_queues; i < adapter->num_tx_queues; i++, tx_que++) {
		struct tx_ring		*txr = &tx_que->txr;

		txr->tx_rs_cidx = txr->tx_rs_pidx = txr->tx_cidx_processed = 0;
		txdctl = IXGBE_READ_REG(hw, IXGBE_TXDCTL(txr->me));
		txdctl |= IXGBE_TXDCTL_ENABLE;
		/* Set WTHRESH to 8, burst writeback */
		txdctl |= (8 << 16);
		/*
		 * When the internal queue falls below PTHRESH (32),
		 * start prefetching as long as there are at least
		 * HTHRESH (1) buffers ready. The values are taken
		 * from the Intel linux driver 3.8.21.
		 * Prefetching enables tx line rate even with 1 queue.
		 */
		txdctl |= (32 << 0) | (1 << 8);
		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(txr->me), txdctl);
	}

	for (i = 0, rx_que = adapter->rx_queues; i < adapter->num_rx_queues; i++, rx_que++) {
		struct rx_ring 		*rxr = &rx_que->rxr;
		rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxr->me));
		if (hw->mac.type == ixgbe_mac_82598EB) {
			/*
			** PTHRESH = 21
			** HTHRESH = 4
			** WTHRESH = 8
			*/
			rxdctl &= ~0x3FFFFF;
			rxdctl |= 0x080420;
		}
		rxdctl |= IXGBE_RXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rxr->me), rxdctl);
		for (int j = 0; j < 10; j++) {
			if (IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxr->me)) &
				IXGBE_RXDCTL_ENABLE)
				break;
			else
				msec_delay(1);
		}
		wmb();
	}

	/* Enable Receive engine */
	rxctrl = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
	if (hw->mac.type == ixgbe_mac_82598EB)
		rxctrl |= IXGBE_RXCTRL_DMBYPS;
	rxctrl |= IXGBE_RXCTRL_RXEN;
	ixgbe_enable_rx_dma(hw, rxctrl);

	/* Set up MSI/X routing */
	if (ixgbe_enable_msix)  {
		ixgbe_configure_ivars(adapter);
		/* Set up auto-mask */
		if (hw->mac.type == ixgbe_mac_82598EB)
			IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
		else {
			IXGBE_WRITE_REG(hw, IXGBE_EIAM_EX(0), 0xFFFFFFFF);
			IXGBE_WRITE_REG(hw, IXGBE_EIAM_EX(1), 0xFFFFFFFF);
		}
	} else {  /* Simple settings for Legacy/MSI */
		ixgbe_set_ivar(adapter, 0, 0, 0);
		ixgbe_set_ivar(adapter, 0, 0, 1);
		IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
	}

#ifdef IXGBE_FDIR
	/* Init Flow director */
	if (hw->mac.type != ixgbe_mac_82598EB) {
		u32 hdrm = 32 << fdir_pballoc;
	  
		hw->mac.ops.setup_rxpba(hw, 0, hdrm, PBA_STRATEGY_EQUAL);
		ixgbe_init_fdir_signature_82599(&adapter->hw, fdir_pballoc);
	}
#endif
	/*
	 * Check on any SFP devices that
	 * need to be kick-started
	 */
	if (hw->phy.type == ixgbe_phy_none) {
		int err = hw->phy.ops.identify(hw);
		if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
			device_printf(dev,
						  "Unsupported SFP+ module type was detected.\n");
			return;
		}
	}

	/* Set moderation on the Link interrupt */
	IXGBE_WRITE_REG(hw, IXGBE_EITR(adapter->vector), IXGBE_LINK_ITR);

	/* Configure Energy Efficient Ethernet for supported devices */
	if (hw->mac.ops.setup_eee) {
		err = hw->mac.ops.setup_eee(hw, adapter->eee_enabled);
		if (err)
			device_printf(dev, "Error setting up EEE: %d\n", err);
	}

	/* Enable power to the phy. */
	ixgbe_set_phy_power(hw, TRUE);


	/* Config/Enable Link */
	ixgbe_config_link(adapter);

	/* Hardware Packet Buffer & Flow Control setup */
	ixgbe_config_delay_values(adapter);

	/* Initialize the FC settings */
	ixgbe_start_hw(hw);

	/* Set up VLAN support and filter */
	ixgbe_setup_vlan_hw_support(ctx);

	/* Setup DMA Coalescing */
	ixgbe_config_dmac(adapter);

	/* And now turn on interrupts */
	ixgbe_if_enable_intr(ctx);

#ifdef PCI_IOV
	/* Enable the use of the MBX by the VF's */
	{
		u32 reg = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
		reg |= IXGBE_CTRL_EXT_PFRSTD;
		IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, reg);
	}
#endif
}


/************************************************************************
 * ixgbe_set_ivar
 *
 *   Setup the correct IVAR register for a particular MSI-X interrupt
 *     (yes this is all very magic and confusing :)
 *    - entry is the register array entry
 *    - vector is the MSI-X vector for this queue
 *    - type is RX/TX/MISC
 ************************************************************************/
static void
ixgbe_set_ivar(struct adapter *adapter, u8 entry, u8 vector, s8 type)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 ivar, index;

	vector |= IXGBE_IVAR_ALLOC_VAL;

	switch (hw->mac.type) {

	case ixgbe_mac_82598EB:
		if (type == -1)
			entry = IXGBE_IVAR_OTHER_CAUSES_INDEX;
		else
			entry += (type * 64);
		index = (entry >> 2) & 0x1F;
		ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(index));
		ivar &= ~(0xFF << (8 * (entry & 0x3)));
		ivar |= (vector << (8 * (entry & 0x3)));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IVAR(index), ivar);
		break;

	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		if (type == -1) { /* MISC IVAR */
			index = (entry & 1) * 8;
			ivar = IXGBE_READ_REG(hw, IXGBE_IVAR_MISC);
			ivar &= ~(0xFF << index);
			ivar |= (vector << index);
			IXGBE_WRITE_REG(hw, IXGBE_IVAR_MISC, ivar);
		} else {          /* RX/TX IVARS */
			index = (16 * (entry & 1)) + (8 * type);
			ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(entry >> 1));
			ivar &= ~(0xFF << index);
			ivar |= (vector << index);
			IXGBE_WRITE_REG(hw, IXGBE_IVAR(entry >> 1), ivar);
		}

	default:
		break;
	}
}

static void
ixgbe_configure_ivars(struct adapter *adapter)
{
	struct  ix_rx_queue	*rx_que = adapter->rx_queues;
	struct  ix_tx_queue	*tx_que = adapter->tx_queues;
	u32			newitr;

	if (ixgbe_max_interrupt_rate > 0)
		newitr = (4000000 / ixgbe_max_interrupt_rate) & 0x0FF8;
	else {
		/*
		** Disable DMA coalescing if interrupt moderation is
		** disabled.
		*/
		adapter->dmac = 0;
		newitr = 0;
	}

	for (int i = 0; i < adapter->num_rx_queues; i++, rx_que++) {
		struct rx_ring *rxr = &rx_que->rxr;

		/* First the RX queue entry */
		ixgbe_set_ivar(adapter, rxr->me, rx_que->msix, 0);

		/* Set an Initial EITR value */
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EITR(rx_que->msix), newitr);
	}
	for (int i = 0; i < adapter->num_tx_queues; i++, tx_que++) {
		struct tx_ring *txr = &tx_que->txr;

		/* ... and the TX */
		ixgbe_set_ivar(adapter, txr->me, tx_que->msix, 1);
	}
	/* For the Link interrupt */
	ixgbe_set_ivar(adapter, 1, adapter->vector, -1);
}
 
static void
ixgbe_config_gpie(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 gpie;

	gpie = IXGBE_READ_REG(hw, IXGBE_GPIE);

	/* Fan Failure Interrupt */
	if (hw->device_id == IXGBE_DEV_ID_82598AT)
		gpie |= IXGBE_SDP1_GPIEN;

	/*
	 * Module detection (SDP2)
	 * Media ready (SDP1)
	 */
	if (hw->mac.type == ixgbe_mac_82599EB) {
		gpie |= IXGBE_SDP2_GPIEN;
		if (hw->device_id != IXGBE_DEV_ID_82599_QSFP_SF_QP)
			gpie |= IXGBE_SDP1_GPIEN;
	}

	/*
	 * Thermal Failure Detection (X540)
	 * Link Detection (X557)
	 */
	if (hw->mac.type == ixgbe_mac_X540 ||
	    hw->device_id == IXGBE_DEV_ID_X550EM_X_SFP ||
	    hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T)
		gpie |= IXGBE_SDP0_GPIEN_X540;

	if (adapter->intr_type == IFLIB_INTR_MSIX) {
		/* Enable Enhanced MSIX mode */
		gpie |= IXGBE_GPIE_MSIX_MODE;
		gpie |= IXGBE_GPIE_EIAME | IXGBE_GPIE_PBA_SUPPORT |
		    IXGBE_GPIE_OCD;
	}

	IXGBE_WRITE_REG(hw, IXGBE_GPIE, gpie);
}

/*
 * Requires adapter->max_frame_size to be set.
 */
static void
ixgbe_config_delay_values(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 rxpb, frame, size, tmp;
  
	frame = adapter->max_frame_size;
  
	/* Calculate High Water */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
		tmp = IXGBE_DV_X540(frame, frame);
		break;
	default:
		tmp = IXGBE_DV(frame, frame);
		break;
	}
	size = IXGBE_BT2KB(tmp);
	rxpb = IXGBE_READ_REG(hw, IXGBE_RXPBSIZE(0)) >> 10;
	hw->fc.high_water[0] = rxpb - size;
  
	/* Now calculate Low Water */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
		tmp = IXGBE_LOW_DV_X540(frame);
		break;
	default:
		tmp = IXGBE_LOW_DV(frame);
		break;
	}
	hw->fc.low_water[0] = IXGBE_BT2KB(tmp);
  
	hw->fc.requested_mode = adapter->fc;
	hw->fc.pause_time = IXGBE_FC_PAUSE;
	hw->fc.send_xon = TRUE;
}

/*********************************************************************
 *  Multicast Update
 *
 *  This routine is called whenever multicast address list is updated.
 *
 **********************************************************************/
#define IXGBE_RAR_ENTRIES 16

static int
ixgbe_mc_filter_apply(void *arg, struct ifmultiaddr *ifma, int count)
{
	struct adapter *adapter = arg;
	struct ixgbe_mc_addr *mta = adapter->mta;

	if (ifma->ifma_addr->sa_family != AF_LINK)
		return (0);
    if (count == MAX_NUM_MULTICAST_ADDRESSES)
		return (0);
    bcopy(LLADDR((struct sockaddr_dl *) ifma->ifma_addr),
	  mta[count].addr, IXGBE_ETH_LENGTH_OF_ADDRESS);
    mta[count].vmdq = adapter->pool;
	return (1);
}

static void
ixgbe_if_multi_set(if_ctx_t ctx)
{
	u32                  fctrl;
	u8                   *update_ptr;
	struct adapter       *adapter = iflib_get_softc(ctx);
	struct ixgbe_mc_addr *mta;
	int                  mcnt = 0;
	struct ifnet         *ifp =  iflib_get_ifp(ctx);
  
	IOCTL_DEBUGOUT("ixgbe_if_multi_set: begin");

	mta = adapter->mta;
	bzero(mta, sizeof(*mta) * MAX_NUM_MULTICAST_ADDRESSES);

	mcnt = if_multi_apply(iflib_get_ifp(ctx), ixgbe_mc_filter_apply, adapter);
  
	fctrl = IXGBE_READ_REG(&adapter->hw, IXGBE_FCTRL);
	fctrl |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
	if (ifp->if_flags & IFF_PROMISC)
		fctrl |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
	else if (mcnt >= MAX_NUM_MULTICAST_ADDRESSES ||
			 ifp->if_flags & IFF_ALLMULTI) {
		fctrl |= IXGBE_FCTRL_MPE;
		fctrl &= ~IXGBE_FCTRL_UPE;
	} else
		fctrl &= ~(IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
  
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_FCTRL, fctrl);
  
	if (mcnt < MAX_NUM_MULTICAST_ADDRESSES) {
		update_ptr = (u8 *)mta;
		ixgbe_update_mc_addr_list(&adapter->hw, update_ptr, mcnt, ixgbe_mc_array_itr, TRUE);
	}
  
    IOCTL_DEBUGOUT("ixgbe_if_multi_set: end");
}

/*
 * This is an iterator function now needed by the multicast
 * shared code. It simply feeds the shared code routine the
 * addresses in the array of ixgbe_set_multi() one by one.
 */
static u8 *
ixgbe_mc_array_itr(struct ixgbe_hw *hw, u8 **update_ptr, u32 *vmdq)
{
	struct ixgbe_mc_addr *mta;

	mta = (struct ixgbe_mc_addr *)*update_ptr;
	*vmdq = mta->vmdq;

	*update_ptr = (u8*)(mta + 1);;
	return (mta->addr);
}

/*********************************************************************
 *  Timer routine
 *
 *  This routine checks for link status,updates statistics,
 *  and runs the watchdog check.
 *
 **********************************************************************/

static void
ixgbe_if_timer(if_ctx_t ctx, uint16_t qid)
{
	struct adapter		*adapter = iflib_get_softc(ctx);

	if (qid != 0)
		return;

	/* Check for pluggable optics */
	if (adapter->sfp_probe && !ixgbe_sfp_probe(ctx))
			return; /* Nothing to do */
	iflib_admin_intr_deferred(ctx);
}

/*
** ixgbe_sfp_probe - called in the local timer to
** determine if a port had optics inserted.
*/  
static bool
ixgbe_sfp_probe(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw	*hw = &adapter->hw;
	device_t	dev = iflib_get_dev(ctx);
	bool		result = FALSE;

	if ((hw->phy.type == ixgbe_phy_nl) &&
	    (hw->phy.sfp_type == ixgbe_sfp_type_not_present)) {
		s32 ret = hw->phy.ops.identify_sfp(hw);
		if (ret)
			goto out;
		ret = hw->phy.ops.reset(hw);
		if (ret == IXGBE_ERR_SFP_NOT_SUPPORTED) {
			device_printf(dev,"Unsupported SFP+ module detected!");
			printf(" Reload driver with supported module.\n");
			adapter->sfp_probe = FALSE;
			goto out;
		} else
			device_printf(dev,"SFP+ module detected!\n");
		/* We now have supported optics */
		adapter->sfp_probe = FALSE;
		/* Set the optics type so system reports correctly */
		ixgbe_setup_optics(adapter);
		result = TRUE;
	}
out:
	return (result);
}

/*************************************************************************
 *
 * Tasklet handler - ixgbe_handle_mod, ixgbe_handle_msf, ixgbe_handle_phy
 *
 *************************************************************************/
/*
** Tasklet for handling SFP module interrupts
*/
static void
ixgbe_handle_mod(void *context)
{
	if_ctx_t ctx = context;
	struct adapter  *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	enum ixgbe_phy_type orig_type = hw->phy.type;
	device_t	dev = iflib_get_dev(ctx);
	u32 err;

	/* Check to see if the PHY type changed */
	if (hw->phy.ops.identify) {
		hw->phy.type = ixgbe_phy_unknown;
		hw->phy.ops.identify(hw);
	}

	if (hw->phy.type != orig_type) {
		device_printf(dev, "Detected phy_type %d\n", hw->phy.type);

		if (hw->phy.type == ixgbe_phy_none) {
			hw->phy.sfp_type = ixgbe_sfp_type_unknown;
			goto out;
		}

		/* Try to do the initialization that was skipped before */
		if (hw->phy.ops.init)
			hw->phy.ops.init(hw);
		if (hw->phy.ops.reset)
			hw->phy.ops.reset(hw);
	}

	err = hw->phy.ops.identify_sfp(hw);
	if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
		device_printf(dev,
		    "Unsupported SFP+ module type was detected.\n");
		goto out;
	}

	err = hw->mac.ops.setup_sfp(hw);
	if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
		device_printf(dev,
		    "Setup failure - unsupported SFP+ module type.\n");
		goto out;
	}
	 if (hw->phy.multispeed_fiber)
		 GROUPTASK_ENQUEUE(&adapter->msf_task);
out:
	/* Update media type */
	switch (hw->mac.ops.get_media_type(hw)) {
		case ixgbe_media_type_fiber:
			adapter->optics = IFM_10G_SR;
			break;
		case ixgbe_media_type_copper:
			adapter->optics = IFM_10G_TWINAX;
			break;
		case ixgbe_media_type_cx4:
			adapter->optics = IFM_10G_CX4;
			break;
		default:
			adapter->optics = 0;
			break;
	}
}


/* Tasklet for handling MSF (multispeed fiber) interrupts */

static void
ixgbe_handle_msf(void *context)
{
	if_ctx_t ctx = context;
	struct adapter  *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	u32 autoneg;
	bool negotiate;

	/* get_supported_phy_layer will call hw->phy.ops.identify_sfp() */
	adapter->phy_layer = ixgbe_get_supported_physical_layer(hw);

	autoneg = hw->phy.autoneg_advertised;
	if ((!autoneg) && (hw->mac.ops.get_link_capabilities))
		hw->mac.ops.get_link_capabilities(hw, &autoneg, &negotiate);
	if (hw->mac.ops.setup_link)
		hw->mac.ops.setup_link(hw, autoneg, TRUE);
	/* Adjust media types shown in ifconfig */
	ifmedia_removeall(adapter->media);
	ixgbe_add_media_types(adapter->ctx);
}


/* Tasklet for handling interrupts from an external PHY */

static void
ixgbe_handle_phy(void *context)
{
	if_ctx_t ctx = context;
	struct adapter  *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	int error;

	error = hw->phy.ops.handle_lasi(hw);
	if (error == IXGBE_ERR_OVERTEMP)
		device_printf(adapter->dev,
		    "CRITICAL: EXTERNAL PHY OVER TEMP!! "
		    " PHY will downshift to lower power state!\n");
	else if (error)
		device_printf(adapter->dev,
		    "Error handling LASI interrupt: %d\n",
		    error);
	return;
}


/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC and deallocates TX/RX buffers.
 *
 **********************************************************************/
static void
ixgbe_if_stop(if_ctx_t ctx)
{
	struct ifnet   *ifp;
	struct adapter *adapter = iflib_get_softc(ctx);

	struct ixgbe_hw *hw = &adapter->hw;
	ifp = iflib_get_ifp(ctx);
   
	INIT_DEBUGOUT("ixgbe_stop: begin\n");

	ixgbe_reset_hw(hw);
	hw->adapter_stopped = FALSE;
	ixgbe_stop_adapter(hw);
	if (hw->mac.type == ixgbe_mac_82599EB)
		ixgbe_stop_mac_link_on_d3_82599(hw);
	/* Turn off the laser - noop with no optics */
	ixgbe_disable_tx_laser(hw);
   
	/* Update the stack */
	adapter->link_up = FALSE;
	ixgbe_if_update_admin_status(ctx);
   
	/* reprogram the RAR[0] in case user changed it. */
	ixgbe_set_rar(&adapter->hw, 0, adapter->hw.mac.addr, 0, IXGBE_RAH_AV);
   
	return;
}

/*
** Note: this routine updates the OS on the link state
**	the real check of the hardware only happens with
**	a link interrupt.
*/
static void
ixgbe_if_update_admin_status(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	struct ixgbe_hw *hw = &adapter->hw;
	device_t	dev = iflib_get_dev(ctx);
	
	if (adapter->link_up){ 
		if (adapter->link_active == FALSE) {
			if (bootverbose)
				device_printf(dev,"Link is up %d Gbps %s \n",
							  ((adapter->link_speed == 128)? 10:1),
							  "Full Duplex");
			adapter->link_active = TRUE;
			/* Update any Flow Control changes */
			ixgbe_fc_enable(hw);
			/* Update DMA coalescing config */
			ixgbe_config_dmac(adapter);
			/* should actually be negotiated value */
			iflib_link_state_change(ctx, LINK_STATE_UP, IF_Gbps(10));

#ifdef PCI_IOV
			ixgbe_ping_all_vfs(adapter);
#endif
      
		}
	} else { /* Link down */
		if (adapter->link_active == TRUE) {
			if (bootverbose)
				device_printf(dev,"Link is Down\n");
			iflib_link_state_change(ctx, LINK_STATE_DOWN, 0);
			adapter->link_active = FALSE;
#ifdef PCI_IOV
			ixgbe_ping_all_vfs(adapter);
#endif
		}
	}

	ixgbe_check_link(&adapter->hw,
					 &adapter->link_speed, &adapter->link_up, 0);
	ixgbe_update_stats_counters(adapter);


/* Re-enable link interrupts */
       IXGBE_WRITE_REG(hw, IXGBE_EIMS, IXGBE_EIMS_LSC);
}


/*********************************************************************
 *
 *  Configure DMA Coalescing
 *
 **********************************************************************/
static void
ixgbe_config_dmac(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbe_dmac_config *dcfg = &hw->mac.dmac_config;

	if (hw->mac.type < ixgbe_mac_X550 ||
		!hw->mac.ops.dmac_config)
		return;

	if (dcfg->watchdog_timer ^ adapter->dmac ||
		dcfg->link_speed ^ adapter->link_speed) {
		dcfg->watchdog_timer = adapter->dmac;
		dcfg->fcoe_en = false;
		dcfg->link_speed = adapter->link_speed;
		dcfg->num_tcs = 1;
    
		INIT_DEBUGOUT2("dmac settings: watchdog %d, link speed %d\n",
					   dcfg->watchdog_timer, dcfg->link_speed);
    
		hw->mac.ops.dmac_config(hw);
	}
}

void
ixgbe_if_enable_intr(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
  	struct ixgbe_hw	*hw = &adapter->hw;
	struct ix_rx_queue	*que = adapter->rx_queues;
	u32		mask, fwsm;

	mask = (IXGBE_EIMS_ENABLE_MASK & ~IXGBE_EIMS_RTX_QUEUE);
	/* Enable Fan Failure detection */
	if (hw->device_id == IXGBE_DEV_ID_82598AT)
		mask |= IXGBE_EIMS_GPI_SDP1;

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599EB:
		mask |= IXGBE_EIMS_ECC;
		/* Temperature sensor on some adapters */
		mask |= IXGBE_EIMS_GPI_SDP0;
		/* SFP+ (RX_LOS_N & MOD_ABS_N) */
		mask |= IXGBE_EIMS_GPI_SDP1;
		mask |= IXGBE_EIMS_GPI_SDP2;
#ifdef IXGBE_FDIR
		mask |= IXGBE_EIMS_FLOW_DIR;
#endif
#ifdef PCI_IOV
		mask |= IXGBE_EIMS_MAILBOX;
#endif
		break;
	case ixgbe_mac_X540:
		/* Detect if Thermal Sensor is enabled */
		fwsm = IXGBE_READ_REG(hw, IXGBE_FWSM);
		if (fwsm & IXGBE_FWSM_TS_ENABLED)
			mask |= IXGBE_EIMS_TS;
		mask |= IXGBE_EIMS_ECC;
#ifdef IXGBE_FDIR
		mask |= IXGBE_EIMS_FLOW_DIR;
#endif
		break;
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
		/* MAC thermal sensor is automatically enabled */
		mask |= IXGBE_EIMS_TS;
		/* Some devices use SDP0 for important information */
		if (hw->device_id == IXGBE_DEV_ID_X550EM_X_SFP ||
			hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T)
			mask |= IXGBE_EIMS_GPI_SDP0_BY_MAC(hw);
		mask |= IXGBE_EIMS_ECC;
#ifdef IXGBE_FDIR
		mask |= IXGBE_EIMS_FLOW_DIR;
#endif
#ifdef PCI_IOV
		mask |= IXGBE_EIMS_MAILBOX;
#endif
		/* falls through */
	default:
		break;
	}

	IXGBE_WRITE_REG(hw, IXGBE_EIMS, mask);

	/* With MSI-X we use auto clear */
     if (adapter->intr_type == IFLIB_INTR_MSIX) {
		 mask = IXGBE_EIMS_ENABLE_MASK;
		 /* Don't autoclear Link */
		 mask &= ~IXGBE_EIMS_OTHER;
		 mask &= ~IXGBE_EIMS_LSC;
#ifdef PCI_IOV
		 mask &= ~IXGBE_EIMS_MAILBOX;
#endif
		 IXGBE_WRITE_REG(hw, IXGBE_EIAC, mask);
	 }

	/*
	** Now enable all queues, this is done separately to
	** allow for handling the extended (beyond 32) MSIX
	** vectors that can be used by 82599
	*/
	for (int i = 0; i < adapter->num_rx_queues; i++, que++)
		ixgbe_enable_queue(adapter, que->msix);

	IXGBE_WRITE_FLUSH(hw);
}
  
static void
ixgbe_if_disable_intr(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if (adapter->intr_type == IFLIB_INTR_MSIX)
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIAC, 0);
	if (adapter->hw.mac.type == ixgbe_mac_82598EB) {
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC, ~0);
	} else {
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC, 0xFFFF0000);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC_EX(0), ~0);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC_EX(1), ~0);
	}
	IXGBE_WRITE_FLUSH(&adapter->hw);
}


static int
ixgbe_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid)
{
	struct adapter	*adapter = iflib_get_softc(ctx);
	struct ix_rx_queue *que = &adapter->rx_queues[rxqid];

	ixgbe_enable_queue(adapter, que->rxr.me);
	return (0);
}

static int
ixgbe_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid)
{
#ifdef notyet
	struct adapter	*adapter = iflib_get_softc(ctx);
	struct ix_tx_queue *que = &adapter->tx_queues[txqid];

	ixgbe_enable_queue(adapter, que->txr.me);
#endif
	return (0);
}

/*
**
** MSIX Interrupt Handlers and Tasklets
**
*/

static void
ixgbe_enable_queue(struct adapter *adapter, u32 vector)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64	queue = (u64)(1 << vector);
	u32	mask;

	if (hw->mac.type == ixgbe_mac_82598EB) {
		mask = (IXGBE_EIMS_RTX_QUEUE & queue);
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, mask);
	} else {
		mask = (queue & 0xFFFFFFFF);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMS_EX(0), mask);
		mask = (queue >> 32);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMS_EX(1), mask);
	}
}

static void
ixgbe_disable_queue(struct adapter *adapter, u32 vector)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64	queue = (u64)(1 << vector);
	u32	mask;

	if (hw->mac.type == ixgbe_mac_82598EB) {
		mask = (IXGBE_EIMS_RTX_QUEUE & queue);
		IXGBE_WRITE_REG(hw, IXGBE_EIMC, mask);
	} else {
		mask = (queue & 0xFFFFFFFF);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMC_EX(0), mask);
		mask = (queue >> 32);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMC_EX(1), mask);
	}
}

/*********************************************************************
 *
 *  Legacy Interrupt Service routine
 *
 **********************************************************************/
int
ixgbe_intr(void *arg)
{
	struct adapter *adapter = arg;
	struct ix_rx_queue *que = adapter->rx_queues;
	struct ixgbe_hw *hw = &adapter->hw;
	if_ctx_t ctx = adapter->ctx;
	u32 reg_eicr;

	reg_eicr = IXGBE_READ_REG(hw, IXGBE_EICR);

	++que->irqs;
	if (reg_eicr == 0) {
		ixgbe_if_enable_intr(ctx);
		return (FILTER_HANDLED);
	}

	/* Check for fan failure */
	if ((hw->device_id == IXGBE_DEV_ID_82598AT) &&
	    (reg_eicr & IXGBE_EICR_GPI_SDP1)) {
		device_printf(adapter->dev, "\nCRITICAL: FAN FAILURE!! "
			      "REPLACE IMMEDIATELY!!\n");
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, IXGBE_EICR_GPI_SDP1_BY_MAC(hw));
	}
	
	/* Link status change */
	if (reg_eicr & IXGBE_EICR_LSC) {
		IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_EIMC_LSC);
		iflib_admin_intr_deferred(ctx);
	}
	/* External PHY interrupt  */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T &&
	    (reg_eicr & IXGBE_EICR_GPI_SDP0_X540)) {
		GROUPTASK_ENQUEUE(&adapter->phy_task);
	}

	return (FILTER_SCHEDULE_THREAD);
}

static void
ixgbe_free_pci_resources(if_ctx_t ctx)
{
        struct adapter *adapter = iflib_get_softc(ctx);
	struct 		ix_rx_queue *que = adapter->rx_queues;
	device_t	dev = iflib_get_dev(ctx);

	/* Release all msix queue resources */
	if (adapter->intr_type == IFLIB_INTR_MSIX)
		iflib_irq_free(ctx, &adapter->irq);

	for (int i = 0; i < adapter->num_rx_queues; i++, que++) {
		iflib_irq_free(ctx, &que->que_irq);
	}

	/*
	 * Free link/admin interrupt
	 */
	if (adapter->pci_mem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
							 PCIR_BAR(0), adapter->pci_mem);
}

/* Sysctls */
/*
** Set flow control using sysctl:
** Flow control values:
** 	0 - off
**	1 - rx pause
**	2 - tx pause
**	3 - full
*/
static int
ixgbe_sysctl_flowcntl(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter;
	int            error, fc;

	adapter = (struct adapter *)arg1;
	fc = adapter->hw.fc.current_mode;

	error = sysctl_handle_int(oidp, &fc, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	/* Don't bother if it's not changed */
	if (fc == adapter->hw.fc.current_mode && fc == adapter->hw.fc.requested_mode && fc == adapter->fc)
		return (0);

	return ixgbe_set_flowcntl(adapter, fc);
}

static int
ixgbe_set_flowcntl(struct adapter *adapter, int fc)
{
	switch (adapter->fc) {
	case ixgbe_fc_rx_pause:
	case ixgbe_fc_tx_pause:
	case ixgbe_fc_full:
		adapter->hw.fc.requested_mode = adapter->fc;
		if (adapter->num_rx_queues > 1)
			ixgbe_disable_rx_drop(adapter);
		break;
	case ixgbe_fc_none:
		adapter->hw.fc.requested_mode = ixgbe_fc_none;
		if (adapter->num_rx_queues > 1)
			ixgbe_enable_rx_drop(adapter);
		break;
	default:
		return (EINVAL);
	}

	adapter->fc = fc;
	/* Don't autoneg if forcing a value */
	adapter->hw.fc.disable_fc_autoneg = TRUE;
	ixgbe_fc_enable(&adapter->hw);

	return (0);
} /* ixgbe_set_flowcntl */

/*
** Enable the hardware to drop packets when the buffer is
** full. This is useful when multiqueue,so that no single
** queue being full stalls the entire RX engine. We only
** enable this when Multiqueue AND when Flow Control is 
** disabled.
*/
static void
ixgbe_enable_rx_drop(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	for (int i = 0; i < adapter->num_rx_queues; i++) {
		struct rx_ring *rxr = &adapter->rx_queues[i].rxr;
		u32 srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(rxr->me));
		srrctl |= IXGBE_SRRCTL_DROP_EN;
		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(rxr->me), srrctl);
	}
#ifdef PCI_IOV
	/* enable drop for each vf */
	for (int i = 0; i < adapter->num_vfs; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_QDE,
						(IXGBE_QDE_WRITE | (i << IXGBE_QDE_IDX_SHIFT) |
						 IXGBE_QDE_ENABLE));
	}
#endif      	
}

static void
ixgbe_disable_rx_drop(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	for (int i = 0; i < adapter->num_rx_queues; i++) {
		struct rx_ring *rxr = &adapter->rx_queues[i].rxr;
		u32 srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(rxr->me));
		srrctl &= ~IXGBE_SRRCTL_DROP_EN;
		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(rxr->me), srrctl);
	}
#ifdef PCI_IOV
	/* disable drop for each vf */
	for (int i = 0; i < adapter->num_vfs; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_QDE,
						(IXGBE_QDE_WRITE | (i << IXGBE_QDE_IDX_SHIFT)));
	}
#endif
}

/*
** Control advertised link speed:
**	Flags:
**	0x1 - advertise 100 Mb
**	0x2 - advertise 1G
**	0x4 - advertise 10G
*/
static int
ixgbe_sysctl_advertise(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter;
	int            error, advertise;

	adapter = (struct adapter *)arg1;
	advertise = adapter->advertise;

	error = sysctl_handle_int(oidp, &advertise, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	/* Checks to validate new value */
	if (adapter->advertise == advertise) /* no change */
		return (0);

	return ixgbe_set_advertise(adapter, advertise);
} /* ixgbe_sysctl_advertise */

/************************************************************************
 * ixgbe_set_advertise - Control advertised link speed
 *
 *   Flags:
 *     0x1 - advertise 100 Mb
 *     0x2 - advertise 1G
 *     0x4 - advertise 10G
 *     0x8 - advertise 10 Mb (yes, Mb)
 ************************************************************************/
static int
ixgbe_set_advertise(struct adapter *adapter, int advertise)
{
	device_t		dev = iflib_get_dev(adapter->ctx);
	struct ixgbe_hw		*hw;
	ixgbe_link_speed	speed = 0;
	int err, link_caps;
	bool negotiate;

	hw = &adapter->hw;
	/* No speed changes for backplane media */
	if (hw->phy.media_type == ixgbe_media_type_backplane)
		return (ENODEV);

	if (!((hw->phy.media_type == ixgbe_media_type_copper) ||
		  (hw->phy.multispeed_fiber))) {
		device_printf(dev, "Advertised speed can only be set on copper or "
			      "multispeed fiber media types.\n");
		return (EINVAL);
	}

	if (advertise < 0x1 || advertise > 0x7) {
		device_printf(dev, "Invalid advertised speed; valid modes are 0x1 through 0x7\n");
		return (EINVAL);
	}

	if (hw->mac.ops.get_link_capabilities) {
		err = hw->mac.ops.get_link_capabilities(hw, &link_caps,
		    &negotiate);
		if (err != IXGBE_SUCCESS) {
			device_printf(dev, "Unable to determine supported advertise speeds\n");
			return (ENODEV);
		}
	}

	/* Set new value and report new advertised mode */
	if (advertise & 0x1) {
		if (!(link_caps & IXGBE_LINK_SPEED_100_FULL)) {
			device_printf(dev, "Interface does not support 100Mb advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_100_FULL;
	}
	if (advertise & 0x2) {
		if (!(link_caps & IXGBE_LINK_SPEED_1GB_FULL)) {
			device_printf(dev, "Interface does not support 1Gb advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_1GB_FULL;
	}
	if (advertise & 0x4) {
		if (!(link_caps & IXGBE_LINK_SPEED_10GB_FULL)) {
			device_printf(dev, "Interface does not support 10Gb advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_10GB_FULL;
	}
	if (advertise & 0x8) {
		if (!(link_caps & IXGBE_LINK_SPEED_10_FULL)) {
			device_printf(dev, "Interface does not support 10Mb advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_10_FULL;
	}

	hw->mac.autotry_restart = TRUE;
	hw->mac.ops.setup_link(hw, speed, TRUE);
	adapter->advertise = advertise;

	return (0);
}

/** Thermal Shutdown Trigger (internal MAC)
 **   - Set this to 1 to cause an overtemp event to occur
 */
static int
ixgbe_sysctl_thermal_test(SYSCTL_HANDLER_ARGS)
{
	struct adapter	*adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	int error, link_caps, fire = 0;
	bool negotiate;

	error = hw->mac.ops.get_link_capabilities(hw, &link_caps, &negotiate);
	if (error != IXGBE_SUCCESS)
		return (0);

	if (fire) {
	  printf("Warning: Thermal Shutdown trigger\n");
		u32 reg = IXGBE_READ_REG(hw, IXGBE_EICS);
		reg |= IXGBE_EICR_TS;
		IXGBE_WRITE_REG(hw, IXGBE_EICS, reg);
	}

	return (0);
} /* ixgbe_get_advertise */

/* Manage DMA Coalescing.
** Control values:
** 	0/1 - off / on (use default value of 1000)
**
**	Legal timer values are:
**	50,100,250,500,1000,2000,5000,10000
**
**	Turning off interrupt moderation will also turn this off.
*/
static int
ixgbe_sysctl_dmac(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	struct ifnet *ifp = iflib_get_ifp(adapter->ctx);
	int		error;
	u16		newval;

	newval = adapter->dmac;
	error = sysctl_handle_int(oidp, &newval, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	switch (newval) {
	case 0:
		/* Disabled */
		adapter->dmac = 0;
		break;
	case 1: /* Enable and use default */
		adapter->dmac = 1000;
		break;
	case 50:
	case 100:
	case 250:
	case 500:
	case 1000:
	case 2000:
	case 5000:
	case 10000:
		/* Legal values - allow */
		adapter->dmac = newval;
		break;
	default:
		/* Do nothing, illegal value */
		return (EINVAL);
	}

	/* Re-initialize hardware if it's already running */
	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		ifp->if_init(ifp);

	return (0);
}

#ifdef IXGBE_DEBUG
/**
 * Sysctl to test power states
 * Values:
 *	0      - set device to D0
 *	3      - set device to D3
 *	(none) - get current device power state
 */
static int
ixgbe_sysctl_power_state(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	device_t dev =  adapter->dev;
	int curr_ps, new_ps, error = 0;

	curr_ps = new_ps = pci_get_powerstate(dev);

	error = sysctl_handle_int(oidp, &new_ps, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (new_ps == curr_ps)
		return (0);

	if (new_ps == 3 && curr_ps == 0)
		error = DEVICE_SUSPEND(dev);
	else if (new_ps == 0 && curr_ps == 3)
		error = DEVICE_RESUME(dev);
	else
		return (EINVAL);

	device_printf(dev, "New state: %d\n", pci_get_powerstate(dev));

	return (error);
}
#endif

/*
 * Read-only sysctl indicating whether EEE support was negotiated
 * on the link.
 */
static int
ixgbe_sysctl_eee_negotiated(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	bool status;

	status = !!(IXGBE_READ_REG(hw, IXGBE_EEE_STAT) & IXGBE_EEE_STAT_NEG);

	return (0);
} /* ixgbe_sysctl_dmac */

#ifdef IXGBE_DEBUG
/************************************************************************
 * ixgbe_sysctl_power_state
 *
 *   Sysctl to test power states
 *   Values:
 *     0      - set device to D0
 *     3      - set device to D3
 *     (none) - get current device power state
 ************************************************************************/
static int
ixgbe_sysctl_power_state(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *)arg1;
	device_t       dev = adapter->dev;
	int            curr_ps, new_ps, error = 0;

	status = !!(IXGBE_READ_REG(hw, IXGBE_EEE_STAT) &
				IXGBE_EEE_RX_LPI_STATUS);

	error = sysctl_handle_int(oidp, &new_ps, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (new_ps == curr_ps)
		return (0);

	status = !!(IXGBE_READ_REG(hw, IXGBE_EEE_STAT) &
				IXGBE_EEE_TX_LPI_STATUS);

	device_printf(dev, "New state: %d\n", pci_get_powerstate(dev));

	return (error);
} /* ixgbe_sysctl_power_state */
#endif

/************************************************************************
 * ixgbe_sysctl_wol_enable
 *
 *   Sysctl to enable/disable the WoL capability,
 *   if supported by the adapter.
 *
 *   Values:
 *     0 - disabled
 *     1 - enabled
 ************************************************************************/
static int
ixgbe_sysctl_wol_enable(SYSCTL_HANDLER_ARGS)
{
	struct adapter  *adapter = (struct adapter *)arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	int             new_wol_enabled;
	int             error = 0;

	new_wol_enabled = hw->wol_enabled;
	error = sysctl_handle_int(oidp, &new_wol_enabled, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);
	new_wol_enabled = !!(new_wol_enabled);
	if (new_wol_enabled == hw->wol_enabled)
		return (0);

	if (new_wol_enabled > 0 && !adapter->wol_support)
		return (ENODEV);
	else
		hw->wol_enabled = new_wol_enabled;

	return (0);
} /* ixgbe_sysctl_wol_enable */

/*
 * Read-only sysctl indicating whether RX Link is in LPI state.
 */
static int
ixgbe_sysctl_eee_rx_lpi_status(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	bool status;

	status = !!(IXGBE_READ_REG(hw, IXGBE_EEE_STAT) &
				IXGBE_EEE_RX_LPI_STATUS);

	return (sysctl_handle_int(oidp, 0, status, req));
}

/*
 * Read-only sysctl indicating whether TX Link is in LPI state.
 */
static int
ixgbe_sysctl_eee_tx_lpi_status(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	bool status;

	status = !!(IXGBE_READ_REG(hw, IXGBE_EEE_STAT) &
				IXGBE_EEE_TX_LPI_STATUS);

	return (sysctl_handle_int(oidp, 0, status, req));
}

/*
 * Read-only sysctl indicating TX Link LPI delay
 */
static int
ixgbe_sysctl_eee_tx_lpi_delay(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 reg;

	reg = IXGBE_READ_REG(hw, IXGBE_EEE_SU);

	return (sysctl_handle_int(oidp, 0, reg >> 26, req));
}

/************************************************************************
 * ixgbe_sysctl_wufc - Wake Up Filter Control
 *
 *   Sysctl to enable/disable the types of packets that the
 *   adapter will wake up on upon receipt.
 *   Flags:
 *     0x1  - Link Status Change
 *     0x2  - Magic Packet
 *     0x4  - Direct Exact
 *     0x8  - Directed Multicast
 *     0x10 - Broadcast
 *     0x20 - ARP/IPv4 Request Packet
 *     0x40 - Direct IPv4 Packet
 *     0x80 - Direct IPv6 Packet
 *
 *   Settings not listed above will cause the sysctl to return an error.
 ************************************************************************/
static int
ixgbe_sysctl_wufc(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *)arg1;
	int            error = 0;
	u32            new_wufc;

	new_wufc = adapter->wufc;

	error = sysctl_handle_int(oidp, &new_wufc, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);
	if (new_wufc == adapter->wufc)
		return (0);

	if (new_wufc & 0xffffff00)
		return (EINVAL);

	new_wufc &= 0xff;
	new_wufc |= (0xffffff & adapter->wufc);
	adapter->wufc = new_wufc;

	return (0);
} /* ixgbe_sysctl_wufc */


#ifdef IXGBE_DEBUG
/************************************************************************
 * ixgbe_sysctl_print_rss_config
 ************************************************************************/
static int
ixgbe_sysctl_print_rss_config(SYSCTL_HANDLER_ARGS)
{
	struct adapter  *adapter = (struct adapter *)arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	device_t        dev = adapter->dev;
	struct sbuf     *buf;
	int             error = 0, reta_size;
	u32             reg;

	buf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	if (!buf) {
		device_printf(dev, "Could not allocate sbuf for output.\n");
		return (ENOMEM);
	}

	// TODO: use sbufs to make a string to print out
	/* Set multiplier for RETA setup and table size based on MAC */
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		reta_size = 128;
		break;
	default:
		reta_size = 32;
		break;
	}

	/* Print out the redirection table */
	sbuf_cat(buf, "\n");
	for (int i = 0; i < reta_size; i++) {
		if (i < 32) {
			reg = IXGBE_READ_REG(hw, IXGBE_RETA(i));
			sbuf_printf(buf, "RETA(%2d): 0x%08x\n", i, reg);
		} else {
			reg = IXGBE_READ_REG(hw, IXGBE_ERETA(i - 32));
			sbuf_printf(buf, "ERETA(%2d): 0x%08x\n", i - 32, reg);
		}
	}

	// TODO: print more config

	error = sbuf_finish(buf);
	if (error)
		device_printf(dev, "Error finishing sbuf: %d\n", error);

	sbuf_delete(buf);

	return (0);
} /* ixgbe_sysctl_print_rss_config */
#endif /* IXGBE_DEBUG */

/*
 * The following two sysctls are for X550 BaseT devices;
 * they deal with the external PHY used in them.
 */
static int
ixgbe_sysctl_phy_temp(SYSCTL_HANDLER_ARGS)
{
	struct adapter	*adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	u16 reg;

	if (hw->device_id != IXGBE_DEV_ID_X550EM_X_10G_T) {
	  device_printf(iflib_get_dev(adapter->ctx),
					  "Device has no supported external thermal sensor.\n");
		return (ENODEV);
	}

	if (hw->phy.ops.read_reg(hw, IXGBE_PHY_CURRENT_TEMP,
							 IXGBE_MDIO_VENDOR_SPECIFIC_1_DEV_TYPE,
							 &reg)) {
	  device_printf(iflib_get_dev(adapter->ctx),
					  "Error reading from PHY's current temperature register\n");
		return (EAGAIN);
	}

	/* Shift temp for output */
	reg = reg >> 8;

	return (sysctl_handle_int(oidp, NULL, reg, req));
} 

/*
 * Sysctl to enable/disable the Energy Efficient Ethernet capability,
 * if supported by the adapter.
 * Values:
 *	0 - disabled
 *	1 - enabled
 */
static int
ixgbe_sysctl_eee_enable(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *) arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	struct ifnet *ifp = iflib_get_ifp(adapter->ctx);
	int new_eee_enabled, error = 0;

	new_eee_enabled = adapter->eee_enabled;
	error = sysctl_handle_int(oidp, &new_eee_enabled, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);
	new_eee_enabled = !!(new_eee_enabled);
	if (new_eee_enabled == adapter->eee_enabled)
		return (0);

	if (new_eee_enabled > 0 && !hw->mac.ops.setup_eee)
		return (ENODEV);
	else
		adapter->eee_enabled = new_eee_enabled;

	/* Re-initialize hardware if it's already running */
	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		ifp->if_init(ifp);

	return (0);
}

/************************************************************************
 * ixgbe_sysctl_phy_overtemp_occurred
 *
 *   Reports (directly from the PHY) whether the current PHY
 *   temperature is over the overtemp threshold.
 ************************************************************************/
static int
ixgbe_sysctl_phy_overtemp_occurred(SYSCTL_HANDLER_ARGS)
{
	struct adapter  *adapter = (struct adapter *)arg1;
	struct ixgbe_hw *hw = &adapter->hw;
	u16             reg;

	if (hw->device_id != IXGBE_DEV_ID_X550EM_X_10G_T) {
		device_printf(adapter->dev,
		    "Device has no supported external thermal sensor.\n");
		return (ENODEV);
	}

	if (hw->phy.ops.read_reg(hw, IXGBE_PHY_OVERTEMP_STATUS,
	    IXGBE_MDIO_VENDOR_SPECIFIC_1_DEV_TYPE, &reg)) {
		device_printf(adapter->dev,
		    "Error reading from PHY's temperature status register\n");
		return (EAGAIN);
	}

	/* Get occurrence bit */
	reg = !!(reg & 0x4000);

	return (sysctl_handle_int(oidp, 0, reg, req));
} /* ixgbe_sysctl_phy_overtemp_occurred */
#ifdef notyet
/* XXX add sysctl */
/************************************************************************
 * ixgbe_sysctl_eee_state
 *
 *   Sysctl to set EEE power saving feature
 *   Values:
 *     0      - disable EEE
 *     1      - enable EEE
 *     (none) - get current device EEE state
 ************************************************************************/
static int
ixgbe_sysctl_eee_state(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter = (struct adapter *)arg1;
	device_t       dev = adapter->dev;
	int            curr_eee, new_eee, error = 0;
	s32            retval;

	curr_eee = new_eee = !!(adapter->feat_en & IXGBE_FEATURE_EEE);

	error = sysctl_handle_int(oidp, &new_eee, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	/* Nothing to do */
	if (new_eee == curr_eee)
		return (0);

	/* Not supported */
	if (!(adapter->feat_cap & IXGBE_FEATURE_EEE))
		return (EINVAL);

	/* Bounds checking */
	if ((new_eee < 0) || (new_eee > 1))
		return (EINVAL);

	retval = adapter->hw.mac.ops.setup_eee(&adapter->hw, new_eee);
	if (retval) {
		device_printf(dev, "Error in EEE setup: 0x%08X\n", retval);
		return (EINVAL);
	}

	/* Restart auto-neg */
	ixgbe_if_init(adapter->ctx);

	device_printf(dev, "New EEE state: %d\n", new_eee);
	return (0);
}

/************************************************************************
 * ixgbe_check_fan_failure
 ************************************************************************/
static void
ixgbe_check_fan_failure(struct adapter *adapter, u32 reg, bool in_interrupt)
{
	u32 mask;

	mask = (in_interrupt) ? IXGBE_EICR_GPI_SDP1_BY_MAC(&adapter->hw) :
	    IXGBE_ESDP_SDP1;

	if (reg & mask)
		device_printf(adapter->dev, "\nCRITICAL: FAN FAILURE!! REPLACE IMMEDIATELY!!\n");
} /* ixgbe_check_fan_failure */

#endif

/************************************************************************
 * ixgbe_rearm_queues
 ************************************************************************/
static void
ixgbe_rearm_queues(struct adapter *adapter, u64 queues)
{
	u32 mask;

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
		mask = (IXGBE_EIMS_RTX_QUEUE & queues);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EICS, mask);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		mask = (queues & 0xFFFFFFFF);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EICS_EX(0), mask);
		mask = (queues >> 32);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EICS_EX(1), mask);
		break;
	default:
		break;
	}
} /* ixgbe_rearm_queues */

