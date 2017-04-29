/*-
 * Copyright (c) 2008-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Lawrence Stewart while studying at the Centre
 * for Advanced Internet Architectures, Swinburne University of Technology, made
 * possible in part by a grant from the Cisco University Research Program Fund
 * at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * An implementation of the CUBIC congestion control algorithm for FreeBSD,
 * based on the Internet Draft "draft-rhee-tcpm-cubic-02" by Rhee, Xu and Ha.
 * Originally released as part of the NewTCP research project at Swinburne
 * University of Technology's Centre for Advanced Internet Architectures,
 * Melbourne, Australia, which was made possible in part by a grant from the
 * Cisco University Research Program Fund at Community Foundation Silicon
 * Valley. More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/vnet.h>

#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/cc/cc.h>
#include <netinet/cc/cc_cubic.h>
#include <netinet/cc/cc_module.h>

static void	cubic_ack_received(struct cc_var *ccv, uint16_t type);
static void	cubic_cb_destroy(struct cc_var *ccv);
static int	cubic_cb_init(struct cc_var *ccv);
static void	cubic_cong_signal(struct cc_var *ccv, uint32_t type);
static void	cubic_conn_init(struct cc_var *ccv);
static int	cubic_mod_init(void);
static void	cubic_post_recovery(struct cc_var *ccv);
static void	cubic_record_rtt(struct cc_var *ccv);
static void	cubic_ssthresh_update(struct cc_var *ccv);

struct cubic {
	/* Cubic K in fixed point form with CUBIC_SHIFT worth of precision. */
	int64_t		K;
	/* Sum of RTT samples across an epoch in ticks. */
	int64_t		sum_rtt_ticks;
	/* cwnd at the most recent congestion event. */
	unsigned long	max_cwnd;
	/* cwnd at the previous congestion event. */
	unsigned long	prev_max_cwnd;
	/* Number of congestion events. */
	uint32_t	num_cong_events;
	/* Minimum observed rtt in ticks. */
	int		min_rtt_ticks;
	/* Mean observed rtt between congestion epochs. */
	int		mean_rtt_ticks;
	/* ACKs since last congestion event. */
	int		epoch_ack_count;
	/* Time of last congestion event in ticks. */
	int		t_last_cong;

	/* Hybrid Slow Start values */

	/* Minimum observed rtt in ms. */
	int		min_rtt_ms;
	/* number of samples taken since start of packet train */
	uint8_t		sample_count;
	/* an early exit condition for hybrid slow start has been found */
	uint8_t		exit_found;
	/* start of hybrid slow start packet train */
	uint32_t	train_start;
	/* value of snd_nxt at reset - used to determine ack value of next reset */
	uint32_t	end_seq;
	/* millisecond granularity value of timestamp at the prior ack */
	uint32_t	last_ack;
	/* the smallest measured RTT within the first HYSTART_MIN_SAMPLES (8) */
	uint32_t	curr_rtt;

	/* assume hz == 1000 for first pass */
	#define	min_rtt_ms	min_rtt_ticks
};

#define USEC_PER_MSEC		1000

#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)

static inline int
clamp(int x, int min, int max) {

	if (x < min)
		return min;
	if (x > max)
		return max;
	return x;
}

#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX) 


SYSCTL_NODE(_net_inet_tcp_cc, OID_AUTO, cubic, CTLFLAG_RW, NULL,
    "cubic congestion control related settings");

//static int hystart = 1;
static int hystart_detect = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window = 16;
static int hystart_ack_delta = 2;

static MALLOC_DEFINE(M_CUBIC, "cubic data",
    "Per connection data required for the CUBIC congestion control algorithm");

struct cc_algo cubic_cc_algo = {
	.name = "cubic",
	.ack_received = cubic_ack_received,
	.cb_destroy = cubic_cb_destroy,
	.cb_init = cubic_cb_init,
	.cong_signal = cubic_cong_signal,
	.conn_init = cubic_conn_init,
	.mod_init = cubic_mod_init,
	.post_recovery = cubic_post_recovery,
};

static void
cubic_ack_received(struct cc_var *ccv, uint16_t type)
{
	struct cubic *cubic_data;
	unsigned long w_tf, w_cubic_next, snd_cwnd, mss;
	int ticks_since_cong;

	cubic_data = ccv->cc_data;
	cubic_record_rtt(ccv);
	mss = CCV(ccv, t_maxseg);
	snd_cwnd = CCV(ccv, snd_cwnd);

	/* Regular ACK */
	if (type != CC_ACK)
		return;
	/* we're not in cong/fast recovery */
	if (IN_RECOVERY(CCV(ccv, t_flags)))
		return;
	/* we're cwnd limited */
	if (!(ccv->flags & CCF_CWND_LIMITED))
		return;

	/* we are slow starting or have no minimum RTT sampled */
	if (snd_cwnd <= CCV(ccv, snd_ssthresh) ||
	    cubic_data->min_rtt_ticks == TCPTV_SRTTBASE) {
		/* Use the logic in NewReno ack_received() for slow start. */
		newreno_cc_algo.ack_received(ccv, type);
		if (snd_cwnd < CCV(ccv, snd_ssthresh))
			return;
	}

	/*
	 * We're either not doing ABC or doing ABC and we've sent a cwnd's
	 * worth of bytes
	 */
	if (V_tcp_do_rfc3465 && !(ccv->flags & CCF_ABC_SENTAWND))
		return;

	ticks_since_cong = ticks - cubic_data->t_last_cong;

	/*
	 * The mean RTT is used to best reflect the equations in
	 * the I-D. Using min_rtt in the tf_cwnd calculation
	 * causes w_tf to grow much faster than it should if the
	 * RTT is dominated by network buffering rather than
	 * propagation delay.
	 */
	w_tf = tf_cwnd(ticks_since_cong,
		       cubic_data->mean_rtt_ticks, cubic_data->max_cwnd,
		       CCV(ccv, t_maxseg));

	w_cubic_next = cubic_cwnd(ticks_since_cong +
				  cubic_data->mean_rtt_ticks, cubic_data->max_cwnd,
				  CCV(ccv, t_maxseg), cubic_data->K);

	ccv->flags &= ~CCF_ABC_SENTAWND;

	if (w_cubic_next < w_tf)
		/*
		 * TCP-friendly region, follow tf
		 * cwnd growth.
		 */
		CCV(ccv, snd_cwnd) = w_tf;

	else if (CCV(ccv, snd_cwnd) < w_cubic_next) {
		/*
		 * Concave or convex region, follow CUBIC
		 * cwnd growth.
		 */
		if (V_tcp_do_rfc3465)
			CCV(ccv, snd_cwnd) = w_cubic_next;
		else
			CCV(ccv, snd_cwnd) += ((w_cubic_next -
						CCV(ccv, snd_cwnd)) *
					       CCV(ccv, t_maxseg)) /
				CCV(ccv, snd_cwnd);
	}

	/*
	 * If we're not in slow start and we're probing for a
	 * new cwnd limit at the start of a connection
	 * (happens when hostcache has a relevant entry),
	 * keep updating our current estimate of the
	 * max_cwnd.
	 */
	if (cubic_data->num_cong_events == 0 &&
	    cubic_data->max_cwnd < CCV(ccv, snd_cwnd))
		cubic_data->max_cwnd = CCV(ccv, snd_cwnd);
}

static void
cubic_cb_destroy(struct cc_var *ccv)
{

	if (ccv->cc_data != NULL)
		free(ccv->cc_data, M_CUBIC);
}

static int
cubic_cb_init(struct cc_var *ccv)
{
	struct cubic *cubic_data = ccv->cc_data;

	if (cubic_data == NULL)
		cubic_data = malloc(sizeof(struct cubic), M_CUBIC, M_NOWAIT|M_ZERO);
	if (cubic_data == NULL)
		return (ENOMEM);

	/* Init some key variables with sensible defaults. */
	cubic_data->t_last_cong = ticks;
	cubic_data->min_rtt_ticks = TCPTV_SRTTBASE;
	cubic_data->mean_rtt_ticks = 1;

	ccv->cc_data = cubic_data;

	return (0);
}

static inline uint32_t
cubic_clock(void)
{
	if (hz == 1000)
		return (ticks);

	return (((ticks + hz) * 1000)/hz);
}

static void
cubic_hystart_init(struct cc_var *ccv)
{
	struct cubic *cd;

	cd = ccv->cc_data;
	cd->train_start = cd->last_ack = cubic_clock();
	cd->end_seq = CCV(ccv, snd_nxt);
	cd->curr_rtt = 0;
	cd->sample_count = cd->exit_found = 0;
}

static void
cubic_hystart_update(struct cc_var *ccv, uint32_t delay)
{
	struct cubic *cd;
	uint32_t now;

	cd = ccv->cc_data;

	if (cd->exit_found & hystart_detect)
		return;

	if (CCV(ccv, snd_cwnd) < hystart_low_window)
		return;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		now = cubic_clock();
		if ((int32_t)(now - cd->last_ack) <= hystart_ack_delta) {
			cd->last_ack = now;
			if ((int32_t)(now - cd->train_start) > cd->min_rtt_ms >> 4) {
				cd->exit_found |= HYSTART_ACK_TRAIN;
				CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd);

			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		if (cd->sample_count < HYSTART_MIN_SAMPLES) {
			if (cd->curr_rtt == 0 || cd->curr_rtt > delay)
				cd->curr_rtt = delay;
			cd->sample_count++;
		} else {
			if (cd->curr_rtt > cd->min_rtt_ms + HYSTART_DELAY_THRESH(cd->min_rtt_ms >> 3)) {
				cd->exit_found |= HYSTART_DELAY;
				CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd);
			}
		}
	}
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
cubic_cong_signal(struct cc_var *ccv, uint32_t type)
{
	struct cubic *cubic_data;
	uint32_t cwin;
	u_int mss;

	cubic_data = ccv->cc_data;
	cwin = CCV(ccv, snd_cwnd);
	mss = CCV(ccv, t_maxseg);

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(CCV(ccv, t_flags))) {
			if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
				cubic_ssthresh_update(ccv);
				cubic_data->num_cong_events++;
				cubic_data->prev_max_cwnd = cubic_data->max_cwnd;
				cubic_data->max_cwnd = cwin;
				CCV(ccv, snd_cwnd) = CCV(ccv, snd_ssthresh);
			}
			ENTER_RECOVERY(CCV(ccv, t_flags));
		}
		break;

	case CC_ECN:
		if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
			cubic_ssthresh_update(ccv);
			cubic_data->num_cong_events++;
			cubic_data->prev_max_cwnd = cubic_data->max_cwnd;
			cubic_data->max_cwnd = cwin;
			cubic_data->t_last_cong = ticks;
			CCV(ccv, snd_cwnd) = CCV(ccv, snd_ssthresh);
			ENTER_CONGRECOVERY(CCV(ccv, t_flags));
		}
		break;

	case CC_RTO:
		/*
		 * Grab the current time and record it so we know when the
		 * most recent congestion event was. Only record it when the
		 * timeout has fired more than once, as there is a reasonable
		 * chance the first one is a false alarm and may not indicate
		 * congestion.
		 */
		if (CCV(ccv, t_rxtshift) >= 2) {
			cubic_data->num_cong_events++;
			cubic_data->t_last_cong = ticks;
			cubic_ssthresh_update(ccv);
			cubic_data->max_cwnd = cwin;
			CCV(ccv, snd_cwnd) = mss;
		}
		break;
	}
}

static void
cubic_conn_init(struct cc_var *ccv)
{
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/*
	 * Ensure we have a sane initial value for max_cwnd recorded. Without
	 * this here bad things happen when entries from the TCP hostcache
	 * get used.
	 */
	cubic_data->max_cwnd = CCV(ccv, snd_cwnd);
}

static int
cubic_mod_init(void)
{

	cubic_cc_algo.after_idle = newreno_cc_algo.after_idle;

	return (0);
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
static void
cubic_post_recovery(struct cc_var *ccv)
{
	struct cubic *cubic_data;
	int pipe;

	cubic_data = ccv->cc_data;
	pipe = 0;

	/* Fast convergence heuristic. */
	if (cubic_data->max_cwnd < cubic_data->prev_max_cwnd)
		cubic_data->max_cwnd = (cubic_data->max_cwnd * CUBIC_FC_FACTOR)
		    >> CUBIC_SHIFT;

	if (IN_FASTRECOVERY(CCV(ccv, t_flags))) {
		/*
		 * If inflight data is less than ssthresh, set cwnd
		 * conservatively to avoid a burst of data, as suggested in
		 * the NewReno RFC. Otherwise, use the CUBIC method.
		 *
		 * XXXLAS: Find a way to do this without needing curack
		 */
		if (V_tcp_do_rfc6675_pipe)
			pipe = tcp_compute_pipe(ccv->ccvc.tcp);
		else
			pipe = CCV(ccv, snd_max) - ccv->curack;

		if (pipe < CCV(ccv, snd_ssthresh))
			CCV(ccv, snd_cwnd) = pipe + CCV(ccv, t_maxseg);
		else
			/* Update cwnd based on beta and adjusted max_cwnd. */
			CCV(ccv, snd_cwnd) = max(1, ((CUBIC_BETA *
			    cubic_data->max_cwnd) >> CUBIC_SHIFT));
	}
	cubic_data->t_last_cong = ticks;

	/* Calculate the average RTT between congestion epochs. */
	if (cubic_data->epoch_ack_count > 0 &&
	    cubic_data->sum_rtt_ticks >= cubic_data->epoch_ack_count) {
		cubic_data->mean_rtt_ticks = (int)(cubic_data->sum_rtt_ticks /
		    cubic_data->epoch_ack_count);
	}

	cubic_data->epoch_ack_count = 0;
	cubic_data->sum_rtt_ticks = 0;
	cubic_data->K = cubic_k(cubic_data->max_cwnd / CCV(ccv, t_maxseg));
}

/*
 * Record the min RTT and sum samples for the epoch average RTT calculation.
 */
static void
cubic_record_rtt(struct cc_var *ccv)
{
	struct cubic *cubic_data;
	int t_srtt_ticks;
	int rtt_us, rtt_s3_ms;

	cubic_data = ccv->cc_data;
	if (ccv->sample_rtt_us >= 0) {
		rtt_us = ccv->sample_rtt_us;
		rtt_s3_ms = (rtt_us << 3)/USEC_PER_MSEC;
		if (SEQ_GT(ccv->curack, cubic_data->end_seq))
			cubic_hystart_init(ccv);

		cubic_hystart_update(ccv, rtt_s3_ms);
	}

	/* Ignore srtt until a min number of samples have been taken. */
	if (CCV(ccv, t_rttupdated) >= CUBIC_MIN_RTT_SAMPLES) {
		t_srtt_ticks = CCV(ccv, t_srtt) / TCP_RTT_SCALE;

		/*
		 * Record the current SRTT as our minrtt if it's the smallest
		 * we've seen or minrtt is currently equal to its initialised
		 * value.
		 *
		 * XXXLAS: Should there be some hysteresis for minrtt?
		 */
		if ((t_srtt_ticks < cubic_data->min_rtt_ticks ||
		    cubic_data->min_rtt_ticks == TCPTV_SRTTBASE)) {
			cubic_data->min_rtt_ticks = max(1, t_srtt_ticks);

			/*
			 * If the connection is within its first congestion
			 * epoch, ensure we prime mean_rtt_ticks with a
			 * reasonable value until the epoch average RTT is
			 * calculated in cubic_post_recovery().
			 */
			if (cubic_data->min_rtt_ticks >
			    cubic_data->mean_rtt_ticks)
				cubic_data->mean_rtt_ticks =
				    cubic_data->min_rtt_ticks;
		}

		/* Sum samples for epoch average RTT calculation. */
		cubic_data->sum_rtt_ticks += t_srtt_ticks;
		cubic_data->epoch_ack_count++;
	}
}

/*
 * Update the ssthresh in the event of congestion.
 */
static void
cubic_ssthresh_update(struct cc_var *ccv)
{
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/*
	 * On the first congestion event, set ssthresh to cwnd * 0.5, on
	 * subsequent congestion events, set it to cwnd * beta.
	 */
	if (cubic_data->num_cong_events == 0)
		CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd) >> 1;
	else
		CCV(ccv, snd_ssthresh) = ((u_long)CCV(ccv, snd_cwnd) *
		    CUBIC_BETA) >> CUBIC_SHIFT;
}


DECLARE_CC_MODULE(cubic, &cubic_cc_algo);
